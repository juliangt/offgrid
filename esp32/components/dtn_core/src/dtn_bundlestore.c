/* dtn_bundlestore.c — the node-plane bundle store on flash. See
 * dtn_bundlestore.h. Semantics mirror node/internal/forward/store.go
 * step for step (docs/node-network.md §7.5): parse fail-closed, the §3.1
 * hop ceiling, local expiry (P-6), dedup by bundle_id (P-7), the §7.3
 * classification, the §7.5 cap with the priority-aware eviction rule
 * (lowest-priority class first, soonest-expiring within it, deterministic
 * tie-breaks), and the TTL janitor. Pinned to Go by the shared forward
 * vectors. */
#include "dtn_bundlestore.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- CRC-32 (IEEE 802.3 / zlib poly 0xEDB88320; the dtn_store frame CRC) */
static uint32_t bstore_crc32(const void *data, size_t n)
{
    static uint32_t table[256];
    static bool have_table;
    if (!have_table) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) {
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            }
            table[i] = c;
        }
        have_table = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p = data;
    while (n--) {
        crc = table[(crc ^ *p++) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ---- log framing: [magic u32][type u32][len u32][crc32 u32] body ----
 * Little-endian fields, host order — the store is the only reader/writer
 * and is endian-stable per device (the dtn_store convention). */
#define BSTORE_MAGIC 0x4C475442u /* "BTGL" */
#define BSTORE_HDR 16
#define BSTORE_MAX_BODY (256u * 1024u)

enum { REC_BPUT = 1, REC_BDEL = 2 };

/* BPUT body: id(32) class(1) hop(1) expires_at(i64) received_at(i64)
 * pdu_len(u32) pdu. */
#define BPUT_FIXED 54

typedef struct {
    uint8_t id[DTN_BUNDLE_ID_LEN];
    int64_t expires_at;
    int64_t received_at;
    uint32_t off; /* frame offset in bundles.log */
    uint32_t len; /* full frame length (HDR + body) */
    uint8_t cls;
    bool used;
} bslot;

struct dtn_bundlestore {
    char path[256];
    int32_t cap;
    FILE *log; /* append + read handle */
    bslot *slots;
    int32_t live;
    int64_t dead_bytes;
    int64_t live_bytes;
    dtn_bstore_counters counters;
};

static int32_t slot_find(const dtn_bundlestore *st, const uint8_t id[DTN_BUNDLE_ID_LEN])
{
    for (int32_t i = 0; i < st->cap; i++) {
        if (st->slots[i].used && memcmp(st->slots[i].id, id, DTN_BUNDLE_ID_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

static int32_t slot_free(const dtn_bundlestore *st)
{
    for (int32_t i = 0; i < st->cap; i++) {
        if (!st->slots[i].used) {
            return i;
        }
    }
    return -1;
}

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static int64_t rd_i64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return (int64_t)v;
}

static void wr_i64(uint8_t *p, int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(u >> (8 * i));
    }
}

/* frame_write appends one CRC-framed record. Returns 0 ok, -1 io. */
static int frame_write(FILE *f, uint32_t type, const void *body, uint32_t len)
{
    uint8_t hdr[BSTORE_HDR];
    uint32_t crc = bstore_crc32(body, len);
    wr_u32(hdr + 0, BSTORE_MAGIC);
    wr_u32(hdr + 4, type);
    wr_u32(hdr + 8, len);
    wr_u32(hdr + 12, crc);
    if (fwrite(hdr, 1, BSTORE_HDR, f) != BSTORE_HDR) {
        return -1;
    }
    if (len && fwrite(body, 1, len, f) != len) {
        return -1;
    }
    return 0;
}

/* frame_read reads the next frame; *type receives the record type and body
 * (malloc'd, caller frees) the payload. Returns 1 ok, 0 clean EOF, -1 torn
 * tail or corrupt frame (the caller truncates at the last full frame). */
static int frame_read(FILE *f, uint32_t *type, uint8_t **body, uint32_t *len)
{
    uint8_t hdr[BSTORE_HDR];
    size_t got = fread(hdr, 1, BSTORE_HDR, f);
    if (got == 0) {
        return 0;
    }
    if (got < BSTORE_HDR || rd_u32(hdr) != BSTORE_MAGIC) {
        return -1;
    }
    *type = rd_u32(hdr + 4);
    *len = rd_u32(hdr + 8);
    uint32_t crc = rd_u32(hdr + 12);
    if (*len > BSTORE_MAX_BODY) {
        return -1;
    }
    uint8_t *buf = malloc(*len ? *len : 1);
    if (!buf) {
        return -1;
    }
    if (*len && fread(buf, 1, *len, f) != *len) {
        free(buf);
        return -1;
    }
    if (bstore_crc32(buf, *len) != crc) {
        free(buf);
        return -1;
    }
    *body = buf;
    return 1;
}

static int log_truncate_at(dtn_bundlestore *st, long off)
{
    if (fflush(st->log) != 0) {
        return -1;
    }
    if (ftruncate(fileno(st->log), off) != 0) {
        return -1;
    }
    return fseek(st->log, 0, SEEK_END) == 0 ? 0 : -1;
}

/* replay scans the log at open: live PUTs into the RAM index, DELs mark
 * unused, a torn tail (power loss mid-append) truncates at the last full
 * frame — the dtn_store power-loss semantics. The read position starts at
 * the file head explicitly: in "a+b" mode the INITIAL read position is
 * implementation-defined, and a head-starting scan is the contract here. */
static int replay(dtn_bundlestore *st)
{
    if (fseek(st->log, 0, SEEK_SET) != 0) {
        return -1;
    }
    for (;;) {
        long frame_off = ftell(st->log);
        uint32_t type, len;
        uint8_t *body = NULL;
        int rc = frame_read(st->log, &type, &body, &len);
        if (rc <= 0) {
            free(body);
            return log_truncate_at(st, frame_off);
        }
        if (type == REC_BPUT && len >= BPUT_FIXED) {
            uint32_t pdu_len = rd_u32(body + 50);
            if (BPUT_FIXED + pdu_len == len) {
                int32_t si = slot_find(st, body);
                if (si < 0) {
                    si = slot_free(st);
                }
                if (si >= 0) {
                    bslot *s = &st->slots[si];
                    memcpy(s->id, body, DTN_BUNDLE_ID_LEN);
                    s->cls = body[32];
                    s->expires_at = rd_i64(body + 34);
                    s->received_at = rd_i64(body + 42);
                    s->off = (uint32_t)frame_off;
                    s->len = (uint32_t)(BSTORE_HDR + len);
                    if (!s->used) {
                        s->used = true;
                        st->live++;
                        st->live_bytes += s->len;
                    }
                }
            }
        } else if (type == REC_BDEL && len == DTN_BUNDLE_ID_LEN) {
            int32_t si = slot_find(st, body);
            if (si >= 0) {
                bslot *s = &st->slots[si];
                s->used = false;
                st->live--;
                st->dead_bytes += s->len;
                st->live_bytes -= s->len;
            }
        }
        free(body);
    }
}

/* read_body fetches the BPUT body of the slot (malloc'd, caller frees). */
static uint8_t *read_body(dtn_bundlestore *st, const bslot *s)
{
    uint32_t full = s->len - BSTORE_HDR;
    uint8_t *body = malloc(full);
    if (!body) {
        return NULL;
    }
    if (fseek(st->log, (long)s->off + BSTORE_HDR, SEEK_SET) != 0 ||
        fread(body, 1, full, st->log) != full) {
        free(body);
        return NULL;
    }
    return body;
}

/* compact rewrites the live PUT records only; the atomic rename keeps the
 * store whole on a crash (the dtn_store pattern). Slot offsets are fixed
 * by a scan of the new log. */
static int compact(dtn_bundlestore *st)
{
    char tmp[sizeof st->path + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", st->path);
    FILE *nf = fopen(tmp, "wb");
    if (!nf) {
        return -1;
    }
    for (int32_t i = 0; i < st->cap; i++) {
        if (!st->slots[i].used) {
            continue;
        }
        uint8_t *body = read_body(st, &st->slots[i]);
        if (!body || frame_write(nf, REC_BPUT, body, st->slots[i].len - BSTORE_HDR) != 0) {
            free(body);
            fclose(nf);
            remove(tmp);
            return -1;
        }
        free(body);
    }
    if (fflush(nf) != 0 || fclose(nf) != 0) {
        remove(tmp);
        return -1;
    }
    fclose(st->log);
    if (rename(tmp, st->path) != 0) {
        st->log = fopen(st->path, "r+b");
        return -1; /* the old store survives; report io */
    }
    st->log = fopen(st->path, "r+b");
    if (!st->log) {
        return -1;
    }
    /* Second pass: fix the slot offsets against the compacted log. */
    for (;;) {
        long frame_off = ftell(st->log);
        uint32_t type, len;
        uint8_t *body = NULL;
        int rc = frame_read(st->log, &type, &body, &len);
        if (rc <= 0) {
            free(body);
            break;
        }
        if (type == REC_BPUT && len >= BPUT_FIXED) {
            int32_t si = slot_find(st, body);
            if (si >= 0) {
                st->slots[si].off = (uint32_t)frame_off;
                st->slots[si].len = (uint32_t)(BSTORE_HDR + len);
            }
        }
        free(body);
    }
    if (fseek(st->log, 0, SEEK_END) != 0) {
        return -1;
    }
    st->dead_bytes = 0;
    st->live_bytes = 0;
    for (int32_t i = 0; i < st->cap; i++) {
        if (st->slots[i].used) {
            st->live_bytes += st->slots[i].len;
        }
    }
    return 0;
}

int dtn_bundlestore_open(dtn_bundlestore **out, const char *dir, int32_t cap)
{
    *out = NULL;
    if (!dir || cap <= 0) {
        return DTN_BSTORE_ERR_ARG;
    }
    mkdir(dir, 0755); /* exists is fine */
    dtn_bundlestore *st = calloc(1, sizeof *st);
    if (!st) {
        return DTN_BSTORE_ERR_IO;
    }
    st->cap = cap;
    if (snprintf(st->path, sizeof st->path, "%s/bundles.log", dir) >= (int)sizeof st->path) {
        free(st);
        return DTN_BSTORE_ERR_ARG;
    }
    st->slots = calloc((size_t)cap, sizeof(bslot));
    if (!st->slots) {
        free(st);
        return DTN_BSTORE_ERR_IO;
    }
    st->log = fopen(st->path, "a+b");
    if (!st->log) {
        free(st->slots);
        free(st);
        return DTN_BSTORE_ERR_IO;
    }
    if (replay(st) != 0) {
        fclose(st->log);
        free(st->slots);
        free(st);
        return DTN_BSTORE_ERR_IO;
    }
    *out = st;
    return DTN_BSTORE_OK;
}

void dtn_bundlestore_close(dtn_bundlestore *st)
{
    if (!st) {
        return;
    }
    if (st->log) {
        fflush(st->log);
        fclose(st->log);
    }
    free(st->slots);
    free(st);
}

dtn_bstore_class dtn_bundlestore_classify(const dtn_bundle_eid *dest,
                                          const dtn_bundle_eid *src)
{
    /* Mirrors forward.Classify: the dest decides management; anonymous
     * source + the og-mail group decides mail; everything else bulk. */
    if (!dest->none && strcmp(dest->authority, "og-admin") == 0) {
        return DTN_BSTORE_CLASS_MGMT;
    }
    if (src->none && !dest->none && strcmp(dest->ssp, "og-mail") == 0) {
        return DTN_BSTORE_CLASS_MAIL;
    }
    return DTN_BSTORE_CLASS_BULK;
}

/* evict_pick selects the evictee slot for an incoming bundle of `cls`
 * (mirror of the Go evictOne ORDER BY: lowest-priority class first, then
 * soonest expiry, then oldest admission, then id ascending — the exact
 * deterministic order the shared vectors pin). Returns the slot index or
 * -1 when nothing may be evicted. */
static int32_t evict_pick(const dtn_bundlestore *st, uint8_t cls,
                          const uint8_t keep[DTN_BUNDLE_ID_LEN])
{
    int32_t best = -1;
    for (int32_t i = 0; i < st->cap; i++) {
        const bslot *s = &st->slots[i];
        if (!s->used || s->cls < cls || memcmp(s->id, keep, DTN_BUNDLE_ID_LEN) == 0) {
            continue;
        }
        if (best < 0) {
            best = i;
            continue;
        }
        const bslot *b = &st->slots[best];
        if (s->cls != b->cls) {
            if (s->cls > b->cls) {
                best = i;
            }
        } else if (s->expires_at != b->expires_at) {
            if (s->expires_at < b->expires_at) {
                best = i;
            }
        } else if (s->received_at != b->received_at) {
            if (s->received_at < b->received_at) {
                best = i;
            }
        } else if (memcmp(s->id, b->id, DTN_BUNDLE_ID_LEN) < 0) {
            best = i;
        }
    }
    return best;
}

static int delete_slot(dtn_bundlestore *st, int32_t si)
{
    uint8_t body[DTN_BUNDLE_ID_LEN];
    bslot *s = &st->slots[si];
    memcpy(body, s->id, DTN_BUNDLE_ID_LEN);
    if (frame_write(st->log, REC_BDEL, body, sizeof body) != 0 || fflush(st->log) != 0) {
        return -1;
    }
    s->used = false;
    st->live--;
    st->dead_bytes += s->len;
    st->live_bytes -= s->len;
    return 0;
}

dtn_bstore_verdict dtn_bundlestore_admit(dtn_bundlestore *st,
                                         const uint8_t *pdu, size_t len,
                                         int64_t now_unix_s)
{
    dtn_bundle b;
    if (!st || !pdu || len == 0) {
        return DTN_BSTORE_AT_CAP; /* argument misuse surfaces as refusal */
    }
    /* 1. Fail-closed profile parse (the P-6 skew rule runs against the
     * local clock — admission's check). */
    if (dtn_bundle_parse(pdu, len, now_unix_s, &b) != DTN_BUNDLE_OK) {
        return DTN_BSTORE_AT_CAP; /* the Go side answers ErrMalformed here */
    }
    /* 2. §3.1 hop ceiling: at the limit the bundle is dead cargo for a v1
     * relay — dropped, counted, acknowledged. */
    if (b.hop >= 7) {
        st->counters.hop_capped++;
        return DTN_BSTORE_HOP_CAPPED;
    }
    /* 3. Local expiry (P-6): expires_at = creation + lifetime, evaluated
     * against the receiver's clock at admission. */
    int64_t expires_at = (int64_t)(b.creation_dtn_ms / 1000) + DTN_BUNDLE_DTN_EPOCH_S +
                         (int64_t)b.lifetime;
    if (expires_at <= now_unix_s) {
        st->counters.expired++;
        return DTN_BSTORE_EXPIRED;
    }
    /* 4. Dedup by the P-7 id (SHA-256 over the PDU after the hop octet). */
    uint8_t id[DTN_BUNDLE_ID_LEN];
    if (dtn_bundle_id(pdu, len, id) != DTN_BUNDLE_OK) {
        return DTN_BSTORE_AT_CAP;
    }
    if (slot_find(st, id) >= 0) {
        st->counters.dup++;
        return DTN_BSTORE_DUP;
    }
    /* 5. Classify (§7.3, EID rules). */
    uint8_t cls = (uint8_t)dtn_bundlestore_classify(&b.destination, &b.source);
    /* 6. Cap + priority-aware eviction. */
    if (st->live >= st->cap) {
        int32_t victim = evict_pick(st, cls, id);
        if (victim < 0) {
            st->counters.at_cap_rejected++;
            return DTN_BSTORE_AT_CAP;
        }
        if (delete_slot(st, victim) != 0) {
            return DTN_BSTORE_AT_CAP;
        }
        st->counters.evicted++;
    }
    /* 7. Append the BPUT record and index it. */
    size_t body_len = BPUT_FIXED + len;
    uint8_t *body = malloc(body_len);
    if (!body) {
        return DTN_BSTORE_AT_CAP;
    }
    long off = ftell(st->log);
    memcpy(body, id, DTN_BUNDLE_ID_LEN);
    body[32] = cls;
    body[33] = b.hop;
    wr_i64(body + 34, expires_at);
    wr_i64(body + 42, now_unix_s);
    wr_u32(body + 50, (uint32_t)len);
    memcpy(body + BPUT_FIXED, pdu, len);
    int rc = frame_write(st->log, REC_BPUT, body, (uint32_t)body_len);
    free(body);
    if (rc != 0 || fflush(st->log) != 0) {
        return DTN_BSTORE_AT_CAP;
    }
    int32_t si = slot_free(st);
    if (si < 0) { /* unreachable: live < cap and every used slot has an id */
        return DTN_BSTORE_AT_CAP;
    }
    bslot *s = &st->slots[si];
    memcpy(s->id, id, DTN_BUNDLE_ID_LEN);
    s->expires_at = expires_at;
    s->received_at = now_unix_s;
    s->off = (uint32_t)off;
    s->len = (uint32_t)(BSTORE_HDR + body_len);
    s->cls = cls;
    s->used = true;
    st->live++;
    st->live_bytes += s->len;
    st->counters.accepted++;
    return DTN_BSTORE_ADMITTED;
}

typedef struct {
    int32_t idx;
    const uint8_t *id;
} live_ent;

static int live_cmp(const void *a, const void *b)
{
    const live_ent *x = a, *y = b;
    return memcmp(x->id, y->id, DTN_BUNDLE_ID_LEN);
}

int dtn_bundlestore_each_live_id(dtn_bundlestore *st, int64_t now_unix_s,
                                 void *cb_ud, dtn_bstore_id_cb cb)
{
    if (!st || !cb) {
        return DTN_BSTORE_ERR_ARG;
    }
    if (st->live == 0) {
        return DTN_BSTORE_OK;
    }
    live_ent *ents = malloc(sizeof(live_ent) * (size_t)st->live);
    if (!ents) {
        return DTN_BSTORE_ERR_IO;
    }
    int32_t n = 0;
    for (int32_t i = 0; i < st->cap; i++) {
        if (st->slots[i].used && st->slots[i].expires_at >= now_unix_s) {
            ents[n].idx = i;
            ents[n].id = st->slots[i].id;
            n++;
        }
    }
    qsort(ents, (size_t)n, sizeof(live_ent), live_cmp);
    for (int32_t i = 0; i < n; i++) {
        cb(cb_ud, st->slots[ents[i].idx].id, st->slots[ents[i].idx].cls);
    }
    free(ents);
    return DTN_BSTORE_OK;
}

int dtn_bundlestore_get_pdu(dtn_bundlestore *st, const uint8_t id[DTN_BUNDLE_ID_LEN],
                            uint8_t *out, size_t cap, size_t *out_len)
{
    if (!st || !id) {
        return DTN_BSTORE_ERR_ARG;
    }
    int32_t si = slot_find(st, id);
    if (si < 0) {
        return 1;
    }
    const bslot *s = &st->slots[si];
    uint32_t full = s->len - BSTORE_HDR;
    if (full < BPUT_FIXED) {
        return DTN_BSTORE_ERR_IO;
    }
    uint8_t *body = read_body(st, s);
    if (!body) {
        return DTN_BSTORE_ERR_IO;
    }
    uint32_t pdu_len = rd_u32(body + 50);
    if (BPUT_FIXED + pdu_len != full) {
        free(body);
        return DTN_BSTORE_ERR_IO;
    }
    if (out_len) {
        *out_len = pdu_len;
    }
    int rc = 0;
    if (!out) {
        rc = 0; /* NULL out = size query */
    } else if (cap < pdu_len) {
        rc = DTN_BSTORE_ERR_IO; /* too small; *out_len carries the need */
    } else {
        memcpy(out, body + BPUT_FIXED, pdu_len);
    }
    free(body);
    return rc;
}

int dtn_bundlestore_janitor(dtn_bundlestore *st, int64_t now_unix_s, int32_t *deleted)
{
    if (!st) {
        return DTN_BSTORE_ERR_ARG;
    }
    int32_t n = 0;
    for (int32_t i = 0; i < st->cap; i++) {
        if (st->slots[i].used && st->slots[i].expires_at < now_unix_s) {
            if (delete_slot(st, i) != 0) {
                return -1;
            }
            n++;
        }
    }
    st->counters.janitor_swept += (uint64_t)n;
    st->counters.expired += (uint64_t)n;
    if (deleted) {
        *deleted = n;
    }
    if (st->dead_bytes > st->live_bytes && (st->dead_bytes + st->live_bytes) > 4096) {
        if (compact(st) != 0) {
            return -1;
        }
    }
    return 0;
}

int32_t dtn_bundlestore_count(const dtn_bundlestore *st)
{
    return st ? st->live : 0;
}

int32_t dtn_bundlestore_cap(const dtn_bundlestore *st)
{
    return st ? st->cap : 0;
}

void dtn_bundlestore_counters(const dtn_bundlestore *st, dtn_bstore_counters *out)
{
    if (out && st) {
        *out = st->counters;
    }
}

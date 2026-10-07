/* dtn_store.c — the §9 storage contract on flash. See dtn_store.h.
 *
 * File layout in the store directory:
 *   super.bin      A/B 64-byte superblock slots (magic, schema version, seq,
 *                  CRC) — the newest VALID slot wins, so a torn superblock
 *                  write never loses the store.
 *   envelopes.log  CRC-framed records: ENV_PUT / ENV_TOMB / BATCH_BEGIN /
 *                  BATCH_COMMIT. Appends are framed; a torn tail (power loss
 *                  mid-append) is truncated at open; an uncommitted batch
 *                  tail is discarded at open — the flash analogue of the Go
 *                  node's single SQLite transaction per sync (§10.4).
 *   directory.log  CRC-framed DIR_UPS records; the latest per pubkey wins.
 *
 * RAM index (docs/esp32-design.md §2/§4): one slot per live envelope — an
 * 8-byte id FINGERPRINT with authoritative on-flash id verification on
 * every dedup/pull hit — plus created_at/deadline/location, so the §10.4
 * pull is a RAM top-K and the §10.6 sweep an index walk. The full store is
 * never resident.
 *
 * Capacity semantics (§8.1): the cap is decided ONCE per batch — a batch
 * arriving at/over the cap is refused whole (429 node_full, nothing
 * stored); a batch admitted below the cap may overshoot it by up to the
 * batch size. Nothing is ever evicted except the TTL janitor.
 *
 * Single-writer, like the Go node's single SQLite connection: the adapter
 * serializes all calls (one task or a mutex). */
#include "dtn_store.h"

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtn_base64.h"

#ifndef DTN_STORE_NO_FSYNC
#include <unistd.h>
#endif

/* ---- CRC-32 (IEEE 802.3 / zlib poly 0xEDB88320; the §4.7 polynomial) ---- */
static uint32_t crc32_buf(const void *data, size_t n)
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

/* ---- on-disk framing ---- */
#define FRAME_MAGIC 0x5444474Cu /* "LGDT" */
#define FRAME_HDR 16
#define MAX_FRAME (64u * 1024u)

enum {
    REC_ENV_PUT = 1,
    REC_ENV_TOMB = 2,
    REC_DIR_UPS = 3,
    REC_BATCH_BEGIN = 4,
    REC_BATCH_COMMIT = 5,
};

/* ENV_PUT record body (little-endian fields, host order — the store is the
 * only reader/writer and is endian-stable per device). */
typedef struct {
    uint8_t id[32];
    uint8_t hint[8];
    int64_t created_at;
    int64_t ttl;
    uint8_t v;
    uint8_t pad[7];
    uint32_t payload_len;
} env_rec;

#define DIR_ENTRY_MAX (64 * 1024)
/* DIR_UPS body: pubkey(44) x25519(44) last_seen(8) epoch(8)
 * alias_len(2) alias alias_len-prekeys_len(2) prekeys */

/* ---- RAM slots ---- */
typedef struct {
    uint64_t fp; /* first 8 bytes of the binary envelope id */
    int64_t created_at;
    int64_t deadline; /* created_at + ttl */
    uint32_t off;     /* ENV_PUT frame offset */
    uint32_t len;     /* full frame length */
    uint8_t hint[8];
    uint8_t v;
    bool used;
} slot;

typedef struct {
    char pubkey[45]; /* Base64 of 32 bytes, NUL-terminated */
    int64_t last_seen;
    uint32_t off;
    uint32_t len;
    bool used;
} dir_slot;

/* batch undo log: the index changes of the pending batch, so abort() can
 * rewind both the file and the RAM index (crash safety needs no undo — an
 * uncommitted batch is discarded by the scan at open). */
#define BATCH_MAX DTN_PUSH_ENVELOPES_MAX
typedef struct {
    int32_t slot_idx;
    slot before;
    bool was_used;
} undo_ent;

struct dtn_store {
    char dir[240];
    int32_t cap;

    FILE *env_log; /* append+read */
    FILE *dir_log;
    FILE *env_rd;  /* read-only handle for fetches (position-independent) */
    FILE *dir_rd;
    long env_size;
    long dir_size;

    slot *slots;      /* cap entries (PSRAM-backed on the reference board) */
    int32_t live;
    int64_t live_bytes;

    dir_slot *dslots; /* DTN_DIRECTORY_MAX entries */
    int32_t dir_live;
    int32_t dir_cap;

    int32_t *cand;    /* pull scratch: candidate slot indices */
    int32_t cand_n;

    /* batch state */
    bool batch_open;
    long batch_mark;
    bool batch_cap_ok;
    undo_ent undo[BATCH_MAX];
    int undo_n;

    /* janitor bookkeeping (§10.7) */
    int64_t last_cleanup_unix;
    int32_t last_cleanup_deleted;
    int64_t ttl_swept_total;

    int schema_on_disk;
    uint32_t super_seq;
    bool pending_migration;
    bool quarantined;
};

/* ---- small helpers ---- */

static uint64_t fp_of_hex(const char *id_hex)
{
    uint8_t id32[32];
    /* id is validated 64-lowercase-hex before it ever reaches the store */
    for (int i = 0; i < 32; i++) {
        char hi = id_hex[2 * i], lo = id_hex[2 * i + 1];
        int vh = (hi >= '0' && hi <= '9') ? hi - '0' : hi - 'a' + 10;
        int vl = (lo >= '0' && lo <= '9') ? lo - '0' : lo - 'a' + 10;
        id32[i] = (uint8_t)((vh << 4) | vl);
    }
    uint64_t fp;
    memcpy(&fp, id32, 8);
    return fp;
}

static void hex8_to_bytes(const char *hint_hex, uint8_t *out)
{
    for (int i = 0; i < 8; i++) {
        char hi = hint_hex[2 * i], lo = hint_hex[2 * i + 1];
        int vh = (hi >= '0' && hi <= '9') ? hi - '0' : hi - 'a' + 10;
        int vl = (lo >= '0' && lo <= '9') ? lo - '0' : lo - 'a' + 10;
        out[i] = (uint8_t)((vh << 4) | vl);
    }
}

static bool rd_exact(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n;
}

static bool wr_exact(FILE *f, const void *buf, size_t n)
{
    return fwrite(buf, 1, n, f) == n;
}

static void sync_file(FILE *f)
{
    if (!f) return;
    fflush(f);
#ifndef DTN_STORE_NO_FSYNC
    fsync(fileno(f));
#else
    (void)f;
#endif
}

static int truncate_file(FILE *f, long len)
{
    fflush(f);
#ifndef DTN_STORE_NO_FSYNC
    if (ftruncate(fileno(f), len) != 0) return -1;
#endif
    fseek(f, len, SEEK_SET);
    sync_file(f);
    return 0;
}

/* ---- frame I/O ---- */

static bool frame_write(FILE *f, uint8_t type, const void *payload,
                        uint32_t len)
{
    uint8_t hdr[FRAME_HDR];
    uint32_t magic = FRAME_MAGIC;
    uint32_t crc = crc32_buf(payload, len);
    memcpy(hdr, &magic, 4);
    hdr[4] = type;
    hdr[5] = hdr[6] = hdr[7] = 0;
    memcpy(hdr + 8, &len, 4);
    memcpy(hdr + 12, &crc, 4);
    bool ok = wr_exact(f, hdr, sizeof(hdr)) &&
              (len == 0 || wr_exact(f, payload, len));
    /* the read-only sibling handle must see every appended frame at once:
     * dedup fetches and pull reads go through it (stdio buffers otherwise
     * hide the bytes) */
    fflush(f);
    return ok;
}

/* 1 = frame ok, 0 = clean EOF, -1 = damaged/EOF mid-frame. */
static int frame_read(FILE *f, uint8_t *type, uint8_t **payload,
                      uint32_t *len)
{
    uint8_t hdr[FRAME_HDR];
    size_t got = fread(hdr, 1, sizeof(hdr), f);
    if (got == 0) return 0;
    if (got < sizeof(hdr)) return -1;
    uint32_t magic, flen, crc;
    memcpy(&magic, hdr, 4);
    memcpy(&flen, hdr + 8, 4);
    memcpy(&crc, hdr + 12, 4);
    if (magic != FRAME_MAGIC || flen > MAX_FRAME) return -1;
    uint8_t *buf = NULL;
    if (flen) {
        buf = malloc(flen);
        if (!buf) return -1;
        if (!rd_exact(f, buf, flen)) {
            free(buf);
            return -1;
        }
    }
    if (crc32_buf(buf, flen) != crc) {
        free(buf);
        return -1;
    }
    *type = hdr[4];
    *payload = buf;
    *len = flen;
    return 1;
}

/* ---- ENV_PUT record codec ---- */

static size_t env_encode(const dtn_envelope *e, uint8_t *buf, size_t cap)
{
    if (sizeof(env_rec) + e->payload_len > cap) return 0;
    env_rec r;
    memset(&r, 0, sizeof(r));
    for (int i = 0; i < 32; i++) {
        char hi = e->id[2 * i], lo = e->id[2 * i + 1];
        r.id[i] = (uint8_t)((((hi >= '0' && hi <= '9') ? hi - '0'
                                                       : hi - 'a' + 10)
                             << 4) |
                            ((lo >= '0' && lo <= '9') ? lo - '0'
                                                      : lo - 'a' + 10));
    }
    hex8_to_bytes(e->dest_hint, r.hint);
    r.created_at = e->created_at;
    r.ttl = e->ttl;
    r.v = (uint8_t)e->v;
    r.payload_len = (uint32_t)e->payload_len;
    memcpy(buf, &r, sizeof(r));
    memcpy(buf + sizeof(r), e->payload, e->payload_len);
    return sizeof(r) + e->payload_len;
}

static bool env_decode(const uint8_t *buf, uint32_t len, dtn_envelope *e)
{
    if (len < sizeof(env_rec)) return false;
    env_rec r;
    memcpy(&r, buf, sizeof(r));
    if (r.payload_len != len - sizeof(env_rec)) return false;
    if (r.payload_len > DTN_PAYLOAD_B64_MAX) return false;
    static const char H[] = "0123456789abcdef";
    memset(e, 0, sizeof(*e));
    e->v = r.v;
    for (int i = 0; i < 32; i++) {
        e->id[2 * i] = H[r.id[i] >> 4];
        e->id[2 * i + 1] = H[r.id[i] & 0x0F];
    }
    e->id[64] = '\0';
    for (int i = 0; i < 8; i++) {
        e->dest_hint[2 * i] = H[r.hint[i] >> 4];
        e->dest_hint[2 * i + 1] = H[r.hint[i] & 0x0F];
    }
    e->dest_hint[16] = '\0';
    e->created_at = r.created_at;
    e->ttl = r.ttl;
    e->payload_len = r.payload_len;
    memcpy(e->payload, buf + sizeof(r), r.payload_len);
    e->payload[r.payload_len] = '\0';
    return true;
}

/* Fetch the envelope record of a slot through the read-only handle. */
static bool env_fetch(const dtn_store *st, const slot *sl, dtn_envelope *e)
{
    FILE *f = st->env_rd;
    if (fseek(f, (long)sl->off, SEEK_SET) != 0) return false;
    uint8_t type;
    uint8_t *payload = NULL;
    uint32_t len;
    int rc = frame_read(f, &type, &payload, &len);
    if (rc != 1 || type != REC_ENV_PUT) {
        free(payload);
        return false;
    }
    bool ok = env_decode(payload, len, e);
    free(payload);
    return ok;
}

/* ---- superblock (A/B, 64-byte slots) ---- */
#define SUPER_SIZE 64
#define SUPER_MAGIC 0x5447444Fu /* "OGDS" */

typedef struct {
    bool valid;
    uint32_t seq;
    int32_t version;
} super_readout;

static void super_read(const char *path, super_readout *out)
{
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "rb");
    if (!f) return;
    uint8_t buf[SUPER_SIZE];
    if (rd_exact(f, buf, sizeof(buf))) {
        uint32_t magic, seq, crc;
        int32_t version;
        memcpy(&magic, buf, 4);
        memcpy(&version, buf + 4, 4);
        memcpy(&seq, buf + 8, 4);
        memcpy(&crc, buf + 12, 4);
        /* the CRC covers the reserved tail (16..63) — never its own field */
        if (magic == SUPER_MAGIC &&
            crc == crc32_buf(buf + 16, SUPER_SIZE - 16)) {
            out->valid = true;
            out->seq = seq;
            out->version = version;
        }
    }
    fclose(f);
}

static void super_write(dtn_store *st, int32_t version, uint32_t seq)
{
    /* alternate the two slots: seq decides, CRC arbitrates torn writes */
    char path[280];
    uint8_t buf[SUPER_SIZE];
    memset(buf, 0, sizeof(buf));
    uint32_t magic = SUPER_MAGIC;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &version, 4);
    memcpy(buf + 8, &seq, 4);
    uint32_t crc = crc32_buf(buf + 16, SUPER_SIZE - 16);
    memcpy(buf + 12, &crc, 4);
    snprintf(path, sizeof(path), "%s/super.%c.bin", st->dir,
             (seq & 1) ? 'a' : 'b');
    FILE *f = fopen(path, "wb");
    if (!f) return;
    if (wr_exact(f, buf, sizeof(buf))) sync_file(f);
    fclose(f);
}

/* ---- compaction (declared early: the janitor triggers it) ---- */
static void compact_envelopes(dtn_store *st);

/* ---- envelopes.log scan (open path) ---- */

#define SCAN_PENDING_MAX BATCH_MAX

static int env_scan(dtn_store *st)
{
    /* pending-batch buffer: puts inside an uncommitted batch apply only on
     * its COMMIT record (the crash-consistent replay of §10.4). Each entry
     * remembers its OWN frame offset — the slot must point at the ENV_PUT,
     * not at the COMMIT marker. */
    dtn_envelope *pending = malloc(sizeof(dtn_envelope) * SCAN_PENDING_MAX);
    long *pending_off = malloc(sizeof(long) * SCAN_PENDING_MAX);
    if (!pending || !pending_off) {
        free(pending);
        free(pending_off);
        return -1;
    }
    int pending_n = 0;
    long batch_start = -1;

    fseek(st->env_log, 0, SEEK_END);
    long size = ftell(st->env_log);
    fseek(st->env_log, 0, SEEK_SET);
    long good = 0;

    for (;;) {
        uint8_t type;
        uint8_t *payload = NULL;
        uint32_t len = 0;
        int rc = frame_read(st->env_log, &type, &payload, &len);
        if (rc != 1) {
            free(payload);
            break; /* clean EOF or damaged tail: stop, truncate below */
        }
        long frame_off = good;
        long after = ftell(st->env_log);

        if (type == REC_BATCH_BEGIN) {
            pending_n = 0;
            batch_start = frame_off;
        } else if (type == REC_BATCH_COMMIT) {
            if (batch_start >= 0) {
                for (int i = 0; i < pending_n; i++) {
                    /* apply: allocate (or re-put over) by fingerprint */
                    uint64_t fp;
                    uint8_t id32[32];
                    /* re-derive the binary id from the decoded envelope */
                    for (int b = 0; b < 32; b++) {
                        char hi = pending[i].id[2 * b];
                        char lo = pending[i].id[2 * b + 1];
                        int vh = (hi >= '0' && hi <= '9') ? hi - '0'
                                                          : hi - 'a' + 10;
                        int vl = (lo >= '0' && lo <= '9') ? lo - '0'
                                                          : lo - 'a' + 10;
                        id32[b] = (uint8_t)((vh << 4) | vl);
                    }
                    memcpy(&fp, id32, 8);
                    int32_t found = -1;
                    for (int32_t k = 0; k < st->cap; k++) {
                        if (st->slots[k].used && st->slots[k].fp == fp) {
                            found = k;
                            break;
                        }
                    }
                    if (found < 0) {
                        for (int32_t k = 0; k < st->cap + BATCH_MAX; k++) {
                            if (!st->slots[k].used) {
                                found = k;
                                break;
                            }
                        }
                    }
                    if (found >= 0) {
                        slot *sl = &st->slots[found];
                        if (!sl->used) {
                            st->live++;
                        } else {
                            st->live_bytes -= sl->len;
                        }
                        memset(sl, 0, sizeof(*sl));
                        sl->fp = fp;
                        sl->created_at = pending[i].created_at;
                        sl->deadline =
                            pending[i].created_at + pending[i].ttl;
                        sl->off = (uint32_t)pending_off[i];
                        sl->len = (uint32_t)(after - pending_off[i]);
                        hex8_to_bytes(pending[i].dest_hint, sl->hint);
                        sl->v = (uint8_t)pending[i].v;
                        sl->used = true;
                        st->live_bytes += sl->len;
                    }
                }
            }
            pending_n = 0;
            batch_start = -1;
        } else if (type == REC_ENV_PUT && len >= sizeof(env_rec)) {
            dtn_envelope e;
            if (env_decode(payload, len, &e)) {
                if (batch_start >= 0) {
                    if (pending_n < SCAN_PENDING_MAX) {
                        pending[pending_n] = e;
                        pending_off[pending_n] = frame_off;
                        pending_n++;
                    } else {
                        /* a well-formed batch never exceeds 100 puts */
                        free(payload);
                        break;
                    }
                } else {
                    /* stray PUT outside a batch (pre-batch format): apply */
                    uint64_t fp;
                    memcpy(&fp, payload, 8);
                    int32_t found = -1;
                    for (int32_t k = 0; k < st->cap; k++) {
                        if (st->slots[k].used && st->slots[k].fp == fp) {
                            found = k;
                            break;
                        }
                    }
                    if (found < 0) {
                        for (int32_t k = 0; k < st->cap + BATCH_MAX; k++) {
                            if (!st->slots[k].used) {
                                found = k;
                                break;
                            }
                        }
                    }
                    if (found >= 0) {
                        slot *sl = &st->slots[found];
                        if (!sl->used) {
                            st->live++;
                        } else {
                            st->live_bytes -= sl->len;
                        }
                        memset(sl, 0, sizeof(*sl));
                        sl->fp = fp;
                        sl->created_at = e.created_at;
                        sl->deadline = e.created_at + e.ttl;
                        sl->off = (uint32_t)frame_off;
                        sl->len = (uint32_t)(after - frame_off);
                        hex8_to_bytes(e.dest_hint, sl->hint);
                        sl->v = (uint8_t)e.v;
                        sl->used = true;
                        st->live_bytes += sl->len;
                    }
                }
            }
        } else if (type == REC_ENV_TOMB && len >= 8) {
            /* tombstones are written only by sweep() AFTER full-id
             * verification, so fp matching here is sound */
            uint64_t fp;
            memcpy(&fp, payload, 8);
            for (int32_t k = 0; k < st->cap; k++) {
                if (st->slots[k].used && st->slots[k].fp == fp) {
                    st->slots[k].used = false;
                    st->live--;
                    st->live_bytes -= st->slots[k].len;
                    break;
                }
            }
        }
        free(payload);
        payload = NULL;
        good = after;
        if (good >= size) break;
    }
    free(pending);
    free(pending_off);

    /* uncommitted batch tail or damaged tail: discard from the boundary */
    long cut = good;
    if (batch_start >= 0 && batch_start < cut) cut = batch_start;
    if (cut < size) {
        if (truncate_file(st->env_log, cut) != 0) return -1;
    }
    fseek(st->env_log, 0, SEEK_END);
    st->env_size = ftell(st->env_log);
    return 0;
}

/* ---- directory.log scan ---- */

static int dir_scan(dtn_store *st)
{
    fseek(st->dir_log, 0, SEEK_END);
    long size = ftell(st->dir_log);
    fseek(st->dir_log, 0, SEEK_SET);
    long good = 0;

    for (;;) {
        uint8_t type;
        uint8_t *payload = NULL;
        uint32_t len = 0;
        int rc = frame_read(st->dir_log, &type, &payload, &len);
        if (rc != 1) {
            free(payload);
            break;
        }
        long frame_off = good;
        long after = ftell(st->dir_log);

        if (type == REC_DIR_UPS && len > 108) {
            char pubkey[45];
            memcpy(pubkey, payload, 44);
            pubkey[44] = '\0';
            int32_t found = -1;
            for (int32_t k = 0; k < st->dir_cap; k++) {
                if (st->dslots[k].used &&
                    memcmp(st->dslots[k].pubkey, pubkey, 45) == 0) {
                    found = k;
                    break;
                }
            }
            if (found < 0) {
                for (int32_t k = 0; k < st->dir_cap; k++) {
                    if (!st->dslots[k].used) {
                        found = k;
                        break;
                    }
                }
            }
            if (found >= 0) {
                dir_slot *ds = &st->dslots[found];
                if (!ds->used) st->dir_live++;
                memset(ds, 0, sizeof(*ds));
                memcpy(ds->pubkey, pubkey, 45);
                memcpy(&ds->last_seen, payload + 88, 8);
                ds->off = (uint32_t)frame_off;
                ds->len = (uint32_t)(after - frame_off);
                ds->used = true;
            }
        }
        free(payload);
        good = after;
        if (good >= size) break;
    }

    if (good < size) {
        if (truncate_file(st->dir_log, good) != 0) return -1;
    }
    fseek(st->dir_log, 0, SEEK_END);
    st->dir_size = ftell(st->dir_log);
    return 0;
}

/* ---- open / close ---- */

static FILE *open_append(const char *path)
{
    /* a+b: writes always land at the end, reads are seekable */
    return fopen(path, "a+b");
}

dtn_store_err dtn_store_open(dtn_store **out, const char *dir,
                             int32_t envelope_capacity)
{
    *out = NULL;
    dtn_store *st = calloc(1, sizeof(*st));
    if (!st) return DTN_STORE_ERR_IO;
    snprintf(st->dir, sizeof(st->dir), "%s", dir);
    st->cap = envelope_capacity > 0 ? envelope_capacity : DTN_ENVELOPE_CAP_MAX;
    st->dir_cap = DTN_DIRECTORY_MAX;
    st->schema_on_disk = DTN_STORAGE_SCHEMA_VERSION;

    mkdir(dir, 0755); /* EEXIST is fine; a real failure surfaces below */

    /* +BATCH_MAX headroom: a batch admitted below the §8.1 cap may
     * overshoot it by up to one batch (docs/esp32-design.md §4) */
    st->slots = calloc((size_t)st->cap + BATCH_MAX, sizeof(slot));
    st->dslots = calloc((size_t)st->dir_cap, sizeof(dir_slot));
    st->cand = calloc((size_t)st->cap, sizeof(int32_t));
    if (!st->slots || !st->dslots || !st->cand) {
        dtn_store_close(st);
        return DTN_STORE_ERR_IO;
    }

    char path[280];

    /* super: newest valid slot; both invalid with existing logs = a corrupt
     * store → quarantine (§13.6: never half-served) */
    char super_a[280], super_b[280];
    snprintf(super_a, sizeof(super_a), "%s/super.a.bin", dir);
    snprintf(super_b, sizeof(super_b), "%s/super.b.bin", dir);
    super_readout a, b;
    super_read(super_a, &a);
    super_read(super_b, &b);
    super_readout *best = NULL;
    if (a.valid && (!b.valid || a.seq >= b.seq)) best = &a;
    if (b.valid && (!a.valid || b.seq > a.seq)) best = &b;

    snprintf(path, sizeof(path), "%s/envelopes.log", dir);
    FILE *probe = fopen(path, "rb");
    bool had_store = (probe != NULL);
    if (probe) fclose(probe);

    if (best) {
        st->schema_on_disk = best->version;
        if (best->version > DTN_STORAGE_SCHEMA_VERSION) {
            /* §15.3 downgrade refusal: refuse to mount, leave untouched */
            dtn_store_close(st);
            return DTN_STORE_ERR_DOWNGRADE;
        }
        if (best->version < DTN_STORAGE_SCHEMA_VERSION) {
            /* forward-only chain: no steps exist below version 4 (the store
             * ships at the version-4 contract level); migrate = stamp */
            st->pending_migration = true;
        }
    } else if (had_store) {
        /* logs exist but no valid superblock: corrupt → quarantine */
        char from[280], to[280];
        snprintf(from, sizeof(from), "%s/envelopes.log", dir);
        snprintf(to, sizeof(to), "%s/envelopes.corrupt.log", dir);
        rename(from, to);
        snprintf(from, sizeof(from), "%s/directory.log", dir);
        snprintf(to, sizeof(to), "%s/directory.corrupt.log", dir);
        rename(from, to);
        st->quarantined = true;
    }
    if (st->pending_migration || st->quarantined || !had_store || best) {
        st->super_seq = best ? best->seq + 1 : 1;
        super_write(st, DTN_STORAGE_SCHEMA_VERSION, st->super_seq);
        st->pending_migration = false;
    }

    snprintf(path, sizeof(path), "%s/envelopes.log", dir);
    st->env_log = open_append(path);
    snprintf(path, sizeof(path), "%s/directory.log", dir);
    st->dir_log = open_append(path);
    snprintf(path, sizeof(path), "%s/envelopes.log", dir);
    st->env_rd = fopen(path, "rb");
    snprintf(path, sizeof(path), "%s/directory.log", dir);
    st->dir_rd = fopen(path, "rb");
    if (!st->env_log || !st->dir_log || !st->env_rd || !st->dir_rd) {
        dtn_store_close(st);
        return DTN_STORE_ERR_IO;
    }

    if (env_scan(st) != 0 || dir_scan(st) != 0) {
        dtn_store_close(st);
        return DTN_STORE_ERR_IO;
    }

    *out = st;
    return DTN_STORE_OK;
}

void dtn_store_close(dtn_store *st)
{
    if (!st) return;
    if (st->batch_open) {
        dtn_store_batch_abort(st);
    }
    if (st->env_log) {
        sync_file(st->env_log);
        fclose(st->env_log);
    }
    if (st->dir_log) {
        sync_file(st->dir_log);
        fclose(st->dir_log);
    }
    if (st->env_rd) fclose(st->env_rd);
    if (st->dir_rd) fclose(st->dir_rd);
    free(st->slots);
    free(st->dslots);
    free(st->cand);
    free(st);
}

/* ---- sync batch (§10.4 fail-closed transaction semantics) ---- */

int dtn_store_batch_begin(dtn_store *st)
{
    if (st->batch_open) return 0; /* idempotent within one request */
    fseek(st->env_log, 0, SEEK_END);
    st->batch_mark = ftell(st->env_log);
    st->batch_cap_ok = st->live < st->cap; /* decided ONCE per batch (§8.1) */
    st->undo_n = 0;
    if (!frame_write(st->env_log, REC_BATCH_BEGIN, NULL, 0)) {
        return -1;
    }
    st->batch_open = true;
    return 0;
}

int dtn_store_batch_put(dtn_store *st, const dtn_envelope *e, int *absorbed)
{
    if (!st->batch_open) return -1;
    *absorbed = 0;

    uint64_t fp = fp_of_hex(e->id);
    int32_t found = -1;
    for (int32_t k = 0; k < st->cap; k++) {
        if (st->slots[k].used && st->slots[k].fp == fp) {
            found = k;
            break;
        }
    }
    if (found >= 0) {
        /* authoritative on-flash verification of the full id (§4 of the
         * design note): a fingerprint match alone is not a dedup hit */
        dtn_envelope have;
        if (!env_fetch(st, &st->slots[found], &have)) return -1;
        if (memcmp(have.id, e->id, DTN_ID_LEN) == 0) {
            *absorbed = 1; /* INSERT OR IGNORE: silently absorbed (§10.4) */
            return 0;
        }
        found = -1; /* fingerprint collision: this is a NEW envelope */
    }
    if (!st->batch_cap_ok) {
        return -2; /* at/over the cap when the batch began: refuse whole */
    }

    uint8_t buf[sizeof(env_rec) + DTN_PAYLOAD_B64_MAX];
    size_t n = env_encode(e, buf, sizeof(buf));
    if (n == 0) return -1;
    fseek(st->env_log, 0, SEEK_END);
    long off = ftell(st->env_log);
    if (!frame_write(st->env_log, REC_ENV_PUT, buf, (uint32_t)n)) return -1;

    if (found < 0) {
        for (int32_t k = 0; k < st->cap + BATCH_MAX; k++) {
            if (!st->slots[k].used) {
                found = k;
                break;
            }
        }
        if (found < 0) return -1; /* cannot happen past batch_cap_ok */
    }
    /* undo-log the previous slot content, then apply */
    if (st->undo_n < BATCH_MAX) {
        st->undo[st->undo_n].slot_idx = found;
        st->undo[st->undo_n].before = st->slots[found];
        st->undo[st->undo_n].was_used = st->slots[found].used;
        st->undo_n++;
    }
    slot *sl = &st->slots[found];
    if (!sl->used) {
        st->live++;
    } else {
        st->live_bytes -= sl->len;
    }
    memset(sl, 0, sizeof(*sl));
    sl->fp = fp;
    sl->created_at = e->created_at;
    sl->deadline = e->created_at + e->ttl;
    sl->off = (uint32_t)off;
    sl->len = (uint32_t)(FRAME_HDR + n);
    hex8_to_bytes(e->dest_hint, sl->hint);
    sl->v = (uint8_t)e->v;
    sl->used = true;
    st->live_bytes += sl->len;
    return 0;
}

int dtn_store_batch_commit(dtn_store *st)
{
    if (!st->batch_open) return 0;
    if (!frame_write(st->env_log, REC_BATCH_COMMIT, NULL, 0)) return -1;
    sync_file(st->env_log); /* the acknowledgement point (WAL rationale) */
    st->batch_open = false;
    fseek(st->env_log, 0, SEEK_END);
    st->env_size = ftell(st->env_log);
    return 0;
}

void dtn_store_batch_abort(dtn_store *st)
{
    if (!st->batch_open) return;
    truncate_file(st->env_log, st->batch_mark);
    /* rewind the RAM index in reverse */
    for (int i = st->undo_n - 1; i >= 0; i--) {
        slot *sl = &st->slots[st->undo[i].slot_idx];
        if (!st->undo[i].was_used) {
            if (sl->used) st->live--;
            st->live_bytes -= sl->len;
            memset(sl, 0, sizeof(*sl));
        } else {
            if (!sl->used) st->live++;
            st->live_bytes -= sl->len;
            *sl = st->undo[i].before;
            st->live_bytes += sl->len;
        }
    }
    st->undo_n = 0;
    st->batch_open = false;
}

/* ---- pull (§10.4 step 3) ---- */

static int cmp_candidate(const void *a, const void *b);
static dtn_store *g_cmp_ctx; /* single-writer model: no concurrent pulls */

struct cand_ent {
    int32_t idx;
    int64_t created_at;
    uint64_t fp;
};

static int cmp_candidate(const void *a, const void *b)
{
    const struct cand_ent *x = a, *y = b;
    (void)g_cmp_ctx;
    if (x->created_at != y->created_at) {
        return x->created_at > y->created_at ? -1 : 1; /* DESC */
    }
    if (x->fp != y->fp) {
        return x->fp < y->fp ? -1 : 1; /* fp ASC proxy; exact id order is
                                          applied on fetch below */
    }
    return x->idx < y->idx ? -1 : 1;
}

struct pull_result {
    dtn_envelope env;
    int64_t created_at;
    uint8_t id32[32];
};

int dtn_store_pull(dtn_store *st, const dtn_known_ids *known, int64_t limit,
                   int64_t now, void *cb_ud, dtn_pull_cb cb,
                   int32_t *served_out)
{
    if (served_out) *served_out = 0;
    if (limit < 1) return 0;
    if (limit > DTN_SYNC_LIMIT_MAX) limit = DTN_SYNC_LIMIT_MAX;

    /* known-id fingerprints, sorted for binary search */
    uint64_t *kfp = NULL;
    int kn = 0;
    if (known && known->count) {
        kfp = malloc(sizeof(uint64_t) * (size_t)known->count);
        if (!kfp) return -1;
        for (int i = 0; i < known->count; i++) {
            kfp[kn++] = fp_of_hex(known->ids[i]);
        }
        for (int i = 1; i < kn; i++) { /* insertion sort (n ≤ 500) */
            uint64_t v = kfp[i];
            int j = i - 1;
            while (j >= 0 && kfp[j] > v) {
                kfp[j + 1] = kfp[j];
                j--;
            }
            kfp[j + 1] = v;
        }
    }

    /* candidates: live envelopes whose deadline is still ahead — the
     * §10.4 INCLUSIVE boundary (created_at + ttl >= now) */
    int32_t cand_n = 0;
    struct cand_ent *cands =
        malloc(sizeof(struct cand_ent) * (size_t)(st->live > 0 ? st->live : 1));
    if (!cands) {
        free(kfp);
        return -1;
    }
    for (int32_t k = 0; k < st->cap && cand_n < st->live; k++) {
        if (!st->slots[k].used) continue;
        if (st->slots[k].deadline < now) continue; /* expired (exclusive on
                                                      the janitor side) */
        cands[cand_n].idx = k;
        cands[cand_n].created_at = st->slots[k].created_at;
        cands[cand_n].fp = st->slots[k].fp;
        cand_n++;
    }
    g_cmp_ctx = st;
    qsort(cands, (size_t)cand_n, sizeof(*cands), cmp_candidate);

    struct pull_result *res = malloc(sizeof(*res) * (size_t)limit);
    if (!res) {
        free(cands);
        free(kfp);
        return -1;
    }
    int res_n = 0;
    int32_t served = 0;

    for (int i = 0; i < cand_n; i++) {
        slot *sl = &st->slots[cands[i].idx];
        /* early exit: strictly older than the worst kept result — every
         * remaining candidate is older too (the candidate order is
         * created_at DESC) */
        if (res_n == limit && cands[i].created_at < res[res_n - 1].created_at) {
            break;
        }
        /* known_ids exclusion: fingerprint shortlist, authoritative full-id
         * verification on hit */
        bool excluded = false;
        if (kn) {
            int lo = 0, hi = kn - 1;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (kfp[mid] == sl->fp) {
                    dtn_envelope e;
                    if (env_fetch(st, sl, &e)) {
                        uint8_t id32[32];
                        for (int b = 0; b < 32; b++) {
                            char hi_c = e.id[2 * b], lo_c = e.id[2 * b + 1];
                            int vh = (hi_c >= '0' && hi_c <= '9')
                                         ? hi_c - '0'
                                         : hi_c - 'a' + 10;
                            int vl = (lo_c >= '0' && lo_c <= '9')
                                         ? lo_c - '0'
                                         : lo_c - 'a' + 10;
                            id32[b] = (uint8_t)((vh << 4) | vl);
                        }
                        for (int kk = 0; kk < known->count; kk++) {
                            uint8_t kid[32];
                            const char *h = known->ids[kk];
                            for (int b = 0; b < 32; b++) {
                                char hi_c = h[2 * b], lo_c = h[2 * b + 1];
                                int vh = (hi_c >= '0' && hi_c <= '9')
                                             ? hi_c - '0'
                                             : hi_c - 'a' + 10;
                                int vl = (lo_c >= '0' && lo_c <= '9')
                                             ? lo_c - '0'
                                             : lo_c - 'a' + 10;
                                kid[b] = (uint8_t)((vh << 4) | vl);
                            }
                            if (memcmp(id32, kid, 32) == 0) {
                                excluded = true;
                                break;
                            }
                        }
                    }
                    break;
                }
                if (kfp[mid] < sl->fp) {
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
        }
        if (excluded) continue;

        dtn_envelope e;
        if (!env_fetch(st, sl, &e)) continue; /* unreadable: skip, never
                                                 half-serve */
        uint8_t id32[32];
        for (int b = 0; b < 32; b++) {
            char hi_c = e.id[2 * b], lo_c = e.id[2 * b + 1];
            int vh = (hi_c >= '0' && hi_c <= '9') ? hi_c - '0'
                                                  : hi_c - 'a' + 10;
            int vl = (lo_c >= '0' && lo_c <= '9') ? lo_c - '0'
                                                  : lo_c - 'a' + 10;
            id32[b] = (uint8_t)((vh << 4) | vl);
        }
        /* exact insertion into the bounded result (created_at DESC, id ASC
         * — SQLite TEXT byte order == binary id byte order). Walk from the
         * oldest end; shift while the entry on the left comes AFTER the new
         * one (it is older, or equal-created with a greater id). */
        int pos = res_n;
        while (pos > 0) {
            struct pull_result *r = &res[pos - 1];
            int cmp;
            if (r->created_at != e.created_at) {
                cmp = r->created_at < e.created_at ? 1 : -1;
            } else {
                cmp = memcmp(r->id32, id32, 32);
                if (cmp == 0) cmp = -1; /* duplicates cannot exist (dedup) */
            }
            if (cmp > 0) {
                if (pos < limit) res[pos] = res[pos - 1];
                pos--;
            } else {
                break;
            }
        }
        if (pos < limit) {
            if (res_n < limit) res_n++;
            res[pos].env = e;
            res[pos].created_at = e.created_at;
            memcpy(res[pos].id32, id32, 32);
        }
    }
    served = res_n;
    for (int i = 0; i < res_n; i++) {
        cb(cb_ud, &res[i].env); /* the §10.4 response order */
        if (served_out) (*served_out)++;
    }
    (void)served;
    free(res);
    free(cands);
    free(kfp);
    return 0;
}

/* ---- TTL janitor (§10.6) ---- */

int dtn_store_sweep(dtn_store *st, int64_t now, int32_t *deleted_out)
{
    if (st->batch_open) return -1; /* single-writer: never mid-batch */
    int32_t deleted = 0;
    for (int32_t k = 0; k < st->cap; k++) {
        slot *sl = &st->slots[k];
        if (!sl->used) continue;
        if (sl->deadline < now) { /* EXCLUSIVE boundary (§10.6) */
            uint8_t payload[40];
            memcpy(payload, &sl->fp, 8);
            dtn_envelope e;
            if (env_fetch(st, sl, &e)) {
                /* tombstone carries the full id for forensic exactness */
                for (int b = 0; b < 32; b++) {
                    char hi = e.id[2 * b], lo = e.id[2 * b + 1];
                    int vh = (hi >= '0' && hi <= '9') ? hi - '0'
                                                      : hi - 'a' + 10;
                    int vl = (lo >= '0' && lo <= '9') ? lo - '0'
                                                      : lo - 'a' + 10;
                    payload[8 + b] = (uint8_t)((vh << 4) | vl);
                }
                frame_write(st->env_log, REC_ENV_TOMB, payload, 40);
            } else {
                frame_write(st->env_log, REC_ENV_TOMB, payload, 8);
            }
            sl->used = false;
            st->live--;
            st->live_bytes -= sl->len;
            deleted++;
        }
    }
    if (deleted) sync_file(st->env_log);
    st->last_cleanup_unix = now;
    st->last_cleanup_deleted = deleted;
    st->ttl_swept_total++;

    /* compaction: dead bytes exceed live bytes (and the log is big enough
     * for the rewrite to pay for itself) */
    long size = 0;
    fseek(st->env_log, 0, SEEK_END);
    size = ftell(st->env_log);
    if (st->live_bytes > 0 && size - (long)st->live_bytes > st->live_bytes &&
        size > 64 * 1024) {
        compact_envelopes(st);
    }
    if (deleted_out) *deleted_out = deleted;
    return 0;
}

/* compaction: rewrite live ENV_PUT records only; atomic rename keeps the
 * old log intact if power is lost mid-rewrite (§4 of the design note) */
static void compact_envelopes(dtn_store *st)
{
    char tmp[280], logp[280];
    snprintf(tmp, sizeof(tmp), "%s/envelopes.log.tmp", st->dir);
    snprintf(logp, sizeof(logp), "%s/envelopes.log", st->dir);
    FILE *t = fopen(tmp, "wb");
    if (!t) return;
    for (int32_t k = 0; k < st->cap; k++) {
        if (!st->slots[k].used) continue;
        dtn_envelope e;
        if (!env_fetch(st, &st->slots[k], &e)) continue;
        uint8_t buf[sizeof(env_rec) + DTN_PAYLOAD_B64_MAX];
        size_t n = env_encode(&e, buf, sizeof(buf));
        if (n == 0) continue;
        frame_write(t, REC_ENV_PUT, buf, (uint32_t)n);
    }
    sync_file(t);
    fclose(t);
    fclose(st->env_log);
    rename(tmp, logp);
    st->env_log = open_append(logp);
    if (!st->env_log) {
        /* unrecoverable without the log: leave closed; the adapter sheds */
        return;
    }
    fclose(st->env_rd);
    st->env_rd = fopen(logp, "rb");
    /* rebuild: offsets changed */
    st->live = 0;
    st->live_bytes = 0;
    memset(st->slots, 0, sizeof(slot) * (size_t)st->cap);
    env_scan(st);
    super_write(st, DTN_STORAGE_SCHEMA_VERSION, ++st->super_seq);
}

/* ---- directory (§10.3) ---- */

int dtn_store_dir_upsert(dtn_store *st, const char *alias, const char *pubkey,
                         const char *x25519, const char *prekeys_raw,
                         int64_t now)
{
    /* the adapter validates shapes (alias regex, 32-byte keys, §10.3
     * prekeys blind validation) and owns the error codes; the store stores
     * VERBATIM and sets last_seen/epoch itself (§6.1: clients cannot
     * influence the epoch) */
    size_t alias_len = strlen(alias);
    size_t pre_len = prekeys_raw ? strlen(prekeys_raw) : 0;
    if (alias_len > 24 || pre_len > 2048) return -1;

    uint8_t *payload = malloc(108 + alias_len + 2 + pre_len);
    if (!payload) return -1;
    memcpy(payload, pubkey, 44);
    memcpy(payload + 44, x25519, 44);
    int64_t epoch = now / DTN_HINT_EPOCH_SECONDS;
    memcpy(payload + 88, &now, 8);
    memcpy(payload + 96, &epoch, 8);
    uint16_t al = (uint16_t)alias_len;
    memcpy(payload + 104, &al, 2);
    memcpy(payload + 106, alias, alias_len);
    uint16_t pl = (uint16_t)pre_len;
    memcpy(payload + 106 + alias_len, &pl, 2);
    if (pre_len) memcpy(payload + 108 + alias_len, prekeys_raw, pre_len);
    uint32_t plen = (uint32_t)(108 + alias_len + pre_len);

    fseek(st->dir_log, 0, SEEK_END);
    long off = ftell(st->dir_log);
    bool ok = frame_write(st->dir_log, REC_DIR_UPS, payload, plen);
    free(payload);
    if (!ok) return -1;

    int32_t found = -1;
    for (int32_t k = 0; k < st->dir_cap; k++) {
        if (st->dslots[k].used &&
            memcmp(st->dslots[k].pubkey, pubkey, 45) == 0) {
            found = k;
            break;
        }
    }
    if (found < 0) {
        for (int32_t k = 0; k < st->dir_cap; k++) {
            if (!st->dslots[k].used) {
                found = k;
                break;
            }
        }
        if (found < 0) {
            /* RAM index exhausted (bounded directory); flash keeps the
             * record — the entry becomes visible after a rescan. The
             * adapter maps this to the shipped row-cap behavior. */
            return -2;
        }
    }
    dir_slot *ds = &st->dslots[found];
    if (!ds->used) st->dir_live++;
    memset(ds, 0, sizeof(*ds));
    memcpy(ds->pubkey, pubkey, 45);
    ds->last_seen = now;
    ds->off = (uint32_t)off;
    ds->len = (uint32_t)(FRAME_HDR + plen);
    ds->used = true;
    sync_file(st->dir_log);
    fseek(st->dir_log, 0, SEEK_END);
    st->dir_size = ftell(st->dir_log);
    return 0;
}

static int cmp_dir_ent(const void *a, const void *b, void *unused)
{
    (void)unused;
    const dir_slot *x = *(dir_slot *const *)a;
    const dir_slot *y = *(dir_slot *const *)b;
    if (x->last_seen != y->last_seen) {
        return x->last_seen > y->last_seen ? -1 : 1; /* DESC */
    }
    return memcmp(x->pubkey, y->pubkey, 45) < 0 ? -1 : 1; /* pubkey ASC */
}

/* qsort_r is not portable C99: a file-static context under the single-writer
 * model is the honest, simple choice (as with the pull comparator). */
static int cmp_dir_ent_np(const void *a, const void *b)
{
    return cmp_dir_ent(a, b, NULL);
}

int dtn_store_dir_get(dtn_store *st, int32_t limit, void *cb_ud,
                      dtn_dir_cb cb, int32_t *served_out)
{
    if (served_out) *served_out = 0;
    if (limit < 1) return 0;
    if (limit > DTN_DIRECTORY_MAX) limit = DTN_DIRECTORY_MAX;

    dir_slot **order = malloc(sizeof(dir_slot *) * (size_t)st->dir_cap);
    if (!order) return -1;
    int32_t n = 0;
    for (int32_t k = 0; k < st->dir_cap; k++) {
        if (st->dslots[k].used) order[n++] = &st->dslots[k];
    }
    qsort(order, (size_t)n, sizeof(*order), cmp_dir_ent_np);

    int32_t served = 0;
    for (int32_t i = 0; i < n && served < limit; i++) {
        dir_slot *ds = order[i];
        if (fseek(st->dir_rd, (long)ds->off, SEEK_SET) != 0) break;
        uint8_t type;
        uint8_t *payload = NULL;
        uint32_t len = 0;
        if (frame_read(st->dir_rd, &type, &payload, &len) != 1 ||
            type != REC_DIR_UPS || len < 108) {
            free(payload);
            continue; /* unreadable: skip, never half-serve */
        }
        char alias[25];
        uint16_t al;
        memcpy(&al, payload + 104, 2);
        if (al > 24) al = 24;
        memcpy(alias, payload + 106, al);
        alias[al] = '\0';
        uint16_t pl = 0;
        if (len > (uint32_t)(108 + al)) {
            memcpy(&pl, payload + 106 + al, 2);
        }
        char prebuf[2049];
        const char *prekeys = NULL;
        if (pl > 0 && pl <= 2048 &&
            len >= (uint32_t)(108 + al + pl)) {
            memcpy(prebuf, payload + 108 + al, pl);
            prebuf[pl] = '\0';
            prekeys = prebuf;
        }
        int64_t last_seen, epoch;
        memcpy(&last_seen, payload + 88, 8);
        memcpy(&epoch, payload + 96, 8);
        cb(cb_ud, alias, ds->pubkey, (const char *)payload + 44, last_seen,
           epoch, prekeys);
        if (served_out) (*served_out)++;
        served++;
        free(payload);
    }
    free(order);
    return 0;
}

int32_t dtn_store_dir_count(const dtn_store *st) { return st->dir_live; }

/* ---- figures ---- */

int32_t dtn_store_envelope_count(const dtn_store *st) { return st->live; }

int64_t dtn_store_db_size(const dtn_store *st)
{
    long e = st->env_size, d = st->dir_size;
    if (st->env_log) {
        fseek(st->env_log, 0, SEEK_END);
        e = ftell(st->env_log);
    }
    if (st->dir_log) {
        fseek(st->dir_log, 0, SEEK_END);
        d = ftell(st->dir_log);
    }
    if (e < 0 || d < 0) return -1;
    return (int64_t)e + d + 2 * SUPER_SIZE;
}

int32_t dtn_store_expiring_within(const dtn_store *st, int64_t now,
                                  int64_t seconds)
{
    /* a pure index count that never reads row content (§10.7) */
    int32_t n = 0;
    int64_t horizon = now + seconds;
    for (int32_t k = 0; k < st->cap; k++) {
        const slot *sl = &st->slots[k];
        if (sl->used && sl->deadline >= now && sl->deadline < horizon) n++;
    }
    return n;
}

int64_t dtn_store_last_cleanup_unix(const dtn_store *st)
{
    return st->last_cleanup_unix;
}

int32_t dtn_store_last_cleanup_deleted(const dtn_store *st)
{
    return st->last_cleanup_deleted;
}

int64_t dtn_store_ttl_swept_total(const dtn_store *st)
{
    return st->ttl_swept_total;
}

int dtn_store_schema_version_on_disk(const dtn_store *st)
{
    return st->schema_on_disk;
}

bool dtn_store_pending_migration(const dtn_store *st)
{
    return st->pending_migration;
}

bool dtn_store_quarantined(const dtn_store *st) { return st->quarantined; }

/* ---- §10.3 blind prekeys admission (shape only — §1: never verify) ----
 *
 * Rules (§4.6/§10.3): the member set is exactly v, spk, spk_sig, ts, opks —
 * every one required; v == 1; spk padded standard Base64 of exactly 32
 * bytes; spk_sig of exactly 64 bytes; ts an integer > 0; opks an array of
 * 8..16 Base64 strings each decoding to exactly 32 bytes; the whole
 * serialized member ≤ 2048 bytes; unknown members are ignored (§15.4) but
 * still syntax-walked. NO signature verification — the node stays blind.
 */
struct prekeys_ctx {
    bool started;       /* saw the top-level bundle object */
    int cur;            /* 0..4 = known member being read; -1 unknown */
    int skip_depth;     /* nested containers of an ignored member */
    bool in_opks;
    int opks;
    bool saw_opks;
    bool bad;
    bool have_spk, have_sig;
    int64_t v;
    bool v_set, ts_set;
    int64_t ts;
};

static void pk_event(void *ud, const dtn_json_event *ev)
{
    struct prekeys_ctx *c = ud;
    if (c->bad) return;

    switch (ev->type) {
    case DTN_JSON_EV_BEGIN_OBJECT:
        if (!c->started) {
            c->started = true; /* the bundle object itself */
        } else if (c->skip_depth > 0) {
            c->skip_depth++;
        } else if (c->cur != -1) {
            c->bad = true; /* object where a scalar/array member belongs */
        } else {
            c->skip_depth = 1; /* ignored member's object subtree */
        }
        return;
    case DTN_JSON_EV_BEGIN_ARRAY:
        if (!c->started) {
            c->bad = true; /* the bundle must be an object */
        } else if (c->skip_depth > 0) {
            c->skip_depth++;
        } else if (c->cur == 4) {
            c->in_opks = true;
            c->opks = 0;
        } else if (c->cur == -1) {
            c->skip_depth = 1; /* ignored member's array subtree */
        } else {
            c->bad = true; /* array where v/spk/sig/ts belongs */
        }
        return;
    case DTN_JSON_EV_END_OBJECT:
        if (c->skip_depth > 0 && --c->skip_depth == 0 && c->cur == -1) {
            /* fallthrough: the ignored member ended; cur stays -1 */
        }
        return;
    case DTN_JSON_EV_END_ARRAY:
        if (c->in_opks) {
            c->in_opks = false;
            c->saw_opks = true;
            c->cur = -1;
            return;
        }
        if (c->skip_depth > 0) c->skip_depth--;
        return;
    case DTN_JSON_EV_KEY: {
        c->cur = -1;
        if (ev->overflow) return; /* too-long key: never a known member */
        if (strcmp(ev->s, "v") == 0) c->cur = 0;
        else if (strcmp(ev->s, "spk") == 0) c->cur = 1;
        else if (strcmp(ev->s, "spk_sig") == 0) c->cur = 2;
        else if (strcmp(ev->s, "ts") == 0) c->cur = 3;
        else if (strcmp(ev->s, "opks") == 0) c->cur = 4;
        return;
    }
    case DTN_JSON_EV_STRING: {
        if (c->skip_depth > 0) return;
        if (c->in_opks) {
            if (c->opks >= 16 || ev->overflow ||
                dtn_base64_decoded_len(ev->s, ev->len) != 32) {
                c->bad = true;
                return;
            }
            c->opks++;
            return;
        }
        if (c->cur == 1) {
            if (ev->overflow || dtn_base64_decoded_len(ev->s, ev->len) != 32) {
                c->bad = true;
                return;
            }
            c->have_spk = true;
        } else if (c->cur == 2) {
            if (ev->overflow || dtn_base64_decoded_len(ev->s, ev->len) != 64) {
                c->bad = true;
                return;
            }
            c->have_sig = true;
        } else if (c->cur >= 0) {
            c->bad = true; /* string into v/ts/opks */
        }
        return;
    }
    case DTN_JSON_EV_NUMBER: {
        if (c->skip_depth > 0) return;
        if (c->in_opks || !ev->is_integer || c->cur < 0) {
            c->bad = true; /* number in opks, float, or into spk/sig */
            return;
        }
        if (c->cur == 0) {
            c->v = ev->num;
            c->v_set = true;
        } else if (c->cur == 3) {
            c->ts = ev->num;
            c->ts_set = true;
        } else {
            c->bad = true;
        }
        return;
    }
    case DTN_JSON_EV_TRUE:
    case DTN_JSON_EV_FALSE:
    case DTN_JSON_EV_NULL:
        if (c->skip_depth == 0 && c->cur >= 0) c->bad = true;
        if (c->in_opks) c->bad = true;
        return;
    }
}

bool dtn_store_valid_prekeys(const char *raw, size_t raw_len)
{
    if (!raw || raw_len == 0 || raw_len > 2048) return false;
    struct prekeys_ctx c;
    memset(&c, 0, sizeof(c));
    c.cur = -1;
    dtn_json_parser p;
    dtn_json_init(&p, pk_event, &c);
    if (dtn_json_feed(&p, raw, raw_len) != DTN_JSONFEED_DONE) return false;
    if (c.bad) return false;
    if (c.skip_depth > 0 || c.in_opks) return false; /* never closed */
    if (!c.v_set || !c.ts_set || !c.have_spk || !c.have_sig || !c.saw_opks) {
        return false; /* every §4.6 member is required */
    }
    if (c.v != 1) return false;
    if (c.ts <= 0) return false;
    if (c.opks < 8 || c.opks > 16) return false;
    return true;
}

void dtn_store_test_crash(dtn_store *st)
{
    /* abandon without the clean-close path: the files keep whatever the
     * last sync captured — the exact post-power-cut state */
    sync_file(st->env_log);
    sync_file(st->dir_log);
    /* the object is deliberately leaked (tests only) */
}

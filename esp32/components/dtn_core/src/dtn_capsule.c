/* dtn_capsule.c — release capsule format v1 + the §9.4 chunk transport
 * (P3.7). The check ORDER and failure codes mirror node/internal/capsule
 * exactly; the shared vectors of tests/vectors/capsule/ (via the generated
 * host/tests/capsule_vectors.h) catch drift. */
#include "dtn_capsule.h"

#include <string.h>

#include "dtn_sha256.h"
#include "dtn_tweetnacl.h"

static const char magic_v1[DTN_CAPSULE_MAGIC_LEN] = {'O', 'F', 'G', 'R', 'I', 'D', 'U', 'P'};

uint64_t dtn_capsule_release_from_semver(unsigned major, unsigned minor, unsigned patch)
{
    return (uint64_t)major * 1000000ULL + (uint64_t)minor * 1000ULL + (uint64_t)patch;
}

/* --- the strict metadata scanner -----------------------------------------
 * v1 pins the 10 members in fixed order with CANONICAL JSON: no whitespace,
 * single commas, minimal integers (no leading zeros, no signs), plain
 * string escapes tolerated (the v1 members are ASCII; a future additive
 * member may escape). Canonical-but-foreign metadata is a forged artifact,
 * not a formatting nuance — anything else is BAD_METADATA. Additive
 * members AFTER the frozen ten are tolerated and ignored (signature still
 * covers them), the §2.1.2 rule. */

typedef struct {
    const char *b;
    size_t len;
    size_t pos;
} mscan;

static int m_peek(const mscan *s)
{
    return s->pos < s->len ? (unsigned char)s->b[s->pos] : -1;
}

static int m_take(mscan *s, char c)
{
    if (m_peek(s) == (unsigned char)c) {
        s->pos++;
        return 1;
    }
    return 0;
}

/* m_string — one JSON string into out (NUL-terminated); refuses to
 * truncate (returns -1 when the value exceeds cap-1). */
static int m_string(mscan *s, char *out, size_t cap)
{
    if (!m_take(s, '"')) return -1;
    size_t n = 0;
    while (1) {
        if (s->pos >= s->len) return -1;
        char c = s->b[s->pos++];
        if (c == '"') break;
        if (c == '\\') {
            if (s->pos >= s->len) return -1;
            char e = s->b[s->pos++];
            switch (e) {
            case '"': case '\\': case '/': c = e; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': { /* skip 4 hex digits; decode to a best-effort UTF-8 byte */
                if (s->pos + 4 > s->len) return -1;
                unsigned v = 0;
                for (int i = 0; i < 4; i++) {
                    char h = s->b[s->pos++];
                    v <<= 4;
                    if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
                    else return -1;
                }
                if (v < 0x80) {
                    c = (char)v;
                } else if (v < 0x800) {
                    c = (char)(0xC0 | (v >> 6));
                    if (n + 3 > cap) return -1; /* two bytes at n, n+1, NUL at n+2 */
                    out[n++] = c;
                    c = (char)(0x80 | (v & 0x3F));
                    out[n++] = c;
                    continue;
                } else {
                    return -1; /* surrogate pairs: not a v1 member value */
                }
                break;
            }
            default:
                return -1;
            }
        } else if ((unsigned char)c < 0x20) {
            return -1; /* raw control byte inside a string */
        }
        if (n + 2 > cap) return -1; /* the char at n and the NUL at n+1 must fit */
        out[n++] = c;
    }
    out[n] = '\0';
    return 0;
}

static int m_uint(mscan *s, uint64_t *out)
{
    size_t start = s->pos;
    uint64_t v = 0;
    while (m_peek(s) >= '0' && m_peek(s) <= '9') {
        v = v * 10 + (uint64_t)(s->b[s->pos] - '0');
        s->pos++;
        if (v > (1ULL << 62)) return -1;
    }
    if (s->pos == start) return -1;
    if (s->b[start] == '0' && s->pos - start > 1) return -1; /* leading zero */
    *out = v;
    return 0;
}

static int m_literal(mscan *s, const char *lit)
{
    mscan save = *s;
    for (const char *p = lit; *p; p++) {
        if (!m_take(s, *p)) {
            *s = save;
            return -1;
        }
    }
    return 0;
}

/* m_skip — walk one arbitrary canonical JSON value without interpreting
 * it (the additive-member tolerance). */
static int m_skip(mscan *s);

static int m_skip_string(mscan *s)
{
    if (!m_take(s, '"')) return -1;
    while (1) {
        if (s->pos >= s->len) return -1;
        char c = s->b[s->pos++];
        if (c == '"') return 0;
        if (c == '\\') {
            if (s->pos >= s->len) return -1;
            s->pos++; /* any escaped char */
        } else if ((unsigned char)c < 0x20) {
            return -1;
        }
    }
}

static int m_skip(mscan *s)
{
    int c = m_peek(s);
    if (c == '"') return m_skip_string(s);
    if (c == '{' || c == '[') {
        char open = (char)c, close = (c == '{') ? '}' : ']';
        int depth = 0;
        while (1) {
            if (s->pos >= s->len) return -1;
            char cur = s->b[s->pos];
            if (cur == '"') {
                if (m_skip_string(s) != 0) return -1;
                continue;
            }
            s->pos++;
            if (cur == open) depth++;
            else if (cur == close) {
                depth--;
                if (depth == 0) return 0;
            }
        }
    }
    if (c == 't') return m_literal(s, "true");
    if (c == 'f') return m_literal(s, "false");
    if (c == 'n') return m_literal(s, "null");
    if (c == '-' || (c >= '0' && c <= '9')) {
        size_t n = 0;
        while (s->pos < s->len) {
            char d = s->b[s->pos];
            if ((d >= '0' && d <= '9') || d == '.' || d == 'e' || d == 'E' || d == '+' || d == '-') {
                s->pos++;
                n++;
            } else {
                break;
            }
        }
        return n > 0 ? 0 : -1;
    }
    return -1;
}

static int hex_lower(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return n > 0;
}

int dtn_capsule_parse(const uint8_t *blob, size_t len, dtn_capsule *out)
{
    static const char *const want[10] = {
        "v", "release", "semver", "vcs", "arch",
        "min_upgrade_from", "spa_embedded", "payload_sha256", "payload_bytes", "created_at",
    };
    if (blob == NULL || out == NULL) return DTN_CAPSULE_BAD_MAGIC;
    memset(out, 0, sizeof(*out));
    if (len < DTN_CAPSULE_HEADER_LEN + DTN_CAPSULE_SIG_LEN) return DTN_CAPSULE_BAD_MAGIC;
    if (memcmp(blob, magic_v1, DTN_CAPSULE_MAGIC_LEN) != 0) return DTN_CAPSULE_BAD_MAGIC;
    if (blob[8] != 0 || blob[9] != 1) return DTN_CAPSULE_BAD_FORMAT;
    uint32_t mlen = ((uint32_t)blob[10] << 24) | ((uint32_t)blob[11] << 16) |
                    ((uint32_t)blob[12] << 8) | (uint32_t)blob[13];
    if (mlen == 0 || mlen > DTN_CAPSULE_MAX_MLEN) return DTN_CAPSULE_BAD_LENGTH;
    if (len < (size_t)DTN_CAPSULE_HEADER_LEN + mlen + DTN_CAPSULE_SIG_LEN) {
        return DTN_CAPSULE_BAD_LENGTH;
    }
    const uint8_t *meta = blob + DTN_CAPSULE_HEADER_LEN;
    size_t payload_len = len - DTN_CAPSULE_HEADER_LEN - mlen - DTN_CAPSULE_SIG_LEN;
    const uint8_t *payload = meta + mlen;
    const uint8_t *sig = payload + payload_len;

    /* The strict fixed-order scan. */
    mscan s = { (const char *)meta, mlen, 0 };
    if (!m_take(&s, '{')) return DTN_CAPSULE_BAD_METADATA;
    uint64_t nums[5] = {0, 0, 0, 0, 0}; /* v, release, min_upgrade_from, payload_bytes, created_at */
    for (int i = 0; i < 10; i++) {
        if (i > 0 && !m_take(&s, ',')) return DTN_CAPSULE_BAD_METADATA;
        char key[24];
        if (m_string(&s, key, sizeof key) != 0) return DTN_CAPSULE_BAD_METADATA;
        if (strcmp(key, want[i]) != 0) return DTN_CAPSULE_BAD_METADATA;
        if (!m_take(&s, ':')) return DTN_CAPSULE_BAD_METADATA;
        int rc = 0;
        switch (i) {
        case 0: rc = m_uint(&s, &nums[0]); break;
        case 1: rc = m_uint(&s, &nums[1]); break;
        case 2: rc = m_string(&s, out->meta.semver, sizeof out->meta.semver); break;
        case 3: rc = m_string(&s, out->meta.vcs, sizeof out->meta.vcs); break;
        case 4: rc = m_string(&s, out->meta.arch, sizeof out->meta.arch); break;
        case 5: rc = m_uint(&s, &nums[2]); break;
        case 6:
            if (m_literal(&s, "true")) {
                if (m_literal(&s, "false")) return DTN_CAPSULE_BAD_METADATA;
            } else {
                out->meta.spa_embedded = 1;
            }
            break;
        case 7: rc = m_string(&s, out->meta.payload_sha256, sizeof out->meta.payload_sha256); break;
        case 8: rc = m_uint(&s, &nums[3]); break;
        default: rc = m_uint(&s, &nums[4]); break;
        }
        if (rc != 0) return DTN_CAPSULE_BAD_METADATA;
    }
    /* Additive space: canonical unknown members after the frozen ten. */
    while (m_peek(&s) == ',') {
        s.pos++;
        char key[24];
        if (m_string(&s, key, sizeof key) != 0) return DTN_CAPSULE_BAD_METADATA;
        if (!m_take(&s, ':')) return DTN_CAPSULE_BAD_METADATA;
        if (m_skip(&s) != 0) return DTN_CAPSULE_BAD_METADATA;
    }
    if (!m_take(&s, '}') || s.pos != s.len) return DTN_CAPSULE_BAD_METADATA;

    /* The §2.1.2 constraint column. */
    if (nums[0] != 1) return DTN_CAPSULE_BAD_VERSION;
    if (nums[1] < 1) return DTN_CAPSULE_BAD_METADATA;
    if (!hex_lower(out->meta.payload_sha256, 64) || out->meta.payload_sha256[64] != '\0') {
        return DTN_CAPSULE_BAD_METADATA;
    }
    if (!out->meta.spa_embedded) return DTN_CAPSULE_BAD_METADATA;
    if (nums[4] == 0 || nums[4] > (uint64_t)INT64_MAX) return DTN_CAPSULE_CREATED_AT_SKEW;

    out->meta.v = (unsigned)nums[0];
    out->meta.release = nums[1];
    out->meta.min_upgrade_from = nums[2];
    out->meta.payload_bytes = nums[3];
    out->meta.created_at = (int64_t)nums[4];
    if ((uint64_t)payload_len != out->meta.payload_bytes) {
        return DTN_CAPSULE_LEN_MISMATCH;
    }
    out->meta_bytes = meta;
    out->meta_len = mlen;
    out->payload = payload;
    out->payload_len = payload_len;
    out->sig = sig;
    return DTN_CAPSULE_OK;
}

int dtn_capsule_verify(const dtn_capsule *c, const uint8_t pub[32])
{
    if (c == NULL) return DTN_CAPSULE_BAD_MAGIC;
    if (pub == NULL) return DTN_CAPSULE_UNPINNED;
    /* Step 2a: the cheap integrity check — hex-decode the metadata digest
     * and compare bytes (the Go side compares the hex strings; identical
     * predicate, no re-encoding needed here). */
    uint8_t sum[32], want[32];
    dtn_sha256(c->payload, c->payload_len, sum);
    for (int i = 0; i < 32; i++) {
        char a = c->meta.payload_sha256[2 * i], b = c->meta.payload_sha256[2 * i + 1];
#define HEXV(ch) ((ch) >= '0' && (ch) <= '9' ? (unsigned)((ch) - '0') : (unsigned)((ch) - 'a' + 10))
        want[i] = (uint8_t)((HEXV(a) << 4) | HEXV(b));
#undef HEXV
    }
    if (memcmp(sum, want, 32) != 0) return DTN_CAPSULE_SHA_MISMATCH;
    /* Step 2b: the Ed25519 signature over meta ‖ payload. The two segments
     * are ADJACENT in the input buffer (§2.1.1: header ‖ meta ‖ payload ‖
     * sig), so the signed message is one contiguous range — stream-hashed
     * by dtn_tn_ed25519_verify with O(1) stack, however big the payload. */
    if (c->sig == NULL || c->meta_bytes == NULL) return DTN_CAPSULE_BAD_SIGNATURE;
    if (dtn_tn_ed25519_verify(pub, c->sig, c->meta_bytes,
                              (unsigned long long)(c->meta_len + c->payload_len)) != 0) {
        return DTN_CAPSULE_BAD_SIGNATURE;
    }
    return DTN_CAPSULE_OK;
}

int dtn_capsule_stage(const uint8_t *blob, size_t len,
                      const uint8_t pub[32], const char *node_arch,
                      uint64_t running_release, uint64_t staged_release,
                      int64_t now_unix, dtn_capsule_meta *out_meta)
{
    /* §2.4.1: an unpinned key means staging is unavailable — fail closed
     * before any work with the bytes. */
    if (pub == NULL) return DTN_CAPSULE_UNPINNED;
    dtn_capsule c;
    int rc = dtn_capsule_parse(blob, len, &c); /* step 1 */
    if (rc != DTN_CAPSULE_OK) return rc;
    rc = dtn_capsule_verify(&c, pub); /* step 2 */
    if (rc != DTN_CAPSULE_OK) return rc;
    if (node_arch != NULL && node_arch[0] != '\0' &&
        strcmp(c.meta.arch, node_arch) != 0) {
        return DTN_CAPSULE_WRONG_ARCH; /* step 3, the §9.1 gate */
    }
    uint64_t floor = staged_release > running_release ? staged_release : running_release;
    if (c.meta.release <= floor) return DTN_CAPSULE_STALE; /* §2.6 rule 2 */
    if (c.meta.min_upgrade_from > running_release) return DTN_CAPSULE_TOO_OLD; /* §2.6 rule 3 */
    if (c.meta.created_at > now_unix + 300) return DTN_CAPSULE_CREATED_AT_SKEW; /* step 6 */
    if (out_meta != NULL) *out_meta = c.meta;
    return DTN_CAPSULE_OK;
}

/* --- the §9.4 chunk transport -------------------------------------------- */

static uint32_t chunk_sum(const uint8_t *data, size_t len)
{
    /* FNV-1a 32: a corruption DETECTOR for differing redelivery (the
     * capsule SHA-256 at verify time is the real boundary). */
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

int dtn_capsule_chunk_parse(const uint8_t *pdu, size_t len, dtn_capsule_chunk *out)
{
    if (pdu == NULL || out == NULL) return 0;
    if (len <= DTN_CAPSULE_CHUNK_HEADER_LEN) return 0;
    uint32_t total = ((uint32_t)pdu[8] << 24) | ((uint32_t)pdu[9] << 16) |
                     ((uint32_t)pdu[10] << 8) | (uint32_t)pdu[11];
    uint32_t idx = ((uint32_t)pdu[12] << 24) | ((uint32_t)pdu[13] << 16) |
                   ((uint32_t)pdu[14] << 8) | (uint32_t)pdu[15];
    if (total < 1 || total > DTN_CAPSULE_CHUNK_MAX_TOTAL) return 0;
    if (idx >= total) return 0;
    memcpy(out->id, pdu, 8);
    out->total = total;
    out->idx = idx;
    out->data = pdu + DTN_CAPSULE_CHUNK_HEADER_LEN;
    out->len = len - DTN_CAPSULE_CHUNK_HEADER_LEN;
    return 1;
}

void dtn_capsule_reasm_init(dtn_capsule_reasm *st)
{
    memset(st, 0, sizeof(*st));
}

static void reasm_forget_done(dtn_capsule_reasm *st, const uint8_t id[8])
{
    for (int i = 0; i < st->done_n; i++) {
        if (memcmp(st->done[i], id, 8) == 0) {
            memmove(st->done[i], st->done[i + 1], (size_t)(st->done_n - i - 1) * 8);
            st->done_n--;
            return;
        }
    }
}

static void reasm_drop(dtn_capsule_reasm *st, int slot)
{
    st->slots[slot].used = 0;
    memset(st->slots[slot].have, 0, sizeof st->slots[slot].have);
    memset(st->slots[slot].sum, 0, sizeof st->slots[slot].sum);
}

static void reasm_remember_done(dtn_capsule_reasm *st, const uint8_t id[8])
{
    if (st->done_n == DTN_CAPSULE_REASM_DONE_CAP) {
        memmove(st->done[0], st->done[1], (size_t)(DTN_CAPSULE_REASM_DONE_CAP - 1) * 8);
        st->done_n--;
    }
    memcpy(st->done[st->done_n++], id, 8);
}

int dtn_capsule_reasm_offer(dtn_capsule_reasm *st,
                            const uint8_t *pdu, size_t len,
                            int64_t now_unix, uint64_t lifetime_s,
                            uint8_t completed_id[8])
{
    dtn_capsule_chunk ch;
    if (!dtn_capsule_chunk_parse(pdu, len, &ch)) {
        st->refused++;
        return DTN_CAPSULE_REASM_BAD;
    }
    st->chunks_in++;
    /* Lazy TTL sweep (the janitor calls nothing here; the next offer and
     * the completion path keep the table honest). */
    for (int i = 0; i < DTN_CAPSULE_REASM_MAX_PARTIALS; i++) {
        if (st->slots[i].used && now_unix > st->slots[i].expires) {
            reasm_drop(st, i);
            st->expired++;
        }
    }
    /* Completed-capsule memory: redelivery after staging absorbs. */
    for (int i = 0; i < st->done_n; i++) {
        if (memcmp(st->done[i], ch.id, 8) == 0) {
            st->dups++;
            return DTN_CAPSULE_REASM_DUP;
        }
    }
    /* Find or allocate the partial. */
    int slot = -1;
    for (int i = 0; i < DTN_CAPSULE_REASM_MAX_PARTIALS; i++) {
        if (st->slots[i].used && memcmp(st->slots[i].id, ch.id, 8) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        int victim = -1;
        int64_t best = 0;
        for (int i = 0; i < DTN_CAPSULE_REASM_MAX_PARTIALS; i++) {
            if (!st->slots[i].used) {
                victim = i;
                break;
            }
            /* Full: evict the soonest-expiring (deterministic; lowest slot
             * breaks ties — the Go side ties on id bytes, unreachable at
             * the vectors' scale). */
            if (victim < 0 || st->slots[i].expires < best) {
                victim = i;
                best = st->slots[i].expires;
            }
        }
        slot = victim;
        reasm_drop(st, slot);
        memset(&st->slots[slot], 0, sizeof st->slots[slot]);
        st->slots[slot].used = 1;
        memcpy(st->slots[slot].id, ch.id, 8);
        st->slots[slot].total = ch.total;
        st->expired++; /* the eviction counter shares the honest bucket */
    }
    dtn_capsule_partial *p = &st->slots[slot];
    if (p->total != ch.total) {
        /* Two totals for one id: forged/corrupt header — fail the whole
         * partial (the §5.4 discipline). */
        reasm_drop(st, slot);
        st->refused++;
        return DTN_CAPSULE_REASM_REFUSED;
    }
    int is_last = (ch.idx == ch.total - 1);
    uint32_t sum = chunk_sum(ch.data, ch.len);
    if (p->have[ch.idx / 8] & (1u << (ch.idx % 8))) {
        if (p->sum[ch.idx] == sum) {
            st->dups++;
            return DTN_CAPSULE_REASM_DUP;
        }
        reasm_drop(st, slot); /* differing redelivery: corruption */
        st->refused++;
        return DTN_CAPSULE_REASM_REFUSED;
    }
    /* Stride discipline: every NON-last chunk carries the same length; the
     * last carries the remainder (never longer). */
    if (!is_last) {
        if (p->stride == 0) p->stride = (uint16_t)ch.len;
        if ((uint16_t)ch.len != p->stride) {
            reasm_drop(st, slot);
            st->refused++;
            return DTN_CAPSULE_REASM_REFUSED;
        }
    } else if (p->stride != 0 && ch.len > p->stride) {
        reasm_drop(st, slot);
        st->refused++;
        return DTN_CAPSULE_REASM_REFUSED;
    }
    /* Memory honesty: the implied capsule size must fit the staging cap. */
    uint64_t tail = is_last ? ch.len : (p->stride ? p->stride : ch.len);
    uint64_t size = (p->stride ? (uint64_t)(p->total - 1) * p->stride + tail : tail);
    if (size > DTN_CAPSULE_MAX_PAYLOAD) {
        reasm_drop(st, slot);
        st->refused++;
        return DTN_CAPSULE_REASM_REFUSED;
    }
    p->have[ch.idx / 8] |= (uint8_t)(1u << (ch.idx % 8));
    p->sum[ch.idx] = sum;
    p->received++;
    p->expires = now_unix + (int64_t)lifetime_s;
    if (p->received < p->total) return DTN_CAPSULE_REASM_STORED;

    /* Complete: hand back the id and remember it (dedup of redelivery). */
    memcpy(completed_id, ch.id, 8);
    reasm_forget_done(st, ch.id);
    reasm_remember_done(st, ch.id);
    reasm_drop(st, slot);
    st->completions++;
    return DTN_CAPSULE_REASM_COMPLETE;
}

int dtn_capsule_reasm_assemble(const uint8_t id[8], uint32_t total,
                               dtn_capsule_chunk_src src, void *ud,
                               uint8_t *out, size_t cap, size_t *out_len)
{
    if (id == NULL || src == NULL || out_len == NULL || total == 0 ||
        total > DTN_CAPSULE_CHUNK_MAX_TOTAL) {
        return -1;
    }
    /* The caller knows WHICH capsule it is assembling (the offer handed it
     * the id); the src callback resolves that capsule's chunks — on a node
     * from the bundle store, in the host suite from the vector arrays. */
    uint64_t bound = 0;
    const uint8_t *probe;
    size_t probe_len;
    for (uint32_t i = 0; i < total; i++) {
        if (src(ud, id, i, total, &probe, &probe_len) != 0) return -1;
        bound += probe_len;
    }
    if (bound > DTN_CAPSULE_MAX_PAYLOAD || bound > cap) return -1;
    size_t off = 0;
    for (uint32_t i = 0; i < total; i++) {
        const uint8_t *d;
        size_t n;
        if (src(ud, id, i, total, &d, &n) != 0) return -1;
        memcpy(out + off, d, n);
        off += n;
    }
    *out_len = off;
    return 0;
}

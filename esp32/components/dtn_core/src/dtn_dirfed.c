/* dtn_dirfed.c — the directory-federation verifier/merger (P3.8, issue #33).
 * The card is offline-maintenance §3.1's canonical-JSON identity card with
 * the detached Ed25519 self-signature — the EXACT bytes the §3.3 mule path
 * and the §3.2 HTTP door mint (one serialization, two transports). The
 * check ORDER and the verdict/outcome vocabulary mirror
 * node/internal/directory exactly; the shared vectors
 * (tests/vectors/directory/vectors.json via the generated
 * host/tests/directory_vectors.h) pin both implementations to the same
 * bytes, verdicts and post-merge row states. */
#include "dtn_dirfed.h"

#include <string.h>

#include "dtn_base64.h"
#include "dtn_ed25519.h"

/* ---- canonical-JSON scanners (the Go scanCard mirror) ----
 * The card grammar is FIXED: {"v":1,"alias":<A>,"ed":<E>,"x":<X>,"ts":<T>,
 * "seq":<S>,"sig":<G>} — no whitespace, fixed member order, canonical
 * integers (no leading zeros), standard Base64 values. Canonicality is
 * enforced by construction: anything that does not match the literals
 * exactly is DTN_DIRFED_ERR_SHAPE. */

static int lit_at(const uint8_t *c, size_t len, size_t *i, const char *s)
{
    size_t n = strlen(s);
    if (*i + n > len || memcmp(c + *i, s, n) != 0) return -1;
    *i += n;
    return 0;
}

/* is_std_b64 — the standard-Base64 alphabet (padding '=' included; pad
 * PLACEMENT is checked by the decoded-length rule below). */
static int is_std_b64(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=';
}

/* b64_field — consume `prefix` (through the opening quote), then exactly
 * b64_encoded_len(want) alphabet chars decoding to EXACTLY want bytes
 * (padding-aware: a 31-byte key encodes to the same 44 characters as a
 * 32-byte one with two pads — the decoded-length pin is what rejects it),
 * then the closing quote. Copies `want` bytes into out. */
static int b64_field(const uint8_t *c, size_t len, size_t *i,
                     const char *prefix, uint8_t *out, size_t want)
{
    size_t start, rawlen, pad = 0, k;
    long dec;

    if (lit_at(c, len, i, prefix) != 0) return -1;
    start = *i;
    while (*i < len && c[*i] != '"') (*i)++;
    if (*i >= len) return -1;
    rawlen = *i - start;
    if (rawlen != (want + 2) / 3 * 4) return -1;
    if (c[*i - 1] == '=') {
        pad = 1;
        if (c[*i - 2] == '=') pad = 2;
    }
    if (rawlen / 4 * 3 - pad != want) return -1;
    for (k = 0; k < rawlen; k++) {
        if (!is_std_b64(c[start + k])) return -1;
    }
    dec = dtn_base64_decode((const char *)c + start, rawlen, out, want);
    if (dec != (long)want) return -1;
    (*i)++; /* the closing quote */
    return 0;
}

/* uint_field — canonical unsigned decimal: at least one digit, no leading
 * zero, no overflow. */
static int uint_field(const uint8_t *c, size_t len, size_t *i, uint64_t *out)
{
    size_t start = *i;
    uint64_t v = 0;

    while (*i < len && c[*i] >= '0' && c[*i] <= '9') (*i)++;
    if (*i == start) return -1;
    if (*i - start > 1 && c[start] == '0') return -1;
    for (size_t k = start; k < *i; k++) {
        uint64_t d = (uint64_t)(c[k] - '0');
        if (v > (UINT64_MAX - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

/* valid_alias — the §8.1 alias regex ^[A-Za-z0-9_.-]{1,24}$, hand-rolled
 * (the portable core has no regex). */
static int valid_alias(const uint8_t *alias, size_t len)
{
    if (len < 1 || len > 24) return 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = alias[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return 0;
    }
    return 1;
}

/* parse_full — the shape scan, plus the two views verify needs: the
 * detached signature and signed_len, the byte length of the §3.1.1 signed
 * string PREFIX (the unsigned members without the closing brace — the
 * complete card replaced that brace with the sig member). */
static int parse_full(const uint8_t *card, size_t len, dtn_dirfed_card *out,
                      uint8_t sig[64], size_t *signed_len)
{
    size_t i = 0, start;
    uint64_t ts, seq;

    if (len == 0 || len > DTN_DIRFED_MAX) return DTN_DIRFED_ERR_SHAPE;
    memset(out, 0, sizeof(*out));
    if (lit_at(card, len, &i, "{\"v\":1,\"alias\":\"") != 0) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    out->v = 1; /* pinned by the consumed literal itself */
    start = i;
    while (i < len && card[i] != '"') i++;
    if (i >= len) return DTN_DIRFED_ERR_SHAPE;
    if (!valid_alias(card + start, i - start)) return DTN_DIRFED_ERR_SHAPE;
    memcpy(out->alias, card + start, i - start);
    out->alias[i - start] = '\0';
    i++; /* the closing quote */
    if (b64_field(card, len, &i, ",\"ed\":\"", out->ed, 32) != 0) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    if (b64_field(card, len, &i, ",\"x\":\"", out->x, 32) != 0) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    if (lit_at(card, len, &i, ",\"ts\":") != 0) return DTN_DIRFED_ERR_SHAPE;
    if (uint_field(card, len, &i, &ts) != 0 || ts == 0 ||
        ts > (uint64_t)0x7fffffffffffffffLL) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    out->created_ts = (int64_t)ts;
    if (lit_at(card, len, &i, ",\"seq\":") != 0) return DTN_DIRFED_ERR_SHAPE;
    if (uint_field(card, len, &i, &seq) != 0 || seq < 1) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    out->seq = seq;
    *signed_len = i;
    if (b64_field(card, len, &i, ",\"sig\":\"", sig, 64) != 0) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    if (lit_at(card, len, &i, "}") != 0 || i != len) {
        return DTN_DIRFED_ERR_SHAPE;
    }
    return DTN_DIRFED_OK;
}

/* dtn_dirfed_parse — the SHAPE half (§3.2's blind validation): the exact
 * canonical form (fixed member order v, alias, ed, x, ts, seq, sig; no
 * whitespace; canonical integers), v == 1, the §8.1 alias regex, 32-byte
 * keys, created_ts > 0, seq ≥ 1, the whole card ≤ DTN_DIRFED_MAX. NO
 * signature check, NO skew check. */
int dtn_dirfed_parse(const uint8_t *card, size_t len, dtn_dirfed_card *out)
{
    uint8_t sig[64];
    size_t signed_len;

    return parse_full(card, len, out, sig, &signed_len);
}

int dtn_dirfed_verify(const uint8_t *card, size_t len, int64_t now,
                      dtn_dirfed_card *out)
{
    /* The §3.1.1 signed byte string: the unsigned-members prefix with the
     * closing brace rebuilt (the complete card replaced that brace with
     * `,"sig":…`). ≤ DTN_DIRFED_MAX + 1, inside the verifier's 2 KiB. */
    uint8_t signed_buf[DTN_DIRFED_MAX + 1];
    uint8_t sig[64];
    size_t signed_len;

    int v = parse_full(card, len, out, sig, &signed_len);
    if (v != DTN_DIRFED_OK) return v;
    memcpy(signed_buf, card, signed_len);
    signed_buf[signed_len] = '}';
    if (dtn_ed25519_verify(out->ed, sig, signed_buf, signed_len + 1) !=
        DTN_ED25519_OK) {
        return DTN_DIRFED_ERR_SIG;
    }
    /* The §3.1 skew rule: created_ts ≤ now + 300 (the receiver's clock is
     * the reference — a card created in the receiver's future is dropped). */
    if (out->created_ts > now + DTN_DIRFED_MAX_SKEW) {
        return DTN_DIRFED_ERR_SKEW;
    }
    return DTN_DIRFED_OK;
}

/* stored_seq_of decodes the stored card TEXT and returns its §3.4 sequence
 * — 0 for an absent card or anything unreadable (rule 2's implied sequence
 * 0; the corruption guard, never a validation path). */
static uint64_t stored_seq_of(const char *card_b64)
{
    dtn_dirfed_card sc;
    uint8_t raw[DTN_DIRFED_MAX];

    if (!card_b64 || card_b64[0] == '\0') return 0;
    long dec = dtn_base64_decode(card_b64, strlen(card_b64),
                                 raw, sizeof(raw));
    if (dec <= 0 || (size_t)dec > DTN_DIRFED_MAX) return 0;
    if (dtn_dirfed_parse(raw, (size_t)dec, &sc) != DTN_DIRFED_OK) return 0;
    return sc.seq;
}

int dtn_dirfed_merge(dtn_store *st, const uint8_t *card, size_t len,
                     int64_t now, int32_t row_cap)
{
    dtn_dirfed_card cardobj;
    dtn_dir_row row;
    char pubkey[45];
    char x25519[45];
    char card_b64[DTN_DIR_CARD_B64_MAX];
    long b64_len;

    /* Verify FIRST with the card's own key (the §3.4 preamble); a card
     * that does not verify never reaches the merge rules. */
    int v = dtn_dirfed_verify(card, len, now, &cardobj);
    if (v != DTN_DIRFED_OK) return v;

    /* The dedup key is the pubkey (rule 1) — the same canonical Base64
     * the directory table keys on (the Go side encodes; this encoder is
     * byte-parity, pinned by the host suite). */
    b64_len = dtn_base64_encode(cardobj.ed, 32, pubkey, sizeof(pubkey));
    if (b64_len != 44) return DTN_DIRFED_MERGE_ERR;
    b64_len = dtn_base64_encode(cardobj.x, 32, x25519, sizeof(x25519));
    if (b64_len != 44) return DTN_DIRFED_MERGE_ERR;
    b64_len = dtn_base64_encode(card, len, card_b64, sizeof(card_b64));
    if (b64_len <= 0 || (size_t)b64_len >= sizeof(card_b64)) {
        return DTN_DIRFED_MERGE_ERR;
    }

    int found = dtn_store_dir_find(st, pubkey, &row) == 0;
    if (!found) {
        /* Rule 1: INSERT — after the row_cap refusal (see the header's
         * scope note: eviction-under-pressure is the Pi side's policy). */
        if (row_cap > 0 && dtn_store_dir_count(st) >= row_cap) {
            return DTN_DIRFED_DROP_AT_CAP;
        }
        if (dtn_store_dir_upsert_full(st, cardobj.alias, pubkey, x25519,
                                      NULL, card_b64, 1, now) != 0) {
            return DTN_DIRFED_MERGE_ERR;
        }
        return DTN_DIRFED_INSERT;
    }

    /* Rules 2–4 against the stored row (a NULL/unreadable stored card is
     * the implied sequence 0 — rule 2's own words). */
    uint64_t stored_seq = stored_seq_of(row.card);
    if (cardobj.seq > stored_seq) {
        /* Rule 2: replace alias/x25519/card, refresh last_seen/epoch;
         * source deliberately untouched (rule 5: promotion works in one
         * direction only) and the §4.6 prekeys bundle preserved. */
        const char *prekeys = row.prekeys[0] != '\0' ? row.prekeys : NULL;
        if (dtn_store_dir_upsert_full(st, cardobj.alias, pubkey, x25519,
                                      prekeys, card_b64, row.source,
                                      now) != 0) {
            return DTN_DIRFED_MERGE_ERR;
        }
        return DTN_DIRFED_REPLACE;
    }
    if (cardobj.seq < stored_seq) {
        return DTN_DIRFED_STALE; /* rule 3: the row is not touched at all */
    }
    /* Rule 4: byte-equal → duplicate; differing → conflict (keep the
     * existing row — the old key survives; the SPA continuity path stays
     * consistent). Byte-compare against the stored card's DECODED bytes. */
    uint8_t stored_raw[DTN_DIRFED_MAX];
    long dec = 0;
    if (row.card[0] != '\0') {
        dec = dtn_base64_decode(row.card, strlen(row.card),
                                stored_raw, sizeof(stored_raw));
    }
    if (dec == (long)len && memcmp(stored_raw, card, len) == 0) {
        return DTN_DIRFED_DUPLICATE;
    }
    return DTN_DIRFED_CONFLICT;
}

/* dtn_rolecert.c — COSE_Sign1 role-cert verify + §2.5 merge rules (P3.1).
 * The check ORDER and failure classes mirror node/internal/nodeid/
 * rolecert.go exactly; the shared vectors pin both to the same bytes. */
#include "dtn_rolecert.h"

#include <string.h>

#include "dtn_cbor.h"
#include "dtn_ed25519.h"
#include "dtn_sha256.h"

/* The COSE_Sign1 protected header of v1: {1: -8} in canonical bytes
 * (A1 01 27 — CBOR -8 is major 1, n=7). Pinned, not interpreted. */
static const uint8_t protected_v1[] = {0xA1, 0x01, 0x27};

/* Sig_structure = ["Signature1", protected, external_aad(empty), payload]:
 * 84 | 6A "Signature1" | 43 A1 01 27 | 40 | 58/59 <len> payload */
static const uint8_t sig_struct_prefix[] = {
    0x84, 0x6A,
    'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
    0x43, 0xA1, 0x01, 0x27,
    0x40,
};

int dtn_rolecert_expired(const dtn_rolecert *c, int64_t now)
{
    return c->expires_ts < now;
}

int dtn_rolecert_has_role(const dtn_rolecert *c, const char *role)
{
    for (size_t i = 0; i < c->role_count; i++) {
        if (strcmp(c->roles[i], role) == 0) return 1;
    }
    return 0;
}

/* kid_of — SHA-256(anchor pub)[0:8], the key-selection slot. */
static void kid_of(const uint8_t anchor_pub[32], uint8_t kid[8])
{
    uint8_t digest[32];
    dtn_sha256(anchor_pub, 32, digest);
    memcpy(kid, digest, 8);
}

/* parse_roles — the closed §2.3 set; anything else (or a duplicate) fails. */
static const char *valid_roles[] = {"edge", "relay", "bridge", "manager", "anchor"};

static int role_known(const char *r)
{
    for (size_t i = 0; i < sizeof(valid_roles) / sizeof(valid_roles[0]); i++) {
        if (strcmp(r, valid_roles[i]) == 0) return 1;
    }
    return 0;
}

/* parse_cert_map — the §2.2 map: exactly 8 pairs, keys 0..7 ascending,
 * each value the table's type. */
static int parse_cert_map(const uint8_t *payload, size_t len, dtn_rolecert *out)
{
    dtn_cbor r;
    size_t pairs;
    uint64_t version = 0, level = 0, issued = 0, expires = 0, seq = 0;
    const char *eid = NULL;
    size_t eid_len = 0;
    const uint8_t *node_key = NULL;
    size_t node_key_len = 0;
    const char *roles[DTN_ROLECERT_ROLES_CAP];
    size_t roles_len[DTN_ROLECERT_ROLES_CAP];
    size_t role_count = 0;

    memset(out, 0, sizeof(*out));
    dtn_cbor_init(&r, payload, len);
    if (dtn_cbor_map(&r, &pairs) != DTN_CBOR_OK || pairs != 8) {
        return DTN_ROLECERT_ERR_SCHEMA;
    }
    for (uint64_t want = 0; want < 8; want++) {
        uint64_t key;
        if (dtn_cbor_uint(&r, &key) != DTN_CBOR_OK || key != want) {
            return DTN_ROLECERT_ERR_SCHEMA; /* fixed key order 0..7 */
        }
        switch (want) {
        case 0:
            if (dtn_cbor_uint(&r, &version) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            if (version != 1) return DTN_ROLECERT_ERR_VERSION;
            break;
        case 1:
            if (dtn_cbor_tstr(&r, &eid, &eid_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        case 2:
            if (dtn_cbor_bstr(&r, &node_key, &node_key_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            if (node_key_len != 32) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        case 3: {
            size_t items;
            if (dtn_cbor_array(&r, &items) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            if (items > DTN_ROLECERT_ROLES_CAP) return DTN_ROLECERT_ERR_SCHEMA;
            for (size_t i = 0; i < items; i++) {
                if (dtn_cbor_tstr(&r, &roles[role_count], &roles_len[role_count]) != DTN_CBOR_OK) {
                    return DTN_ROLECERT_ERR_SCHEMA;
                }
                role_count++;
            }
            dtn_cbor_pop(&r);
            break;
        }
        case 4:
            if (dtn_cbor_uint(&r, &level) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        case 5:
            if (dtn_cbor_uint(&r, &issued) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        case 6:
            if (dtn_cbor_uint(&r, &expires) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        default: /* 7: seq */
            if (dtn_cbor_uint(&r, &seq) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_SCHEMA;
            break;
        }
    }
    if (!dtn_cbor_done(&r)) return DTN_ROLECERT_ERR_SCHEMA;

    /* ---- schema checks (the §2.2 constraint column) ---- */
    if (eid_len < (size_t)DTN_NODEID_EID_MAX || eid_len > (size_t)DTN_NODEID_EID_MAX) {
        return DTN_ROLECERT_ERR_SCHEMA;
    }
    for (size_t i = 0; i < role_count; i++) {
        /* the longest valid role is "manager" (7 chars): anything longer is
         * definitionally outside the closed §2.3 set — same class the Go
         * side reports (set membership, not shape) */
        if (roles_len[i] == 0 || roles_len[i] >= DTN_ROLECERT_ROLE_MAX) {
            return DTN_ROLECERT_ERR_ROLE;
        }
        for (size_t j = 0; j < i; j++) {
            if (roles_len[i] == roles_len[j] &&
                memcmp(roles[i], roles[j], roles_len[i]) == 0) {
                return DTN_ROLECERT_ERR_SCHEMA; /* roles are a set */
            }
        }
        char name[DTN_ROLECERT_ROLE_MAX];
        memcpy(name, roles[i], roles_len[i]);
        name[roles_len[i]] = '\0';
        if (!role_known(name)) return DTN_ROLECERT_ERR_ROLE;
    }
    if (level > DTN_ROLECERT_MAX_LEVEL) return DTN_ROLECERT_ERR_LEVEL;
    if (role_count == 0 && level != 0) return DTN_ROLECERT_ERR_LEVEL;
    if (role_count > 0 && level == 0) return DTN_ROLECERT_ERR_LEVEL;
    if (issued == 0 || issued > (uint64_t)(0x7fffffffffffffffLL)) return DTN_ROLECERT_ERR_TS;
    if (expires == 0 || expires > (uint64_t)(0x7fffffffffffffffLL)) return DTN_ROLECERT_ERR_TS;
    if (seq < 1) return DTN_ROLECERT_ERR_SEQ;

    /* ---- fill the struct ---- */
    memcpy(out->eid, eid, eid_len);
    out->eid[eid_len] = '\0';
    memcpy(out->node_key, node_key, 32);
    for (size_t i = 0; i < role_count; i++) {
        memcpy(out->roles[i], roles[i], roles_len[i]);
        out->roles[i][roles_len[i]] = '\0';
    }
    out->role_count = role_count;
    out->level = (unsigned)level;
    out->issued_ts = (int64_t)issued;
    out->expires_ts = (int64_t)expires;
    out->seq = seq;

    /* ---- the §2.1 binding check ---- */
    if (dtn_nodeid_eid_binding(out->node_key, out->eid) != 0) {
        return DTN_ROLECERT_ERR_BINDING;
    }

    /* ---- timestamp sanity (the clock-relative skew check runs in
     * dtn_rolecert_verify, which owns `now`) ---- */
    if (out->issued_ts <= 0) return DTN_ROLECERT_ERR_TS;
    if (out->expires_ts <= out->issued_ts) return DTN_ROLECERT_ERR_TS;

    return DTN_ROLECERT_OK;
}

int dtn_rolecert_verify(const uint8_t *cose, size_t len,
                        const uint8_t anchor_pub[32], int64_t now,
                        dtn_rolecert *out)
{
    dtn_cbor r;
    size_t items;
    const uint8_t *protected = NULL, *payload = NULL, *sig = NULL, *kid = NULL;
    size_t protected_len = 0, payload_len = 0, sig_len = 0, kid_len = 0;
    uint8_t want_kid[8];
    uint8_t sig_struct[sizeof(sig_struct_prefix) + 3 + DTN_ROLECERT_MAX];
    size_t sig_struct_len;
    int rc;

    if (len > DTN_ROLECERT_MAX) return DTN_ROLECERT_ERR_COSE;

    /* COSE_Sign1 = [protected bstr, unprotected map(1) {4: kid bstr(8)},
     * payload bstr, signature bstr(64)] with no trailing bytes. */
    dtn_cbor_init(&r, cose, len);
    if (dtn_cbor_array(&r, &items) != DTN_CBOR_OK || items != 4) {
        return DTN_ROLECERT_ERR_COSE;
    }
    if (dtn_cbor_bstr(&r, &protected, &protected_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_COSE;
    {
        size_t pairs;
        uint64_t label;
        if (dtn_cbor_map(&r, &pairs) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_COSE;
        if (pairs != 1) return DTN_ROLECERT_ERR_COSE;
        if (dtn_cbor_uint(&r, &label) != DTN_CBOR_OK || label != 4) return DTN_ROLECERT_ERR_COSE;
        if (dtn_cbor_bstr(&r, &kid, &kid_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_COSE;
        dtn_cbor_pop(&r);
    }
    if (dtn_cbor_bstr(&r, &payload, &payload_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_COSE;
    if (dtn_cbor_bstr(&r, &sig, &sig_len) != DTN_CBOR_OK) return DTN_ROLECERT_ERR_COSE;
    if (!dtn_cbor_done(&r)) return DTN_ROLECERT_ERR_COSE;

    /* Protected header pinned to the exact canonical bytes of {1: -8}. */
    if (protected_len != sizeof(protected_v1) ||
        memcmp(protected, protected_v1, sizeof(protected_v1)) != 0) {
        return DTN_ROLECERT_ERR_PROTECTED;
    }
    /* kid MUST be the pinned anchor's fingerprint (key selection, §2.2). */
    kid_of(anchor_pub, want_kid);
    if (kid_len != sizeof(want_kid) || memcmp(kid, want_kid, sizeof(want_kid)) != 0) {
        return DTN_ROLECERT_ERR_ANCHOR_FP;
    }
    /* Ed25519 over the reconstructed Sig_structure. */
    sig_struct_len = 0;
    memcpy(sig_struct, sig_struct_prefix, sizeof(sig_struct_prefix));
    sig_struct_len += sizeof(sig_struct_prefix);
    if (payload_len < 24) {
        sig_struct[sig_struct_len++] = (uint8_t)(0x40 + payload_len); /* 0x58 = 0x40|len */
    } else if (payload_len <= 0xff) {
        sig_struct[sig_struct_len++] = 0x58;
        sig_struct[sig_struct_len++] = (uint8_t)payload_len;
    } else if (payload_len <= 0xffff) {
        sig_struct[sig_struct_len++] = 0x59;
        sig_struct[sig_struct_len++] = (uint8_t)(payload_len >> 8);
        sig_struct[sig_struct_len++] = (uint8_t)(payload_len & 0xff);
    } else {
        return DTN_ROLECERT_ERR_COSE;
    }
    memcpy(sig_struct + sig_struct_len, payload, payload_len);
    sig_struct_len += payload_len;

    if (dtn_ed25519_verify(anchor_pub, sig, sig_struct, sig_struct_len) != DTN_ED25519_OK) {
        return DTN_ROLECERT_ERR_SIGNATURE;
    }

    rc = parse_cert_map(payload, payload_len, out);
    if (rc != DTN_ROLECERT_OK) return rc;

    /* the §4.3 skew rule: issued_ts ≤ now + 300 */
    if (out->issued_ts > now + DTN_ROLECERT_MAX_SKEW) return DTN_ROLECERT_ERR_TS;

    /* §2.5 rule 5: expired is a POSITIVE result (signed, valid) that the
     * callers treat as absent. */
    if (dtn_rolecert_expired(out, now)) return DTN_ROLECERT_EXPIRED;
    return DTN_ROLECERT_OK;
}

/* --- the §2.5 cache ----------------------------------------------------------- */

void dtn_rolecert_cache_init(dtn_rolecert_cache *c)
{
    memset(c, 0, sizeof(*c));
}

static dtn_rolecert_slot *find_slot(dtn_rolecert_cache *c, const char *eid)
{
    for (size_t i = 0; i < c->used; i++) {
        if (strcmp(c->slots[i].cert.eid, eid) == 0) return &c->slots[i];
    }
    return NULL;
}

static int slot_store(dtn_rolecert_slot *s, const dtn_rolecert *cert,
                      const uint8_t *raw, size_t raw_len)
{
    s->cert = *cert;
    memcpy(s->raw, raw, raw_len);
    s->raw_len = raw_len;
    return 0;
}

int dtn_rolecert_cache_merge(dtn_rolecert_cache *c, const uint8_t *cose, size_t len,
                             const uint8_t anchor_pub[32], int64_t now,
                             dtn_rolecert_merge_status *out)
{
    dtn_rolecert cert;
    int rc = dtn_rolecert_verify(cose, len, anchor_pub, now, &cert);

    out->revoked = 0;
    out->reason = rc;
    if (rc == DTN_ROLECERT_EXPIRED) {
        /* rule 5: treated as absent — not stored, nothing replaced (a lapsed
         * cert must not raise the seq floor behind the anchor's back). */
        out->outcome = DTN_ROLECERT_MERGE_EXPIRED_DROPPED;
        return DTN_ROLECERT_OK;
    }
    if (rc != DTN_ROLECERT_OK) {
        out->outcome = DTN_ROLECERT_MERGE_INVALID;
        return DTN_ROLECERT_OK;
    }
    out->revoked = (cert.role_count == 0);

    dtn_rolecert_slot *slot = find_slot(c, cert.eid);
    if (slot == NULL) {
        if (c->used >= DTN_ROLECERT_CACHE_CAP) {
            out->outcome = DTN_ROLECERT_MERGE_INVALID; /* cache full: fail closed */
            out->reason = -1;
            return DTN_ROLECERT_OK;
        }
        slot = &c->slots[c->used++];
        slot_store(slot, &cert, cose, len);
        out->outcome = DTN_ROLECERT_MERGE_REPLACED;
        return DTN_ROLECERT_OK;
    }

    if (cert.seq > slot->cert.seq) {
        slot_store(slot, &cert, cose, len); /* rule 1: replace */
        out->outcome = DTN_ROLECERT_MERGE_REPLACED;
    } else if (cert.seq < slot->cert.seq) {
        c->stale_dropped++; /* rule 2: stale */
        out->outcome = DTN_ROLECERT_MERGE_STALE_DROPPED;
    } else if (slot->raw_len == len && memcmp(slot->raw, cose, len) == 0) {
        out->outcome = DTN_ROLECERT_MERGE_UNCHANGED; /* identical redelivery */
    } else {
        c->conflicts++; /* rule 3: equal seq, differing bytes — attack signal */
        out->outcome = DTN_ROLECERT_MERGE_CONFLICT_KEPT;
        out->revoked = (slot->cert.role_count == 0);
    }
    return DTN_ROLECERT_OK;
}

int dtn_rolecert_cache_effective(const dtn_rolecert_cache *c, const char *eid,
                                 int64_t now, const dtn_rolecert **out)
{
    for (size_t i = 0; i < c->used; i++) {
        if (strcmp(c->slots[i].cert.eid, eid) == 0) {
            const dtn_rolecert *cert = &c->slots[i].cert;
            if (out) *out = cert;
            if (dtn_rolecert_expired(cert, now)) return DTN_ROLECERT_STATE_EXPIRED;
            if (cert->role_count == 0) return DTN_ROLECERT_STATE_REVOKED;
            return DTN_ROLECERT_STATE_AUTHORITY;
        }
    }
    if (out) *out = NULL;
    return DTN_ROLECERT_STATE_ABSENT;
}

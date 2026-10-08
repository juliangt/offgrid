/* dtn_mgmt.c — the §8.2 enforcement pipeline (P3.6). The check ORDER and
 * failure classes mirror node/internal/mgmt exactly; the shared vectors pin
 * both to the same bytes. */
#include "dtn_mgmt.h"

#include <stdio.h>
#include <string.h>

#include "dtn_cbor.h"
#include "dtn_ed25519.h"
#include "dtn_sha256.h"

/* The COSE_Sign1 protected header of v1: {1: -8} in canonical bytes — the
 * same pinned header every node-plane COSE object carries. */
static const uint8_t protected_v1[] = {0xA1, 0x01, 0x27};

/* Sig_structure = ["Signature1", protected, external_aad(empty), payload]:
 * 84 | 6A "Signature1" | 43 A1 01 27 | 40 | 58/59 <len> payload */
static const uint8_t sig_struct_prefix[] = {
    0x84, 0x6A,
    'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
    0x43, 0xA1, 0x01, 0x27,
    0x40,
};

/* The frozen v1 command table (name → required §2.4 level). Keep in sync
 * with node/internal/mgmt/mgmt.go — the vectors catch drift. */
static const struct { const char *name; int level; } command_table[] = {
    {"get_status", 0},
    {"force_janitor", 1},
    {"trigger_sync", 1},
    {"set_quiet_hours", 1},
    {"set_store_cap", 2},
    {"set_budgets", 2},
    {"set_dial_interval", 2},
    {"federation_on", 2},
    {"federation_off", 2},
    {"install_cert", 3},
    {"factory_reset_node_plane", 3},
};

int dtn_mgmt_required_level(const char *cmd)
{
    for (size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); i++) {
        if (strcmp(command_table[i].name, cmd) == 0) return command_table[i].level;
    }
    return -1;
}

void dtn_mgmt_seqs_init(dtn_mgmt_seqs *s)
{
    memset(s, 0, sizeof(*s));
}

uint64_t dtn_mgmt_seq_last(const dtn_mgmt_seqs *s, const char *eid)
{
    for (size_t i = 0; i < s->used; i++) {
        if (strcmp(s->slots[i].eid, eid) == 0) return s->slots[i].last_seq;
    }
    return 0;
}

int dtn_mgmt_seq_commit(dtn_mgmt_seqs *s, const char *eid, uint64_t seq)
{
    for (size_t i = 0; i < s->used; i++) {
        if (strcmp(s->slots[i].eid, eid) == 0) {
            s->slots[i].last_seq = seq;
            return 0;
        }
    }
    if (s->used >= DTN_MGMT_SEQS_CAP) return -1; /* table full: fail closed */
    snprintf(s->slots[s->used].eid, sizeof(s->slots[s->used].eid), "%s", eid);
    s->slots[s->used].last_seq = seq;
    s->used++;
    return 0;
}

/* split_cose — [protected bstr, unprotected map(1) {4: kid bstr(8)},
 * payload bstr, sig bstr(64)], no trailing bytes. Views into cose. */
static int split_cose(const uint8_t *cose, size_t len,
                      const uint8_t **protected, size_t *protected_len,
                      const uint8_t **kid, size_t *kid_len,
                      const uint8_t **payload, size_t *payload_len,
                      const uint8_t **sig, size_t *sig_len)
{
    dtn_cbor r;
    size_t items, pairs;
    uint64_t label;

    dtn_cbor_init(&r, cose, len);
    if (dtn_cbor_array(&r, &items) != DTN_CBOR_OK || items != 4) return -1;
    if (dtn_cbor_bstr(&r, protected, protected_len) != DTN_CBOR_OK) return -1;
    if (dtn_cbor_map(&r, &pairs) != DTN_CBOR_OK || pairs != 1) return -1;
    if (dtn_cbor_uint(&r, &label) != DTN_CBOR_OK || label != 4) return -1;
    if (dtn_cbor_bstr(&r, kid, kid_len) != DTN_CBOR_OK) return -1;
    dtn_cbor_pop(&r);
    if (dtn_cbor_bstr(&r, payload, payload_len) != DTN_CBOR_OK) return -1;
    if (dtn_cbor_bstr(&r, sig, sig_len) != DTN_CBOR_OK) return -1;
    if (!dtn_cbor_done(&r)) return -1;
    return 0;
}

/* parse_args — the args map: ≤ DTN_MGMT_ARGS_MAX pairs, tstr keys in
 * ascending order (canonical CBOR), values limited to uint | tstr | bstr.
 * String/bstr values VIEW into the payload (valid while cose lives). */
static int parse_args(dtn_cbor *r, dtn_mgmt_arg *args, size_t *count)
{
    size_t pairs;
    if (dtn_cbor_map(r, &pairs) != DTN_CBOR_OK) return -1;
    if (pairs > DTN_MGMT_ARGS_MAX) return -1;
    for (size_t i = 0; i < pairs; i++) {
        const char *key;
        size_t key_len;
        uint8_t head;
        if (dtn_cbor_tstr(r, &key, &key_len) != DTN_CBOR_OK) return -1;
        if (key_len == 0 || key_len >= DTN_MGMT_ARG_KEY_MAX) return -1;
        if (i > 0 && strncmp(key, args[i - 1].key, DTN_MGMT_ARG_KEY_MAX) <= 0) {
            return -1; /* canonical CBOR: keys strictly ascending */
        }
        dtn_mgmt_arg *a = &args[*count];
        memset(a, 0, sizeof(*a));
        memcpy(a->key, key, key_len);
        a->key[key_len] = '\0';
        if (dtn_cbor_peek(r, &head) != DTN_CBOR_OK) return -1;
        switch (head >> 5) {
        case 0: { /* uint */
            uint64_t u;
            if (dtn_cbor_uint(r, &u) != DTN_CBOR_OK) return -1;
            a->kind = DTN_MGMT_ARG_UINT;
            a->u = u;
            break;
        }
        case 2: { /* bstr */
            if (dtn_cbor_bstr(r, &a->bytes, &a->bytes_len) != DTN_CBOR_OK) return -1;
            a->kind = DTN_MGMT_ARG_BSTR;
            break;
        }
        case 3: { /* tstr */
            if (dtn_cbor_tstr(r, &a->str, &a->str_len) != DTN_CBOR_OK) return -1;
            a->kind = DTN_MGMT_ARG_TSTR;
            break;
        }
        default:
            return -1; /* outside the v1 value set */
        }
        (*count)++;
    }
    dtn_cbor_pop(r);
    return 0;
}

/* parse_command_map — the §8.1 map: exactly 6 pairs, keys 0..5 in order,
 * each value the table's type. */
static int parse_command_map(const uint8_t *payload, size_t len, dtn_mgmt_cmd *out)
{
    dtn_cbor r;
    size_t pairs;
    uint64_t key;

    memset(out, 0, sizeof(*out));
    dtn_cbor_init(&r, payload, len);
    if (dtn_cbor_map(&r, &pairs) != DTN_CBOR_OK || pairs != 6) return -1;
    for (uint64_t want = 0; want < 6; want++) {
        if (dtn_cbor_uint(&r, &key) != DTN_CBOR_OK || key != want) return -1;
        switch (want) {
        case 0: { /* cmd */
            const char *cmd;
            size_t cmd_len;
            if (dtn_cbor_tstr(&r, &cmd, &cmd_len) != DTN_CBOR_OK) return -1;
            if (cmd_len == 0 || cmd_len >= DTN_MGMT_CMD_MAX) return -1;
            memcpy(out->cmd, cmd, cmd_len);
            out->cmd[cmd_len] = '\0';
            break;
        }
        case 1: /* args */
            if (parse_args(&r, out->args, &out->arg_count) != DTN_CBOR_OK) return -1;
            break;
        case 2: { /* target_node: "" (broadcast) or an exact node EID */
            const char *target;
            size_t target_len;
            if (dtn_cbor_tstr(&r, &target, &target_len) != DTN_CBOR_OK) return -1;
            if (target_len > DTN_NODEID_EID_MAX) return -1;
            memcpy(out->target, target, target_len);
            out->target[target_len] = '\0';
            /* the reader's tstr is a VIEW (not NUL-terminated): the EID
             * parser needs the terminated copy above. */
            if (target_len > 0 &&
                dtn_nodeid_eid_fingerprint(out->target, (uint8_t[8]){0}) != 0) {
                return -1;
            }
            break;
        }
        case 3: { /* issued_ts */
            uint64_t u;
            if (dtn_cbor_uint(&r, &u) != DTN_CBOR_OK) return -1;
            if (u > (uint64_t)0x7fffffffffffffffLL) return -1;
            out->issued_ts = (int64_t)u;
            break;
        }
        case 4: { /* expiry */
            uint64_t u;
            if (dtn_cbor_uint(&r, &u) != DTN_CBOR_OK) return -1;
            if (u > (uint64_t)0x7fffffffffffffffLL) return -1;
            out->expiry = (int64_t)u;
            break;
        }
        default: /* 5: seq */
            if (dtn_cbor_uint(&r, &out->seq) != DTN_CBOR_OK) return -1;
            break;
        }
    }
    return dtn_cbor_done(&r) ? 0 : -1;
}

/* verify_signature — Ed25519 over the reconstructed RFC 9052 Sig_structure
 * (the same machinery dtn_rolecert.c uses for the anchor's certs; here the
 * key is the signer's CERTIFIED node key). */
static int verify_signature(const uint8_t *cose, size_t len, const uint8_t node_key[32])
{
    const uint8_t *protected, *payload, *sig;
    size_t protected_len, payload_len, sig_len;
    const uint8_t *kid;
    size_t kid_len;
    uint8_t sig_struct[sizeof(sig_struct_prefix) + 4 + DTN_MGMT_MAX];
    size_t off = 0;

    if (split_cose(cose, len, &protected, &protected_len, &kid, &kid_len,
                   &payload, &payload_len, &sig, &sig_len) != 0) {
        return -1;
    }
    memcpy(sig_struct, sig_struct_prefix, sizeof(sig_struct_prefix));
    off += sizeof(sig_struct_prefix);
    if (payload_len < 24) {
        sig_struct[off++] = (uint8_t)(0x40 + payload_len);
    } else if (payload_len <= 0xff) {
        sig_struct[off++] = 0x58;
        sig_struct[off++] = (uint8_t)payload_len;
    } else if (payload_len <= 0xffff) {
        sig_struct[off++] = 0x59;
        sig_struct[off++] = (uint8_t)(payload_len >> 8);
        sig_struct[off++] = (uint8_t)(payload_len & 0xff);
    } else {
        return -1;
    }
    memcpy(sig_struct + off, payload, payload_len);
    off += payload_len;
    if (dtn_ed25519_verify(node_key, sig, sig_struct, off) != DTN_ED25519_OK) {
        return -1;
    }
    return 0;
}

int dtn_mgmt_decide(const dtn_rolecert_cache *certs,
                    const char *local_eid,
                    const uint8_t *cose, size_t len,
                    int64_t now,
                    dtn_mgmt_seqs *seqs,
                    dtn_mgmt_cmd *out)
{
    dtn_mgmt_cmd cmd;
    const uint8_t *protected, *payload, *sig;
    size_t protected_len, payload_len, sig_len;
    const uint8_t *kid;
    size_t kid_len;
    char signer_eid[DTN_NODEID_EID_MAX + 1];
    const dtn_rolecert *cert;
    int state, required;

    if (out) memset(out, 0, sizeof(*out));

    /* 1. SHAPE (§8.1 fixed layout). */
    if (len == 0 || len > DTN_MGMT_MAX) return DTN_MGMT_ERR_SHAPE;
    if (split_cose(cose, len, &protected, &protected_len, &kid, &kid_len,
                   &payload, &payload_len, &sig, &sig_len) != 0) {
        return DTN_MGMT_ERR_SHAPE;
    }
    if (protected_len != sizeof(protected_v1) ||
        memcmp(protected, protected_v1, sizeof(protected_v1)) != 0) {
        return DTN_MGMT_ERR_SHAPE;
    }
    if (kid_len != DTN_NODEID_FP_LEN || sig_len != 64) {
        return DTN_MGMT_ERR_SHAPE;
    }
    if (parse_command_map(payload, payload_len, &cmd) != 0) {
        return DTN_MGMT_ERR_SHAPE;
    }

    /* 2. The signer's cert: the kid IS the §2.1 fingerprint — derive, never
     * re-hash; then the §2.5 effective state (valid, unrevoked, unexpired). */
    {
        uint8_t fp[DTN_NODEID_FP_LEN];
        memcpy(fp, kid, DTN_NODEID_FP_LEN);
        dtn_nodeid_eid(fp, signer_eid);
    }
    state = dtn_rolecert_cache_effective(certs, signer_eid, now, &cert);
    if (state != DTN_ROLECERT_STATE_AUTHORITY || cert == NULL) {
        return DTN_MGMT_ERR_SIG;
    }

    /* 3. COSE verify with the signer's CERTIFIED node key. */
    if (verify_signature(cose, len, cert->node_key) != 0) {
        return DTN_MGMT_ERR_SIG;
    }
    cmd.level = cert->level;
    snprintf(cmd.signer_eid, sizeof(cmd.signer_eid), "%s", signer_eid);

    /* 4. Target gate (§8.2): execute only when this node is the target or
     * the command is a documented broadcast. */
    if (cmd.target[0] != '\0' && strcmp(cmd.target, local_eid) != 0) {
        return DTN_MGMT_ERR_TARGET;
    }

    /* 5. Command table: unknown names are refused unconfirmed (forward
     * compat). */
    required = dtn_mgmt_required_level(cmd.cmd);
    if (required < 0) {
        return DTN_MGMT_ERR_UNKNOWN;
    }

    /* 6. Level gate (§2.4): the cert level is the signer's whole authority. */
    if ((int)cmd.level < required) {
        return DTN_MGMT_ERR_LEVEL;
    }

    /* 7. Seq freshness (§8.2): strictly monotonic per signer. */
    if (cmd.seq < 1 || cmd.seq <= dtn_mgmt_seq_last(seqs, signer_eid)) {
        return DTN_MGMT_ERR_SEQ;
    }

    /* 8. Expiry / issued sanity against the LOCAL clock (§8.2). */
    if (cmd.issued_ts <= 0 || cmd.issued_ts > now + DTN_MGMT_MAX_SKEW ||
        cmd.expiry <= cmd.issued_ts ||
        cmd.expiry - cmd.issued_ts > DTN_MGMT_MAX_VALIDITY ||
        now >= cmd.expiry) {
        return DTN_MGMT_ERR_EXPIRED;
    }

    /* 9. Verdict OK: commit the per-signer floor (at execution — the Go
     * side moves its floor at execution too) and hand the command over. */
    if (dtn_mgmt_seq_commit(seqs, signer_eid, cmd.seq) != 0) {
        return DTN_MGMT_ERR_SEQ; /* table full: fail closed */
    }
    if (out) *out = cmd;
    return DTN_MGMT_OK;
}

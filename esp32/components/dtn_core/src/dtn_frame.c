/* dtn_frame.c — the §5.4 link frame + bundle window (see dtn_frame.h).
 *
 * Go mirror: node/internal/link/frame.go and window.go; the shared link
 * vectors (host/tests/link_vectors.h) pin byte-exact encodings and
 * verdicts on both sides.
 */

#include "dtn_frame.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Frame header + plaintext frames                                     */
/* ------------------------------------------------------------------ */

uint8_t dtn_frame_encode_header(dtn_frame_type type, uint8_t flags)
{
    return (uint8_t)(DTN_FRAME_VERSION << 6 | ((uint8_t)type << 3) | (flags & 0x07));
}

static int frame_type_encrypted(dtn_frame_type type)
{
    return type != DTN_FRAME_BEACON;
}

int dtn_frame_parse_header(uint8_t h, dtn_frame_type *type, uint8_t *flags)
{
    if ((uint8_t)(h >> 6) != DTN_FRAME_VERSION) {
        return DTN_FRAME_ERR_VERSION;
    }
    *type = (dtn_frame_type)((h >> 3) & 0x07);
    if (*type > DTN_FRAME_BUNDLE_FRAG) {
        return DTN_FRAME_ERR_TYPE;
    }
    *flags = (uint8_t)(h & 0x07);
    if (*flags != 0) {
        return DTN_FRAME_ERR_FLAGS;
    }
    return DTN_FRAME_OK;
}

int dtn_frame_encode(dtn_frame_type type, const uint8_t *payload, size_t payload_len,
                     uint8_t *out, size_t *out_len)
{
    if (payload_len > DTN_FRAME_PAYLOAD_MAX) {
        return DTN_FRAME_ERR_OVERSIZE;
    }
    out[0] = dtn_frame_encode_header(type, 0);
    if (payload_len > 0 && payload != NULL) {
        memcpy(out + 1, payload, payload_len);
    }
    *out_len = 1 + payload_len;
    return DTN_FRAME_OK;
}

int dtn_frame_parse(const uint8_t *in, size_t in_len,
                    dtn_frame_type *type, const uint8_t **payload, size_t *payload_len)
{
    uint8_t flags = 0;
    int rc;

    if (in_len < 1) {
        return DTN_FRAME_ERR_TRUNCATED;
    }
    rc = dtn_frame_parse_header(in[0], type, &flags);
    if (rc != DTN_FRAME_OK) {
        return rc;
    }
    *payload = in + 1;
    *payload_len = in_len - 1;
    if (frame_type_encrypted(*type)) {
        if (*payload_len > DTN_LINK_NONCE_LEN + DTN_FRAME_PAYLOAD_MAX + DTN_LINK_TAG_LEN) {
            return DTN_FRAME_ERR_OVERSIZE;
        }
        if (*payload_len < DTN_LINK_NONCE_LEN + DTN_LINK_TAG_LEN) {
            return DTN_FRAME_ERR_TRUNCATED;
        }
    } else if (*payload_len > DTN_FRAME_PAYLOAD_MAX) {
        return DTN_FRAME_ERR_OVERSIZE;
    }
    return DTN_FRAME_OK;
}

/* ------------------------------------------------------------------ */
/* Session frames                                                      */
/* ------------------------------------------------------------------ */

int dtn_frame_seal(dtn_link_session *s, dtn_frame_type type,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t *out_len)
{
    uint8_t head;
    int rc;

    if (!frame_type_encrypted(type)) {
        return DTN_FRAME_ERR_STATE; /* beacons are plaintext by definition */
    }
    if (payload_len > DTN_FRAME_PAYLOAD_MAX) {
        return DTN_FRAME_ERR_OVERSIZE;
    }
    head = dtn_frame_encode_header(type, 0);
    rc = dtn_link_session_seal(s, &head, 1, payload, payload_len, out + 1);
    if (rc != DTN_LINK_OK) {
        return DTN_FRAME_ERR_STATE;
    }
    out[0] = head;
    *out_len = 1 + DTN_LINK_NONCE_LEN + payload_len + DTN_LINK_TAG_LEN;
    return DTN_FRAME_OK;
}

int dtn_frame_open(dtn_link_session *s, const uint8_t *in, size_t in_len,
                   dtn_frame_type *type, uint8_t *out, size_t *out_len)
{
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int rc;

    rc = dtn_frame_parse(in, in_len, type, &payload, &payload_len);
    if (rc != DTN_FRAME_OK) {
        return rc;
    }
    if (!frame_type_encrypted(*type)) {
        return DTN_FRAME_ERR_STATE; /* use dtn_frame_parse for beacons */
    }
    rc = dtn_link_session_open(s, &in[0], 1, payload, payload_len, out);
    if (rc != DTN_LINK_OK) {
        return DTN_FRAME_ERR_AUTH;
    }
    *out_len = payload_len - DTN_LINK_NONCE_LEN - DTN_LINK_TAG_LEN;
    return DTN_FRAME_OK;
}

/* ------------------------------------------------------------------ */
/* Beacons                                                             */
/* ------------------------------------------------------------------ */

#define DTN_FRAME_BEACON_VERSION 1

void dtn_frame_beacon(const uint8_t fingerprint[DTN_LINK_FP_LEN], uint8_t out[DTN_FRAME_BEACON_LEN])
{
    out[0] = DTN_FRAME_BEACON_VERSION;
    memcpy(out + 1, fingerprint, DTN_LINK_FP_LEN);
}

int dtn_frame_parse_beacon(const uint8_t *payload, size_t payload_len,
                           uint8_t fingerprint[DTN_LINK_FP_LEN])
{
    if (payload_len != DTN_FRAME_BEACON_LEN) {
        return DTN_FRAME_ERR_TRUNCATED;
    }
    if (payload[0] != DTN_FRAME_BEACON_VERSION) {
        return DTN_FRAME_ERR_VERSION;
    }
    memcpy(fingerprint, payload + 1, DTN_LINK_FP_LEN);
    return DTN_FRAME_OK;
}

/* ------------------------------------------------------------------ */
/* Bundle window                                                       */
/* ------------------------------------------------------------------ */

uint8_t dtn_win_header(uint8_t win_id, uint8_t idx, uint8_t total)
{
    /* The 2-bit field carries total−1 so counts 1..4 fit (frozen). */
    return (uint8_t)((win_id & 0x0f) << 4 | (idx & 0x03) << 2 | ((total - 1) & 0x03));
}

int dtn_win_parse_header(uint8_t h, uint8_t *win_id, uint8_t *idx, uint8_t *total)
{
    *win_id = (uint8_t)(h >> 4);
    *idx = (uint8_t)((h >> 2) & 0x03);
    *total = (uint8_t)((h & 0x03) + 1);
    if (*idx >= *total) {
        return DTN_FRAME_ERR_TRUNCATED; /* idx ≥ total is corruption */
    }
    return DTN_FRAME_OK;
}

int dtn_win_split(uint8_t win_id, const uint8_t *content, size_t content_len,
                  uint8_t *out, size_t out_cap,
                  const uint8_t *frames[DTN_WIN_MAX_TOTAL], size_t frame_lens[DTN_WIN_MAX_TOTAL])
{
    size_t count = (content_len + DTN_WIN_PAYLOAD_PER_FRAME - 1) / DTN_WIN_PAYLOAD_PER_FRAME;
    size_t off = 0;
    size_t i;

    if (count < 1) {
        count = 1;
    }
    if (count > DTN_WIN_MAX_TOTAL) {
        return DTN_FRAME_ERR_OVERSIZE; /* refuse, never grow the window */
    }
    if (out_cap < count * (1 + DTN_WIN_PAYLOAD_PER_FRAME)) {
        return DTN_FRAME_ERR_OVERSIZE; /* buffer bound, caller bug */
    }
    for (i = 0; i < count; i++) {
        const size_t chunk = content_len - off < DTN_WIN_PAYLOAD_PER_FRAME
                                 ? content_len - off
                                 : DTN_WIN_PAYLOAD_PER_FRAME;
        out[0] = dtn_win_header(win_id, (uint8_t)i, (uint8_t)count);
        memcpy(out + 1, content + off, chunk);
        frames[i] = out;
        frame_lens[i] = 1 + chunk;
        out += 1 + DTN_WIN_PAYLOAD_PER_FRAME;
        off += chunk;
    }
    return (int)count;
}

void dtn_win_reassembler_init(dtn_win_reassembler *r, uint64_t timeout_ms, uint64_t now_ms)
{
    memset(r, 0, sizeof(*r));
    r->timeout_ms = timeout_ms;
    r->now_ms = now_ms;
}

int dtn_win_active(const dtn_win_reassembler *r)
{
    return r->active;
}

int dtn_win_expire(dtn_win_reassembler *r, uint64_t now_ms)
{
    int i, removed = 0;
    r->now_ms = now_ms;
    for (i = 0; i < r->active;) {
        if (now_ms - r->windows[i].created_ms > r->timeout_ms) {
            /* Remove by swap with the last active window. */
            r->windows[i] = r->windows[r->active - 1];
            r->win_ids[i] = r->win_ids[r->active - 1];
            r->active--;
            removed++;
            r->expired++;
        } else {
            i++;
        }
    }
    return removed;
}

dtn_win_verdict dtn_win_push(dtn_win_reassembler *r, const uint8_t *payload, size_t len,
                             uint8_t *out, size_t *out_len)
{
    uint8_t win_id, idx, total;
    int i, slot = -1;
    dtn_win_state *w;

    (void)dtn_win_expire(r, r->now_ms);
    if (len < 1) {
        r->rejected++;
        return DTN_WIN_INVALID;
    }
    if (dtn_win_parse_header(payload[0], &win_id, &idx, &total) != DTN_FRAME_OK) {
        r->rejected++;
        return DTN_WIN_INVALID;
    }
    for (i = 0; i < r->active; i++) {
        if (r->win_ids[i] == win_id) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (r->active >= DTN_WIN_MAX_ACTIVE) {
            r->rejected++;
            return DTN_WIN_FULL;
        }
        slot = r->active++;
        memset(&r->windows[slot], 0, sizeof(r->windows[slot]));
        r->windows[slot].total = total;
        r->windows[slot].created_ms = r->now_ms;
        r->win_ids[slot] = win_id;
    }
    w = &r->windows[slot];
    if (total != w->total) {
        r->rejected++;
        return DTN_WIN_INVALID; /* corruption, not a sibling */
    }
    if (len - 1 > DTN_WIN_PAYLOAD_PER_FRAME) {
        r->rejected++;
        return DTN_WIN_INVALID;
    }
    if (w->seen[idx]) {
        /* An identical retransmission is the redundancy mechanism:
         * idempotent, counted. Different bytes for a seen idx are
         * corruption: refused. */
        const size_t chunk = len - 1;
        if (chunk != w->part_lens[idx] ||
            memcmp(w->content + (size_t)idx * DTN_WIN_PAYLOAD_PER_FRAME, payload + 1, chunk) != 0) {
            r->rejected++;
            return DTN_WIN_DUP;
        }
        r->dup_copies++;
        return DTN_WIN_DUPLICATE;
    }
    w->seen[idx] = 1;
    /* Copy the chunk into the window's own storage (views would dangle). */
    {
        const size_t chunk = len - 1;
        memcpy(w->content + (size_t)idx * DTN_WIN_PAYLOAD_PER_FRAME, payload + 1, chunk);
        w->part_lens[idx] = chunk;
    }
    w->got++;
    if (w->got < w->total) {
        return DTN_WIN_PARTIAL;
    }
    /* Complete: concatenate by idx order, byte-exact. */
    {
        size_t off = 0, j;
        for (j = 0; j < w->total; j++) {
            memcpy(out + off, w->content + (size_t)j * DTN_WIN_PAYLOAD_PER_FRAME, w->part_lens[j]);
            off += w->part_lens[j];
        }
        *out_len = off;
    }
    /* Remove the completed window (swap with the last). */
    *w = r->windows[r->active - 1];
    r->win_ids[slot] = r->win_ids[r->active - 1];
    r->active--;
    return DTN_WIN_DONE;
}

/* dtn_prekeys.c — the §10.3 blind bundle-shape validator. See dtn_prekeys.h.
 * Rules (§4.6/§10.3): member set exactly v, spk, spk_sig, ts, opks — every
 * one required; v == 1; spk = padded standard Base64 of exactly 32 bytes;
 * spk_sig of 64; ts an integer > 0; opks an array of 8..16 Base64 strings
 * each decoding to 32 bytes; unknown members are ignored (§15.4) but still
 * syntax-walked. NO signature verification — the node stays blind (§1). */
#include "dtn_prekeys.h"

#include <string.h>

#include "dtn_base64.h"

static void pk_event(void *ud, const dtn_json_event *ev)
{
    dtn_prekeys_val *c = ud;
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
            c->opks_seen = 0;
            if (c->out) c->out->opk_count = 0;
        } else if (c->cur == -1) {
            c->skip_depth = 1; /* ignored member's array subtree */
        } else {
            c->bad = true; /* array where v/spk/sig/ts belongs */
        }
        return;
    case DTN_JSON_EV_END_OBJECT:
        if (c->skip_depth > 0) c->skip_depth--;
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
            if (c->opks_seen >= 16 || ev->overflow ||
                dtn_base64_decoded_len(ev->s, ev->len) != 32) {
                c->bad = true;
                return;
            }
            c->opks_seen++;
            if (c->out) {
                c->out->opk_count = c->opks_seen;
                memcpy(c->out->opks[c->opks_seen - 1], ev->s, ev->len);
                c->out->opks[c->opks_seen - 1][ev->len] = '\0';
            }
            return;
        }
        if (c->cur == 1) {
            if (ev->overflow ||
                dtn_base64_decoded_len(ev->s, ev->len) != 32) {
                c->bad = true;
                return;
            }
            c->have_spk = true;
            if (c->out) {
                memcpy(c->out->spk, ev->s, ev->len);
                c->out->spk[ev->len] = '\0';
            }
        } else if (c->cur == 2) {
            if (ev->overflow ||
                dtn_base64_decoded_len(ev->s, ev->len) != 64) {
                c->bad = true;
                return;
            }
            c->have_sig = true;
            if (c->out) {
                memcpy(c->out->spk_sig, ev->s, ev->len);
                c->out->spk_sig[ev->len] = '\0';
            }
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
            if (c->out) c->out->v = ev->num;
        } else if (c->cur == 3) {
            c->ts = ev->num;
            c->ts_set = true;
            if (c->out) c->out->ts = ev->num;
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

void dtn_prekeys_val_init(dtn_prekeys_val *pv, dtn_prekeys_members *out)
{
    memset(pv, 0, sizeof(*pv));
    pv->cur = -1;
    pv->out = out;
    if (out) memset(out, 0, sizeof(*out));
    dtn_json_init(&pv->json, pk_event, pv);
}

dtn_json_feed_result dtn_prekeys_val_feed(dtn_prekeys_val *pv,
                                          const char *data, size_t len)
{
    dtn_json_feed_result r = dtn_json_feed(&pv->json, data, len);
    if (r == DTN_JSONFEED_ERR_SYNTAX || r == DTN_JSONFEED_ERR_RANGE ||
        r == DTN_JSONFEED_ERR_DEPTH) {
        pv->bad = true;
    }
    return r;
}

bool dtn_prekeys_val_ok(dtn_prekeys_val *pv)
{
    if (pv->bad) return false;
    if (pv->skip_depth > 0 || pv->in_opks) return false; /* never closed */
    if (!pv->v_set || !pv->ts_set || !pv->have_spk || !pv->have_sig ||
        !pv->saw_opks) {
        return false; /* every §4.6 member is required */
    }
    if (pv->v != 1) return false;
    if (pv->ts <= 0) return false;
    if (pv->opks_seen < 8 || pv->opks_seen > 16) return false;
    return true;
}

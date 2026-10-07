/* dtn_sync.c — streaming §10.4 processor. See dtn_sync.h for the contract.
 *
 * Type-mismatch parity with encoding/json (the reference decoder), which the
 * precedence resolver depends on:
 *   - a type mismatch on a TYPED struct field (v/created_at/ttl as float or
 *     string, known_ids members as numbers, …) fails THE DECODE → 400
 *     invalid_json;
 *   - JSON null on a typed field is a silent no-op (zero value) — e.g. null
 *     v decodes fine and fails VALIDATION instead (invalid_envelope);
 *   - meta is captured as raw bytes and validated later: a non-object meta,
 *     a float/string/null meta.orig_v fail VALIDATION (invalid_envelope),
 *     never the decode;
 *   - `limit: null` decodes into the nil pointer → the member is absent;
 *   - duplicate known_ids/push_envelopes keys: the LAST array replaces the
 *     first entirely (restart semantics below). */
#include "dtn_sync.h"

#include <string.h>

/* processor states */
enum {
    PS_INIT = 0,     /* awaiting the top-level object */
    PS_TOP_MEMBERS,  /* inside the top object (between members) */
    PS_KNOWN_VAL,    /* inside the known_ids array */
    PS_PUSH_VAL,     /* inside the push_envelopes array */
    PS_ENV_MEMBERS,  /* inside one envelope object */
    PS_META_MEMBERS, /* inside the envelope's meta object */
    PS_SKIP,         /* walking (syntax-validating) an ignored subtree */
    PS_CLOSED,       /* top-level value complete */
};

/* top-level keys */
enum { TOPK_NONE = 0, TOPK_KNOWN, TOPK_PUSH, TOPK_LIMIT, TOPK_OTHER };
/* envelope keys; ENVK_META doubles as the "meta.orig_v expected" marker
 * while inside PS_META_MEMBERS */
enum {
    ENVK_NONE = 0,
    ENVK_V,
    ENVK_ID,
    ENVK_HINT,
    ENVK_CREATED,
    ENVK_TTL,
    ENVK_PAYLOAD,
    ENVK_META,
    ENVK_OTHER,
};

static void record_json_err(dtn_sync *s) { s->json_err = true; }
static void type_error(dtn_sync *s) { record_json_err(s); }

static const char *key_of(const dtn_json_event *ev)
{
    return ev->overflow ? NULL : ev->s;
}

static int top_key(const char *k)
{
    if (!k) return TOPK_OTHER;
    if (strcmp(k, "known_ids") == 0) return TOPK_KNOWN;
    if (strcmp(k, "push_envelopes") == 0) return TOPK_PUSH;
    if (strcmp(k, "limit") == 0) return TOPK_LIMIT;
    return TOPK_OTHER;
}

static int env_key(const char *k)
{
    if (!k) return ENVK_OTHER;
    if (strcmp(k, "v") == 0) return ENVK_V;
    if (strcmp(k, "id") == 0) return ENVK_ID;
    if (strcmp(k, "dest_hint") == 0) return ENVK_HINT;
    if (strcmp(k, "created_at") == 0) return ENVK_CREATED;
    if (strcmp(k, "ttl") == 0) return ENVK_TTL;
    if (strcmp(k, "payload") == 0) return ENVK_PAYLOAD;
    if (strcmp(k, "meta") == 0) return ENVK_META;
    return ENVK_OTHER;
}

static void env_reset(dtn_sync *s)
{
    memset(&s->env, 0, sizeof(s->env));
    memset(&s->flags, 0, sizeof(s->flags));
}

/* A pushed envelope object completed: validate, then stage into the pending
 * batch — unless a recorded violation already forbids storage work. (The Go
 * node validates every envelope before its single INSERT; staging a prefix
 * and rolling it back on rejection is the streaming-observable equivalent,
 * docs/esp32-design.md §4.) */
static void env_stage(dtn_sync *s)
{
    s->pushed_count++;
    if (s->pushed_count > DTN_PUSH_ENVELOPES_MAX) {
        s->too_many_push = true;
        return;
    }
    if (s->env_invalid || s->too_many_push || s->storage_err || s->node_full) {
        return; /* this batch can never commit; stop staging */
    }
    dtn_env_err err;
    if (s->flags.id_ovf) {
        err = DTN_ENV_ERR_ID;
    } else if (s->flags.hint_ovf) {
        err = DTN_ENV_ERR_DEST_HINT;
    } else if (s->flags.payload_ovf) {
        err = DTN_ENV_ERR_PAYLOAD;
    } else if (s->flags.meta_not_obj || s->flags.meta_origv_bad) {
        err = DTN_ENV_ERR_META;
    } else {
        err = dtn_envelope_validate(&s->env, s->now);
    }
    if (err != DTN_ENV_OK) {
        s->env_invalid = true;
        return;
    }
    if (!s->batch_open) {
        if (s->sink.begin(s->sink.ud) != 0) {
            s->storage_err = true;
            return;
        }
        s->batch_open = true;
    }
    int absorbed = 0;
    int rc = s->sink.put(s->sink.ud, &s->env, &absorbed);
    if (rc == -2) {
        s->node_full = true; /* at/over the §8.1 cap: nothing stored (§8.1) */
        return;
    }
    if (rc != 0) {
        s->storage_err = true; /* keep parsing: later violations may win */
        return;
    }
    if (absorbed) {
        s->absorbed_count++;
    }
}

/* A duplicate top-level push_envelopes key REPLACES the first array in the
 * Go decoder, so nothing of it may survive: discard the pending batch and
 * reset the push-scoped violations (storage errors stay sticky — the I/O
 * really happened, and a re-run hits the same failure). */
static void push_restart(dtn_sync *s)
{
    if (s->batch_open) {
        s->sink.abort(s->sink.ud);
        s->batch_open = false;
    }
    s->pushed_count = 0;
    s->absorbed_count = 0;
    s->too_many_push = false;
    s->env_invalid = false;
    s->node_full = false;
}

static void known_restart(dtn_sync *s)
{
    if (s->known) {
        s->known->count = 0;
    }
    s->known_too_many = false;
    s->known_invalid = false;
}

/* Enter skip mode for an unknown/invalid-typed subtree. */
static void skip_into(dtn_sync *s, int return_state, int depth)
{
    s->st = PS_SKIP;
    s->skip_return = return_state;
    s->skip_depth = depth;
}

static void on_event(void *ud, const dtn_json_event *ev)
{
    dtn_sync *s = (dtn_sync *)ud;

    switch (ev->type) {
    case DTN_JSON_EV_BEGIN_OBJECT:
    case DTN_JSON_EV_BEGIN_ARRAY:
        switch (s->st) {
        case PS_INIT:
            if (ev->type != DTN_JSON_EV_BEGIN_OBJECT) {
                type_error(s); /* top level must be an object (Go struct) */
                skip_into(s, PS_CLOSED, 0);
            } else {
                s->st = PS_TOP_MEMBERS;
            }
            return;
        case PS_TOP_MEMBERS:
            if (s->cur_top_key == TOPK_KNOWN) {
                known_restart(s); /* duplicates replace */
                s->st = PS_KNOWN_VAL;
            } else if (s->cur_top_key == TOPK_PUSH) {
                push_restart(s);
                s->st = PS_PUSH_VAL;
            } else {
                if (s->cur_top_key == TOPK_LIMIT) {
                    type_error(s); /* limit must be a JSON number */
                }
                skip_into(s, PS_TOP_MEMBERS, 1);
            }
            return;
        case PS_KNOWN_VAL:
            type_error(s); /* container inside known_ids: decode failure */
            skip_into(s, PS_KNOWN_VAL, 1);
            return;
        case PS_PUSH_VAL:
            if (ev->type == DTN_JSON_EV_BEGIN_OBJECT) {
                env_reset(s);
                s->st = PS_ENV_MEMBERS;
            } else {
                type_error(s); /* array inside push_envelopes */
                skip_into(s, PS_PUSH_VAL, 1);
            }
            return;
        case PS_ENV_MEMBERS:
            if (ev->type == DTN_JSON_EV_BEGIN_OBJECT &&
                s->cur_env_key == ENVK_META) {
                /* meta IS an object: enter its member context (§15.3) */
                s->env.meta_flags = 1;
                s->st = PS_META_MEMBERS;
                return;
            }
            if (s->cur_env_key == ENVK_META) {
                s->flags.meta_not_obj = true; /* array meta: not '{' (Go) */
            }
            skip_into(s, PS_ENV_MEMBERS, 1);
            return;
        case PS_META_MEMBERS:
            skip_into(s, PS_META_MEMBERS, 1); /* unknown meta member: ignored */
            return;
        case PS_SKIP:
            s->skip_depth++;
            return;
        default:
            return;
        }

    case DTN_JSON_EV_END_OBJECT:
    case DTN_JSON_EV_END_ARRAY:
        switch (s->st) {
        case PS_SKIP:
            if (s->skip_depth > 0) {
                s->skip_depth--;
                return;
            }
            s->st = s->skip_return;
            return;
        case PS_KNOWN_VAL:
            s->st = PS_TOP_MEMBERS;
            s->cur_top_key = TOPK_NONE;
            return;
        case PS_PUSH_VAL:
            s->st = PS_TOP_MEMBERS;
            s->cur_top_key = TOPK_NONE;
            return;
        case PS_ENV_MEMBERS:
            s->st = PS_PUSH_VAL;
            env_stage(s);
            return;
        case PS_META_MEMBERS:
            s->st = PS_ENV_MEMBERS;
            s->cur_env_key = ENVK_NONE;
            return;
        case PS_TOP_MEMBERS:
            s->st = PS_CLOSED;
            return;
        default:
            return;
        }

    case DTN_JSON_EV_KEY:
        switch (s->st) {
        case PS_TOP_MEMBERS:
            s->cur_top_key = top_key(key_of(ev));
            return;
        case PS_ENV_MEMBERS:
            s->cur_env_key = env_key(key_of(ev));
            return;
        case PS_META_MEMBERS:
            s->cur_env_key =
                (!ev->overflow && strcmp(key_of(ev), "orig_v") == 0)
                    ? ENVK_META
                    : ENVK_OTHER;
            return;
        default:
            return;
        }

    case DTN_JSON_EV_STRING:
        switch (s->st) {
        case PS_TOP_MEMBERS:
            if (s->cur_top_key != TOPK_NONE && s->cur_top_key != TOPK_OTHER) {
                type_error(s); /* string into []string / []Envelope / *int */
            }
            return;
        case PS_KNOWN_VAL: {
            /* every element counts toward the slice length (Go decodes the
             * whole array before any format check — §10.4 order) */
            uint16_t idx = s->known->count;
            s->known->count++;
            bool ok = !ev->overflow && ev->len == DTN_ID_LEN &&
                      dtn_is_hex_n(ev->s, DTN_ID_LEN);
            if (!ok) {
                s->known_invalid = true;
                return;
            }
            if (idx >= s->known->cap) {
                s->known_too_many = true;
                return;
            }
            memcpy(s->known->ids[idx], ev->s, DTN_ID_LEN + 1);
            return;
        }
        case PS_PUSH_VAL:
            type_error(s); /* string into []Envelope */
            return;
        case PS_ENV_MEMBERS:
            switch (s->cur_env_key) {
            case ENVK_ID:
                if (ev->overflow || ev->len > DTN_ID_LEN) {
                    s->flags.id_ovf = true; /* can never match the regex */
                } else {
                    memcpy(s->env.id, ev->s, ev->len);
                    s->env.id[ev->len] = '\0';
                }
                return;
            case ENVK_HINT:
                if (ev->overflow || ev->len > DTN_DEST_HINT_LEN) {
                    s->flags.hint_ovf = true;
                } else {
                    memcpy(s->env.dest_hint, ev->s, ev->len);
                    s->env.dest_hint[ev->len] = '\0';
                }
                return;
            case ENVK_PAYLOAD:
                if (ev->overflow || ev->len > DTN_PAYLOAD_B64_MAX) {
                    s->flags.payload_ovf = true; /* decodes > 400 or invalid */
                } else {
                    memcpy(s->env.payload, ev->s, ev->len);
                    s->env.payload[ev->len] = '\0';
                    s->env.payload_len = ev->len;
                }
                return;
            case ENVK_META:
                s->flags.meta_not_obj = true; /* string meta is not '{' (Go) */
                return;
            default:
                type_error(s); /* string into an int64 field */
                return;
            }
        case PS_META_MEMBERS:
            if (s->cur_env_key == ENVK_META) {
                /* meta.orig_v as string: raw captured, fails the == 1 check
                 * at validation time (invalid_envelope, not invalid_json) */
                s->env.meta_flags = 1;
                s->flags.meta_origv_bad = true;
            }
            return;
        default:
            return;
        }

    case DTN_JSON_EV_NUMBER:
        switch (s->st) {
        case PS_TOP_MEMBERS:
            if (s->cur_top_key == TOPK_KNOWN || s->cur_top_key == TOPK_PUSH) {
                type_error(s);
            } else if (s->cur_top_key == TOPK_LIMIT) {
                if (!ev->is_integer) {
                    type_error(s); /* float into *int: decode failure (Go) */
                    return;
                }
                s->have_limit = true;
                s->limit_val = ev->num;
            }
            return;
        case PS_KNOWN_VAL:
        case PS_PUSH_VAL:
            type_error(s);
            return;
        case PS_ENV_MEMBERS:
            if (!ev->is_integer) {
                if (s->cur_env_key >= ENVK_V && s->cur_env_key <= ENVK_TTL) {
                    type_error(s); /* float into int64 envelope field */
                } else if (s->cur_env_key == ENVK_META) {
                    s->env.meta_flags = 1;
                    s->flags.meta_origv_bad = true; /* float orig_v: fails ==1 */
                } else if (s->cur_env_key >= ENVK_ID &&
                           s->cur_env_key <= ENVK_PAYLOAD) {
                    type_error(s); /* number into a string field */
                }
                return;
            }
            switch (s->cur_env_key) {
            case ENVK_V:
                s->env.v = ev->num;
                return;
            case ENVK_CREATED:
                s->env.created_at = ev->num;
                return;
            case ENVK_TTL:
                s->env.ttl = ev->num;
                return;
            case ENVK_ID:
            case ENVK_HINT:
            case ENVK_PAYLOAD:
                type_error(s);
                return;
            default:
                return; /* unknown member: walked, ignored */
            }
        case PS_META_MEMBERS:
            if (s->cur_env_key == ENVK_META) {
                s->env.meta_flags = 1;
                if (!ev->is_integer) {
                    s->flags.meta_origv_bad = true; /* fails == 1 (Go) */
                } else {
                    s->env.meta_orig_v_present = 1;
                    s->env.meta_orig_v = ev->num;
                }
            }
            return;
        default:
            return;
        }

    case DTN_JSON_EV_TRUE:
    case DTN_JSON_EV_FALSE:
        switch (s->st) {
        case PS_TOP_MEMBERS:
            if (s->cur_top_key != TOPK_NONE && s->cur_top_key != TOPK_OTHER) {
                type_error(s);
            }
            return;
        case PS_KNOWN_VAL:
        case PS_PUSH_VAL:
            type_error(s);
            return;
        case PS_ENV_MEMBERS:
            if (s->cur_env_key == ENVK_META) {
                s->flags.meta_not_obj = true;
            } else if (s->cur_env_key != ENVK_OTHER &&
                       s->cur_env_key != ENVK_NONE) {
                type_error(s);
            }
            return;
        case PS_META_MEMBERS:
            if (s->cur_env_key == ENVK_META) {
                s->env.meta_flags = 1;
                s->flags.meta_origv_bad = true; /* bool into int64 (Go fails) */
            }
            return;
        default:
            return;
        }

    case DTN_JSON_EV_NULL:
        switch (s->st) {
        case PS_TOP_MEMBERS:
            if (s->cur_top_key == TOPK_LIMIT) {
                s->have_limit = false; /* nil pointer: member absent (Go) */
                s->limit_val = 0;
            } else if (s->cur_top_key == TOPK_KNOWN) {
                known_restart(s); /* nil slice replaces */
            } else if (s->cur_top_key == TOPK_PUSH) {
                push_restart(s);
            }
            return;
        case PS_KNOWN_VAL:
            /* null element → "" (Go zero value): counts AND fails format */
            if (s->known) s->known->count++;
            s->known_invalid = true;
            return;
        case PS_PUSH_VAL:
            /* null element → zero envelope → v == 0 → invalid_envelope */
            env_reset(s);
            s->pushed_count++;
            if (s->pushed_count > DTN_PUSH_ENVELOPES_MAX) {
                s->too_many_push = true;
            } else if (!s->env_invalid && !s->too_many_push) {
                s->env_invalid = true;
            }
            return;
        case PS_ENV_MEMBERS:
            switch (s->cur_env_key) {
            case ENVK_V:
            case ENVK_CREATED:
            case ENVK_TTL:
                return; /* null into int64: no-op, zero value stays (Go) */
            case ENVK_META:
                s->flags.meta_not_obj = true; /* raw "null" is not '{' */
                return;
            default:
                return; /* null string/id fields: zero values, fail validate */
            }
        case PS_META_MEMBERS:
            if (s->cur_env_key == ENVK_META) {
                /* orig_v: null decodes to 0, which fails the == 1 check */
                s->env.meta_flags = 1;
                s->flags.meta_origv_bad = true;
            }
            return;
        default:
            return;
        }
    }
}

void dtn_sync_init(dtn_sync *s, int64_t now, const dtn_sync_sink *sink,
                   dtn_known_ids *known)
{
    memset(s, 0, sizeof(*s));
    s->sink = *sink;
    s->known = known;
    s->now = now;
    s->st = PS_INIT;
    dtn_json_init(&s->json, on_event, s);
}

dtn_json_feed_result dtn_sync_feed(dtn_sync *s, const char *data, size_t len)
{
    if (s->body_too_large || s->st == PS_CLOSED) {
        return DTN_JSONFEED_DONE; /* the caller still drains the socket */
    }

    dtn_json_feed_result r = dtn_json_feed(&s->json, data, len);
    if (r == DTN_JSONFEED_ERR_SYNTAX || r == DTN_JSONFEED_ERR_RANGE ||
        r == DTN_JSONFEED_ERR_DEPTH) {
        record_json_err(s);
    }
    if (r == DTN_JSONFEED_DONE) {
        s->st = PS_CLOSED;
    }
    /* only bytes the decoder actually read count toward the 1 MiB cap —
     * a body whose first value closes under the cap is fine however much
     * trailing data follows (encoding/json reads one value) */
    if (s->json.consumed > (size_t)DTN_BODY_MAX_BYTES) {
        s->body_too_large = true;
    }
    return r;
}

size_t dtn_sync_consumed(const dtn_sync *s) { return s->json.consumed; }

bool dtn_sync_done(const dtn_sync *s) { return s->st == PS_CLOSED; }

int64_t dtn_sync_pushed(const dtn_sync *s) { return s->pushed_count; }
int64_t dtn_sync_absorbed(const dtn_sync *s) { return s->absorbed_count; }

int64_t dtn_sync_limit(const dtn_sync *s)
{
    return s->have_limit ? s->limit_val : DTN_SYNC_LIMIT_DEFAULT;
}

const dtn_known_ids *dtn_sync_known(const dtn_sync *s) { return s->known; }

dtn_sync_err dtn_sync_finish(dtn_sync *s, bool budget_allowed)
{
    dtn_sync_err verdict;

    if (s->body_too_large) {
        verdict = DTN_SYNC_ERR_BODY_TOO_LARGE;
    } else if (s->json_err || s->st != PS_CLOSED) {
        verdict = DTN_SYNC_ERR_JSON;
    } else if (s->have_limit &&
               (s->limit_val < 1 || s->limit_val > DTN_SYNC_LIMIT_MAX)) {
        verdict = DTN_SYNC_ERR_INVALID_LIMIT;
    } else if (s->known_too_many ||
               (s->known && s->known->count > DTN_KNOWN_IDS_MAX)) {
        verdict = DTN_SYNC_ERR_TOO_MANY_KNOWN;
    } else if (s->known_invalid) {
        verdict = DTN_SYNC_ERR_INVALID_KNOWN;
    } else if (s->too_many_push || s->pushed_count > DTN_PUSH_ENVELOPES_MAX) {
        verdict = DTN_SYNC_ERR_TOO_MANY_PUSH;
    } else if (!budget_allowed) {
        verdict = DTN_SYNC_ERR_RATE_LIMITED;
    } else if (s->env_invalid) {
        verdict = DTN_SYNC_ERR_INVALID_ENVELOPE;
    } else if (s->node_full) {
        verdict = DTN_SYNC_ERR_NODE_FULL;
    } else if (s->storage_err) {
        verdict = DTN_SYNC_ERR_STORAGE;
    } else {
        if (s->batch_open && s->sink.commit(s->sink.ud) != 0) {
            s->sink.abort(s->sink.ud);
            s->batch_open = false;
            return DTN_SYNC_ERR_STORAGE;
        }
        s->batch_open = false;
        return DTN_SYNC_OK;
    }

    if (s->batch_open) {
        s->sink.abort(s->sink.ud);
        s->batch_open = false;
    }
    return verdict;
}

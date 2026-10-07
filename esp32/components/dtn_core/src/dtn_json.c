/* dtn_json.c — implementation of the incremental strict JSON reader.
 * See dtn_json.h for the Go-encoding/json parity contract. */
#include "dtn_json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const char LITS[] = "true\0false\0null";
static const int LIT_LEN[3] = {4, 5, 4};
static const int LIT_OFF[3] = {0, 5, 11};

void dtn_json_init(dtn_json_parser *p,
                   void (*emit)(void *ud, const dtn_json_event *ev), void *ud)
{
    memset(p, 0, sizeof(*p));
    p->emit = emit;
    p->ud = ud;
}

static void emit_simple(dtn_json_parser *p, dtn_json_ev type)
{
    dtn_json_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    p->emit(p->ud, &ev);
}

static void cap_put(dtn_json_parser *p, char c)
{
    p->str_decoded++;
    if (p->cap_len + 1 < DTN_JSON_CAPTURE_MAX) {
        p->capture[p->cap_len++] = c;
    } else {
        p->cap_overflow = true;
    }
}

static void cap_put_cp(dtn_json_parser *p, uint32_t cp)
{
    if (cp < 0x80) {
        cap_put(p, (char)cp);
    } else if (cp < 0x800) {
        cap_put(p, (char)(0xC0 | (cp >> 6)));
        cap_put(p, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        cap_put(p, (char)(0xE0 | (cp >> 12)));
        cap_put(p, (char)(0x80 | ((cp >> 6) & 0x3F)));
        cap_put(p, (char)(0x80 | (cp & 0x3F)));
    } else {
        cap_put(p, (char)(0xF0 | (cp >> 18)));
        cap_put(p, (char)(0x80 | ((cp >> 12) & 0x3F)));
        cap_put(p, (char)(0x80 | ((cp >> 6) & 0x3F)));
        cap_put(p, (char)(0x80 | (cp & 0x3F)));
    }
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void emit_string_token(dtn_json_parser *p)
{
    dtn_json_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = p->str_is_key ? DTN_JSON_EV_KEY : DTN_JSON_EV_STRING;
    if (p->cap_overflow) {
        ev.s = NULL;
        ev.len = p->str_decoded;
        ev.overflow = true;
    } else {
        p->capture[p->cap_len] = '\0';
        ev.s = p->capture;
        ev.len = p->cap_len;
    }
    p->emit(p->ud, &ev);
}

/* May a VALUE start here? (Keys are handled separately by string_start.) */
static int value_allowed(const dtn_json_parser *p)
{
    const dtn_json_frame *f;
    if (p->depth == 0) {
        return 1; /* the single top-level value */
    }
    f = &p->stack[p->depth - 1];
    if (f->is_object) {
        return f->state == DTN_JSON_F_WANT_VAL;
    }
    return f->state == DTN_JSON_F_FIRST || f->state == DTN_JSON_F_WANT_VAL;
}

/* A scalar VALUE just completed. Returns 1 when the document is complete
 * (top-level scalar), 0 otherwise. */
static int complete_value(dtn_json_parser *p)
{
    dtn_json_frame *f;
    if (p->depth == 0) {
        p->done = true;
        return 1;
    }
    f = &p->stack[p->depth - 1];
    f->state = DTN_JSON_F_WANT_COMMA; /* value_allowed() guaranteed validity */
    return 0;
}

/* The container that just closed was itself a value in its parent. */
static int complete_container(dtn_json_parser *p)
{
    if (p->depth == 0) {
        p->done = true;
        return 1;
    }
    return complete_value(p);
}

/* Open a container as a value. */
static int open_container(dtn_json_parser *p, int is_object)
{
    if (!value_allowed(p)) {
        return -1;
    }
    if (p->depth >= DTN_JSON_MAX_DEPTH) {
        return -2; /* depth */
    }
    p->stack[p->depth].is_object = (uint8_t)(is_object != 0);
    p->stack[p->depth].state = DTN_JSON_F_FIRST;
    p->depth++;
    emit_simple(p, is_object ? DTN_JSON_EV_BEGIN_OBJECT
                             : DTN_JSON_EV_BEGIN_ARRAY);
    return 0;
}

static void string_start(dtn_json_parser *p)
{
    const dtn_json_frame *f = p->depth ? &p->stack[p->depth - 1] : NULL;
    p->str_is_key = f != NULL && f->is_object &&
                    (f->state == DTN_JSON_F_FIRST ||
                     f->state == DTN_JSON_F_WANT_KEY);
    p->cap_len = 0;
    p->cap_overflow = false;
    p->str_decoded = 0;
    p->sur = 0;
    p->in_escape = false;
    p->str_done = false;
    p->state = DTN_JSON_ST_STR;
}

/* One byte of string decoding (ST_STR / ST_ESC / ST_U). Sets str_done at the
 * closing quote. Returns 0 ok, -1 syntax error. */
static int string_byte(dtn_json_parser *p, char c)
{
    if (p->state == DTN_JSON_ST_ESC) {
        p->state = DTN_JSON_ST_STR;
        /* an escape after a dangling high surrogate repairs it first */
        if (c != 'u' && p->sur) {
            cap_put_cp(p, 0xFFFD);
            p->sur = 0;
        }
        switch (c) {
        case '"': cap_put(p, '"'); return 0;
        case '\\': cap_put(p, '\\'); return 0;
        case '/': cap_put(p, '/'); return 0;
        case 'b': cap_put(p, '\b'); return 0;
        case 'f': cap_put(p, '\f'); return 0;
        case 'n': cap_put(p, '\n'); return 0;
        case 'r': cap_put(p, '\r'); return 0;
        case 't': cap_put(p, '\t'); return 0;
        case 'u':
            p->state = DTN_JSON_ST_U;
            p->u_acc = 0;
            p->u_digits = 0;
            return 0;
        default:
            return -1;
        }
    }
    if (p->state == DTN_JSON_ST_U) {
        int v = hex_val(c);
        if (v < 0) return -1;
        p->u_acc = (p->u_acc << 4) | (uint32_t)v;
        if (++p->u_digits < 4) return 0;
        p->u_digits = 0;
        if (p->sur) {
            if (p->u_acc >= 0xDC00 && p->u_acc <= 0xDFFF) {
                uint32_t cp = 0x10000 + ((p->sur - 0xD800) << 10) +
                              (p->u_acc - 0xDC00);
                cap_put_cp(p, cp);
                p->sur = 0;
            } else {
                cap_put_cp(p, 0xFFFD); /* repair the dangling high surrogate */
                p->sur = 0;
                if (p->u_acc >= 0xD800 && p->u_acc <= 0xDBFF) {
                    p->sur = p->u_acc;
                } else if (p->u_acc >= 0xDC00 && p->u_acc <= 0xDFFF) {
                    cap_put_cp(p, 0xFFFD);
                } else {
                    cap_put_cp(p, p->u_acc);
                }
            }
        } else if (p->u_acc >= 0xD800 && p->u_acc <= 0xDBFF) {
            p->sur = p->u_acc;
        } else if (p->u_acc >= 0xDC00 && p->u_acc <= 0xDFFF) {
            cap_put_cp(p, 0xFFFD); /* lone low surrogate */
        } else {
            cap_put_cp(p, p->u_acc);
        }
        p->u_acc = 0;
        p->state = DTN_JSON_ST_STR;
        return 0;
    }
    /* ST_STR body */
    if (c == '\\') {
        p->state = DTN_JSON_ST_ESC;
        return 0;
    }
    if (c == '"') {
        if (p->sur) { /* dangling high surrogate at the quote */
            cap_put_cp(p, 0xFFFD);
            p->sur = 0;
        }
        p->str_done = true;
        return 0;
    }
    if ((unsigned char)c < 0x20) return -1;
    if (p->sur) {
        /* a plain char after a dangling high surrogate repairs it first */
        cap_put_cp(p, 0xFFFD);
        p->sur = 0;
    }
    cap_put(p, c);
    return 0;
}

/* Complete the number token buffered in p->num. */
static dtn_json_feed_result finish_number(dtn_json_parser *p)
{
    dtn_json_event ev;
    bool integer = true;
    size_t j = 0;

    if (p->num_len == 0 || p->num_len >= sizeof(p->num)) goto syntax;

    /* --- JSON number grammar --- */
    if (p->num[j] == '-') j++;
    if (j >= p->num_len) goto syntax;
    if (p->num[j] == '0') {
        j++;
    } else if (p->num[j] >= '1' && p->num[j] <= '9') {
        while (j < p->num_len && p->num[j] >= '0' && p->num[j] <= '9') j++;
    } else {
        goto syntax;
    }
    if (j < p->num_len && p->num[j] == '.') {
        integer = false;
        j++;
        if (j >= p->num_len || p->num[j] < '0' || p->num[j] > '9') goto syntax;
        while (j < p->num_len && p->num[j] >= '0' && p->num[j] <= '9') j++;
    }
    if (j < p->num_len && (p->num[j] == 'e' || p->num[j] == 'E')) {
        integer = false;
        j++;
        if (j < p->num_len && (p->num[j] == '+' || p->num[j] == '-')) j++;
        if (j >= p->num_len || p->num[j] < '0' || p->num[j] > '9') goto syntax;
        while (j < p->num_len && p->num[j] >= '0' && p->num[j] <= '9') j++;
    }
    if (j != p->num_len) goto syntax;

    memset(&ev, 0, sizeof(ev));
    ev.type = DTN_JSON_EV_NUMBER;
    ev.is_integer = integer;
    if (integer) {
        int neg = 0;
        size_t k = 0;
        uint64_t acc = 0, lim;
        if (p->num[k] == '-') {
            neg = 1;
            k++;
        }
        lim = neg ? 9223372036854775808ULL /* INT64_MIN magnitude */
                  : 9223372036854775807ULL;
        for (; k < p->num_len; k++) {
            uint64_t d = (uint64_t)(p->num[k] - '0');
            if (acc > (lim - d) / 10ULL) {
                return DTN_JSONFEED_ERR_RANGE;
            }
            acc = acc * 10ULL + d;
        }
        ev.num = neg ? (int64_t)(0ULL - acc) : (int64_t)acc;
    } else {
        errno = 0;
        (void)strtod(p->num, NULL);
        if (errno == ERANGE) {
            return DTN_JSONFEED_ERR_RANGE;
        }
        ev.num = 0;
    }
    p->emit(p->ud, &ev);
    return DTN_JSONFEED_OK;

syntax:
    p->err = true;
    return DTN_JSONFEED_ERR_SYNTAX;
}

dtn_json_feed_result dtn_json_feed(dtn_json_parser *p,
                                   const char *data, size_t len)
{
    if (p->err) return DTN_JSONFEED_ERR_SYNTAX;
    if (p->done) return DTN_JSONFEED_DONE;

    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        p->consumed++;
    again:
        switch (p->state) {
        case DTN_JSON_ST_STR:
        case DTN_JSON_ST_ESC:
        case DTN_JSON_ST_U: {
            if (string_byte(p, c) != 0) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            if (p->str_done) {
                bool was_key = p->str_is_key;
                emit_string_token(p);
                p->str_is_key = false;
                p->state = DTN_JSON_ST_VALUE;
                if (was_key) {
                    p->stack[p->depth - 1].state = DTN_JSON_F_WANT_COLON;
                } else if (complete_value(p) != 0) {
                    return DTN_JSONFEED_DONE;
                }
            }
            continue;
        }

        case DTN_JSON_ST_NUM: {
            if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
                c == 'e' || c == 'E') {
                if (p->num_len + 1 >= sizeof(p->num)) {
                    p->err = true;
                    return DTN_JSONFEED_ERR_SYNTAX;
                }
                p->num[p->num_len++] = c;
                continue;
            }
            {
                dtn_json_feed_result r = finish_number(p);
                if (r != DTN_JSONFEED_OK) {
                    return r;
                }
                p->state = DTN_JSON_ST_VALUE;
                if (complete_value(p) != 0) {
                    return DTN_JSONFEED_DONE;
                }
                goto again; /* reprocess the terminator byte */
            }
        }

        case DTN_JSON_ST_LIT: {
            const char *lit = LITS + LIT_OFF[p->lit_kind - 1];
            if (lit[p->lit_pos] != c) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            if (++p->lit_pos == LIT_LEN[p->lit_kind - 1]) {
                emit_simple(p, p->lit_kind == 1 ? DTN_JSON_EV_TRUE
                               : p->lit_kind == 2 ? DTN_JSON_EV_FALSE
                                                  : DTN_JSON_EV_NULL);
                p->state = DTN_JSON_ST_VALUE;
                if (complete_value(p) != 0) {
                    return DTN_JSONFEED_DONE;
                }
                /* the literal's last char is consumed; no reprocess */
            }
            continue;
        }

        default: /* DTN_JSON_ST_VALUE */
            break;
        }

        switch (c) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
            continue;

        case ':':
            if (p->depth == 0 || !p->stack[p->depth - 1].is_object ||
                p->stack[p->depth - 1].state != DTN_JSON_F_WANT_COLON) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            p->stack[p->depth - 1].state = DTN_JSON_F_WANT_VAL;
            continue;

        case ',':
            if (p->depth == 0 ||
                p->stack[p->depth - 1].state != DTN_JSON_F_WANT_COMMA) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            p->stack[p->depth - 1].state =
                p->stack[p->depth - 1].is_object ? DTN_JSON_F_WANT_KEY
                                                 : DTN_JSON_F_WANT_VAL;
            continue;

        case '}':
        case ']': {
            dtn_json_ev closed;
            int obj = (c == '}');
            if (p->depth == 0 ||
                p->stack[p->depth - 1].is_object != (uint8_t)obj) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            if (p->stack[p->depth - 1].state != DTN_JSON_F_FIRST &&
                p->stack[p->depth - 1].state != DTN_JSON_F_WANT_COMMA) {
                p->err = true; /* close where a member was required */
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            closed = obj ? DTN_JSON_EV_END_OBJECT : DTN_JSON_EV_END_ARRAY;
            p->depth--;
            emit_simple(p, closed);
            if (complete_container(p) != 0) {
                return DTN_JSONFEED_DONE;
            }
            continue;
        }

        case '{':
        case '[': {
            int rc = open_container(p, c == '{');
            if (rc == -2) {
                return DTN_JSONFEED_ERR_DEPTH;
            }
            if (rc != 0) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            continue;
        }

        case '"':
            if (!value_allowed(p) &&
                !(p->depth > 0 && p->stack[p->depth - 1].is_object &&
                  (p->stack[p->depth - 1].state == DTN_JSON_F_FIRST ||
                   p->stack[p->depth - 1].state == DTN_JSON_F_WANT_KEY))) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            string_start(p);
            continue;

        case 't':
        case 'f':
        case 'n':
            if (!value_allowed(p)) {
                p->err = true;
                return DTN_JSONFEED_ERR_SYNTAX;
            }
            p->lit_kind = (c == 't') ? 1 : (c == 'f') ? 2 : 3;
            p->lit_pos = 0;
            p->state = DTN_JSON_ST_LIT;
            goto again; /* reprocess the first literal char */

        default:
            if ((c >= '0' && c <= '9') || c == '-') {
                if (!value_allowed(p)) {
                    p->err = true;
                    return DTN_JSONFEED_ERR_SYNTAX;
                }
                p->num_len = 0;
                p->num[p->num_len++] = c;
                p->state = DTN_JSON_ST_NUM;
                continue;
            }
            p->err = true;
            return DTN_JSONFEED_ERR_SYNTAX;
        }
    }
    return DTN_JSONFEED_OK;
}

/* dtn_json.h — incremental, strict, allocation-free JSON reader (SAX-style).
 *
 * Exists for one reason: the §8.1 sync body limit is 1 MiB and classic
 * ESP32-class RAM is ~300 KB usable — the body can never be resident
 * (docs/esp32-design.md §2). The parser consumes arbitrary chunks and emits
 * events; at most one token (an envelope string field, ≤ 536 decoded bytes)
 * is ever buffered.
 *
 * Strictness is deliberately Go-encoding/json-parity (the reference node
 * decodes with encoding/json and the parity contract is byte-level):
 *   - no comments, no trailing commas, raw control chars in strings, or
 *     single-quoted strings → syntax error;
 *   - numbers: integer syntax in int64 range for integers (INT64_MIN
 *     included); float/exponent syntax is VALID JSON but not an integer —
 *     assigning it to an integer field is the consumer's type error; any
 *     number whose magnitude exceeds its type (int64 / double) → hard
 *     error, wherever it appears (encoding/json behavior);
 *   - \uXXXX escapes decoded to UTF-8, surrogate pairs combined, invalid
 *     escapes and lone surrogates replaced with U+FFFD (encoding/json
 *     repairs invalid UTF-8, it does not reject it);
 *   - duplicate keys: the consumer sees every member, so "last wins" is its
 *     decision (encoding/json behavior);
 *   - unknown members are walked (syntax still validated) and skipped
 *     without capture;
 *   - after the first complete top-level value the parser reports DONE and
 *     ignores any further input (encoding/json Decode reads one value).
 */
#ifndef DTN_JSON_H
#define DTN_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DTN_JSON_MAX_DEPTH 64
#define DTN_JSON_CAPTURE_MAX 768 /* ≥ the largest captured field (536) */

typedef enum {
    DTN_JSON_EV_BEGIN_OBJECT,
    DTN_JSON_EV_END_OBJECT,
    DTN_JSON_EV_BEGIN_ARRAY,
    DTN_JSON_EV_END_ARRAY,
    DTN_JSON_EV_KEY,     /* s/len: decoded key (overflow → s=NULL) */
    DTN_JSON_EV_STRING,  /* s/len: decoded value (overflow → s=NULL, len=total) */
    DTN_JSON_EV_NUMBER,  /* num: value if is_integer; is_integer=false marks
                             float/exponent syntax (valid JSON, not an int) */
    DTN_JSON_EV_TRUE,
    DTN_JSON_EV_FALSE,
    DTN_JSON_EV_NULL,
} dtn_json_ev;

typedef struct {
    dtn_json_ev type;
    const char *s;   /* EV_KEY / EV_STRING: decoded bytes, NUL-terminated */
    size_t len;      /* decoded length */
    int64_t num;     /* EV_NUMBER */
    bool is_integer; /* EV_NUMBER */
    bool overflow;   /* EV_KEY / EV_STRING: decoded length > CAPTURE_MAX-1 */
} dtn_json_event;

typedef enum {
    DTN_JSONFEED_OK = 0,      /* consumed; feed more */
    DTN_JSONFEED_DONE,        /* first top-level value complete */
    DTN_JSONFEED_ERR_SYNTAX,  /* malformed JSON */
    DTN_JSONFEED_ERR_RANGE,   /* number out of range */
    DTN_JSONFEED_ERR_DEPTH,   /* nesting beyond DTN_JSON_MAX_DEPTH */
} dtn_json_feed_result;

/* per-frame member states */
enum {
    DTN_JSON_F_FIRST = 0, /* obj: key or close; arr: value or close */
    DTN_JSON_F_WANT_KEY,  /* obj after ',' (a trailing comma now invalid) */
    DTN_JSON_F_WANT_COLON,
    DTN_JSON_F_WANT_VAL,  /* obj after ':'; arr after ',' */
    DTN_JSON_F_WANT_COMMA,
};

typedef struct {
    uint8_t is_object;
    uint8_t state;
} dtn_json_frame;

/* scanner states */
enum {
    DTN_JSON_ST_VALUE = 0,
    DTN_JSON_ST_STR,
    DTN_JSON_ST_ESC,
    DTN_JSON_ST_U,
    DTN_JSON_ST_NUM,
    DTN_JSON_ST_LIT,
};

typedef struct dtn_json_parser {
    void (*emit)(void *ud, const dtn_json_event *ev);
    void *ud;

    char capture[DTN_JSON_CAPTURE_MAX];
    size_t cap_len;
    bool cap_overflow;
    size_t str_decoded; /* total decoded length, even past capture capacity */
    bool str_is_key;
    bool str_done; /* set by the decoder at the closing quote */

    dtn_json_frame stack[DTN_JSON_MAX_DEPTH];
    int depth;

    int state;
    bool done;
    bool err;
    size_t consumed; /* bytes actually read for the first value */

    bool in_escape;
    uint32_t u_acc;
    int u_digits;
    uint32_t sur; /* pending high surrogate, 0 = none */

    char num[48];
    size_t num_len;

    int lit_kind; /* 1=true 2=false 3=null */
    int lit_pos;
} dtn_json_parser;

void dtn_json_init(dtn_json_parser *p,
                   void (*emit)(void *ud, const dtn_json_event *ev), void *ud);

/* Feed len bytes. Events are delivered synchronously via the registered
 * callback. After DONE the parser ignores any further input. */
dtn_json_feed_result dtn_json_feed(dtn_json_parser *p,
                                   const char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DTN_JSON_H */

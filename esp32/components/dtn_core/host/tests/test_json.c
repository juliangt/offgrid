/* test_json.c — strictness and encoding-parity of the incremental reader. */
#include "harness.h"

#include "dtn_json.h"

#include <stdlib.h>
#include <string.h>

#define MAXEV 64
static dtn_json_event evs[MAXEV];
static int nev;

static void collect(void *ud, const dtn_json_event *ev)
{
    (void)ud;
    if (nev < MAXEV) {
        evs[nev] = *ev;
        if (ev->s && !ev->overflow) {
            /* copy the payload: the capture buffer moves on */
            char *copy = malloc(ev->len + 1);
            memcpy(copy, ev->s, ev->len);
            copy[ev->len] = '\0';
            evs[nev].s = copy;
        }
        nev++;
    }
}

static void reset(void)
{
    for (int i = 0; i < nev; i++) {
        if (evs[i].s) free((void *)evs[i].s);
    }
    nev = 0;
}

/* Parse a full document in one feed; returns the feed result. */
static dtn_json_feed_result parse(dtn_json_parser *p, const char *doc)
{
    reset();
    dtn_json_init(p, collect, NULL);
    return dtn_json_feed(p, doc, strlen(doc));
}

/* Parse feeding one byte at a time. */
static dtn_json_feed_result parse_bytewise(dtn_json_parser *p, const char *doc)
{
    reset();
    dtn_json_init(p, collect, NULL);
    dtn_json_feed_result r = DTN_JSONFEED_OK;
    for (size_t i = 0; doc[i]; i++) {
        r = dtn_json_feed(p, &doc[i], 1);
        if (r != DTN_JSONFEED_OK) break;
    }
    return r;
}

static const dtn_json_event *ev_at(int i)
{
    return (i < nev) ? &evs[i] : NULL;
}

void test_json(void)
{
    dtn_json_parser p;

    T_BEGIN("json: flat object with mixed members");
    CHECK(parse(&p, "{\"v\":1,\"id\":\"ab\",\"flag\":true,\"x\":null}") ==
          DTN_JSONFEED_DONE);
    CHECK_EQ_INT(nev, 10); /* BO, K v, N, K id, S, K flag, T, K x, NULL, EO */
    CHECK(ev_at(0)->type == DTN_JSON_EV_BEGIN_OBJECT);
    CHECK(ev_at(1)->type == DTN_JSON_EV_KEY);
    CHECK_STR(ev_at(1)->s, "v");
    CHECK(ev_at(2)->type == DTN_JSON_EV_NUMBER && ev_at(2)->is_integer &&
          ev_at(2)->num == 1);
    CHECK(ev_at(4)->type == DTN_JSON_EV_STRING && strcmp(ev_at(4)->s, "ab") == 0);
    CHECK(ev_at(6)->type == DTN_JSON_EV_TRUE);
    CHECK(ev_at(8)->type == DTN_JSON_EV_NULL);

    T_BEGIN("json: nested arrays and objects");
    CHECK(parse(&p, "{\"a\":[1,{\"b\":[2,3]},[]]}") == DTN_JSONFEED_DONE);
    CHECK_EQ_INT(nev, 15);

    T_BEGIN("json: \\u escapes and surrogate pairs");
    CHECK(parse(&p, "{\"k\":\"A\\u0041\\n\\uD83D\\uDE00\"}") == DTN_JSONFEED_DONE);
    const dtn_json_event *sv = NULL;
    for (int i = 0; i < nev; i++) {
        if (evs[i].type == DTN_JSON_EV_STRING) sv = &evs[i];
    }
    CHECK(sv && sv->len == 7); /* 'A','A','\n', 4-byte emoji */
    CHECK(sv && memcmp(sv->s, "AA\n\xF0\x9F\x98\x80", 7) == 0);

    T_BEGIN("json: lone surrogate repaired to U+FFFD (encoding/json parity)");
    CHECK(parse(&p, "{\"k\":\"\\uD800x\"}") == DTN_JSONFEED_DONE);
    sv = NULL;
    for (int i = 0; i < nev; i++) {
        if (evs[i].type == DTN_JSON_EV_STRING) sv = &evs[i];
    }
    CHECK(sv && sv->len == 4 && memcmp(sv->s, "\xEF\xBF\xBDx", 4) == 0);

    T_BEGIN("json: float/exponent syntax is valid JSON, not an integer");
    CHECK(parse(&p, "{\"a\":1.5,\"b\":2e3,\"c\":-0.5}") == DTN_JSONFEED_DONE);
    int nonint = 0;
    for (int i = 0; i < nev; i++) {
        if (evs[i].type == DTN_JSON_EV_NUMBER && !evs[i].is_integer) nonint++;
    }
    CHECK_EQ_INT(nonint, 3);

    T_BEGIN("json: INT64_MIN ok, INT64_MIN-1 range error");
    CHECK(parse(&p, "{\"a\":-9223372036854775808}") == DTN_JSONFEED_DONE);
    CHECK(evs[2].num == (-9223372036854775807LL - 1));
    CHECK(parse(&p, "{\"a\":-9223372036854775809}") == DTN_JSONFEED_ERR_RANGE);
    CHECK(parse(&p, "{\"a\":9223372036854775808}") == DTN_JSONFEED_ERR_RANGE);
    CHECK(parse(&p, "{\"a\":1e999}") == DTN_JSONFEED_ERR_RANGE);

    T_BEGIN("json: syntax errors");
    CHECK(parse(&p, "{\"a\":1,}") == DTN_JSONFEED_ERR_SYNTAX);   /* trailing */
    CHECK(parse(&p, "{\"a\" 1}") == DTN_JSONFEED_ERR_SYNTAX);    /* no colon */
    CHECK(parse(&p, "{a:1}") == DTN_JSONFEED_ERR_SYNTAX);        /* bare key */
    CHECK(parse(&p, "{\"a\":\"b\n\"}") == DTN_JSONFEED_ERR_SYNTAX); /* raw ctrl */
    CHECK(parse(&p, "{\"a\":\"x\\q\"}") == DTN_JSONFEED_ERR_SYNTAX); /* escape */
    CHECK(parse(&p, "{\"a\":01}") == DTN_JSONFEED_ERR_SYNTAX);   /* leading 0 */
    CHECK(parse(&p, "{\"a\":tru}") == DTN_JSONFEED_ERR_SYNTAX);
    CHECK(parse(&p, "{\"a\":.5}") == DTN_JSONFEED_ERR_SYNTAX);
    CHECK(parse(&p, "{\"a\":1}{\"b\":2}") == DTN_JSONFEED_DONE); /* 1st value */

    T_BEGIN("json: truncated input streams (the consumer decides at finish)");
    /* a streaming parser cannot call a truncated document a syntax error —
     * the sync processor turns "never closed" into invalid_json (§10.4) */
    CHECK(parse(&p, "[1,2") == DTN_JSONFEED_OK);
    CHECK(parse(&p, "nul") == DTN_JSONFEED_OK);
    CHECK(parse(&p, "{\"a\":") == DTN_JSONFEED_OK);

    T_BEGIN("json: trailing data after the first value is ignored");
    CHECK(parse(&p, "{\"a\":1} garbage {{{") == DTN_JSONFEED_DONE);

    T_BEGIN("json: deep nesting beyond the cap");
    {
        char deep[256];
        deep[0] = '\0';
        for (int i = 0; i < 65; i++) strcat(deep, "[");
        CHECK(parse(&p, deep) == DTN_JSONFEED_ERR_DEPTH);
        deep[0] = '\0';
        for (int i = 0; i < 64; i++) strcat(deep, "[");
        for (int i = 0; i < 64; i++) strcat(deep, "]");
        CHECK(parse(&p, deep) == DTN_JSONFEED_DONE); /* 64 deep is fine */
    }

    T_BEGIN("json: chunk feeding (byte-at-a-time) is byte-identical");
    CHECK(parse_bytewise(&p, "{\"a\":[1,{\"b\":\"es\\u0041\"},true]}") ==
          DTN_JSONFEED_DONE);
    int found = 0;
    for (int i = 0; i < nev; i++) {
        if (evs[i].type == DTN_JSON_EV_STRING && evs[i].s &&
            strcmp(evs[i].s, "esA") == 0) found++;
    }
    CHECK_EQ_INT(found, 1);

    T_BEGIN("json: overflow strings report length without capture");
    {
        char big[2048];
        big[0] = '\0';
        strcat(big, "{\"a\":\"");
        for (int i = 0; i < 1900; i++) strcat(big, "x");
        strcat(big, "\"}");
        reset();
        dtn_json_init(&p, collect, NULL);
        CHECK(dtn_json_feed(&p, big, strlen(big)) == DTN_JSONFEED_DONE);
        const dtn_json_event *o = NULL;
        for (int i = 0; i < nev; i++) {
            if (evs[i].type == DTN_JSON_EV_STRING) o = &evs[i];
        }
        CHECK(o && o->overflow && o->s == NULL && o->len == 1900);
    }
}

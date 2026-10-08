/* radio_fake.c — the in-memory radio implementations for the host suite
 * (see radio_fake.h). */
#include "radio_fake.h"

#include <string.h>

/* Per-radio binding (ctx points here; the HAL sees an opaque pointer). */
typedef struct {
    radio_channel *ch;
    uint8_t id;
} radio_fake_binding;

static radio_fake_binding g_bind[RADIO_FAKE_MAX_RADIOS];
static int g_bind_n;

static radio_fake_binding *bind_of(const dtn_radio *r)
{
    int i;
    for (i = 0; i < g_bind_n; i++) {
        if (r->ctx == &g_bind[i]) {
            return &g_bind[i];
        }
    }
    return NULL;
}

void radio_fake_reset(void)
{
    g_bind_n = 0;
}

void radio_channel_init(radio_channel *ch)
{
    memset(ch, 0, sizeof(*ch));
    radio_fake_reset();
}

void radio_channel_set_drops(radio_channel *ch, const uint8_t *script, int n)
{
    memset(ch->script, 0, sizeof(ch->script));
    if (n > RADIO_FAKE_MAX_DROPS) {
        n = RADIO_FAKE_MAX_DROPS;
    }
    if (n > 0) {
        memcpy(ch->script, script, (size_t)n);
    }
    ch->script_n = n;
}

void radio_channel_add_busy(radio_channel *ch, uint64_t from_ms, uint64_t to_ms)
{
    if (ch->busy_n < RADIO_FAKE_MAX_BUSY) {
        ch->busy_from[ch->busy_n] = from_ms;
        ch->busy_to[ch->busy_n] = to_ms;
        ch->busy_n++;
    }
}

void radio_channel_advance(radio_channel *ch, uint64_t ms)
{
    ch->now_ms += ms;
}

static int fake_init(dtn_radio *r, uint8_t id)
{
    (void)r;
    (void)id;
    return DTN_RADIO_OK; /* binding happened in the *_init constructor */
}

static int fake_send(dtn_radio *r, const uint8_t *frame, size_t len)
{
    const radio_fake_binding *b = bind_of(r);
    radio_channel *ch;
    int i;

    if (b == NULL || len == 0 || len > DTN_RADIO_MTU) {
        return DTN_RADIO_ERR_STATE;
    }
    ch = b->ch;
    ch->tx_seen++; /* the channel counts handed frames for the drop script */
    if (ch->script_n > 0 && ch->tx_seen <= ch->script_n &&
        ch->script[ch->tx_seen - 1]) {
        return DTN_RADIO_OK; /* silently lost — the lossy channel model */
    }
    for (i = 0; i < ch->n_radios; i++) {
        if (ch->ids[i] == b->id) {
            continue; /* no self-reception */
        }
        if (ch->qlen[i] - ch->qhead[i] < RADIO_FAKE_QLEN) {
            const size_t tail = (ch->qhead[i] + ch->qlen[i]) % RADIO_FAKE_QLEN;
            memcpy(ch->q[i][tail], frame, len);
            ch->qlen_i[i][tail] = len;
            ch->qlen[i]++;
        } /* a full queue drops silently (host tests keep it drained) */
    }
    return DTN_RADIO_OK;
}

static int fake_recv(dtn_radio *r, uint8_t *frame, size_t *len)
{
    const radio_fake_binding *b = bind_of(r);
    radio_channel *ch;
    int me = -1, i;
    size_t head;

    if (b == NULL) {
        return DTN_RADIO_ERR_STATE;
    }
    ch = b->ch;
    for (i = 0; i < ch->n_radios; i++) {
        if (ch->ids[i] == b->id) {
            me = i;
            break;
        }
    }
    if (me < 0 || ch->qlen[me] == ch->qhead[me]) {
        return DTN_RADIO_ERR_STATE; /* queue empty */
    }
    head = ch->qhead[me] % RADIO_FAKE_QLEN;
    memcpy(frame, ch->q[me][head], ch->qlen_i[me][head]);
    *len = ch->qlen_i[me][head];
    ch->qhead[me]++;
    return DTN_RADIO_OK;
}

static int fake_cad(dtn_radio *r)
{
    const radio_fake_binding *b = bind_of(r);
    radio_channel *ch;
    int i;

    if (b == NULL) {
        return DTN_RADIO_ERR_STATE;
    }
    ch = b->ch;
    for (i = 0; i < ch->busy_n; i++) {
        if (ch->now_ms >= ch->busy_from[i] && ch->now_ms <= ch->busy_to[i]) {
            return DTN_RADIO_ERR_BUSY;
        }
    }
    return DTN_RADIO_OK;
}

static int fake_sleep(dtn_radio *r)
{
    (void)r;
    return DTN_RADIO_OK;
}

static int bind_init(dtn_radio *r, radio_channel *ch, uint8_t id)
{
    radio_fake_binding *b;
    int slot, i;

    if (g_bind_n >= RADIO_FAKE_MAX_RADIOS) {
        return DTN_RADIO_ERR_STATE;
    }
    b = &g_bind[g_bind_n++];
    b->ch = ch;
    b->id = id;
    r->ctx = b;
    slot = -1;
    for (i = 0; i < ch->n_radios; i++) {
        if (ch->ids[i] == id) {
            slot = i; /* rebind of an existing id: reuse its queue */
        }
    }
    if (slot < 0) {
        if (ch->n_radios >= RADIO_FAKE_MAX_RADIOS) {
            return DTN_RADIO_ERR_STATE;
        }
        slot = ch->n_radios++;
        ch->ids[slot] = id;
    }
    ch->qlen[slot] = 0;
    ch->qhead[slot] = 0;
    r->init = fake_init;
    r->send = fake_send;
    r->recv = fake_recv;
    r->cad = fake_cad;
    r->sleep = fake_sleep;
    return DTN_RADIO_OK;
}

int radio_fake_loopback_init(dtn_radio *r, radio_channel *ch, uint8_t id)
{
    return bind_init(r, ch, id);
}

int radio_fake_lossy_init(dtn_radio *r, radio_channel *ch, uint8_t id)
{
    /* The lossy radio IS the loopback machinery plus a scripted channel;
     * the distinction lives in the script, not the code. */
    return bind_init(r, ch, id);
}

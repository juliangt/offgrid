/* dtn_mac.c — the node-plane MAC v1 pure logic (see dtn_mac.h).
 *
 * Every timing decision flows through the injected clock and the CAD
 * callback; every random draw through the injected rand. The host tests
 * script the channel (busy windows, drops) and pin the exact backoff
 * sequence, the duty-budget deferrals, the class budgets and the
 * wake-window scheduling.
 */

#include "dtn_mac.h"

#include <string.h>

void dtn_mac_init(dtn_mac *m, dtn_radio *radio,
                  uint64_t (*now_ms)(struct dtn_mac *m),
                  uint32_t (*rand)(struct dtn_mac *m),
                  void *user)
{
    memset(m, 0, sizeof(*m));
    m->radio = radio;
    m->now_ms = now_ms;
    m->rand = rand;
    m->user = user;
    m->duty_ppm = DTN_MAC_DUTY_DEFAULT_PPM;
}

void dtn_mac_set_duty(dtn_mac *m, uint64_t ppm)
{
    m->duty_ppm = ppm;
}

void dtn_mac_contact_begin(dtn_mac *m)
{
    memset(m->contact_sent, 0, sizeof(m->contact_sent));
}

uint32_t dtn_mac_contact_sent(const dtn_mac *m, dtn_mac_class cls)
{
    return m->contact_sent[cls];
}

uint64_t dtn_mac_duty_used_ms(const dtn_mac *m, uint64_t now_ms)
{
    uint64_t used = 0;
    int i;
    for (i = 0; i < m->duty.n; i++) {
        if (now_ms >= m->duty.start_ms[i] &&
            now_ms - m->duty.start_ms[i] < DTN_MAC_DUTY_WINDOW_MS) {
            used += m->duty.ms[i];
        }
    }
    return used;
}

/* duty_allows reports whether sending airtime_ms more stays inside the
 * rolling budget (used + airtime ≤ ppm × 1 h). */
static int duty_allows(const dtn_mac *m, uint64_t now_ms, uint32_t airtime_ms)
{
    const uint64_t budget = m->duty_ppm * DTN_MAC_DUTY_WINDOW_MS / 1000000ULL;
    return dtn_mac_duty_used_ms(m, now_ms) + airtime_ms <= budget;
}

static void duty_record(dtn_mac *m, uint64_t now_ms, uint32_t airtime_ms)
{
    const uint64_t minute = 60000;
    int i, slot = -1;
    for (i = 0; i < m->duty.n; i++) {
        if (now_ms >= m->duty.start_ms[i] && now_ms - m->duty.start_ms[i] < minute) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (m->duty.n < 60) {
            slot = m->duty.n++;
        } else {
            /* Evict the oldest bucket (the one that expires first). */
            slot = 0;
            for (i = 1; i < m->duty.n; i++) {
                if (m->duty.start_ms[i] < m->duty.start_ms[slot]) {
                    slot = i;
                }
            }
        }
        m->duty.start_ms[slot] = (now_ms / minute) * minute;
        m->duty.ms[slot] = 0;
    }
    m->duty.ms[slot] += airtime_ms;
}

static uint32_t contact_cap(dtn_mac_class cls)
{
    switch (cls) {
    case DTN_MAC_CLASS_MGMT:
        return 0xFFFFFFFFu; /* management is not airtime-budgeted (§7.3) */
    case DTN_MAC_CLASS_BULK:
        return DTN_MAC_CONTACT_BULK_FRAMES;
    default:
        return DTN_MAC_CONTACT_MAIL_FRAMES;
    }
}

dtn_mac_rc dtn_mac_send(dtn_mac *m, dtn_mac_class cls,
                        const uint8_t *frame, size_t len, uint32_t airtime_ms)
{
    uint32_t backoff = DTN_MAC_BACKOFF_BASE_MS;
    int try_;

    if (m->radio == NULL || m->now_ms == NULL || m->rand == NULL || m->wait_ms == NULL) {
        return DTN_MAC_ERR;
    }
    if (m->contact_sent[cls] >= contact_cap(cls)) {
        return DTN_MAC_DEFERRED_BUDGET;
    }
    if (!duty_allows(m, m->now_ms(m), airtime_ms)) {
        return DTN_MAC_DEFERRED_DUTY;
    }
    for (try_ = 0; try_ < DTN_MAC_BACKOFF_MAX_TRIES; try_++) {
        if (m->radio->cad(m->radio) == DTN_RADIO_OK) {
            const int rc = m->radio->send(m->radio, frame, len);
            if (rc != DTN_RADIO_OK) {
                return DTN_MAC_ERR;
            }
            duty_record(m, m->now_ms(m), airtime_ms);
            m->contact_sent[cls]++;
            return DTN_MAC_SENT;
        }
        /* Busy: exponential randomized backoff (§5.3) — base doubled each
         * try, ceiling 8 s, jitter = rand % backoff, then the injected
         * wait moves the (fake) clock. */
        m->backoffs++;
        m->last_backoff_ms = backoff + (m->rand(m) % backoff);
        if (m->wait_ms != NULL) {
            m->wait_ms(m, m->last_backoff_ms);
        }
        if (backoff < DTN_MAC_BACKOFF_CEILING_MS) {
            const uint64_t doubled = (uint64_t)backoff * 2;
            backoff = doubled > DTN_MAC_BACKOFF_CEILING_MS ? DTN_MAC_BACKOFF_CEILING_MS
                                                           : (uint32_t)doubled;
        }
    }
    return DTN_MAC_CHANNEL_LOST;
}

/* ------------------------------------------------------------------ */
/* Wake/beacon window bookkeeping (§5.3)                               */
/* ------------------------------------------------------------------ */

int dtn_mac_note_peer(dtn_mac *m, const uint8_t fp[DTN_LINK_FP_LEN],
                      uint64_t obs_ms, uint32_t period_ms)
{
    int i;
    for (i = 0; i < m->n_peers; i++) {
        if (memcmp(m->peers[i].fp, fp, DTN_LINK_FP_LEN) == 0) {
            m->peers[i].last_seen_ms = obs_ms;
            m->peers[i].period_ms = period_ms;
            m->peers[i].observations++;
            return 0;
        }
    }
    if (m->n_peers >= DTN_MAC_MAX_PEERS) {
        return -1;
    }
    memcpy(m->peers[m->n_peers].fp, fp, DTN_LINK_FP_LEN);
    m->peers[m->n_peers].last_seen_ms = obs_ms;
    m->peers[m->n_peers].period_ms = period_ms;
    m->peers[m->n_peers].observations = 1;
    m->n_peers++;
    return 0;
}

int dtn_mac_next_window(dtn_mac *m, const uint8_t fp[DTN_LINK_FP_LEN],
                        uint64_t from_ms, uint64_t *next_ms)
{
    int i;
    for (i = 0; i < m->n_peers; i++) {
        if (memcmp(m->peers[i].fp, fp, DTN_LINK_FP_LEN) == 0) {
            const uint64_t period = m->peers[i].period_ms;
            const uint64_t last = m->peers[i].last_seen_ms;
            uint64_t next;
            if (period == 0) {
                return -1;
            }
            if (from_ms <= last) {
                next = last;
            } else {
                const uint64_t ahead = from_ms - last;
                next = last + ((ahead + period - 1) / period) * period;
            }
            *next_ms = next;
            return 0;
        }
    }
    return -1;
}

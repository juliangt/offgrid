/* dtn_mac.h — the node-plane MAC v1 pure logic (issue #33 P3.3, §5.3 of
 * docs/node-network.md): CAD listen-before-talk with exponential
 * randomized backoff (base 250 ms doubling to an 8 s ceiling), a rolling
 * per-region duty budget (default 10 %/hour), per-contact airtime budgets
 * (§7.4), and wake/beacon window bookkeeping for solar repeaters.
 *
 * Pure logic over the dtn_radio HAL: the clock and the randomness are
 * INJECTED (fake clock + fake rand make the tests deterministic); the
 * radio is the HAL vtable of dtn_radio.h. No retransmit protocol exists —
 * loss is tolerated by design (store-and-forward, §7); the MAC's job is
 * airtime discipline, not delivery.
 */
#ifndef DTN_MAC_H
#define DTN_MAC_H

#include <stddef.h>
#include <stdint.h>

#include "dtn_radio.h"
#include "dtn_session.h" /* DTN_LINK_FP_LEN (the fingerprint length) */

/* §5.3 MAC v1 constants (frozen defaults; the region parameterizes the
 * duty budget — EU sub-band rules are stricter and win). */
#define DTN_MAC_BACKOFF_BASE_MS 250
#define DTN_MAC_BACKOFF_CEILING_MS 8000
#define DTN_MAC_BACKOFF_MAX_TRIES 12
#define DTN_MAC_DUTY_WINDOW_MS (60ULL * 60 * 1000) /* rolling 1 h */
#define DTN_MAC_DUTY_DEFAULT_PPM 100000ULL         /* 10 %/hour */
#define DTN_MAC_CONTACT_MAIL_FRAMES 64             /* §7.4: LoRa contact, mail */
#define DTN_MAC_CONTACT_BULK_FRAMES 512            /* §7.4: bulk, mail queue empty */
#define DTN_MAC_MAX_PEERS 8

typedef enum {
    DTN_MAC_CLASS_MGMT = 0, /* management preempts (queue discipline only) */
    DTN_MAC_CLASS_MAIL = 1,
    DTN_MAC_CLASS_BULK = 2,
} dtn_mac_class;

/* Verdicts of dtn_mac_send. */
typedef enum {
    DTN_MAC_SENT = 0,
    DTN_MAC_DEFERRED_DUTY = -1, /* the rolling budget is exhausted */
    DTN_MAC_DEFERRED_BUDGET = -2, /* the per-contact class budget is spent */
    DTN_MAC_CHANNEL_LOST = -3,  /* backoff attempts exhausted */
    DTN_MAC_ERR = -4,
} dtn_mac_rc;

typedef struct {
    uint8_t fp[DTN_LINK_FP_LEN]; /* peer fingerprint (§7.5: no content) */
    uint64_t last_seen_ms;       /* the peer's last observed wake window */
    uint32_t period_ms;          /* the peer's observed wake period */
    uint32_t observations;
} dtn_mac_peer;

typedef struct dtn_mac {
    dtn_radio *radio;
    /* Injected clock, randomness and delay (deterministic tests; real
     * drivers use the tick timer, the hardware RNG and a task delay one
     * layer up). wait_ms(ms) suspends the caller for the backoff. */
    uint64_t (*now_ms)(struct dtn_mac *m);
    uint32_t (*rand)(struct dtn_mac *m);
    void (*wait_ms)(struct dtn_mac *m, uint32_t delay_ms);
    void *user;
    /* Region parameter (ppm of the rolling 1 h window). */
    uint64_t duty_ppm;
    /* Rolling duty accounting: 60 per-minute buckets cover the whole
     * rolling hour regardless of how many frames it took (bounded memory:
     * 60 × 12 B). */
    struct {
        uint64_t start_ms[60]; /* each bucket covers [start, start+60 000) */
        uint32_t ms[60];
        int n;
    } duty;
    /* Per-contact class budgets (frames sent since the last contact reset). */
    uint32_t contact_sent[3];
    /* Wake-window bookkeeping per peer (solar repeaters, §5.3). */
    dtn_mac_peer peers[DTN_MAC_MAX_PEERS];
    int n_peers;
    /* Diagnostics the tests pin. */
    uint64_t backoffs;
    uint32_t last_backoff_ms;
} dtn_mac;

void dtn_mac_init(dtn_mac *m, dtn_radio *radio,
                  uint64_t (*now_ms)(struct dtn_mac *m),
                  uint32_t (*rand)(struct dtn_mac *m),
                  void *user);

/* Sets the region's duty budget (ppm of the rolling hour). */
void dtn_mac_set_duty(dtn_mac *m, uint64_t ppm);

/* CAD listen-before-talk with exponential randomized backoff:
 * cad → busy ⇒ sleep (base << n) + rand()%that, retry, up to
 * DTN_MAC_BACKOFF_MAX_TRIES. A clear channel and a budget in credit send
 * immediately. The caller states the frame's airtime (the §5.3 formula)
 * and its queue class; the duty budget and the per-contact budget gate.
 *
 *   DTN_MAC_SENT             — handed to the radio (delivery not guaranteed)
 *   DTN_MAC_DEFERRED_DUTY    — the rolling budget is exhausted; retry later
 *   DTN_MAC_DEFERRED_BUDGET  — the class's per-contact budget is spent
 *   DTN_MAC_CHANNEL_LOST     — busy past the final backoff
 */
dtn_mac_rc dtn_mac_send(dtn_mac *m, dtn_mac_class cls,
                        const uint8_t *frame, size_t len, uint32_t airtime_ms);

/* Per-contact budget bookkeeping (§7.4): a new contact resets the class
 * counters. bulk is only allowed while the mail queue is empty — the
 * caller asserts that (the MAC trusts the queue discipline). */
void dtn_mac_contact_begin(dtn_mac *m);
uint32_t dtn_mac_contact_sent(const dtn_mac *m, dtn_mac_class cls);

/* Rolling duty usage over the last hour, ms. */
uint64_t dtn_mac_duty_used_ms(const dtn_mac *m, uint64_t now_ms);

/* Wake/beacon window bookkeeping (§5.3): record that peer fingerprint was
 * observed awake at obs_ms with wake period period_ms; the scheduling
 * query returns the next predicted window ≥ from_ms (peers concentrate
 * transmission there). Returns 0 and fills *next_ms, or -1 for an unknown
 * peer / full table. */
int dtn_mac_note_peer(dtn_mac *m, const uint8_t fp[DTN_LINK_FP_LEN],
                      uint64_t obs_ms, uint32_t period_ms);
int dtn_mac_next_window(dtn_mac *m, const uint8_t fp[DTN_LINK_FP_LEN],
                        uint64_t from_ms, uint64_t *next_ms);

#endif /* DTN_MAC_H */

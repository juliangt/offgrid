/* radio_fake.h — the two in-memory dtn_radio implementations for the host
 * suite (see dtn_radio.h): a lossless loopback and a scripted lossy
 * channel (per-frame drops, CAD busy windows). Test doubles only — never
 * compiled into the firmware build.
 *
 * Channel model: every radio bound to a radio_channel hears every OTHER
 * bound radio's transmission (broadcast medium, the §5.1 profile), minus
 * the frames the channel's drop script loses. The channel clock is the
 * test's — radio_channel_advance moves it; the MAC's fake clock must be
 * kept in sync by the test (or driven from the channel).
 */
#ifndef RADIO_FAKE_H
#define RADIO_FAKE_H

#include <stdint.h>

#include "dtn_radio.h"

#define RADIO_FAKE_MAX_RADIOS 4
#define RADIO_FAKE_QLEN 16
#define RADIO_FAKE_MAX_DROPS 64
#define RADIO_FAKE_MAX_BUSY 8

typedef struct {
    /* The drop script: the tx_seen-th frame handed to any send() is lost
     * when script[tx_seen-1] != 0 (tx_seen counts handed frames). */
    uint8_t script[RADIO_FAKE_MAX_DROPS];
    int script_n;
    int tx_seen;
    /* CAD busy windows (inclusive from/to, channel clock ms). */
    uint64_t busy_from[RADIO_FAKE_MAX_BUSY];
    uint64_t busy_to[RADIO_FAKE_MAX_BUSY];
    int busy_n;
    uint64_t now_ms;
    /* Bound radios and their receive queues (lengths ride alongside). */
    uint8_t ids[RADIO_FAKE_MAX_RADIOS];
    uint8_t q[RADIO_FAKE_MAX_RADIOS][RADIO_FAKE_QLEN][DTN_RADIO_MTU];
    size_t qlen_i[RADIO_FAKE_MAX_RADIOS][RADIO_FAKE_QLEN];
    size_t qlen[RADIO_FAKE_MAX_RADIOS];
    size_t qhead[RADIO_FAKE_MAX_RADIOS];
    int n_radios;
} radio_channel;

void radio_channel_init(radio_channel *ch);
/* Scripts the drop list (a leading prefix is enough; shorter lists only
 * cover their own prefix). */
void radio_channel_set_drops(radio_channel *ch, const uint8_t *script, int n);
void radio_channel_add_busy(radio_channel *ch, uint64_t from_ms, uint64_t to_ms);
void radio_channel_advance(radio_channel *ch, uint64_t ms);
/* Resets the fake binding table (call between tests). */
void radio_fake_reset(void);

/* Binds a radio. Both implementations share the channel machinery; the
 * lossy variant is the one tests script drops/busy against (loopback with
 * an empty script is lossless). */
int radio_fake_loopback_init(dtn_radio *r, radio_channel *ch, uint8_t id);
int radio_fake_lossy_init(dtn_radio *r, radio_channel *ch, uint8_t id);

#endif /* RADIO_FAKE_H */

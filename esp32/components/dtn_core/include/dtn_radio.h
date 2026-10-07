/* dtn_radio.h — the node-plane radio HAL (issue #33 P3.3).
 *
 * The sx126x REGISTER-LEVEL driver port (BSD LoRaMac-node) is deferred to
 * hardware bring-up: register sequences cannot be verified in this
 * environment, and unverifiable radio code has no place in the portable
 * core. What the plane needs ABOVE the driver is this vtable — the MAC
 * (dtn_mac.c) and the link layer are written against it, and the host
 * suite drives them through two in-memory implementations:
 *
 *   - loopback: everything sent is received (functional tests);
 *   - lossy: a scripted channel with per-frame drops, busy-channel
 *     windows for CAD, and collision injection (bench-style tests).
 *
 * The real adapter is an sx126x implementation of exactly this vtable,
 * landed with two-unit bench hardware (§11 rows note the deferral).
 * Callback style: send/recv report through completion callbacks; cad
 * reports channel activity through its callback. All calls are
 * synchronous on the host; the ESP32 port runs them from its radio task.
 */
#ifndef DTN_RADIO_H
#define DTN_RADIO_H

#include <stddef.h>
#include <stdint.h>

#define DTN_RADIO_MTU 255 /* the SX126x payload limit */

typedef enum {
    DTN_RADIO_OK = 0,
    DTN_RADIO_ERR_BUSY = -1,     /* channel busy (CAD hit) */
    DTN_RADIO_ERR_DROPPED = -2,  /* the channel lost the frame (lossy) */
    DTN_RADIO_ERR_STATE = -3,
} dtn_radio_rc;

typedef struct dtn_radio {
    void *ctx;
    /* init prepares the radio; id is the local device tag (host tests). */
    int (*init)(struct dtn_radio *r, uint8_t id);
    /* send transmits one frame (≤ DTN_RADIO_MTU); 0 = handed to the
     * channel (delivery is NOT guaranteed — the channel model decides). */
    int (*send)(struct dtn_radio *r, const uint8_t *frame, size_t len);
    /* recv polls one received frame; returns 0 and fills frame/len when a
     * frame is available, DTN_RADIO_ERR_STATE when the queue is empty. */
    int (*recv)(struct dtn_radio *r, uint8_t *frame, size_t *len);
    /* cad performs channel-activity detection: 0 = clear, BUSY = active. */
    int (*cad)(struct dtn_radio *r);
    /* sleep parks the radio (the solar repeater's lever, §5.3). */
    int (*sleep)(struct dtn_radio *r);
} dtn_radio;

#endif /* DTN_RADIO_H */

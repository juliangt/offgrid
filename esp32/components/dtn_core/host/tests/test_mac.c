/* test_mac.c — P3.3 node-plane MAC v1 host tests (issue #33, §5.3).
 *
 * A scripted fake channel (radio_fake) + an injected fake clock and
 * deterministic rand make every MAC decision reproducible: the
 * busy-channel backoff sequence, duty-budget deferrals, per-contact
 * budgets, the wake-window scheduling for solar repeaters, and the
 * lossy-channel end-to-end case (frames dropped at the radio still
 * reassemble when any window loses at most its redundancy, and never
 * corrupt sibling windows).
 */
#include "harness.h"

#include <string.h>

#include "dtn_frame.h"
#include "dtn_mac.h"
#include "dtn_session.h"
#include "dtn_tweetnacl.h"
#include "radio_fake.h"
#include "link_vectors.h"

/* Fake clock + deterministic LCG rand (both injected). */
static uint64_t g_clock_ms;
static uint32_t g_rand_state;
static radio_channel *g_ch;

static uint64_t fake_now(struct dtn_mac *m)
{
    (void)m;
    return g_clock_ms;
}

static uint32_t fake_rand(struct dtn_mac *m)
{
    (void)m;
    g_rand_state = g_rand_state * 1664525u + 1013904223u;
    return g_rand_state >> 8;
}

static void fake_wait(struct dtn_mac *m, uint32_t delay_ms)
{
    (void)m;
    g_clock_ms += delay_ms;
    g_ch->now_ms = g_clock_ms; /* the channel clock stays in step */
}

static void bind_fakes(radio_channel *ch, dtn_radio *tx, dtn_radio *rx)
{
    radio_channel_init(ch);
    g_ch = ch;
    CHECK(radio_fake_loopback_init(tx, ch, 1) == DTN_RADIO_OK);
    CHECK(radio_fake_lossy_init(rx, ch, 2) == DTN_RADIO_OK);
    g_clock_ms = 0;
}

/* Busy-channel backoff: with the channel busy until t=1000 ms, the send
 * backs off with the §5.3 shape (base 250 ms doubling to the 8 s ceiling,
 * jitter from the deterministic rand) and lands as soon as CAD clears. */
static void test_mac_backoff(void)
{
    radio_channel ch_storage;
    dtn_radio radio;
    dtn_mac mac;
    uint8_t frame[32];

    bind_fakes(&ch_storage, &radio, &radio);
    radio_channel_add_busy(g_ch, 0, 999); /* busy for the first second */
    g_rand_state = 42;
    dtn_mac_init(&mac, &radio, fake_now, fake_rand, NULL);
    mac.wait_ms = fake_wait;
    memset(frame, 0xA5, sizeof(frame));

    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 50) == DTN_MAC_SENT);
    CHECK(mac.backoffs >= 1);
    CHECK(g_clock_ms > 900); /* the send landed after the busy window */
    CHECK(mac.last_backoff_ms >= DTN_MAC_BACKOFF_BASE_MS); /* base + jitter */

    /* A second busy channel: the backoff DOUBLES. */
    radio_channel_add_busy(g_ch, g_clock_ms, g_clock_ms + 2000);
    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 50) == DTN_MAC_SENT);
    CHECK(mac.last_backoff_ms >= DTN_MAC_BACKOFF_BASE_MS * 2);

    /* A permanently busy channel exhausts the tries and reports honestly. */
    radio_channel_add_busy(g_ch, 0, 0xFFFFFFFFull);
    g_clock_ms = 200000; /* outside the earlier windows */
    g_ch->now_ms = g_clock_ms;
    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 50) == DTN_MAC_CHANNEL_LOST);
}

/* Duty budget: a 1 % budget with 350 ms frames allows exactly 102 frames
 * (36 000 ms / 350); the next send DEFERS instead of exceeding, and an
 * hour of passing time restores it. */
static void test_mac_duty(void)
{
    radio_channel ch_storage;
    dtn_radio radio;
    dtn_mac mac;
    uint8_t frame[64];
    int i, sent = 0;

    bind_fakes(&ch_storage, &radio, &radio);
    g_rand_state = 7;
    dtn_mac_init(&mac, &radio, fake_now, fake_rand, NULL);
    mac.wait_ms = fake_wait;
    dtn_mac_set_duty(&mac, 10000); /* 1 %/hour */
    dtn_mac_contact_begin(&mac);
    memset(frame, 0x5A, sizeof(frame));

    for (i = 0; i < 200; i++) {
        const dtn_mac_rc rc = dtn_mac_send(&mac, DTN_MAC_CLASS_MGMT, frame, sizeof(frame), 350);
        if (rc == DTN_MAC_SENT) {
            sent++;
        } else if (rc == DTN_MAC_DEFERRED_DUTY) {
            break;
        } else {
            CHECK(0); /* nothing else may happen on a clear channel */
        }
    }
    CHECK(sent == 102);
    CHECK(dtn_mac_duty_used_ms(&mac, g_clock_ms) <= 36000);
    fake_wait(&mac, DTN_MAC_DUTY_WINDOW_MS);
    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MGMT, frame, sizeof(frame), 350) == DTN_MAC_SENT);
}

/* Per-contact budgets (§7.4): mail caps at 64 frames per contact; a
 * contact reset restores it. */
static void test_mac_contact_budget(void)
{
    radio_channel ch_storage;
    dtn_radio radio;
    dtn_mac mac;
    uint8_t frame[16];
    int i;

    bind_fakes(&ch_storage, &radio, &radio);
    g_rand_state = 9;
    dtn_mac_init(&mac, &radio, fake_now, fake_rand, NULL);
    mac.wait_ms = fake_wait;
    dtn_mac_set_duty(&mac, 1000000); /* 100 %: duty never binds here */
    dtn_mac_contact_begin(&mac);
    memset(frame, 0x77, sizeof(frame));

    for (i = 0; i < DTN_MAC_CONTACT_MAIL_FRAMES; i++) {
        CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 10) == DTN_MAC_SENT);
    }
    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 10) == DTN_MAC_DEFERRED_BUDGET);
    CHECK(dtn_mac_contact_sent(&mac, DTN_MAC_CLASS_MAIL) == DTN_MAC_CONTACT_MAIL_FRAMES);
    dtn_mac_contact_begin(&mac);
    CHECK(dtn_mac_send(&mac, DTN_MAC_CLASS_MAIL, frame, sizeof(frame), 10) == DTN_MAC_SENT);
}

/* Wake/beacon windows: observations land in the peer table and the
 * scheduling query returns the next predicted period multiple (peers
 * concentrate transmission there, §5.3). */
static void test_mac_beacon_windows(void)
{
    radio_channel ch_storage;
    dtn_radio radio;
    dtn_mac mac;
    static const uint8_t fp[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    static const uint8_t other[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    uint64_t next = 0;

    bind_fakes(&ch_storage, &radio, &radio);
    g_rand_state = 11;
    dtn_mac_init(&mac, &radio, fake_now, fake_rand, NULL);
    mac.wait_ms = fake_wait;

    /* The repeater was seen awake at t=1000 with a 2 s period. */
    CHECK(dtn_mac_note_peer(&mac, fp, 1000, 2000) == 0);
    CHECK(dtn_mac_next_window(&mac, fp, 1200, &next) == 0);
    CHECK(next == 3000);
    CHECK(dtn_mac_next_window(&mac, fp, 3050, &next) == 0);
    CHECK(next == 5000);
    CHECK(dtn_mac_next_window(&mac, fp, 500, &next) == 0);
    CHECK(next == 1000);
    CHECK(dtn_mac_next_window(&mac, other, 0, &next) == -1);
    /* A second observation refreshes the phase (and counts). */
    CHECK(dtn_mac_note_peer(&mac, fp, 91000, 2000) == 0);
    CHECK(dtn_mac_next_window(&mac, fp, 91000, &next) == 0);
    CHECK(next == 91000);
}

/* ------------------------------------------------------------------ */
/* Lossy-channel end-to-end                                            */
/* ------------------------------------------------------------------ */

/* Handshake helper shared by both scenarios. */
static int e2e_handshake(dtn_link_session *tx_sess, dtn_link_session *rx_sess)
{
    uint8_t seed_i[32], seed_r[32], scalar_i[32], scalar_r[32];
    dtn_link_hs_cfg cfg_i, cfg_r;
    dtn_link_initiator ini;
    dtn_link_responder res;
    int w;

    for (w = 0; w < 32; w++) {
        seed_i[w] = (uint8_t)(0xA0 + w);
        seed_r[w] = (uint8_t)(0xB0 + w);
        scalar_i[w] = (uint8_t)(0x11 + w);
        scalar_r[w] = (uint8_t)(0x22 + w);
    }
    memset(&cfg_i, 0, sizeof(cfg_i));
    memset(&cfg_r, 0, sizeof(cfg_r));
    memcpy(cfg_i.local_seed, seed_i, 32);
    memcpy(cfg_r.local_seed, seed_r, 32);
    if (dtn_tn_ed25519_keypair(cfg_i.local_pub, cfg_i.local_seed) != 0 ||
        dtn_tn_ed25519_keypair(cfg_r.local_pub, cfg_r.local_seed) != 0) {
        return -1;
    }
    memcpy(cfg_i.peer_pub, cfg_r.local_pub, 32);
    memcpy(cfg_r.peer_pub, cfg_i.local_pub, 32);
    cfg_i.eph = scalar_i;
    cfg_r.eph = scalar_r;
    if (dtn_link_initiator_start(&ini, &cfg_i) != DTN_LINK_OK) {
        return -1;
    }
    if (dtn_link_responder_read1(&res, &cfg_r, ini.msg1, ini.msg1_len) != DTN_LINK_OK) {
        return -2;
    }
    if (dtn_link_responder_write2(&res) != DTN_LINK_OK) {
        return -3;
    }
    /* The e2e exchange must reproduce the shared vectors' bytes too. */
    CHECK(memcmp(res.msg2, LINK_HS_VECS[0].msg2, DTN_LINK_MSG2_LEN) == 0);
    if (dtn_link_initiator_read2(&ini, res.msg2, res.msg2_len) != DTN_LINK_OK) {
        return -4;
    }
    if (dtn_link_initiator_msg3(&ini) != DTN_LINK_OK) {
        return -5;
    }
    if (dtn_link_responder_read3(&res, ini.msg3, ini.msg3_len) != DTN_LINK_OK) {
        return -6;
    }
    *tx_sess = ini.session;
    *rx_sess = res.session;
    return 0;
}

/* Runs one lossy scenario: 3 interleaved 500 B windows (3 frames each),
 * every frame sent with `redundancy` copies through the lossy radio; the
 * script (1 = dropped at the given 1-based handed-frame position) eats
 * copies. completions_wanted names which windows must complete
 * byte-exact; the others must still be pending (never corrupt). */
static void lossy_scenario(const char *name, const uint8_t *script, int script_n,
                           int redundancy, const int completions_wanted[3])
{
    radio_channel ch_storage;
    dtn_radio tx_radio, rx_radio;
    dtn_link_session tx_sess, rx_sess;
    dtn_win_reassembler reasm;
    static uint8_t content[3][500];
    static uint8_t bufs[3][DTN_WIN_MAX_TOTAL][1 + DTN_WIN_PAYLOAD_PER_FRAME];
    static size_t frame_len[3][DTN_WIN_MAX_TOTAL];
    int w, f, copy_, completions = 0;

    T_BEGIN(name);
    bind_fakes(&ch_storage, &tx_radio, &rx_radio);
    { const int hs_rc = e2e_handshake(&tx_sess, &rx_sess); CHECK(hs_rc == 0); }
    radio_channel_set_drops(g_ch, script, script_n);

    for (w = 0; w < 3; w++) {
        int i, n;
        const uint8_t *frames[DTN_WIN_MAX_TOTAL] = {0};
        size_t lens[DTN_WIN_MAX_TOTAL] = {0};
        for (i = 0; i < 500; i++) {
            content[w][i] = (uint8_t)(0xA0 + w * 16 + (i % 16));
        }
        /* Split into per-frame buffers (the fake send copies from them). */
        n = dtn_win_split((uint8_t)(w + 1), content[w], 500,
                          (uint8_t *)bufs[w], sizeof(bufs[w]), frames, lens);
        CHECK(n == 3);
        for (f = 0; f < n; f++) {
            frame_len[w][f] = lens[f];
            memcpy(bufs[w][f], frames[f], lens[f]);
        }
    }
    dtn_win_reassembler_init(&reasm, 60000, 0);
    /* Redundancy = each frame's copies go out BACK TO BACK (an alternate,
     * not a second pass): handed position = ((w*3 + f) * redundancy + copy) + 1. */
    for (w = 0; w < 3; w++) {
        for (f = 0; f < 3; f++) {
            for (copy_ = 0; copy_ < redundancy; copy_++) {
                uint8_t wire[DTN_FRAME_ONAIR_MAX];
                size_t wire_len = 0;
                CHECK(dtn_frame_seal(&tx_sess, DTN_FRAME_BUNDLE_FRAG,
                                     bufs[w][f], frame_len[w][f], wire, &wire_len) == DTN_FRAME_OK);
                CHECK(tx_radio.send(&tx_radio, wire, wire_len) == DTN_RADIO_OK);
            }
        }
    }
    /* Receive: every delivered frame opens and pushes. */
    for (;;) {
        uint8_t wire[DTN_FRAME_ONAIR_MAX];
        size_t wire_len = 0, pt_len = 0, content_len = 0;
        dtn_frame_type t;
        uint8_t pt[DTN_FRAME_PAYLOAD_MAX];
        uint8_t out[DTN_WIN_MAX_BYTES];
        if (rx_radio.recv(&rx_radio, wire, &wire_len) != DTN_RADIO_OK) {
            break;
        }
        CHECK(dtn_frame_open(&rx_sess, wire, wire_len, &t, pt, &pt_len) == DTN_FRAME_OK);
        CHECK(t == DTN_FRAME_BUNDLE_FRAG);
        if (dtn_win_push(&reasm, pt, pt_len, out, &content_len) == DTN_WIN_DONE) {
            const int done_win = (int)out[0] - 0xA0; /* content is 0xA0+w*16.. */
            completions++;
            CHECK(content_len == 500);
            CHECK(memcmp(out, content[done_win / 16], 500) == 0); /* byte-exact */
        }
    }
    CHECK(completions == completions_wanted[0] + completions_wanted[1] + completions_wanted[2]);
    CHECK(reasm.rejected == 0);
}

void test_link_lossy_e2e(void)
{
    /* Scenario A: window 2's (w=1) middle frame loses BOTH copies — that
     * window cannot complete; the siblings must still complete
     * byte-exact. Handed order: position = ((w*3 + f) * 2 + copy) + 1;
     * w1/f1's copies sit at positions 9 and 10. */
    {
        uint8_t script[19] = {0};
        script[8] = 1;
        script[9] = 1;
        const int want[3] = {1, 0, 1};
        lossy_scenario("link/mac: lossy e2e — lost frame never corrupts siblings",
                       script, 19, 2, want);
    }
    /* Scenario B: two frames lose one copy each (positions 1 and 8:
     * copy0/w0/f0 and copy1/w1/f0) — every window keeps at least one copy
     * per frame, so ALL three complete byte-exact (the §1 loss-recovery
     * AC holds on the node plane). */
    {
        uint8_t script[19] = {0};
        script[0] = 1;
        script[7] = 1;
        const int want[3] = {1, 1, 1};
        lossy_scenario("link/mac: lossy e2e — a window losing at most its redundancy completes",
                       script, 19, 2, want);
    }
}

void test_mac(void)
{
    T_BEGIN("mac: busy-channel backoff sequence");
    test_mac_backoff();
    T_BEGIN("mac: duty-budget exhaustion defers sends");
    test_mac_duty();
    T_BEGIN("mac: per-contact class budgets");
    test_mac_contact_budget();
    T_BEGIN("mac: wake/beacon window bookkeeping");
    test_mac_beacon_windows();
    test_link_lossy_e2e();
}

/*
 * Off-grid DTN messaging SPA — binding limits and constants (§8.1).
 *
 * Part of the pure protocol engine (no DOM here). This is the first
 * app script: it only defines the shared constants every later script
 * reads. The full engine is exported as `DTN` by engine.js so the
 * shipped code can be exercised headless from Node (see
 * tests/crypto_roundtrip.mjs).
 *
 * Syntax is kept ES5 + Promises on purpose: captive-portal mini-browsers
 * run the OS WebView, which can be years behind the device browser.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 1. Binding limits and constants (§8.1)
 * ------------------------------------------------------------------- */
var TRANSIT_CAPACITY = 100;                    // mule transit_queue capacity (§8.1)
var TTL_DEFAULT = 604800;                      // 7 days
var TTL_MIN = 3600;
var TTL_MAX = 2592000;                         // 30 days
var MESSAGE_MAX_BYTES = 128;                   // plaintext limit PER ENVELOPE, UTF-8 bytes (§8.1)
var ALIAS_REGEX = /^[A-Za-z0-9_.-]{1,24}$/;    // sender alias (§4.1)
var PAYLOAD_MIN_BYTES = 248;                   // derived bounds (§8.2)
var PAYLOAD_MAX_BYTES = 400;

/* Long-message chunking (§4.4 — client-side convention inside the box).
 * The §8.1 plaintext limit stays binding per envelope; a longer text is
 * split into several ordinary envelopes that share TTL and created_at.
 * Per-chunk text budget (§4.4): the four signed metadata members occupy at
 * most 58 bytes of inner_json (w=13, g=31, i≤7, n≤7), so the §8.2 envelope
 * bound still binds per envelope:
 *   inner = 176 + M + A + 58   →   payload = 248 + M + A + 58 ≤ 400
 *   ⇔ M + A ≤ 94   (CHUNK_TEXT_PLUS_ALIAS_LIMIT)
 * i.e. a chunked envelope carries at most 94 - |alias| bytes of text —
 * always ≤ 128 (§8.1), and every pushed envelope stays within [248, 400]. */
var CHUNK_TAG = "chunk1";                      // inner `w` schema tag (§4.4, §15-style)
var CHUNK_MAX_PARTS = 16;                      // hard cap: envelopes per message (§4.4)
var CHUNK_G_BYTES = 16;                        // §4.4 message id `g`: 16 random bytes
var CHUNK_META_MAX_BYTES = 58;                 // worst-case inner footprint of w,g,i,n
var CHUNK_TEXT_PLUS_ALIAS_LIMIT = 152 - CHUNK_META_MAX_BYTES; // = 94 (§8.2 budget, see above)
var CHUNK_WARN_PARTS = 8;                      // ≥ this many envelopes → UI warns about
                                               // the share of a 100-envelope mule queue
/* Delivery acknowledgments (§4.5 — client-side convention inside the box).
 * An ack is an ordinary v1 envelope whose signed-then-encrypted inner
 * follows the versioned "ack1" convention; nodes and mules stay blind.
 * The ack metadata occupies at most 88 bytes of inner_json
 * (,"w":"ack1" = 11, ,"r":"<64 hex>" = 71, ,"y":1 = 6), so with m = ""
 * the §8.2 envelope bound still holds per ack envelope:
 *   payload = 248 + 0 + A + 88 = 336 + A ≤ 360 ≤ 400   (A ≤ 24, §4.1)
 * and one delivered message produces at most ONE ack envelope (§4.5). */
var ACK_TAG = "ack1";                          // inner `w` schema tag (§4.5, §15-style)
var ACK_TYPE_RECEIVED = 1;                     // ack `y` type 1: message received (§4.5)
var ACK_META_MAX_BYTES = 88;                   // worst-case inner footprint of w,r,y
var SENT_HISTORY_MAX = 200;                    // sender-side sent-record cap (local hygiene)

var PUBKEY_B64_LEN = 44;                       // 32 raw bytes (§4.1)
var SIGNATURE_B64_LEN = 88;                    // 64 raw bytes (§4.1)
var CANONICAL_HOST = "offgrid.local:8080";  // same origin on every node (§12)
var CANONICAL_URL = "http://" + CANONICAL_HOST;

/* Rotating dest_hint (§6.1 — issue #26, spec 1.6.0). The static §6.1
 * derivation let any directory-holding node operator recompute every
 * user's hint forever and link stored envelopes to aliases. Since 1.6.0
 * the hint a SENDER embeds is derived per epoch:
 *   hint(E) = lowercase_hex(HKDF-SHA256(ikm = X25519 public key (raw 32 B),
 *                                       salt = E as 8-byte big-endian,
 *                                       info = HINT_INFO, L = 32)[0:8])
 * with E = floor(unix_seconds / HINT_EPOCH_SECONDS) taken from NODE data
 * (the directory entry's server-set `epoch` on send; the highest epoch
 * observed from the node on receive), never from the device clock while
 * any node is reachable — nodes have no NTP, the NODE's clock is the
 * shared reference. A recipient recognizes {static legacy, hint(E),
 * hint(E-1)}; the legacy candidate retires at the fixed spec deadline. */
var HINT_EPOCH_SECONDS = 86400;                // 24 h epoch, UTC (§6.1)
var HINT_INFO = "offgrid-dest-hint";           // HKDF info string, exact bytes (§6.1)
var HINT_LENGTH_BYTES = 8;                     // hint = first 8 OKM bytes as 16 hex chars
var HINT_TRANSITION_DEADLINE = 1795996800;     // 2026-11-30T00:00:00Z (§6.1): from then on
                                               // the SPA stops recognizing the static hint —
                                               // mail from pre-1.6 senders no longer arrives
                                               // (their SPA refreshes from any visited node,
                                               // so the practical exposure is days).

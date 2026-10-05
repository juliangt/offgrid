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

/* Prekey bundles — bounded forward secrecy (§4.6 — issue #27, spec 1.7.0).
 * The envelope format is UNTOUCHED: the box targets a prekey public from the
 * recipient's published bundle (random one-time prekey, else the signed
 * medium-term prekey, else the long-term identity key) while dest_hint stays
 * derived from the STABLE identity key (§6.1). The secret that opened an
 * envelope is wiped synchronously (the forward-secrecy event). Node-side
 * admission is blind-shape only; the SPK signature is verified CLIENT-side
 * (the canonical bundle string is the §5-style fixed-order form
 * {"b":1,"k":<k>,"spk":<spk>,"ts":<ts>,"opk":<count>}, §4.6). */
var PREKEY_BUNDLE_VERSION = 1;                 // bundle schema version (§15-style)
var PREKEY_SPK_TTL_SECONDS = 2592000;          // 30 days: SPK rotation anchor (bundle ts)
var PREKEY_OPK_LOW_WATER = 4;                  // replenish when unconsumed stock ≤ this
var PREKEY_OPK_BATCH_TARGET = 12;              // fresh OPKs per batch (8..16 admission window)
var PREKEY_OPK_MIN = 8;                        // node admission floor (§10.3)
var PREKEY_OPK_MAX = 16;                       // node admission ceiling (§10.3)
var PREKEY_BUNDLE_MAX_BYTES = 2048;            // node admission cap for the serialized member
var PREKEY_PUBLIC_B64_LEN = 44;                // Base64 of a 32-byte X25519 public
var PREKEY_SIG_B64_LEN = 88;                   // Base64 of a 64-byte Ed25519 signature

/* Identity QR — in-person contact exchange (§4.7 — issue #28, spec 1.8.0).
 * A versioned, self-authenticating UTF-8 payload ("OFFGRID1:" + Base64 of a
 * canonical JSON object) carries the alias, the Ed25519 identity key and the
 * X25519 encryption key, signed by the publisher's Ed25519 key plus a CRC-32
 * OUTSIDE the signature for fast accidental-corruption detection. The
 * signature covers the canonical string
 *   {"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>}
 * (fixed member order, §5 canonical rules; §4.7). NO prekeys travel in the
 * QR (they would triple its size); contacts merge with the directory at
 * send time (§4.7). The QR text is rendered to a <canvas> by the vendored
 * qrcode-generator (js/vendor/qrcode.js — zero external assets). */
var QR_PAYLOAD_PREFIX = "OFFGRID1:"            // scanner-recognizable header (§4.7)
var QR_PAYLOAD_VERSION = 1                     // payload schema version (§15-style)
var QR_MAX_VERSION = 15;                       // encoder cap: QR versions 1..15, byte mode
var QR_ECC_LEVEL = "M";                        // encoder ECC level (§4.7)
var QR_TS_SKEW_SECONDS = 300;                  // future-ts allowance, same 300 s as §4.3 step 6
var QR_QUIET_ZONE_MODULES = 4;                 // canvas quiet zone (ISO/IEC 18004)

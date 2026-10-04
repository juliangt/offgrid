/*
 * Off-grid DTN messaging SPA — identity, derivations and envelopes
 * (§4, §6, §7). Part of the pure protocol engine (no DOM here); needs
 * the vendored tweetnacl (js/vendor/nacl.min.js, UMD → self.nacl).
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 5. Identity, derivations and envelopes (§4, §6, §7).
 * ------------------------------------------------------------------- */

/* tweetnacl comes from the vendored nacl.min.js (UMD → self.nacl). */
var naclRef = (typeof nacl !== "undefined") ? nacl :
              (typeof self !== "undefined" && self.nacl ? self.nacl : null);

function requireNacl() {
  if (!naclRef) throw new Error("tweetnacl embed is missing");
  return naclRef;
}

/*
 * Identity derivation (deterministic, documented for backup/restore):
 *
 *   master seed : 32 random bytes (crypto.getRandomValues, §7.2) — the
 *                 ONLY secret the user must back up.
 *   Ed25519     : nacl.sign.keyPair.fromSeed(seed)
 *                 (the nacl standard: seed IS the Ed25519 private seed)
 *   X25519      : nacl.box.keyPair.fromSecretKey(SHA-256(seed))
 *                 (a seed-only deterministic derivation; tweetnacl has no
 *                 fromSeed for box keys, so the seed is stretched to the
 *                 32-byte X25519 secret with SHA-256)
 *
 * The same seed always reconstructs the same key pairs, so the Base64
 * backup text restores the full identity after a browser data wipe.
 */
function identityFromSeed(seed) {
  var nacl = requireNacl();
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  var sign = nacl.sign.keyPair.fromSeed(seed);
  var boxSeed = sha256(seed);
  var box = nacl.box.keyPair.fromSecretKey(boxSeed);
  return {
    seed: seed,                                  /* Uint8Array(32) — backup secret */
    seedB64: b64encode(seed),                    /* the backup text (§11) */
    signPublic: sign.publicKey,                  /* Uint8Array(32) Ed25519 public */
    signSecret: sign.secretKey,                  /* Uint8Array(64) Ed25519 secret */
    signPublicB64: b64encode(sign.publicKey),    /* directory `pubkey` (§10.3) */
    boxPublic: box.publicKey,                    /* Uint8Array(32) X25519 public */
    boxSecret: box.secretKey,                    /* Uint8Array(32) X25519 secret */
    boxPublicB64: b64encode(box.publicKey),      /* directory `x25519` (§10.3) */
    hint: deriveDestHint(box.publicKey)          /* own dest_hint (§6.1) */
  };
}

function createIdentity() {
  return identityFromSeed(randomBytes(32));
}

/* §6.1: dest_hint = lowercase_hex(SHA-256(recipient X25519 pubkey)[0:8]). */
function deriveDestHint(x25519PublicRaw) {
  if (!(x25519PublicRaw instanceof Uint8Array) || x25519PublicRaw.length !== 32) {
    throw new Error("X25519 public key must be 32 raw bytes");
  }
  return hexEncode(sha256(x25519PublicRaw).subarray(0, 8));
}

/* §6.2: id = lowercase_hex(SHA-256(canonical §5.2 string)). */
function computeEnvelopeId(v, destHint, createdAt, ttl, payload) {
  return hexEncode(sha256(utf8Encode(canonicalEnvelopeString(v, destHint, createdAt, ttl, payload))));
}

/*
 * Envelope construction — §4.2 sign-then-encrypt, binding order:
 *   1. inner {m,a,k,t} → canonical §5.1 string
 *   2. s = Ed25519 detached signature over those canonical bytes
 *   3. full inner {m,a,k,s,t} → canonical §4.1 JSON → UTF-8 bytes
 *   4. fresh ephemeral X25519 key pair + fresh 24-byte nonce
 *   5. box = crypto_box(inner_bytes, nonce, recipient_x25519_pub, eph_sec)
 *   6. payload = b64(eph_pub ‖ nonce ‖ box); dest_hint §6.1; id §6.2
 * `t` (inner timestamp) equals created_at (§4.1: clients SHOULD).
 */
/*
 * Module D — Phase 2/3 evolution mapping (normative source: spec §14).
 *
 * The envelope built below is the Phase 1 (JSON over Wi-Fi) encoding of
 * semantic fields that are FROZEN across all transports (§14.1): v, id,
 * dest_hint, created_at, ttl, payload (+ reserved hop_count) and inner
 * m, a, k, s, t. No field is ever repurposed. Sign-then-encrypt is
 * invariant: the sender's Ed25519 signature and alias always travel
 * inside the ciphertext on every transport.
 *
 * Phase 1 (this code path — JSON over HTTP/Wi-Fi): hex ids and padded
 * Base64 payload travel as text; hop_count is always ABSENT (absent ==
 * 0) and never appears in Phase 1 code paths.
 *
 * Phase 2 — BLE L2CAP CoC, bitchat alignment (§14.2): one
 * Connection-Oriented Channel per peer over a fixed dynamic PSM.
 * Frame layout: length(2 bytes, big-endian) || CBOR envelope; the L2CAP
 * layer segments/reassembles (one envelope = one SDU) and the negotiated
 * MTU (>= 512 B) carries the maximum binary envelope (399 B, §14.3)
 * plus the 2-byte length prefix in a single SDU. JSON -> CBOR field
 * mapping (canonical CBOR per RFC 8949 preferred serialization,
 * integer map keys ascending):
 *
 *     CBOR key   JSON field    CBOR type       Notes
 *     0          v             uint            constant 1
 *     1          id            bstr (32 B)     SHA-256 bytes (hex decoded)
 *     2          dest_hint     bstr (8 B)      raw 8 bytes (hex decoded)
 *     3          created_at    uint            unix seconds
 *     4          ttl           uint            seconds
 *     5          payload       bstr            eph_pub || nonce || box
 *     6          hop_count     uint (0-7)      optional; absent == 0
 *
 *   hop_count counts peer-to-peer relays (incremented by each relaying
 *   peer, envelope dropped at 7); it is reserved and stays 0/absent in
 *   Phase 1 (§14.1). The inner payload switches to canonical CBOR with
 *   integer keys (0=m, 1=a, 2=k, 3=s, 4=t) in Phases 2/3 — the signature
 *   then covers that CBOR map without key 3, the exact analogue of the
 *   §5.1 signed string used here.
 *
 * Phase 3 — LoRa P2P SX1262 at 915 MHz (§14.3): radio frames carry at
 * most 222 bytes and the Phase 2 CBOR envelope never fits one frame
 * (floor 244 B; the exact size math is normative in spec §14.3 — not
 * duplicated here). Two modes:
 *   (a) two-frame fragmentation: each frame prefixes a 1-byte fragment
 *       header followed by up to 221 envelope bytes (2 x 221 = 442 >=
 *       399, so every Phase 1-legal message fits 2 frames):
 *
 *         bit 7..4   bit 3..2   bit 1..0
 *         win_id(4)  idx(2)     total(2)
 *
 *       win_id is a random per-message window tag; reassembly
 *       concatenates by idx within (win_id, total);
 *   (b) short-message single-frame mode (M <= 48, no id/dest_hint/
 *       alias; id recomputed from frame bytes) fits the 222-byte MTU
 *       exactly — see spec §14.3(b).
 */
function buildEnvelope(opts) {
  var nacl = requireNacl();
  if (!opts || typeof opts !== "object") throw new Error("buildEnvelope: options required");
  var recipientPub = opts.recipientBoxPublic;
  if (!(recipientPub instanceof Uint8Array) || recipientPub.length !== 32) {
    throw new Error("recipient X25519 public key must be 32 raw bytes");
  }
  var message = typeof opts.message === "string" ? opts.message : "";
  if (messageByteLength(message) > MESSAGE_MAX_BYTES) {
    throw new Error("message exceeds " + MESSAGE_MAX_BYTES + " UTF-8 bytes (§8.1)");
  }
  if (!validateAlias(opts.alias)) {
    throw new Error("alias does not match " + ALIAS_REGEX.toString() + " (§8.1)");
  }
  var createdAt = assertInt(opts.createdAt, "created_at");
  if (createdAt <= 0) throw new Error("created_at must be > 0 (§3.1)");
  var ttl = (opts.ttl === undefined || opts.ttl === null) ? TTL_DEFAULT : assertInt(opts.ttl, "ttl");
  if (ttl < TTL_MIN || ttl > TTL_MAX) throw new Error("ttl outside [" + TTL_MIN + ", " + TTL_MAX + "] (§8.1)");

  var k = b64encode(opts.signPublic);
  var t = createdAt;

  /* 1–2: sign the canonical §5.1 bytes (no s member). */
  var signedString = canonicalSignedString(message, opts.alias, k, t);
  var s = b64encode(nacl.sign.detached(utf8Encode(signedString), opts.signSecret));

  /* 3: complete inner JSON bytes. */
  var innerBytes = utf8Encode(canonicalInnerJson(message, opts.alias, k, s, t));

  /* 4–5: ephemeral box toward the recipient. */
  var eph = nacl.box.keyPair();
  var nonce = randomBytes(24);
  var boxed = nacl.box(innerBytes, nonce, recipientPub, eph.secretKey);

  /* 6: payload, dest_hint, id. */
  var payload = b64encode(concatBytes(eph.publicKey, nonce, boxed));
  var destHint = deriveDestHint(recipientPub);
  return {
    v: 1,
    id: computeEnvelopeId(1, destHint, createdAt, ttl, payload),
    dest_hint: destHint,
    created_at: createdAt,
    ttl: ttl,
    payload: payload
  };
}

/* Structural envelope validation shared by the decrypt path (§3.1) and
 * the pull storage path (transit records, §11), widened to the §15.3
 * supported version set {1, 2}: v == 1 MUST NOT carry `meta`; v == 2 MAY
 * carry it as a JSON object whose `orig_v`, when present, is the integer
 * 1 — unknown meta keys are ignored, never validated (§15.1/§15.3). All
 * other checks are version-invariant: every field outside `meta` keeps
 * its §3.1 type and bounds, and a v2 envelope's crypto scope (the
 * payload) is byte-identical to its v1 original (§15.1). */
function validEnvelopeShape(env) {
  if (!env || typeof env !== "object") return false;
  if (env.v !== 1 && env.v !== 2) return false;
  if (env.meta !== undefined) {
    if (env.v === 1) return false;               /* meta MUST be absent on v1 (§15.3) */
    if (typeof env.meta !== "object" || Array.isArray(env.meta) || env.meta === null) return false;
    if (env.meta.orig_v !== undefined && env.meta.orig_v !== 1) return false;
  }
  return typeof env.id === "string" && HEX64_REGEX.test(env.id) &&
    typeof env.dest_hint === "string" && HEX16_REGEX.test(env.dest_hint) &&
    typeof env.created_at === "number" && isFinite(env.created_at) &&
    Math.floor(env.created_at) === env.created_at && env.created_at > 0 &&
    typeof env.ttl === "number" && isFinite(env.ttl) &&
    Math.floor(env.ttl) === env.ttl && env.ttl >= TTL_MIN && env.ttl <= TTL_MAX &&
    typeof env.payload === "string";
}

/*
 * Recipient procedure §4.3 + §11: classify by dest_hint, open the box,
 * validate the inner fields, verify the detached signature. ANY failure
 * returns {ok:false} — never an error that could leak information — and
 * the caller only counts it in telemetry.
 */
function decryptEnvelope(env, identity, now) {
  try {
    var nacl = requireNacl();
    if (!validEnvelopeShape(env)) return { ok: false, reason: "bad_envelope" };
    if (env.dest_hint !== identity.hint) return { ok: false, reason: "not_mine" };

    /* §3.1 payload bounds; §4.3 split 32/24/rest. */
    var raw = b64decode(env.payload);
    if (!raw || raw.length < PAYLOAD_MIN_BYTES || raw.length > PAYLOAD_MAX_BYTES) {
      return { ok: false, reason: "bad_payload" };
    }
    var ephPub = raw.subarray(0, 32);
    var nonce = raw.subarray(32, 56);
    var boxed = raw.subarray(56);

    var innerBytes = nacl.box.open(boxed, nonce, ephPub, identity.boxSecret);
    if (!innerBytes) return { ok: false, reason: "crypto" };

    var inner;
    try {
      inner = JSON.parse(utf8Decode(innerBytes));
    } catch (e) {
      return { ok: false, reason: "bad_inner" };
    }
    /* §4.1: inner_json has exactly these fields. */
    if (!inner || typeof inner !== "object" || Array.isArray(inner)) {
      return { ok: false, reason: "bad_inner" };
    }
    if (Object.keys(inner).length !== 5 ||
        !("m" in inner) || !("a" in inner) || !("k" in inner) || !("s" in inner) || !("t" in inner)) {
      return { ok: false, reason: "bad_inner" };
    }
    if (typeof inner.m !== "string" || messageByteLength(inner.m) > MESSAGE_MAX_BYTES ||
        !validateAlias(inner.a) ||
        typeof inner.k !== "string" || inner.k.length !== PUBKEY_B64_LEN ||
        typeof inner.s !== "string" || inner.s.length !== SIGNATURE_B64_LEN ||
        !b64decode(inner.k) || !b64decode(inner.s) ||
        typeof inner.t !== "number" || !isFinite(inner.t) || Math.floor(inner.t) !== inner.t) {
      return { ok: false, reason: "bad_inner" };
    }
    if (typeof now === "number" && isFinite(now) && inner.t > now + 300) {
      return { ok: false, reason: "from_future" }; /* §4.3 step 6 */
    }

    /* §4.3 step 5: rebuild the §5.1 string and verify with k. */
    var signedString = canonicalSignedString(inner.m, inner.a, inner.k, inner.t);
    var sigOk = false;
    try {
      sigOk = nacl.sign.detached.verify(utf8Encode(signedString), b64decode(inner.s), b64decode(inner.k));
    } catch (e) {
      sigOk = false;
    }
    if (!sigOk) return { ok: false, reason: "bad_signature" };

    return { ok: true, m: inner.m, a: inner.a, t: inner.t, k: inner.k };
  } catch (e) {
    return { ok: false, reason: "crypto" };
  }
}

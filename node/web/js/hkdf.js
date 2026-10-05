/*
 * Off-grid DTN messaging SPA — HMAC-SHA256 and HKDF-SHA256 (RFC 2104,
 * RFC 5869), built on the vendored pure-JS SHA-256 of sha256.js. Used
 * only for the §6.1 rotating dest_hint derivation. Part of the pure
 * protocol engine (no DOM here). ES5 on purpose: captive-portal
 * mini-browsers run the OS WebView. No new vendored library: tweetnacl
 * has no HKDF, and one hand-rolled 30-line construction on top of the
 * already-vendored hash beats a second vendored dependency.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 3.1 HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869) — used only for
 *     the §6.1 rotating dest_hint derivation.
 * ------------------------------------------------------------------- */

var HMAC_BLOCK_SIZE = 64;   /* SHA-256 block size in bytes (RFC 2104) */

/* HMAC-SHA256(key, message): standard two-pass construction. A key longer
 * than the block size is hashed first (RFC 2104); shorter keys are
 * zero-padded to the block size. Deterministic and synchronous, exactly
 * like sha256 — one code path in every WebView. */
function hmacSha256(key, message) {
  if (!(key instanceof Uint8Array) || !(message instanceof Uint8Array)) {
    throw new Error("HMAC-SHA256 expects Uint8Array inputs");
  }
  var k = key.length > HMAC_BLOCK_SIZE ? sha256(key) : key;
  var padded = new Uint8Array(HMAC_BLOCK_SIZE);
  padded.set(k);
  var ipad = new Uint8Array(HMAC_BLOCK_SIZE);
  var opad = new Uint8Array(HMAC_BLOCK_SIZE);
  for (var i = 0; i < HMAC_BLOCK_SIZE; i++) {
    ipad[i] = padded[i] ^ 0x36;
    opad[i] = padded[i] ^ 0x5c;
  }
  var inner = sha256(concatBytes(ipad, message));
  return sha256(concatBytes(opad, inner));
}

/* HKDF-SHA256 (RFC 5869): extract-then-expand.
 *   PRK = HMAC-SHA256(salt, IKM)            (salt absent → HashLen zeros)
 *   OKM = T(1) ‖ T(2) ‖ … truncated to L    (T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i))
 * The §6.1 derivation calls this with L = 32 (one full block, single
 * expansion iteration); the loop keeps the general RFC shape so the
 * RFC 5869 multi-block test vectors pin it honestly. */
function hkdfSha256(ikm, salt, info, length) {
  if (!(ikm instanceof Uint8Array) || ikm.length === 0) {
    throw new Error("HKDF: ikm must be a non-empty Uint8Array");
  }
  if (typeof length !== "number" || !isFinite(length) ||
      Math.floor(length) !== length || length < 1 || length > 255 * 32) {
    throw new Error("HKDF: length must be an integer within [1, 8160]");
  }
  /* RFC 5869 §2.2: an absent salt is a string of HashLen zeros. (For
   * HMAC-SHA256 an empty key would be equivalent — zero-padded to the
   * block either way — but stay literal to the RFC.) */
  var prk = hmacSha256(salt instanceof Uint8Array && salt.length > 0 ? salt : new Uint8Array(32), ikm);
  var hashLen = 32;
  var n = Math.ceil(length / hashLen);
  var okm = new Uint8Array(length);
  var t = new Uint8Array(0);
  var counter = new Uint8Array(1);
  var filled = 0;
  for (var i = 1; i <= n; i++) {
    counter[0] = i;
    t = hmacSha256(prk, concatBytes(t, info instanceof Uint8Array ? info : new Uint8Array(0), counter));
    var take = Math.min(hashLen, length - filled);
    okm.set(t.subarray(0, take), filled);
    filled += take;
  }
  return okm;
}

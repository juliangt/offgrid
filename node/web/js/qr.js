/*
 * Off-grid DTN messaging SPA — identity QR payloads and contacts (§4.7,
 * issue #28). Both sides of the in-person exchange:
 *
 *   publisher: qrBuildPayload serializes its alias + Ed25519 identity key +
 *              X25519 encryption key into a versioned, self-authenticating
 *              payload ("OFFGRID1:" + Base64 of a canonical JSON object)
 *              signed by its Ed25519 key, with a CRC-32 OUTSIDE the
 *              signature for fast accidental-corruption detection. The SPA
 *              renders the text as a QR code on a <canvas> (vendored
 *              qrcode-generator, js/vendor/qrcode.js) and shows the same
 *              string as copyable text — the universal fallback.
 *   importer : qrParsePayload verifies structure, key lengths, CRC-32 and
 *              the Ed25519 signature — every failure is a VISIBLE rejection
 *              naming the reason (a deliberate difference from the §4.3
 *              silent discard: the user is looking at the screen during an
 *              in-person exchange) and NOTHING is stored on failure.
 *
 * Contacts are device-local (IndexedDB `contacts` store, §15.6 migration
 * v5) and merge with directory lookups at send time: a fresh directory
 * entry supplies prekeys (§4.6) and the hint epoch (§6.1); offline-cold,
 * addressing falls back to the identity key with the documented §6.1
 * static-hint behavior.
 *
 * Zero external assets: the only QR machinery is the vendored encoder plus
 * the native canvas and (feature-detected) BarcodeDetector APIs. Everything
 * here is pure and DOM-free; canvas/camera wiring lives in ui.js. Part of
 * the pure protocol engine. ES5 on purpose: captive-portal mini-browsers
 * run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 5.1d CRC-32 (IEEE 802.3) — the fast accidental-corruption check.
 * ------------------------------------------------------------------- */

/*
 * §4.7 CRC-32 definition (binding): the standard CRC-32 of IEEE 802.3 /
 * ITU-T V.42 / zlib (reflected polynomial 0xEDB88320, initial value
 * 0xFFFFFFFF, final XOR 0xFFFFFFFF — ISO 3309 as implemented by zlib),
 * computed over the UTF-8 bytes of the canonical signed string and written
 * as 8 lowercase hex characters. It sits OUTSIDE the signature: it catches
 * scan/paste corruption instantly without crypto, while a tampered payload
 * still fails the Ed25519 check (a forger can recompute the CRC, but not
 * the signature).
 */
var QR_CRC32_TABLE = (function () {
  var table = new Uint32Array(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function qrCrc32(bytes) {
  /* Duck-typed (length-indexed) rather than instanceof: the headless test
   * harness and the browser live in different Uint8Array realms. */
  if (!bytes || typeof bytes.length !== "number") throw new Error("qrCrc32: bytes required");
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) {
    crc = QR_CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/* The §4.7 wire form of the CRC: exactly 8 lowercase hex characters. */
function qrCrc32Hex(bytes) {
  var crc = qrCrc32(bytes);
  var hex = crc.toString(16);
  while (hex.length < 8) hex = "0" + hex;
  return hex;
}

/* ---------------------------------------------------------------------
 * 5.1e The §4.7 canonical strings, payload construction and parsing.
 * ------------------------------------------------------------------- */

/*
 * §4.7 signed byte string (binding): canonical JSON per §5 — UTF-8, no
 * whitespace, fixed member order v, alias, ed, x, ts, integers in minimal
 * decimal form, minimal string escaping (the alias is §8.1-ASCII and the
 * keys are Base64, so escaping never fires in practice). The Ed25519
 * signature and the CRC-32 both cover exactly these bytes:
 *
 *   {"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>}
 */
function qrCanonicalPayloadString(alias, edB64, xB64, ts) {
  return '{"v":' + String(QR_PAYLOAD_VERSION) +
         ',"alias":' + jsonEscapeString(alias) +
         ',"ed":' + jsonEscapeString(edB64) +
         ',"x":' + jsonEscapeString(xB64) +
         ',"ts":' + String(assertInt(ts, "ts")) + "}";
}

/* §4.7 complete payload object, fixed member order v, alias, ed, x, ts,
 * sig, crc — canonical like the signed string (deterministic bytes, so a
 * payload rebuilt from the same identity is byte-identical). */
function qrCanonicalObjectString(alias, edB64, xB64, ts, sig, crc) {
  return qrCanonicalPayloadString(alias, edB64, xB64, ts).slice(0, -1) + /* drop the closing brace */
         ',"sig":' + jsonEscapeString(sig) +
         ',"crc":' + jsonEscapeString(crc) + "}";
}

/*
 * §4.7 publisher rule: sign-then-wrap. The identity contributes its alias,
 * Ed25519 public key (the `ed` member — the contact's identity) and X25519
 * public key (the `x` member — the encryption key). ts is a unix-seconds
 * integer (> 0). NO prekeys travel in the QR: they would roughly triple
 * the payload and hurt scan reliability — senders merge the contact with
 * the directory at send time instead (§4.7).
 */
function qrBuildPayload(identity, tsSec) {
  var nacl = requireNacl();
  if (!identity || typeof identity !== "object") throw new Error("qrBuildPayload: identity required");
  if (!validateAlias(identity.alias)) {
    throw new Error("alias does not match " + ALIAS_REGEX.toString() + " (§8.1)");
  }
  var edB64 = (typeof identity.signPublicB64 === "string") ? identity.signPublicB64 : b64encode(identity.signPublic);
  var xB64 = (typeof identity.boxPublicB64 === "string") ? identity.boxPublicB64 : b64encode(identity.boxPublic);
  if (typeof edB64 !== "string" || edB64.length !== PUBKEY_B64_LEN) throw new Error("Ed25519 public key must be 44 Base64 characters");
  if (typeof xB64 !== "string" || xB64.length !== PUBKEY_B64_LEN) throw new Error("X25519 public key must be 44 Base64 characters");
  var ts = assertInt(tsSec, "ts");
  if (ts <= 0) throw new Error("ts must be > 0");
  var canonical = utf8Encode(qrCanonicalPayloadString(identity.alias, edB64, xB64, ts));
  var sig = b64encode(nacl.sign.detached(canonical, identity.signSecret));
  var crc = qrCrc32Hex(canonical);
  var object = utf8Encode(qrCanonicalObjectString(identity.alias, edB64, xB64, ts, sig, crc));
  return QR_PAYLOAD_PREFIX + b64encode(object);
}

/* Trim the leading/trailing ASCII whitespace a human paste may carry
 * (§4.7: a scanner never adds whitespace; the paste box may). */
function qrTrimAscii(text) {
  if (typeof text !== "string") return text;
  return text.replace(/^[ \t\r\n\f\v]+/, "").replace(/[ \t\r\n\f\v]+$/, "");
}

/*
 * §4.7 importer rule (binding) — verify in THIS order, stopping at the
 * first failure and reporting its reason (the UI shows it verbatim; the §4.7
 * rejection is VISIBLE, unlike the §4.3 silent discard of envelope damage):
 *
 *   1. prefix          "OFFGRID1:" (§4.7 header)            → bad_prefix
 *   2. Base64          strict RFC 4648 with padding (§3.3)   → bad_base64
 *   3. JSON            UTF-8, single object                  → bad_json
 *   4. member set      exactly v, alias, ed, x, ts, sig, crc → bad_members
 *   5. v               MUST be 1 (unknown v = another spec)  → bad_version
 *   6. alias           §8.1 regex                            → bad_alias
 *   7. keys            ed/x: 44 Base64 chars, 32 raw bytes   → bad_key
 *   8. ts              integer > 0, ≤ now + 300 (§4.3 skew)  → bad_ts
 *   9. crc             8 lowercase hex == CRC-32 (step 0)    → bad_crc
 *  10. signature       88 Base64 chars, 64 bytes, verifies   → bad_signature
 *
 * On success the parsed contact {ed, x, alias, ts} is returned — the CALLER
 * persists it (store.saveContact with source "qr" | "paste"); a failed
 * parse never produces a contact (nothing is stored).
 */
function qrParsePayload(text, nowSec) {
  function fail(reason) { return { ok: false, reason: reason }; }
  var s = qrTrimAscii(text);
  if (typeof s !== "string" || s.length < QR_PAYLOAD_PREFIX.length ||
      s.slice(0, QR_PAYLOAD_PREFIX.length) !== QR_PAYLOAD_PREFIX) {
    return fail("bad_prefix");
  }
  var objectBytes = b64decode(s.slice(QR_PAYLOAD_PREFIX.length));
  if (!objectBytes) return fail("bad_base64");
  var object;
  try {
    object = JSON.parse(utf8Decode(objectBytes));
  } catch (e) {
    return fail("bad_json");
  }
  if (!object || typeof object !== "object" || Array.isArray(object)) return fail("bad_json");
  var members = ["v", "alias", "ed", "x", "ts", "sig", "crc"];
  if (Object.keys(object).length !== members.length) return fail("bad_members");
  for (var i = 0; i < members.length; i++) {
    if (!(members[i] in object)) return fail("bad_members");
  }
  if (object.v !== QR_PAYLOAD_VERSION) return fail("bad_version");
  if (!validateAlias(object.alias)) return fail("bad_alias");
  var edBytes = (typeof object.ed === "string" && object.ed.length === PUBKEY_B64_LEN) ? b64decode(object.ed) : null;
  var xBytes = (typeof object.x === "string" && object.x.length === PUBKEY_B64_LEN) ? b64decode(object.x) : null;
  if (!edBytes || edBytes.length !== 32 || !xBytes || xBytes.length !== 32) return fail("bad_key");
  if (typeof object.ts !== "number" || !isFinite(object.ts) ||
      Math.floor(object.ts) !== object.ts || object.ts <= 0) return fail("bad_ts");
  if (typeof nowSec === "number" && isFinite(nowSec) && object.ts > nowSec + QR_TS_SKEW_SECONDS) {
    return fail("bad_ts"); /* future-dated payload (§4.3 step 6 skew allowance) */
  }
  if (typeof object.crc !== "string" || !/^[0-9a-f]{8}$/.test(object.crc)) return fail("bad_crc");
  var canonical = utf8Encode(qrCanonicalPayloadString(object.alias, object.ed, object.x, object.ts));
  if (qrCrc32Hex(canonical) !== object.crc) return fail("bad_crc");
  var sigBytes = (typeof object.sig === "string" && object.sig.length === SIGNATURE_B64_LEN) ? b64decode(object.sig) : null;
  if (!sigBytes || sigBytes.length !== 64) return fail("bad_signature");
  var sigOk = false;
  try {
    sigOk = requireNacl().sign.detached.verify(canonical, sigBytes, edBytes);
  } catch (e) {
    sigOk = false;
  }
  if (!sigOk) return fail("bad_signature");
  return { ok: true, contact: { ed: object.ed, x: object.x, alias: object.alias, ts: object.ts } };
}

/*
 * The device-local contact record (§4.7): {ed, x, alias, added_at, source}
 * with `ed` the Ed25519 public key — the PRIMARY KEY of the `contacts`
 * store (identity = key; the alias is cosmetic, §4.7 trust model).
 * `source` is "qr" (camera scan) or "paste" (the universal fallback).
 */
function qrContactRecord(parsed, source, nowSec) {
  if (!parsed || !parsed.ok || !parsed.contact) throw new Error("qrContactRecord: a verified parse result is required");
  if (source !== "qr" && source !== "paste") throw new Error("qrContactRecord: source must be \"qr\" or \"paste\"");
  return {
    ed: parsed.contact.ed,
    x: parsed.contact.x,
    alias: parsed.contact.alias,
    added_at: assertInt(nowSec, "added_at"),
    source: source
  };
}

/*
 * §4.7 recipient merge (pure): local contacts ∪ directory entries, deduped
 * by the Ed25519 key. When BOTH exist for a key, the DIRECTORY entry
 * supplies the fresh key material — x25519, epoch (§6.1 hint addressing)
 * and prekeys (§4.6 bundles) — while the CONTACT's local alias wins as the
 * display label (the alias is cosmetic, §4.7 trust model). A contact
 * without a directory entry carries only {ed, x, alias}: the sender then
 * addresses the identity key with the §6.1 offline-cold static hint (no
 * epoch) and the §4.6 identity fallback (no bundle). Result sorted by
 * alias then ed (deterministic picker order); malformed rows skipped.
 */
function qrMergeRecipients(directory, contacts) {
  var dir = Array.isArray(directory) ? directory : [];
  var cont = Array.isArray(contacts) ? contacts : [];
  var byEd = {};
  var out = [];
  var i;
  for (i = 0; i < dir.length; i++) {
    var e = dir[i];
    if (!e || typeof e.pubkey !== "string" || !e.pubkey || typeof e.x25519 !== "string" || !e.x25519) continue;
    byEd[e.pubkey] = {
      ed: e.pubkey,
      pubkey: e.pubkey,
      alias: (typeof e.alias === "string") ? e.alias : "",
      x25519: e.x25519,
      last_seen: e.last_seen,
      epoch: e.epoch,
      prekeys: e.prekeys,
      in_directory: true,
      contact: false
    };
    out.push(byEd[e.pubkey]);
  }
  for (i = 0; i < cont.length; i++) {
    var c = cont[i];
    if (!c || typeof c.ed !== "string" || !c.ed || typeof c.x !== "string" || !c.x) continue;
    var merged = byEd[c.ed];
    if (merged) {
      merged.contact = true;
      if (c.alias) merged.alias = c.alias; /* local label wins; keys stay fresh (§4.7) */
    } else {
      merged = {
        ed: c.ed,
        pubkey: c.ed,
        alias: (typeof c.alias === "string") ? c.alias : "",
        x25519: c.x,
        last_seen: undefined,
        epoch: undefined,          /* §6.1: no server epoch → offline-cold static hint */
        prekeys: undefined,        /* §4.6: no bundle → identity-key addressing */
        in_directory: false,
        contact: true
      };
      byEd[c.ed] = merged;
      out.push(merged);
    }
  }
  out.sort(function (a, b) {
    if (a.alias !== b.alias) return a.alias < b.alias ? -1 : 1;
    if (a.ed !== b.ed) return a.ed < b.ed ? -1 : 1;
    return 0;
  });
  return out;
}

/* ---------------------------------------------------------------------
 * 5.1f QR matrix (vendored encoder → plain boolean matrix; ui.js paints
 *      the canvas).
 * ------------------------------------------------------------------- */

/*
 * Encode a payload text into a QR matrix with the VENDORED
 * qrcode-generator (js/vendor/qrcode.js, MIT): byte mode, ECC level M,
 * versions 1..QR_MAX_VERSION (§4.7 cap — the maximum identity payload
 * fits version 15). Returns {version, size, modules} with modules[r][c]
 * booleans (true = dark). The §4.7 payload is ASCII by construction
 * (alias §8.1-ASCII, Base64 keys, decimal integers, hex CRC, fixed JSON
 * scaffolding), so byte-mode encoding is exact; anything non-ASCII is a
 * programming error and throws. Throws "payload too large" beyond v15.
 */
function qrMakeMatrix(text) {
  if (typeof text !== "string" || /[^\x00-\x7f]/.test(text)) {
    throw new Error("qrMakeMatrix: the §4.7 payload is ASCII-only by construction");
  }
  var factory = (typeof qrcode !== "undefined") ? qrcode :
                (typeof self !== "undefined" && self.qrcode ? self.qrcode : null);
  if (!factory) throw new Error("vendored qrcode-generator is missing (js/vendor/qrcode.js)");
  var lastError = null;
  for (var v = 1; v <= QR_MAX_VERSION; v++) {
    try {
      var qr = factory(v, QR_ECC_LEVEL);
      qr.addData(text, "Byte");
      qr.make();
      var size = qr.getModuleCount();
      var modules = [];
      for (var r = 0; r < size; r++) {
        var row = [];
        for (var c = 0; c < size; c++) row.push(qr.isDark(r, c) === true);
        modules.push(row);
      }
      return { version: v, size: size, modules: modules };
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error("payload too large for QR version " + QR_MAX_VERSION + " (ECC " + QR_ECC_LEVEL + "): " +
                  (lastError && lastError.message ? lastError.message : "no version fits"));
}

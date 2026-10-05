/*
 * Off-grid DTN messaging SPA — canonical serialization (§5 — BINDING).
 * Part of the pure protocol engine (no DOM here).
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 4. Canonical serialization (§5 — BINDING).
 *    Member order is the FIXED order of the spec, not lexicographic.
 *    Strings are hand-built with minimal escaping (§5): \" \\ and
 *    U+0000–U+001F only; `/` is never escaped; non-ASCII goes out as raw
 *    UTF-8. Integers are validated before serialization (§3.3).
 * ------------------------------------------------------------------- */

function jsonEscapeString(s) {
  var out = '"';
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    var code = s.charCodeAt(i);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 8) out += "\\b";
    else if (code === 9) out += "\\t";
    else if (code === 10) out += "\\n";
    else if (code === 12) out += "\\f";
    else if (code === 13) out += "\\r";
    else if (code < 0x20) {
      var hex = code.toString(16);
      while (hex.length < 4) hex = "0" + hex;
      out += "\\u" + hex;
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function assertInt(n, name) {
  if (typeof n !== "number" || !isFinite(n) || Math.floor(n) !== n) {
    throw new Error(name + " must be a JSON integer (§3.3)");
  }
  return n;
}

/* §5.1 signed byte string: inner_json with the s member removed before
 * serialization, fixed key order m, a, k, t. */
function canonicalSignedString(m, a, k, t) {
  return '{"m":' + jsonEscapeString(m) +
         ',"a":' + jsonEscapeString(a) +
         ',"k":' + jsonEscapeString(k) +
         ',"t":' + String(assertInt(t, "t")) + "}";
}

/* §4.1 complete inner_json, fixed key order m, a, k, s, t. */
function canonicalInnerJson(m, a, k, s, t) {
  return '{"m":' + jsonEscapeString(m) +
         ',"a":' + jsonEscapeString(a) +
         ',"k":' + jsonEscapeString(k) +
         ',"s":' + jsonEscapeString(s) +
         ',"t":' + String(assertInt(t, "t")) + "}";
}

/* §4.4 signed byte string of a CHUNKED inner: the §5.1 form gains the
 * chunk-convention members in FIXED order w, g, i, n after t. Only
 * chunked messages use this form — a plain (flat) inner keeps the §5.1
 * string byte-identical to the pre-§4.4 construction (§4.4 binding). */
function canonicalChunkedSignedString(m, a, k, t, w, g, i, n) {
  return canonicalSignedString(m, a, k, t).slice(0, -1) +   /* drop the closing brace */
         ',"w":' + jsonEscapeString(w) +
         ',"g":' + jsonEscapeString(g) +
         ',"i":' + String(assertInt(i, "i")) +
         ',"n":' + String(assertInt(n, "n")) + "}";
}

/* §4.4 complete inner_json of a chunked message: §4.1 order m, a, k, s, t
 * followed by w, g, i, n (same fixed order as the signed string, with s
 * in its §4.1 position). */
function canonicalChunkedInnerJson(m, a, k, s, t, w, g, i, n) {
  return canonicalInnerJson(m, a, k, s, t).slice(0, -1) +   /* drop the closing brace */
         ',"w":' + jsonEscapeString(w) +
         ',"g":' + jsonEscapeString(g) +
         ',"i":' + String(assertInt(i, "i")) +
         ',"n":' + String(assertInt(n, "n")) + "}";
}

/* §5.2 hashed byte string for the envelope id, fixed key order v,
 * dest_hint, created_at, ttl, payload (id itself excluded). */
function canonicalEnvelopeString(v, destHint, createdAt, ttl, payload) {
  return '{"v":' + String(assertInt(v, "v")) +
         ',"dest_hint":' + jsonEscapeString(destHint) +
         ',"created_at":' + String(assertInt(createdAt, "created_at")) +
         ',"ttl":' + String(assertInt(ttl, "ttl")) +
         ',"payload":' + jsonEscapeString(payload) + "}";
}

function validateAlias(alias) {
  return typeof alias === "string" && ALIAS_REGEX.test(alias);
}

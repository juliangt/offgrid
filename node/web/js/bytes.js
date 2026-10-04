/*
 * Off-grid DTN messaging SPA — byte helpers: UTF-8, Base64 (§3.3), hex,
 * randomness (§7.2). Part of the pure protocol engine (no DOM here).
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 2. Byte helpers: UTF-8, Base64 (§3.3), hex, randomness (§7.2)
 * ------------------------------------------------------------------- */

/* UTF-8 encode with TextEncoder semantics: lone surrogates become
 * U+FFFD. Hand-rolled (instead of TextEncoder) because the captive
 * mini-browsers this SPA targets may not provide it. */
function utf8Encode(str) {
  var bytes = [];
  var i = 0;
  while (i < str.length) {
    var c1 = str.charCodeAt(i);
    var code;
    if (c1 >= 0xd800 && c1 <= 0xdbff && i + 1 < str.length) {
      var c2 = str.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        code = 0x10000 + ((c1 - 0xd800) << 10) + (c2 - 0xdc00);
        i += 2;
      } else {
        code = 0xfffd; /* lone high surrogate */
        i += 1;
      }
    } else if (c1 >= 0xd800 && c1 <= 0xdfff) {
      code = 0xfffd; /* lone low surrogate */
      i += 1;
    } else {
      code = c1;
      i += 1;
    }
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 63));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    } else {
      bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    }
  }
  return new Uint8Array(bytes);
}

/* UTF-8 decode; malformed sequences become U+FFFD. Only ever used on
 * bytes we produced ourselves (MAC-verified inner payloads). */
function utf8Decode(bytes) {
  var out = "";
  var i = 0;
  while (i < bytes.length) {
    var b = bytes[i];
    var code;
    if (b < 0x80) {
      code = b;
      i += 1;
    } else if ((b & 0xe0) === 0xc0 && i + 1 < bytes.length) {
      code = ((b & 31) << 6) | (bytes[i + 1] & 63);
      i += 2;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < bytes.length) {
      code = ((b & 15) << 12) | ((bytes[i + 1] & 63) << 6) | (bytes[i + 2] & 63);
      i += 3;
    } else if ((b & 0xf8) === 0xf0 && i + 3 < bytes.length) {
      code = ((b & 7) << 18) | ((bytes[i + 1] & 63) << 12) | ((bytes[i + 2] & 63) << 6) | (bytes[i + 3] & 63);
      i += 4;
    } else {
      code = 0xfffd; /* truncated or invalid lead byte */
      i += 1;
    }
    if (code >= 0x10000) {
      code -= 0x10000;
      out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      out += String.fromCharCode(code);
    }
  }
  return out;
}

/* UTF-8 byte length of a string (the §8.1 counter is bytes, not chars). */
function messageByteLength(str) {
  return utf8Encode(String(str)).length;
}

/* Base64, RFC 4648 standard alphabet with padding (§3.3 — Base64url is
 * invalid). Encoding always pads; decoding is strict and returns null on
 * any malformed input instead of throwing. */
var B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var B64_REVERSE = (function () {
  var t = {};
  for (var i = 0; i < B64_ALPHABET.length; i++) t[B64_ALPHABET.charAt(i)] = i;
  return t;
})();

function b64encode(bytes) {
  var out = [];
  var len = bytes.length;
  for (var i = 0; i < len; i += 3) {
    var b0 = bytes[i];
    var has1 = i + 1 < len;
    var has2 = i + 2 < len;
    var b1 = has1 ? bytes[i + 1] : 0;
    var b2 = has2 ? bytes[i + 2] : 0;
    out.push(B64_ALPHABET.charAt(b0 >> 2));
    out.push(B64_ALPHABET.charAt(((b0 & 3) << 4) | (b1 >> 4)));
    out.push(has1 ? B64_ALPHABET.charAt(((b1 & 15) << 2) | (b2 >> 6)) : "=");
    out.push(has2 ? B64_ALPHABET.charAt(b2 & 63) : "=");
  }
  return out.join("");
}

function b64decode(str) {
  if (typeof str !== "string" || str.length % 4 !== 0) return null;
  if (str.length === 0) return new Uint8Array(0); /* valid Base64 of the empty byte string */
  var pad = 0;
  if (str.charAt(str.length - 1) === "=") pad += 1;
  if (str.charAt(str.length - 2) === "=") pad += 1;
  if (pad === 2 && str.charAt(str.length - 3) === "=") return null; /* "===" is never valid */
  var outLen = (str.length >> 2) * 3 - pad;
  if (outLen < 0) return null;
  var out = new Uint8Array(outLen);
  var o = 0;
  var chunks = str.length >> 2;
  for (var c = 0; c < chunks; c++) {
    var n = 0;
    var last = c === chunks - 1;
    var padHere = last ? pad : 0;
    for (var j = 0; j < 4 - padHere; j++) {
      var v = B64_REVERSE[str.charAt(c * 4 + j)];
      if (v === undefined) return null; /* invalid character (includes Base64url) */
      n = (n << 6) | v;
    }
    n = n << (6 * padHere); /* align remaining bytes */
    if (o < outLen) out[o++] = (n >> 16) & 0xff;
    if (o < outLen) out[o++] = (n >> 8) & 0xff;
    if (o < outLen) out[o++] = n & 0xff;
  }
  return out;
}

/* Lowercase hex (§3.3). hexDecode is strict lowercase and returns null on
 * any malformed input. */
var HEX_DIGITS = "0123456789abcdef";

function hexEncode(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    out += HEX_DIGITS.charAt(bytes[i] >> 4);
    out += HEX_DIGITS.charAt(bytes[i] & 15);
  }
  return out;
}

function hexDecode(str) {
  if (typeof str !== "string" || str.length === 0 || str.length % 2 !== 0) return null;
  var out = new Uint8Array(str.length >> 1);
  for (var i = 0; i < str.length; i++) {
    var hi = HEX_DIGITS.indexOf(str.charAt(i));
    if (hi < 0) return null;
    var lo = HEX_DIGITS.indexOf(str.charAt(i + 1));
    if (lo < 0) return null;
    out[i >> 1] = (hi << 4) | lo;
    i += 1;
  }
  return out;
}

var HEX64_REGEX = /^[0-9a-f]{64}$/;   /* envelope id (§3.1) */
var HEX16_REGEX = /^[0-9a-f]{16}$/;   /* dest_hint (§3.1) */

/* All entropy comes from crypto.getRandomValues (§7.2). Throws when the
 * runtime offers no PRNG rather than falling back to something weaker. */
function randomBytes(n) {
  var source = null;
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    source = crypto;
  } else if (typeof self !== "undefined" && self.crypto && self.crypto.getRandomValues) {
    source = self.crypto;
  }
  if (!source) throw new Error("no PRNG available (crypto.getRandomValues)");
  var out = new Uint8Array(n);
  source.getRandomValues(out);
  return out;
}

function concatBytes() {
  var total = 0;
  var i;
  for (i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total);
  var off = 0;
  for (i = 0; i < arguments.length; i++) {
    out.set(arguments[i], off);
    off += arguments[i].length;
  }
  return out;
}

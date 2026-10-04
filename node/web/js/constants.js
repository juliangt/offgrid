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
var MESSAGE_MAX_BYTES = 128;                   // plaintext limit, UTF-8 bytes
var ALIAS_REGEX = /^[A-Za-z0-9_.-]{1,24}$/;    // sender alias (§4.1)
var PAYLOAD_MIN_BYTES = 248;                   // derived bounds (§8.2)
var PAYLOAD_MAX_BYTES = 400;
var PUBKEY_B64_LEN = 44;                       // 32 raw bytes (§4.1)
var SIGNATURE_B64_LEN = 88;                    // 64 raw bytes (§4.1)
var CANONICAL_HOST = "offgrid.local:8080";  // same origin on every node (§12)
var CANONICAL_URL = "http://" + CANONICAL_HOST;

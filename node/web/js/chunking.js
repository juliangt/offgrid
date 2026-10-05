/*
 * Off-grid DTN messaging SPA — long-message chunking (§4.4), both sides:
 *
 *   sender   : split a long text into equal-ish code-point-aligned chunks
 *              of at most MESSAGE_MAX_BYTES (128) UTF-8 bytes and emit one
 *              ordinary envelope per chunk (same created_at and ttl — no
 *              per-chunk TTL games, §4.4);
 *   recipient: pure reassembly state machine over the group id `g` —
 *              out-of-order arrival, duplicate chunks and partial expiry.
 *
 * Everything here is pure and DOM-free; the persistence lives in store.js
 * (inbox_parts) and the wiring in ui.js. Part of the pure protocol engine.
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * Sender side: splitting (§4.4).
 * ------------------------------------------------------------------- */

/* Greedy pack of `text` into chunks of at most `capBytes` UTF-8 bytes,
 * never splitting a code point (surrogate pairs travel together). Greedy
 * packing at a fixed cap yields the minimal number of pieces for a
 * sequence of indivisible items. */
function chunkPackCapped(text, capBytes) {
  var chunks = [];
  var cur = "";
  var curBytes = 0;
  var i = 0;
  while (i < text.length) {
    var unit = 1;
    var c1 = text.charCodeAt(i);
    if (c1 >= 0xd800 && c1 <= 0xdbff && i + 1 < text.length) {
      var c2 = text.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) unit = 2;   /* one code point = one surrogate pair */
    }
    var piece = text.substr(i, unit);
    var pieceBytes = messageByteLength(piece);
    if (curBytes > 0 && curBytes + pieceBytes > capBytes) {
      chunks.push(cur);
      cur = piece;
      curBytes = pieceBytes;
    } else {
      cur += piece;
      curBytes += pieceBytes;
    }
    i += unit;
  }
  if (cur !== "" || chunks.length === 0) chunks.push(cur);
  return chunks;
}

/*
 * §4.4 per-chunk text budget for a sender: a chunked inner carries the
 * signed metadata (w, g, i, n — worst case CHUNK_META_MAX_BYTES = 58 bytes
 * of inner_json), and the §8.2 envelope bound still binds per envelope:
 *
 *   inner = 176 + M + A + 58   →   payload = 248 + M + A + 58 ≤ 400
 *   ⇔ M + A ≤ CHUNK_TEXT_PLUS_ALIAS_LIMIT (= 94)
 *
 * so the chunks are packed at 94 - |alias| bytes of text each — always
 * below the §8.1 128-byte plaintext limit, and every emitted envelope
 * stays within the §8.2 decoded-payload bounds [248, 400] (the node would
 * reject anything else, §10.5). The alias is ASCII-only (§4.1 regex), so
 * its byte length is its character length; an invalid alias falls back to
 * the 24-char maximum (most conservative budget).
 */
function chunkTextBudget(alias) {
  var aBytes = 24; /* ALIAS_REGEX max: most conservative fallback */
  if (validateAlias(alias) && messageByteLength(alias) <= 24) aBytes = messageByteLength(alias);
  var budget = CHUNK_TEXT_PLUS_ALIAS_LIMIT - aBytes;
  return budget >= 1 ? budget : 1;
}

/*
 * §4.4 splitting rule: split `text` into equal-ish chunks of at most the
 * sender's §4.4 budget (94 - |alias|, see chunkTextBudget) UTF-8 bytes
 * each — every chunk also respects the §8.1 128-byte limit with room to
 * spare — never splitting a code point. The count starts at the byte
 * lower bound ceil(total / budget) and grows to the fixed point of the
 * equal-ish retargeting (a chunk boundary can lose up to 3 bytes to a
 * code point that does not fit, so the lower bound is not always
 * achievable — e.g. 33 emoji = 132 B need 3 chunks of 11, not 2). Returns
 * [] when the text is empty or would need more than CHUNK_MAX_PARTS
 * envelopes — the sender must refuse it (§4.4 cap). A text that already
 * fits in one envelope comes back unsplit: the flat §4.1 inner is used,
 * byte-identical to the pre-§4.4 construction.
 */
function chunkSplitText(text, alias) {
  if (typeof text !== "string" || text.length === 0) return [];
  var total = messageByteLength(text);
  if (total <= MESSAGE_MAX_BYTES) return [text];
  var budget = chunkTextBudget(alias);
  var n = Math.ceil(total / budget);
  if (n > CHUNK_MAX_PARTS) return [];
  var chunks = [];
  /* Each pass either fixes n or strictly grows it; the guard bounds the
   * loop and makes the > CHUNK_MAX_PARTS bail the only exit for texts
   * whose code-point layout defeats the cap. */
  for (var guard = 0; guard <= CHUNK_MAX_PARTS + 1; guard++) {
    chunks = chunkPackCapped(text, Math.ceil(total / n));
    if (chunks.length === n || chunks.length > CHUNK_MAX_PARTS) break;
    n = chunks.length;
  }
  if (chunks.length > CHUNK_MAX_PARTS || chunks.length < 1) return [];
  return chunks;
}

/* Number of envelopes a text will cost (§4.4 preview): 0 means the text
 * cannot be sent (empty, or it would exceed the CHUNK_MAX_PARTS cap). */
function chunkPlannedCount(text, alias) {
  return chunkSplitText(text, alias).length;
}

/* Composer byte ceiling for a sender: the longest text that still fits
 * CHUNK_MAX_PARTS envelopes under the §4.4 budget (the binding cap is the
 * envelope count; this byte figure is its alias-dependent consequence). */
function chunkComposerLimit(alias) {
  return CHUNK_MAX_PARTS * chunkTextBudget(alias);
}

/*
 * §4.4 sender: build ALL envelopes of one message.
 *   - total ≤ 128 B: exactly one flat envelope (opts pass straight to
 *     buildEnvelope — the §5.1 signed string is the pre-§4.4 one);
 *   - longer: chunkSplitText, one shared random 16-byte message id `g`
 *     (Base64), one envelope per chunk with chunk {g, i, n}. Every
 *     envelope gets the SAME created_at and ttl (§4.4: no life extension
 *     for any chunk), so each one is an ordinary §3.1 envelope.
 * Returns the array of envelopes in chunk order; throws when the message
 * cannot be sent under the §4.4 cap.
 */
function buildMessageEnvelopes(opts) {
  if (!opts || typeof opts !== "object") throw new Error("buildMessageEnvelopes: options required");
  var text = typeof opts.message === "string" ? opts.message : "";
  var chunks = chunkSplitText(text, opts.alias);
  if (chunks.length === 0) {
    throw new Error("message is empty or would need more than " + CHUNK_MAX_PARTS +
                    " envelopes (§4.4 cap)");
  }
  if (chunks.length === 1) {
    return [buildEnvelope(opts)];
  }
  var g = b64encode(randomBytes(CHUNK_G_BYTES));
  var out = [];
  for (var i = 0; i < chunks.length; i++) {
    out.push(buildEnvelope({
      recipientBoxPublic: opts.recipientBoxPublic,
      message: chunks[i],
      alias: opts.alias,
      signSecret: opts.signSecret,
      signPublic: opts.signPublic,
      createdAt: opts.createdAt,
      ttl: opts.ttl,
      chunk: { g: g, i: i, n: chunks.length }
    }));
  }
  return out;
}

/* ---------------------------------------------------------------------
 * Recipient side: pure reassembly state (§4.4).
 *
 * A partial state is one inbox_parts record:
 *   { g, n, a, k, t, created_at, ttl, received_at, parts: { "<i>": {m, id} } }
 * `created_at`/`ttl` come from the (shared) envelope fields, so the
 * partial expires exactly when its chunks expire (§4.4: aligned expiry).
 * `k` is the sender's Ed25519 public key (§4.1 inner field, additive
 * since §4.5): the ack emitted at reassembly completion (§4.5) resolves
 * the sender's X25519 key from it via the directory. Partials persisted
 * before §4.5 carry no `k` — their completion emits no ack (best-effort).
 * ------------------------------------------------------------------- */

function chunkNewState(g, n, a, t, createdAt, ttl, receivedAt, k) {
  return { g: g, n: n, a: a, k: k, t: t, created_at: createdAt, ttl: ttl,
           received_at: receivedAt, parts: {} };
}

/* Merge one decrypted chunk into `state`; returns a NEW state (the input
 * is never mutated). First write per index wins: a re-delivered chunk
 * (a duplicate that slipped past upstream envelope-id dedup) is a no-op,
 * and a conflicting re-send of an index cannot rewrite held text. */
function chunkStateWithPart(state, i, m, envId) {
  var parts = {};
  for (var k in state.parts) {
    if (Object.prototype.hasOwnProperty.call(state.parts, k)) parts[k] = state.parts[k];
  }
  var key = String(i);
  if (!Object.prototype.hasOwnProperty.call(parts, key)) {
    parts[key] = { m: m, id: envId };
  }
  var out = {};
  for (var f in state) {
    if (Object.prototype.hasOwnProperty.call(state, f)) out[f] = state[f];
  }
  out.parts = parts;
  return out;
}

/* How many of the n chunks are held. */
function chunkStateHave(state) {
  var count = 0;
  for (var k in state.parts) {
    if (Object.prototype.hasOwnProperty.call(state.parts, k)) count += 1;
  }
  return count;
}

function chunkStateComplete(state) {
  return chunkStateHave(state) === state.n;
}

/* Full text = chunk texts concatenated in index order (never the arrival
 * order). Only meaningful once chunkStateComplete(state) holds. */
function chunkStateText(state) {
  var idxs = [];
  for (var k in state.parts) {
    if (Object.prototype.hasOwnProperty.call(state.parts, k)) idxs.push(parseInt(k, 10));
  }
  idxs.sort(function (x, y) { return x - y; });
  var text = "";
  for (var j = 0; j < idxs.length; j++) {
    text += state.parts[String(idxs[j])].m;
  }
  return text;
}

/* §4.4 partial expiry: aligned with the chunks' own TTL deadline — the
 * same inclusive-servable / exclusive-expired boundary the node uses
 * (§10.4/§10.6). A partial is swept strictly after created_at + ttl. */
function chunkStateExpired(state, nowSec) {
  return state.created_at + state.ttl < nowSec;
}

/* The inbox record of a completed message. Its storage id is derived from
 * the group id ("g:" + g), NOT from any single envelope id: the row
 * represents all n envelopes, and every chunk envelope id is already in
 * seen_ids (§11 known_ids composition), so the synthetic id never has to
 * stand in for an envelope. */
function chunkInboxRecord(state) {
  return {
    id: "g:" + state.g,
    m: chunkStateText(state),
    a: state.a,
    t: state.t,
    received_at: state.received_at,
    g: state.g,
    parts: state.n
  };
}

/*
 * Off-grid DTN messaging SPA — pure mule logic: classification (§11),
 * FIFO eviction (§8.1) and the §15 versioning policy (blind v1→v2
 * conversion, capabilities negotiation, outgoing batch gate). Part of
 * the pure protocol engine (no DOM).
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 6. Pure mule logic: classification (§11) and FIFO eviction (§8.1).
 * ------------------------------------------------------------------- */

/* Split pulled envelopes into mine (dest_hint matches own hint) and
 * foreign (to be carried). Order is preserved. */
function classifyPullEnvelopes(pulled, ownHint) {
  var mine = [];
  var foreign = [];
  for (var i = 0; i < pulled.length; i++) {
    var env = pulled[i];
    if (env && env.dest_hint === ownHint) mine.push(env);
    else foreign.push(env);
  }
  return { mine: mine, foreign: foreign };
}

/* Transit capacity is 100 with FIFO eviction by created_at (§8.1): the
 * oldest envelopes are evicted first. Ties break on id for determinism.
 * Returns {kept, evicted}; `kept` preserves the input order. */
function evictTransitQueue(queue, capacity) {
  var cap = capacity || TRANSIT_CAPACITY;
  if (queue.length <= cap) return { kept: queue.slice(), evicted: [] };
  var byAge = queue.slice().sort(function (x, y) {
    if (x.created_at !== y.created_at) return x.created_at - y.created_at;
    return x.id < y.id ? -1 : (x.id > y.id ? 1 : 0);
  });
  var evictSet = {};
  for (var i = 0; i < byAge.length - cap; i++) evictSet[byAge[i].id] = true;
  var kept = [];
  var evicted = [];
  for (var j = 0; j < queue.length; j++) {
    if (evictSet[queue[j].id]) evicted.push(queue[j]);
    else kept.push(queue[j]);
  }
  return { kept: kept, evicted: evicted };
}

/* ---------------------------------------------------------------------
 * 6.1 Versioned envelopes (§15): blind v1→v2 conversion, capabilities
 *     negotiation and the outgoing batch gate. Pure and DOM-free: the
 *     sync loop (ui.js) only wires these to the HTTP cycle.
 * ------------------------------------------------------------------- */

/* §15.1 blind v1→v2 transform: set v = 2, set meta.orig_v = 1, leave
 * every other member value-identical (payload untouched bit-for-bit —
 * §15.7 d; ttl/created_at never refreshed — §15.7 e). `meta` is outside
 * all cryptographic scope (excluded from the §5.2 hashed string), so
 * `id` is COPIED, never recomputed: it was computed once at creation
 * over the core fields and conversion MUST NOT change it (§15.1 id
 * stability — what makes node dedup version-agnostic).
 * Returns a NEW object; the input is never mutated, so the stored v1
 * form stays intact and the conversion stays invertible by construction
 * (set v = 1, drop meta — §15.6). Only v == 1 is accepted: anything else
 * returns null (never convert downward or upward, so double conversion
 * is impossible). */
function convertEnvelopeV1toV2(env) {
  if (!env || typeof env !== "object" || env.v !== 1) return null;
  return {
    v: 2,
    id: env.id,
    dest_hint: env.dest_hint,
    created_at: env.created_at,
    ttl: env.ttl,
    payload: env.payload,
    meta: { orig_v: 1 }
  };
}

/* §15.5 capabilities document → the negotiation ceiling the mule acts on
 * (max_envelope_version). Well-formed means: `envelope_versions` is a
 * non-empty array of distinct ascending integers and the derived members
 * agree (min = first, max = last). Unknown members are ignored (§15.4);
 * anything malformed, missing or mistyped → null, which the caller must
 * treat as "push the original, unconverted form" (§15.5 fallback). */
function maxAdvertisedEnvelopeVersion(capabilities) {
  if (!capabilities || typeof capabilities !== "object" || Array.isArray(capabilities)) return null;
  var versions = capabilities.envelope_versions;
  if (!Array.isArray(versions) || versions.length < 1) return null;
  var min = capabilities.min_envelope_version;
  var max = capabilities.max_envelope_version;
  if (typeof min !== "number" || !isFinite(min) || Math.floor(min) !== min) return null;
  if (typeof max !== "number" || !isFinite(max) || Math.floor(max) !== max) return null;
  if (min !== versions[0] || max !== versions[versions.length - 1]) return null;
  for (var i = 0; i < versions.length; i++) {
    var v = versions[i];
    if (typeof v !== "number" || !isFinite(v) || Math.floor(v) !== v) return null;
    if (i > 0 && v <= versions[i - 1]) return null; /* strictly ascending, no duplicates */
  }
  return max;
}

/* §15.6 outgoing batch gate — negotiation + conversion, pure. For each
 * envelope of the outgoing sync batch:
 *   - maxV == null (capabilities unobtainable, §15.5) or the envelope is
 *     already at/below the ceiling: the ORIGINAL, unconverted form goes
 *     out — syncing is never blocked by capabilities;
 *   - env.v > maxV: WITHHELD — the caller keeps it in transit_queue;
 *     never dropped, never converted downward (§15.6);
 *   - env.v === 1 with maxV >= 2: the CONVERTED v2 copy goes out
 *     (§15.1 blind transform).
 * Returns {batch, withheld}. The input array and its envelopes are never
 * mutated: conversion applies only to the outgoing copy, while the stored
 * record keeps its original version — that is what makes the conversion
 * invertible and dedup-safe (ids are stable under conversion, §15.1). */
function prepareOutgoingBatch(envelopes, maxV) {
  if (typeof maxV !== "number" || !isFinite(maxV) || Math.floor(maxV) !== maxV) maxV = null;
  var list = envelopes || [];
  var batch = [];
  var withheld = [];
  for (var i = 0; i < list.length; i++) {
    var env = list[i];
    if (!env || (maxV !== null && typeof env.v === "number" && env.v > maxV)) {
      withheld.push(env);
      continue;
    }
    if (env.v === 1 && maxV >= 2) batch.push(convertEnvelopeV1toV2(env));
    else batch.push(env);
  }
  return { batch: batch, withheld: withheld };
}

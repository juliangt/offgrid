/*
 * Off-grid DTN messaging SPA — pure mule logic: classification (§11)
 * and FIFO eviction (§8.1). Part of the pure protocol engine (no DOM).
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

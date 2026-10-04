/*
 * Off-grid DTN messaging SPA — local store, IndexedDB
 * "dtn_local_store" v1 (§11, §15.6). Extends the DTN export with the
 * persistence API; no DOM here, so the store stays usable headless.
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 8. Local store — IndexedDB "dtn_local_store" v1 (§11, plan 2.3).
 *    Stores:
 *      identity      singleton under the fixed key "identity" (seed+keys)
 *      inbox         decrypted own messages, keyed by envelope id
 *      transit_queue foreign envelopes being carried, keyed by envelope id
 *      seen_ids      dedup memory of every envelope id ever pulled or
 *                    pushed, so known_ids = inbox ∪ transit ∪ seen (§11)
 *      meta          key/value state: last sync, sent/evicted counters
 *    Schema migrations are the explicit migrations chain of §15.6 (the
 *    client-side analogue of the node's forward-only SQLite chain,
 *    §15.3): IDB_MIGRATIONS holds one {version, migrate} step per schema
 *    version, applied in ascending order by runIdbMigrations inside
 *    idbOpen's onupgradeneeded. All helpers are Promise-wrapped and only
 *    touch the indexedDB global when called (Node headless runs never
 *    call them).
 * ------------------------------------------------------------------- */
var DB_NAME = "dtn_local_store";
var DB_VERSION = 1;
var STORE_IDENTITY = "identity";
var STORE_INBOX = "inbox";
var STORE_TRANSIT = "transit_queue";
var STORE_SEEN = "seen_ids";
var STORE_META = "meta";
var IDENTITY_KEY = "identity";

/* ---------------------------------------------------------------------
 * Migrations chain (§15.6 — normative, mirrors the node's §15.3 chain):
 * one entry per schema version, strictly ascending, each migrating FROM
 * the previous version TO `version`. The chain is:
 *   - additive-only: a step only CREATEs stores/indexes; it never
 *     mutates or deletes existing records (§15.6);
 *   - idempotent: runIdbMigrations gates every step on the database's
 *     current version, so each step runs at most once per database and
 *     a re-open at DB_VERSION runs none;
 *   - forward-only: version N+1 is a delta from N only (§15.6). Future
 *     schema changes APPEND one step and bump DB_VERSION by one — no
 *     artificial bumps, never rewrite history.
 * IndexedDB runs the whole chain inside the versionchange upgrade
 * transaction, so a crash mid-chain leaves a consistent prefix and the
 * next open resumes from the database version — the exact analogue of
 * the node's per-step transaction (§15.3).
 * ------------------------------------------------------------------- */
var IDB_MIGRATIONS = [
  {
    version: 1,
    /* v1 initial schema (§11): the five stores of the mule. */
    migrate: function (db) {
      db.createObjectStore(STORE_IDENTITY);                      /* out-of-line keys */
      db.createObjectStore(STORE_INBOX, { keyPath: "id" });
      db.createObjectStore(STORE_TRANSIT, { keyPath: "id" });
      db.createObjectStore(STORE_SEEN);                          /* key = envelope id */
      db.createObjectStore(STORE_META);                          /* key = state name */
    }
  }
  /* Future versions append here, e.g. (never added speculatively):
   * { version: 2, migrate: function (db) { db.createObjectStore(...) } }
   */
];

/* §15.6 chain runner: apply, in ascending order, every step newer than
 * the database's current version (`e.oldVersion`; 0 for a fresh
 * database). Each step therefore runs at most once per database. */
function runIdbMigrations(db, oldVersion) {
  for (var i = 0; i < IDB_MIGRATIONS.length; i++) {
    if (IDB_MIGRATIONS[i].version > oldVersion) IDB_MIGRATIONS[i].migrate(db);
  }
}

function idbOpen() {
  return new Promise(function (resolve, reject) {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is not available in this browser"));
      return;
    }
    var req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = function (e) {
      runIdbMigrations(e.target.result, e.oldVersion);
    };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error || new Error("no se pudo abrir IndexedDB")); };
    req.onblocked = function () { reject(new Error("IndexedDB blocked by another tab")); };
  });
}

/* Cached connection; a failed open resets the cache so a retry can work. */
var dbPromise = null;
function getDB() {
  if (!dbPromise) {
    dbPromise = idbOpen().then(null, function (err) {
      dbPromise = null;
      throw err;
    });
  }
  return dbPromise;
}

/* Run fn(store) inside a fresh transaction and settle with the tx. */
function withStore(storeName, mode, fn) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, mode);
      var result;
      try {
        result = fn(tx.objectStore(storeName));
      } catch (e) {
        reject(e);
        return;
      }
      tx.oncomplete = function () { resolve(result); };
      tx.onerror = function () { reject(tx.error || new Error("transaction failed")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* Read every value of a store through a cursor (works on old WebViews
 * that lack getAll). */
function storeGetAll(storeName) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var out = [];
      var tx = db.transaction(storeName, "readonly");
      var req = tx.objectStore(storeName).openCursor();
      req.onsuccess = function (e) {
        var cursor = e.target.result;
        if (cursor) {
          out.push(cursor.value);
          cursor.continue();
        }
      };
      tx.oncomplete = function () { resolve(out); };
      tx.onerror = function () { reject(tx.error || new Error("lectura fallida")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* Read every key of a store through a cursor. */
function storeGetAllKeys(storeName) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var out = [];
      var tx = db.transaction(storeName, "readonly");
      var req = tx.objectStore(storeName).openCursor();
      req.onsuccess = function (e) {
        var cursor = e.target.result;
        if (cursor) {
          out.push(cursor.key);
          cursor.continue();
        }
      };
      tx.oncomplete = function () { resolve(out); };
      tx.onerror = function () { reject(tx.error || new Error("lectura fallida")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

function storePut(storeName, value, key) {
  return withStore(storeName, "readwrite", function (store) {
    if (key === undefined) store.put(value);
    else store.put(value, key);
    return key === undefined ? value : key;
  });
}

/* Single-request read helpers: the promise must settle with the request's
 * RESULT (not the request object), so these get their own wrappers instead
 * of withStore (whose resolution value is the fn(store) return). */
function storeGet(storeName, key) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, "readonly");
      var req = tx.objectStore(storeName).get(key);
      req.onsuccess = function () { resolve(req.result); };
      tx.oncomplete = function () { /* settled by req.onsuccess */ };
      tx.onerror = function () { reject(tx.error || new Error("lectura fallida")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

function storeCount(storeName) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, "readonly");
      var req = tx.objectStore(storeName).count();
      req.onsuccess = function () { resolve(req.result); };
      tx.oncomplete = function () { /* settled by req.onsuccess */ };
      tx.onerror = function () { reject(tx.error || new Error("lectura fallida")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* ----- identity (singleton) ----- */

function loadIdentity() {
  return storeGet(STORE_IDENTITY, IDENTITY_KEY);
}

function saveIdentity(identity) {
  return storePut(STORE_IDENTITY, identity, IDENTITY_KEY);
}

/* ----- inbox ----- */

function addInboxMessages(records) {
  if (!records.length) return Promise.resolve(0);
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_INBOX, "readwrite");
      var store = tx.objectStore(STORE_INBOX);
      for (var i = 0; i < records.length; i++) store.put(records[i]);
      tx.oncomplete = function () { resolve(records.length); };
      tx.onerror = function () { reject(tx.error || new Error("could not save the message")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* Inbox rows, newest first by sender timestamp (§4.1: t orders display). */
function listInbox() {
  return storeGetAll(STORE_INBOX).then(function (rows) {
    rows.sort(function (x, y) {
      return (y.t - x.t) || (y.received_at - x.received_at);
    });
    return rows;
  });
}

/* ----- transit_queue (mule cargo, §2/§11) ----- */

/* Keep exactly the six §3.1 wire fields when pushing a carried record. */
function toEnvelopeWire(rec) {
  return {
    v: rec.v,
    id: rec.id,
    dest_hint: rec.dest_hint,
    created_at: rec.created_at,
    ttl: rec.ttl,
    payload: rec.payload
  };
}

function transitRecordOf(env, nowSec) {
  if (!validEnvelopeShape(env)) return null;
  return {
    v: env.v,
    id: env.id,
    dest_hint: env.dest_hint,
    created_at: env.created_at,
    ttl: env.ttl,
    payload: env.payload,
    added_at: nowSec
  };
}

/* Merge pulled envelopes into the transit queue inside one readwrite
 * transaction, applying the §8.1 FIFO eviction at capacity 100. Duplicates
 * (already-carried ids) are skipped. Resolves {added, evicted}. */
function addTransitEnvelopes(envelopes) {
  if (!envelopes || !envelopes.length) return Promise.resolve({ added: 0, evicted: [] });
  var nowSec = Math.floor(Date.now() / 1000);
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_TRANSIT, "readwrite");
      var store = tx.objectStore(STORE_TRANSIT);
      var existing = [];
      var added = 0;
      var evicted = [];
      var cursorReq = store.openCursor();
      cursorReq.onsuccess = function (e) {
        var cursor = e.target.result;
        if (cursor) {
          existing.push(cursor.value);
          cursor.continue();
          return;
        }
        /* Cursor exhausted; the transaction is still open, so merge, evict
         * and write back within this same callback. */
        var byId = {};
        for (var i = 0; i < existing.length; i++) byId[existing[i].id] = existing[i];
        for (var j = 0; j < envelopes.length; j++) {
          var rec = transitRecordOf(envelopes[j], nowSec);
          if (rec && !byId[rec.id]) {
            byId[rec.id] = rec;
            added += 1;
          }
        }
        var merged = [];
        for (var key in byId) {
          if (Object.prototype.hasOwnProperty.call(byId, key)) merged.push(byId[key]);
        }
        var outcome = evictTransitQueue(merged, TRANSIT_CAPACITY);
        evicted = outcome.evicted;
        for (var k = 0; k < outcome.kept.length; k++) store.put(outcome.kept[k]);
        for (var m = 0; m < outcome.evicted.length; m++) store.delete(outcome.evicted[m].id);
      };
      tx.oncomplete = function () { resolve({ added: added, evicted: evicted }); };
      tx.onerror = function () { reject(tx.error || new Error("could not update the transit queue")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

function listTransit() {
  return storeGetAll(STORE_TRANSIT);
}

function removeTransitIds(ids) {
  if (!ids || !ids.length) return Promise.resolve(0);
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_TRANSIT, "readwrite");
      var store = tx.objectStore(STORE_TRANSIT);
      for (var i = 0; i < ids.length; i++) store.delete(ids[i]);
      tx.oncomplete = function () { resolve(ids.length); };
      tx.onerror = function () { reject(tx.error || new Error("could not clear the transit queue")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* ----- seen_ids: permanent dedup memory (§11 known_ids composition) ----- */

function markSeenIds(ids) {
  if (!ids || !ids.length) return Promise.resolve(0);
  var seenAt = Math.floor(Date.now() / 1000);
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_SEEN, "readwrite");
      var store = tx.objectStore(STORE_SEEN);
      for (var i = 0; i < ids.length; i++) {
        if (typeof ids[i] === "string" && ids[i]) store.put({ id: ids[i], seen_at: seenAt }, ids[i]);
      }
      tx.oncomplete = function () { resolve(ids.length); };
      tx.onerror = function () { reject(tx.error || new Error("could not mark the envelope as seen")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

function listSeenIds() {
  return storeGetAllKeys(STORE_SEEN);
}

/* ----- meta: last sync state and counters ----- */

function getMeta(key) {
  return storeGet(STORE_META, key);
}

function setMeta(key, value) {
  return storePut(STORE_META, value, key);
}

DTN.loadIdentity = loadIdentity;
DTN.saveIdentity = saveIdentity;
DTN.addInboxMessages = addInboxMessages;
DTN.listInbox = listInbox;
DTN.addTransitEnvelopes = addTransitEnvelopes;
DTN.listTransit = listTransit;
DTN.removeTransitIds = removeTransitIds;
DTN.markSeenIds = markSeenIds;
DTN.listSeenIds = listSeenIds;
DTN.getMeta = getMeta;
DTN.setMeta = setMeta;
DTN.toEnvelopeWire = toEnvelopeWire;
DTN.DB_VERSION = DB_VERSION;
DTN.IDB_MIGRATIONS = IDB_MIGRATIONS;
DTN.runIdbMigrations = runIdbMigrations;

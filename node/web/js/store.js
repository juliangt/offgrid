/*
 * Off-grid DTN messaging SPA — local store, IndexedDB
 * "dtn_local_store" v1 (§11, §15.6). Extends the DTN export with the
 * persistence API; no DOM here, so the store stays usable headless.
 * ES5 on purpose: captive-portal mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 8. Local store — IndexedDB "dtn_local_store" (§11, §15.6, plan 2.3).
 *    Stores:
 *      identity      singleton under the fixed key "identity" (seed+keys)
 *      inbox         decrypted own messages, keyed by inbox-record id
 *                    (envelope id for flat messages, "g:"+g for reassembled
 *                    chunked messages, §4.4)
 *      inbox_parts   partial chunked messages awaiting reassembly, keyed by
 *                    the §4.4 group id `g` (created by migration v2)
 *      sent          sender-side sent-message records keyed by the §4.5
 *                    ack reference id (created by migration v3); tracks
 *                    queued → sent → delivered (§4.5)
 *      prekeys       the §4.6 prekey stock under the fixed key "stock"
 *                    (created by migration v4): spk {pubB64, secret,
 *                    published_at}, unconsumed opks [{pubB64, secret}]
 *                    and tombstones [pubB64] — the SECRETS never leave
 *                    the device and are wiped on use/replenish (§4.6)
 *      contacts      identities exchanged in person via the §4.7 QR
 *                    payload (created by migration v5), keyed by the
 *                    contact's Ed25519 public key: {ed, x, alias,
 *                    added_at, source ("qr" | "paste")} — identity = key,
 *                    the alias is cosmetic (§4.7)
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
var DB_VERSION = 5;
var STORE_IDENTITY = "identity";
var STORE_INBOX = "inbox";
var STORE_PARTS = "inbox_parts";
var STORE_SENT = "sent";
var STORE_PREKEYS = "prekeys";
var STORE_CONTACTS = "contacts";
var PREKEY_STOCK_KEY = "stock";
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
  },
  {
    version: 2,
    /* v2 (§4.4 long messages, issue #24): the inbox_parts store for
     * partial chunked messages, keyed by the group id `g`. Strictly
     * additive: one new store, no existing store or record is touched
     * (§15.6); flat messages keep their v1 shape and semantics. */
    migrate: function (db) {
      db.createObjectStore(STORE_PARTS, { keyPath: "g" });
    }
  },
  {
    version: 3,
    /* v3 (§4.5 delivery acks, issue #25): the sent store for sender-side
     * sent-message records, keyed by the §4.5 ack reference id. Strictly
     * additive: one new store, no existing store or record is touched
     * (§15.6); a database without ack tracking keeps working unchanged. */
    migrate: function (db) {
      db.createObjectStore(STORE_SENT, { keyPath: "id" });
    }
  },
  {
    version: 4,
    /* v4 (§4.6 prekey bundles, issue #27): the prekeys store holding the
     * ONE device-local stock record (key "stock"): the signed medium-term
     * prekey secret, the unconsumed one-time prekey secrets and the
     * tombstones of wiped pubs. Strictly additive: one new store, no
     * existing store or record is touched (§15.6); a database without
     * prekeys keeps working unchanged (the first sync publishes the first
     * bundle — prekeyNeedsReplenish treats a missing stock as "needed").
     * Prekey secrets are fresh random pairs, never derived from the
     * identity seed, so the seed backup opens no prekey-addressed mail. */
    migrate: function (db) {
      db.createObjectStore(STORE_PREKEYS);                      /* out-of-line keys */
    }
  },
  {
    version: 5,
    /* v5 (§4.7 identity QR, issue #28): the contacts store for identities
     * exchanged IN PERSON via the OFFGRID1 payload, keyed by the contact's
     * Ed25519 public key (keyPath "ed" — identity = key, the §4.7 trust
     * model). Records: {ed, x, alias, added_at, source} with source "qr"
     * (camera scan) or "paste" (the universal fallback). Strictly
     * additive: one new store, no existing store or record is touched
     * (§15.6); a database without contacts keeps working unchanged — the
     * recipient picker simply falls back to the directory alone. */
    migrate: function (db) {
      db.createObjectStore(STORE_CONTACTS, { keyPath: "ed" });
    }
  }
  /* Future versions append here, e.g. (never added speculatively):
   * { version: 6, migrate: function (db) { db.createObjectStore(...) } }
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

/* ----- inbox_parts: partial chunked messages (§4.4) ----- */

/* Merge one decrypted chunk envelope into its partial state, inside ONE
 * readwrite transaction over inbox_parts + inbox: the merged state is
 * stored, and when the n-th chunk completes the message it lands in the
 * inbox store and the partial state is deleted — atomically. The merge
 * rules are the pure §4.4 ones of chunking.js (first write per index
 * wins, so re-delivered duplicates are no-ops).
 * `env` is the pulled envelope (its created_at/ttl are shared by all
 * chunks of the message), `dec` the decryptEnvelope result carrying
 * `chunk: {g, i, n}` and the sender's Ed25519 key `k` (kept in the
 * partial state so the §4.5 ack can be addressed at completion, even
 * when the last chunk arrives in a later sync). Resolves
 * {complete, record?, ack_task?} — ack_task carries the §4.5 ack
 * parameters (reference id = the LAST chunk's envelope id, the sender's
 * key and the shared lifetime) when the message completed. */
function addInboxChunkPart(env, dec, nowSec) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction([STORE_PARTS, STORE_INBOX], "readwrite");
      var parts = tx.objectStore(STORE_PARTS);
      var inbox = tx.objectStore(STORE_INBOX);
      var outcome = { complete: false };
      var req = parts.get(dec.chunk.g);
      req.onsuccess = function () {
        /* First chunk of the group seeds the state; the partial expires
         * with the chunks' own shared TTL deadline (§4.4, no extension). */
        var state = req.result ||
          chunkNewState(dec.chunk.g, dec.chunk.n, dec.a, dec.t,
                        env.created_at, env.ttl, nowSec, dec.k);
        var merged = chunkStateWithPart(state, dec.chunk.i, dec.m, env.id);
        if (chunkStateComplete(merged)) {
          outcome.record = chunkInboxRecord(merged);
          inbox.put(outcome.record);
          parts.delete(dec.chunk.g);
          outcome.complete = true;
          /* §4.5: ONE ack per message, emitted exactly at reassembly
           * completion, referencing the agreed id — the LAST chunk's
           * envelope id (§4.5 reference rule). The deletion above makes a
           * second completion (and a second ack) impossible. */
          outcome.ack_task = {
            r: merged.parts[String(merged.n - 1)].id,
            sender_key: merged.k,
            sender_alias: merged.a,
            created_at: merged.created_at,
            ttl: merged.ttl,
            type: ACK_TYPE_RECEIVED
          };
        } else {
          parts.put(merged);
        }
      };
      tx.oncomplete = function () { resolve(outcome); };
      tx.onerror = function () { reject(tx.error || new Error("could not store the message chunk")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

function listChunkPartials() {
  return storeGetAll(STORE_PARTS);
}

function removeChunkPartial(g) {
  return withStore(STORE_PARTS, "readwrite", function (store) {
    store.delete(g);
    return g;
  });
}

/* §4.4 passive purge of expired partials: aligned with the chunks' TTL
 * deadline (created_at + ttl < now, the §10.6 boundary). Called on sync
 * and on inbox render — NEVER from a timer (the SPA has none). Resolves
 * with the number of partials swept. */
function purgeExpiredChunkPartials(nowSec) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_PARTS, "readwrite");
      var store = tx.objectStore(STORE_PARTS);
      var swept = 0;
      var req = store.openCursor();
      req.onsuccess = function (e) {
        var cursor = e.target.result;
        if (cursor) {
          if (chunkStateExpired(cursor.value, nowSec)) {
            cursor.delete();
            swept += 1;
          }
          cursor.continue();
        }
      };
      tx.oncomplete = function () { resolve(swept); };
      tx.onerror = function () { reject(tx.error || new Error("could not sweep expired partials")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* ----- sent: sender-side delivery tracking (§4.5) ----- */

/* Add one sent record (the pure shape of sentNewRecord, keyed by the §4.5
 * ack reference id) and enforce the local history cap SENT_HISTORY_MAX
 * (oldest by created_at evicted first — local hygiene only; the network
 * is never consulted about it). */
function addSentRecord(record) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_SENT, "readwrite");
      var store = tx.objectStore(STORE_SENT);
      store.put(record);
      tx.oncomplete = function () { resolve(record); };
      tx.onerror = function () { reject(tx.error || new Error("could not save the sent message")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  }).then(function (rec) {
    return capSentHistory().then(function () { return rec; });
  });
}

/* Soft local cap: keep the SENT_HISTORY_MAX newest records by created_at
 * (ties break on the record id for determinism). */
function capSentHistory() {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_SENT, "readwrite");
      var store = tx.objectStore(STORE_SENT);
      var rows = [];
      var req = store.openCursor();
      req.onsuccess = function (e) {
        var cursor = e.target.result;
        if (cursor) {
          rows.push(cursor.value);
          cursor.continue();
          return;
        }
        if (rows.length <= SENT_HISTORY_MAX) return;
        rows.sort(function (x, y) {
          return (y.created_at - x.created_at) || (x.id < y.id ? -1 : (x.id > y.id ? 1 : 0));
        });
        for (var i = SENT_HISTORY_MAX; i < rows.length; i++) store.delete(rows[i].id);
      };
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error || new Error("could not cap the sent history")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* Sent records, newest first by sender timestamp (mirrors listInbox). */
function listSent() {
  return storeGetAll(STORE_SENT).then(function (rows) {
    rows.sort(function (x, y) {
      return (y.t - x.t) || (y.created_at - x.created_at);
    });
    return rows;
  });
}

/* queued → sent (§4.5): flip every still-queued record that owns ANY of
 * `envIds` — the ids the sync cycle just pushed to a node ("carried by a
 * mule" from here on). Resolves the number of records flipped. */
function markSentPushed(envIds) {
  if (!envIds || !envIds.length) return Promise.resolve(0);
  var pushed = {};
  for (var i = 0; i < envIds.length; i++) pushed[envIds[i]] = true;
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_SENT, "readwrite");
      var store = tx.objectStore(STORE_SENT);
      var flipped = 0;
      var req = store.openCursor();
      req.onsuccess = function (e) {
        var cursor = e.target.result;
        if (!cursor) return;
        var rec = cursor.value;
        if (rec.state === "queued" && rec.env_ids) {
          for (var j = 0; j < rec.env_ids.length; j++) {
            if (pushed[rec.env_ids[j]]) {
              rec.state = "sent";
              rec.sent_at = Math.floor(Date.now() / 1000);
              cursor.update(rec);
              flipped += 1;
              break;
            }
          }
        }
        cursor.continue();
      };
      tx.oncomplete = function () { resolve(flipped); };
      tx.onerror = function () { reject(tx.error || new Error("could not update the sent state")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* A verified ack arrives (§4.5): bind it to the sent record its
 * reference names (ackMatchesSent — the signature's key must be the
 * recipient the message was sent to), then flip sent/queued → delivered.
 * An ack that binds to nothing (unknown reference, wrong signer, already
 * delivered) is a silent no-op — acks are idempotent and never re-acked.
 * Resolves {matched, delivered}. */
function applyAckToSent(dec, nowSec) {
  return storeGet(STORE_SENT, dec && dec.ack ? dec.ack.r : null).then(function (record) {
    if (!record || !ackMatchesSent(dec, record)) return { matched: false, delivered: false };
    if (record.state === "delivered") return { matched: true, delivered: false };
    return storePut(STORE_SENT, sentDeliveredRecord(record, nowSec)).then(function () {
      return { matched: true, delivered: true };
    });
  });
}

/* ----- prekeys: the §4.6 device-local stock ----- */

function loadPrekeyState() {
  return storeGet(STORE_PREKEYS, PREKEY_STOCK_KEY);
}

function savePrekeyState(state) {
  return storePut(STORE_PREKEYS, state, PREKEY_STOCK_KEY);
}

/* Wipe-on-use (§4.6 recipient rule 2 — the forward-secrecy event): remove
 * the OPK secret for pubB64 from the stock and tombstone its public, in
 * ONE readwrite transaction (atomic; a crash leaves either the old or the
 * new stock, never a half-wiped mix). The mutation is the PURE
 * prekeyStateWithoutOpk — unknown pubs are a no-op, so a duplicate
 * delivery of the same-OPK envelope cannot double-tombstone. Resolves
 * true when a wipe happened, false when there was nothing to wipe. */
function wipeOpkSecret(pubB64) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE_PREKEYS, "readwrite");
      var store = tx.objectStore(STORE_PREKEYS);
      var wiped = false;
      var req = store.get(PREKEY_STOCK_KEY);
      req.onsuccess = function () {
        var next = prekeyStateWithoutOpk(req.result, pubB64);
        if (next !== req.result) {
          wiped = true;
          store.put(next, PREKEY_STOCK_KEY);
        }
      };
      tx.oncomplete = function () { resolve(wiped); };
      tx.onerror = function () { reject(tx.error || new Error("could not wipe the one-time prekey")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* ----- contacts: identities exchanged via the §4.7 QR payload ----- */

/*
 * Upsert one contact keyed by its Ed25519 public key (the §4.7 trust
 * model: identity = key). Re-adding an existing contact (a second scan or
 * a fresh paste) refreshes alias/x/source inside ONE readwrite
 * transaction while keeping the ORIGINAL added_at (first contact wins the
 * timeline). The record shape is validated by qrContactRecord upstream;
 * a malformed record is rejected here defensively.
 */
function saveContact(record) {
  return getDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      if (!record || typeof record.ed !== "string" || !record.ed ||
          typeof record.x !== "string" || !record.x ||
          typeof record.alias !== "string" || !record.alias) {
        reject(new Error("invalid contact record"));
        return;
      }
      var tx = db.transaction(STORE_CONTACTS, "readwrite");
      var store = tx.objectStore(STORE_CONTACTS);
      var req = store.get(record.ed);
      req.onsuccess = function () {
        var existing = req.result;
        var next = {
          ed: record.ed,
          x: record.x,
          alias: record.alias,
          added_at: (existing && typeof existing.added_at === "number") ? existing.added_at : record.added_at,
          source: record.source
        };
        store.put(next);
      };
      tx.oncomplete = function () { resolve(record); };
      tx.onerror = function () { reject(tx.error || new Error("could not save the contact")); };
      tx.onabort = function () { reject(tx.error || new Error("transaction aborted")); };
    });
  });
}

/* Contacts, sorted by alias then ed (the deterministic picker order of
 * qrMergeRecipients, §4.7). */
function listContacts() {
  return storeGetAll(STORE_CONTACTS).then(function (rows) {
    rows.sort(function (x, y) {
      if (x.alias !== y.alias) return x.alias < y.alias ? -1 : 1;
      if (x.ed !== y.ed) return x.ed < y.ed ? -1 : 1;
      return 0;
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
DTN.addInboxChunkPart = addInboxChunkPart;
DTN.listChunkPartials = listChunkPartials;
DTN.removeChunkPartial = removeChunkPartial;
DTN.purgeExpiredChunkPartials = purgeExpiredChunkPartials;
DTN.STORE_PARTS = STORE_PARTS;
DTN.addSentRecord = addSentRecord;
DTN.listSent = listSent;
DTN.markSentPushed = markSentPushed;
DTN.applyAckToSent = applyAckToSent;
DTN.STORE_SENT = STORE_SENT;
DTN.STORE_PREKEYS = STORE_PREKEYS;
DTN.PREKEY_STOCK_KEY = PREKEY_STOCK_KEY;
DTN.loadPrekeyState = loadPrekeyState;
DTN.savePrekeyState = savePrekeyState;
DTN.wipeOpkSecret = wipeOpkSecret;
DTN.STORE_CONTACTS = STORE_CONTACTS;
DTN.saveContact = saveContact;
DTN.listContacts = listContacts;
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

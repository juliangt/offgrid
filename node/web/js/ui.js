/*
 * Off-grid DTN messaging SPA — UI wiring. Everything here only runs
 * from initUi(), invoked at the bottom only when the document and the
 * #dtn-app container exist, so the engine and store scripts stay
 * usable headless from Node. ES5 + XHR on purpose: captive-portal
 * mini-browsers run the OS WebView, which can be years behind the
 * device browser.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 9. UI wiring (plan 2.7). Everything below only runs from initUi(),
 *    which is invoked at the very bottom only when the document and the
 *    #dtn-app container exist — the engine and store scripts stay usable
 *    headless.
 * ------------------------------------------------------------------- */

function $(id) {
  return document.getElementById(id);
}

function showEl(el) { if (el) el.hidden = false; }
function hideEl(el) { if (el) el.hidden = true; }

function setText(id, text) {
  var el = $(id);
  if (el) el.textContent = text;
}

/* In-memory view state (never a substitute for the IndexedDB truth). */
var uiState = {
  identity: null,   /* identity record incl. alias, loaded from the store */
  directory: [],    /* last GET /api/v1/directory result */
  sending: false
};

/* ----- tiny network helpers (XHR works on every WebView; fetch may not) -- */

function xhrJSON(method, path, body) {
  return new Promise(function (resolve, reject) {
    try {
      var xhr = new XMLHttpRequest();
      xhr.open(method, path, true);
      xhr.timeout = 20000;
      if (body !== undefined) xhr.setRequestHeader("Content-Type", "application/json");
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch (e) {
            reject(new Error("invalid response from the node"));
          }
        } else {
          reject(new Error("HTTP " + xhr.status));
        }
      };
      xhr.onerror = function () { reject(new Error("no contact with the node")); };
      xhr.ontimeout = function () { reject(new Error("request timed out")); };
      xhr.send(body === undefined ? null : JSON.stringify(body));
    } catch (e) {
      reject(e);
    }
  });
}

function postJson(path, body) {
  return xhrJSON("POST", path, body);
}

function getJson(path) {
  return xhrJSON("GET", path);
}

/* ----- clipboard with execCommand fallback for captive WebViews ----- */

function copyText(text, done) {
  var fallback = function () {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    done(ok);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
  } else {
    fallback();
  }
}

function wireCopyButtons() {
  var buttons = document.querySelectorAll("[data-copy-target]");
  for (var i = 0; i < buttons.length; i++) {
    (function (btn) {
      btn.addEventListener("click", function () {
        var target = $(btn.getAttribute("data-copy-target"));
        if (!target) return;
        var text = (target.tagName === "TEXTAREA" || target.tagName === "INPUT") ? target.value : target.textContent;
        copyText(text, function (ok) {
          var old = btn.textContent;
          btn.textContent = ok ? "Copied!" : "Could not copy";
          setTimeout(function () { btn.textContent = old; }, 1500);
        });
      });
    })(buttons[i]);
  }
}

/* ----- time formatting (English labels, task 2.1 as amended) ----- */

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function relativeTime(unixSec) {
  var d = nowSec() - unixSec;
  if (!(d >= 0)) return "in the future";
  if (d < 45) return "now";
  if (d < 3600) return Math.max(1, Math.round(d / 60)) + " min ago";
  if (d < 86400) return Math.round(d / 3600) + " h ago";
  if (d < 7 * 86400) return Math.round(d / 86400) + " d ago";
  return new Date(unixSec * 1000).toLocaleDateString();
}

function absoluteTime(unixSec) {
  return new Date(unixSec * 1000).toLocaleString();
}

/* ----- screens and tabs ----- */

function showScreen(name) {
  hideEl($("screen-register"));
  hideEl($("screen-app"));
  showEl($(name === "register" ? "screen-register" : "screen-app"));
}

var TABS = ["compose", "inbox", "identity"];

function selectTab(name) {
  for (var i = 0; i < TABS.length; i++) {
    var t = TABS[i];
    var panel = $("tab-" + t);
    var btn = $("tab-btn-" + t);
    if (panel) panel.hidden = t !== name;
    if (btn) btn.className = "tab" + (t === name ? " active" : "");
  }
  if (name === "inbox") renderInbox();
  if (name === "identity") renderIdentityTab();
  if (name === "compose") refreshDirectory();
}

/* ----- directory (§10.3 GET) ----- */

function refreshDirectory() {
  var select = $("compose-to");
  if (!select) return Promise.resolve([]);
  return getJson("/api/v1/directory").then(function (entries) {
    uiState.directory = Array.isArray(entries) ? entries : [];
    renderDirectory();
    return uiState.directory;
  }, function () {
    uiState.directory = [];
    select.textContent = "";
    var opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "Could not load the directory. Retry with \"Refresh directory\".";
    select.appendChild(opt);
    updateSendEnabled();
    return [];
  });
}

function renderDirectory() {
  var select = $("compose-to");
  if (!select) return;
  select.textContent = "";
  var own = uiState.identity ? uiState.identity.signPublicB64 : null;
  var count = 0;
  for (var i = 0; i < uiState.directory.length; i++) {
    var entry = uiState.directory[i];
    if (!entry || !entry.alias || !entry.x25519) continue;
    if (own && entry.pubkey === own) continue; /* never offer yourself as a recipient */
    var opt = document.createElement("option");
    opt.value = entry.x25519;
    opt.textContent = entry.alias + " · " + relativeTime(entry.last_seen || 0);
    opt.title = "Last seen: " + absoluteTime(entry.last_seen || 0);
    select.appendChild(opt);
    count += 1;
  }
  if (count === 0) {
    var empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "No other users are registered on this node yet.";
    select.appendChild(empty);
  }
  updateSendEnabled();
}

function currentRecipient() {
  var select = $("compose-to");
  if (!select || !select.value) return null;
  for (var i = 0; i < uiState.directory.length; i++) {
    if (uiState.directory[i] && uiState.directory[i].x25519 === select.value) return uiState.directory[i];
  }
  return null;
}

/* ----- composer with the §8.1 UTF-8 byte counter ----- */

function updateCounter() {
  var text = $("compose-text").value;
  var len = DTN.messageByteLength(text);
  var counter = $("byte-counter");
  counter.textContent = len + "/" + DTN.MESSAGE_MAX_BYTES;
  if (len > DTN.MESSAGE_MAX_BYTES) counter.className = "over";
  else counter.className = "";
  updateSendEnabled();
}

function updateSendEnabled() {
  var btn = $("btn-send");
  if (!btn) return;
  var len = DTN.messageByteLength($("compose-text").value);
  btn.disabled = uiState.sending || !currentRecipient() || len < 1 || len > DTN.MESSAGE_MAX_BYTES;
}

function showStatus(el, kind, text) {
  el.hidden = false;
  el.className = kind === "ok" ? "status-ok" : (kind === "error" ? "status-error" : "");
  el.textContent = text;
}

/* Send flow (plan 2.5): build the envelope per §4.2/§5/§6, remember its id
 * so it is never re-pulled (§10.4), count it, and hand it to the node
 * immediately. The mule sync engine (section 10) takes over from the next
 * sync onwards. */
function onSend() {
  if (uiState.sending) return;
  var statusEl = $("compose-status");
  var identity = uiState.identity;
  if (!identity) return;

  var entry = currentRecipient();
  if (!entry) {
    showStatus(statusEl, "error", "Pick a recipient from the directory.");
    return;
  }
  var text = $("compose-text").value;
  var len = DTN.messageByteLength(text);
  if (len < 1) {
    showStatus(statusEl, "error", "Write a message.");
    return;
  }
  if (len > DTN.MESSAGE_MAX_BYTES) {
    showStatus(statusEl, "error", "The message exceeds the 128-byte limit.");
    return;
  }
  var recipientRaw = DTN.b64decode(entry.x25519);
  if (!recipientRaw || recipientRaw.length !== 32) {
    showStatus(statusEl, "error", "The recipient key is not valid.");
    return;
  }

  uiState.sending = true;
  updateSendEnabled();
  showStatus(statusEl, "", "Signing and encrypting…");

  var env;
  try {
    env = DTN.buildEnvelope({
      recipientBoxPublic: recipientRaw,
      message: text,
      alias: identity.alias,
      signSecret: identity.signSecret,
      signPublic: identity.signPublic,
      createdAt: nowSec()
    });
  } catch (e) {
    uiState.sending = false;
    updateSendEnabled();
    showStatus(statusEl, "error", "Could not build the envelope: " + e.message);
    return;
  }

  DTN.markSeenIds([env.id]).then(function () {
    return DTN.getMeta("sent_count").then(function (n) {
      return DTN.setMeta("sent_count", (typeof n === "number" ? n : 0) + 1);
    });
  }).then(function () {
    /* §11: hand the envelope to the node immediately (it rides the same
     * mule cycle as every other sync). */
    return performSync([env]);
  }).then(function (summary) {
    uiState.sending = false;
    if (!summary || summary.status !== "ok") {
      /* The node was unreachable: the envelope joins the transit queue in
       * its ORIGINAL v1 form (§15.6 — the stored record keeps the version
       * it was minted under; any §15.1 conversion happens only on the
       * wire copy during a sync) and retries automatically on the next
       * sync. */
      return DTN.addTransitEnvelopes([env]).then(function () {
        $("compose-text").value = "";
        updateCounter();
        updateSendEnabled();
        showStatus(statusEl, "error", "Could not deliver to the node yet. The message stayed in your transit queue and will retry on the next sync.");
        renderTelemetry();
      });
    }
    $("compose-text").value = "";
    updateCounter();
    updateSendEnabled();
    showStatus(statusEl, "ok", "Message encrypted and dropped at the node. It will arrive when a mule carries it to its recipient.");
    renderTelemetry();
  }, function (err) {
    uiState.sending = false;
    updateSendEnabled();
    showStatus(statusEl, "error", "Send failed (" + err.message + "). Please retry.");
    renderTelemetry();
  });
}

/* ----- inbox (§11 display: sender alias + time + text) ----- */

function renderInbox() {
  return DTN.listInbox().then(function (rows) {
    var list = $("inbox-list");
    var emptyMsg = $("inbox-empty");
    if (!list) return;
    list.textContent = "";
    if (!rows.length) {
      showEl(emptyMsg);
      return;
    }
    hideEl(emptyMsg);
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var li = document.createElement("li");
      var head = document.createElement("div");
      head.className = "msg-head";
      var sender = document.createElement("strong");
      sender.textContent = row.a;
      var time = document.createElement("span");
      time.className = "time";
      time.textContent = relativeTime(row.t);
      time.title = absoluteTime(row.t);
      head.appendChild(sender);
      head.appendChild(time);
      var body = document.createElement("div");
      body.className = "msg-body";
      body.textContent = row.m;
      li.appendChild(head);
      li.appendChild(body);
      list.appendChild(li);
    }
  });
}

/* ----- identity tab ----- */

function renderIdentityTab() {
  var identity = uiState.identity;
  if (!identity) return;
  setText("id-alias", identity.alias);
  setText("id-pubkey", identity.signPublicB64);
  setText("id-x25519", identity.boxPublicB64);
  setText("id-hint", identity.hint);
  var seedEl = $("id-seed");
  if (seedEl) seedEl.value = identity.seedB64;
}

function toggleSeed() {
  var seedEl = $("id-seed");
  var btn = $("btn-show-seed");
  if (!seedEl || !btn) return;
  seedEl.hidden = !seedEl.hidden;
  btn.textContent = seedEl.hidden ? "Show seed" : "Hide seed";
}

/* ----- telemetry panel (§11) ----- */

function transitCount() {
  return storeCount(STORE_TRANSIT);
}

function renderLastSyncValue(v) {
  var el = $("tel-lastsync");
  if (!el) return;
  if (!v || typeof v !== "object" || !v.at) {
    el.textContent = "never";
    return;
  }
  var when = relativeTime(v.at);
  if (v.status === "ok") el.textContent = "ok (" + when + ")";
  else if (v.status === "error") el.textContent = "failed (" + when + ")";
  else el.textContent = when;
}

function renderTelemetry() {
  return Promise.all([
    transitCount(),
    DTN.getMeta("sent_count"),
    DTN.getMeta("evicted_total"),
    DTN.getMeta("last_sync")
  ]).then(function (results) {
    setText("tel-transit", String(results[0]));
    setText("tel-sent", String(typeof results[1] === "number" ? results[1] : 0));
    var evicted = typeof results[2] === "number" ? results[2] : 0;
    setText("tel-evicted", String(evicted));
    if (evicted > 0) showEl($("tel-evicted-wrap"));
    else hideEl($("tel-evicted-wrap"));
    renderLastSyncValue(results[3]);
  });
}

/* ----- registration (plan 2.4) ----- */

function setRegError(msg) {
  var el = $("reg-error");
  if (!msg) {
    hideEl(el);
    return;
  }
  showEl(el);
  el.textContent = msg;
}

function setImportError(msg) {
  var el = $("import-error");
  if (!msg) {
    hideEl(el);
    return;
  }
  showEl(el);
  el.textContent = msg;
}

/* Publish {alias, pubkey, x25519} to the node's directory (§10.3). */
function publishIdentity(identity) {
  return postJson("/api/v1/directory", {
    alias: identity.alias,
    pubkey: identity.signPublicB64,
    x25519: identity.boxPublicB64
  });
}

function onRegister() {
  var alias = $("reg-alias").value.replace(/^\s+|\s+$/g, "");
  if (!DTN.validateAlias(alias)) {
    setRegError("Invalid alias: use 1 to 24 letters, numbers, dot, dash or underscore.");
    return;
  }
  var btn = $("btn-register");
  var btnLabel = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Generating keys…";
  setRegError("");

  var identity = DTN.createIdentity();
  identity.alias = alias;
  identity.registered_at = nowSec();

  publishIdentity(identity).then(function () {
    return DTN.saveIdentity(identity);
  }).then(function () {
    btn.textContent = btnLabel;
    uiState.identity = identity;
    /* Show the seed backup before letting the user into the app. */
    hideEl($("reg-card"));
    $("reg-seed").value = identity.seedB64;
    showEl($("reg-backup"));
    $("btn-finish-register").disabled = !$("reg-confirm").checked;
  }, function (err) {
    btn.disabled = false;
    btn.textContent = btnLabel;
    setRegError("Could not register on the node (" + err.message + "). Please retry.");
  });
}

function onFinishRegister() {
  enterApp();
}

/* Import: the seed reconstructs both key pairs deterministically (§11
 * backup); the alias is not derivable, so it is re-entered and the
 * directory upsert re-publishes the same public keys. */
function onImport() {
  var seedText = $("import-seed").value.replace(/^\s+|\s+$/g, "");
  var alias = $("import-alias").value.replace(/^\s+|\s+$/g, "");
  if (!DTN.validateAlias(alias)) {
    setImportError("Invalid alias: use 1 to 24 letters, numbers, dot, dash or underscore.");
    return;
  }
  var seed = DTN.b64decode(seedText);
  if (!seed || seed.length !== 32) {
    setImportError("Invalid seed: it must be Base64 of 32 bytes (44 characters with padding).");
    return;
  }
  var btn = $("btn-import");
  btn.disabled = true;
  setImportError("");

  var identity;
  try {
    identity = DTN.identityFromSeed(seed);
  } catch (e) {
    btn.disabled = false;
    setImportError("Invalid seed: " + e.message);
    return;
  }
  identity.alias = alias;
  identity.registered_at = nowSec();

  publishIdentity(identity).then(function () {
    return DTN.saveIdentity(identity);
  }).then(function () {
    uiState.identity = identity;
    enterApp();
  }, function (err) {
    btn.disabled = false;
    setImportError("Could not restore the identity (" + err.message + "). Please retry.");
  });
}

/* ----- boot ----- */

function enterApp() {
  showScreen("app");
  renderIdentityTab();
  renderTelemetry();
  renderInbox();
  refreshDirectory();
  /* §11: sync automatically on page load (push + pull cycle). */
  performSync([]).then(function () {
    renderTelemetry();
    renderInbox();
  }, function () {
    renderTelemetry();
  });
}

function showRegister() {
  showScreen("register");
}

function wireStaticHandlers() {
  wireCopyButtons();
  $("tab-btn-compose").addEventListener("click", function () { selectTab("compose"); });
  $("tab-btn-inbox").addEventListener("click", function () { selectTab("inbox"); });
  $("tab-btn-identity").addEventListener("click", function () { selectTab("identity"); });

  $("btn-register").addEventListener("click", onRegister);
  $("reg-confirm").addEventListener("change", function () {
    $("btn-finish-register").disabled = !$("reg-confirm").checked;
  });
  $("btn-finish-register").addEventListener("click", onFinishRegister);
  $("btn-import").addEventListener("click", onImport);

  $("btn-refresh-dir").addEventListener("click", refreshDirectory);
  $("compose-text").addEventListener("input", updateCounter);
  $("compose-to").addEventListener("change", updateSendEnabled);
  $("btn-send").addEventListener("click", onSend);
  $("btn-show-seed").addEventListener("click", toggleSeed);
  $("btn-sync").addEventListener("click", onManualSync);
}

/* Manual sync button (§11): full push/pull cycle against the node. */
function onManualSync() {
  var btn = $("btn-sync");
  btn.disabled = true;
  performSync([]).then(function () {
    btn.disabled = false;
    renderTelemetry();
    renderInbox();
  }, function () {
    btn.disabled = false;
    renderTelemetry();
  });
}

function initUi() {
  setupBanner();
  wireStaticHandlers();
  DTN.loadIdentity().then(function (identity) {
    if (identity && DTN.validateAlias(identity.alias) && identity.signPublicB64 && identity.boxPublicB64) {
      uiState.identity = identity;
      enterApp();
    } else {
      showRegister();
    }
  }, function () {
    showRegister();
  });
}

/* ---------------------------------------------------------------------
 * 10. Mule sync engine (§10.4 + §11, plan 2.6) and captive banner
 *     (plan §1.4).
 * ------------------------------------------------------------------- */

var SYNC_KNOWN_CHUNK = 500;   /* §8.1 known_ids cap per request */
var SYNC_PUSH_CHUNK = 100;    /* §8.1 push cap per request */
var SYNC_LIMIT_FIRST = 50;    /* §11: pull with limit 50 */
var SYNC_LIMIT_MORE = 200;    /* §8.1 max: drain remaining known_ids chunks */
var CAPABILITIES_PATH = "/api/v1/capabilities"; /* §15.5 version advertisement */

/* Syncs serialize through this tail so a send during a running sync is
 * never lost (it runs right after). */
var syncChain = Promise.resolve();

function chunkArray(arr, size) {
  var out = [];
  for (var i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/* §15.5: fetch the node's version advertisement and reduce it to the
 * negotiation ceiling (max_envelope_version). ANY failure — a 404 on an
 * older node, a transport error, a malformed body — resolves null, the
 * documented fallback: the batch then goes out in its original,
 * unconverted form (§15.5, §15.6). Syncing is NEVER blocked by a
 * capabilities failure. */
function fetchMaxEnvelopeVersion() {
  return getJson(CAPABILITIES_PATH).then(function (caps) {
    return DTN.maxAdvertisedEnvelopeVersion(caps);
  }, function () {
    return null;
  });
}

/* One full mule cycle:
 *   - known_ids = inbox ids ∪ transit ids ∪ seen ids ∪ ids being pushed
 *     (§11). Beyond 500, known_ids are split across several POSTs; the
 *     first request always lists the ids it pushes (§10.4) and uses
 *     limit 50, the drain requests use the maximum 200.
 *   - capabilities: GET /api/v1/capabilities (§15.5) rides along with the
 *     storage reads; on any failure the ceiling is null and the batch
 *     goes out unconverted (§15.5 fallback, never a blocked sync).
 *   - push = outgoing envelopes (own sends) + the whole transit queue,
 *     gated through DTN.prepareOutgoingBatch (§15.6): at a node that
 *     advertises max_envelope_version >= 2 the carried v1 envelopes go
 *     out as blind v2 conversions (§15.1), envelopes above the node's
 *     ceiling are withheld (they simply stay in transit_queue — never
 *     dropped, never converted downward), and stored records keep their
 *     original version (conversion touches the wire copy only; ids are
 *     stable, so delivered-withheld bookkeeping and dedup are unchanged).
 *     Chunked at 100 per request; envelopes whose push succeeded leave
 *     the queue (the node holds a copy now); failed chunks stay and
 *     retry on the next sync.
 *   - pull classification (§11): dest_hint == own hint → decrypt+verify,
 *     success → inbox, ANY failure → silent reject counted in telemetry;
 *     everything else → transit_queue with FIFO eviction at capacity 100.
 *     Pulled envelopes are stored and served at their stored version
 *     (v1 or v2, §15.3) — never rejected or rewritten for being v2.
 *   - every pulled id lands in seen_ids either way.
 * Resolves a summary; never rejects (per-request errors are counted). */
function performSync(outgoing) {
  outgoing = outgoing || [];
  var run = function () { return runSync(outgoing); };
  var p = syncChain.then(run, run);
  var settled = p.then(function (summary) {
    return recordSyncMeta(summary).then(function () { return summary; });
  }, function (err) {
    /* Storage failure outside the HTTP cycle: record it and rethrow so
     * callers can show feedback. */
    return DTN.setMeta("last_sync", {
      status: "error",
      at: nowSec(),
      detail: err && err.message ? String(err.message) : "error"
    }).then(function () { throw err; });
  });
  syncChain = settled.then(function () {}, function () {});
  return settled;
}

function runSync(outgoing) {
  return DTN.loadIdentity().then(function (identity) {
    if (!identity || !identity.hint || !identity.boxSecret) {
      return { status: "error", reason: "no_identity", pulled: 0, fresh: 0,
               mine: 0, inboxAdded: 0, rejected: 0, transitAdded: 0,
               evicted: 0, errors: 0 };
    }
    var outgoingIds = [];
    for (var i = 0; i < outgoing.length; i++) {
      if (outgoing[i] && typeof outgoing[i].id === "string") outgoingIds.push(outgoing[i].id);
    }
    /* §10.4: pushed ids must be in known_ids; marking them seen up front
     * also survives a lost response (the node may hold them anyway). */
    return DTN.markSeenIds(outgoingIds).then(function () {
      /* §15.5: the capabilities GET rides along with the storage reads —
       * it costs one request and never blocks the sync. */
      return Promise.all([
        DTN.listInbox(), DTN.listTransit(), DTN.listSeenIds(),
        fetchMaxEnvelopeVersion()
      ]);
    }).then(function (lists) {
      var inboxRows = lists[0];
      var transitRows = lists[1];
      var seenIds = lists[2];
      var maxV = lists[3]; /* null → §15.5 fallback: original, unconverted form */
      var known = {};
      var i;
      for (i = 0; i < inboxRows.length; i++) known[inboxRows[i].id] = true;
      for (i = 0; i < transitRows.length; i++) known[transitRows[i].id] = true;
      for (i = 0; i < seenIds.length; i++) known[seenIds[i]] = true;
      for (i = 0; i < outgoingIds.length; i++) known[outgoingIds[i]] = true;

      /* §15.6: the outgoing batch (own sends + the whole transit queue)
       * goes through the negotiation/conversion gate. Conversion touches
       * only the wire copies — stored transit records keep their original
       * version (§15.1: ids are stable) — and withheld envelopes simply
       * stay in transit_queue for the next sync, still counted as
       * carried by the telemetry (§11). */
      var carriedWire = [];
      for (i = 0; i < transitRows.length; i++) carriedWire.push(DTN.toEnvelopeWire(transitRows[i]));
      var gate = DTN.prepareOutgoingBatch(outgoing.concat(carriedWire), maxV);
      var pushList = gate.batch;

      /* outgoing ids first so the first request's known_ids always cover
       * its own push_envelopes (§10.4). */
      var knownKeys = outgoingIds.slice();
      var inKeys = {};
      for (i = 0; i < knownKeys.length; i++) inKeys[knownKeys[i]] = true;
      var allKnown = Object.keys(known);
      for (i = 0; i < allKnown.length; i++) {
        if (!inKeys[allKnown[i]]) {
          inKeys[allKnown[i]] = true;
          knownKeys.push(allKnown[i]);
        }
      }

      var knownChunks = chunkArray(knownKeys, SYNC_KNOWN_CHUNK);
      var pushChunks = chunkArray(pushList, SYNC_PUSH_CHUNK);
      var requestCount = Math.max(knownChunks.length, pushChunks.length, 1);

      var pulled = [];
      var errors = [];
      var pushOk = [];
      var seq = Promise.resolve();
      var request = function (idx) {
        seq = seq.then(function () {
          var body = {
            known_ids: knownChunks[idx] || [],
            push_envelopes: pushChunks[idx] || [],
            limit: idx === 0 ? SYNC_LIMIT_FIRST : SYNC_LIMIT_MORE
          };
          return postJson("/api/v1/sync", body).then(function (resp) {
            pushOk.push(idx);
            if (resp && Array.isArray(resp.pull_envelopes)) {
              for (var j = 0; j < resp.pull_envelopes.length; j++) pulled.push(resp.pull_envelopes[j]);
            }
          }, function (err) {
            errors.push(err);
          });
        });
      };
      for (i = 0; i < requestCount; i++) request(i);

      return seq.then(function () {
        /* Empty the queue of everything delivered; failed chunks stay. */
        var delivered = [];
        for (var c = 0; c < pushOk.length; c++) {
          var chunk = pushChunks[pushOk[c]] || [];
          for (var k = 0; k < chunk.length; k++) delivered.push(chunk[k].id);
        }
        return DTN.removeTransitIds(delivered).then(function () {
          return processPulled(pulled, known, identity);
        });
      }).then(function (summary) {
        summary.errors = errors.length;
        summary.pushed = pushList.length;
        summary.withheld = gate.withheld.length;
        return summary;
      });
    });
  });
}

/* §11 classification of the pulled envelopes + persistence. */
function processPulled(pulled, known, identity) {
  var fresh = [];
  var pulledIds = [];
  var dedup = {};
  for (var i = 0; i < pulled.length; i++) {
    var env = pulled[i];
    if (!env || typeof env.id !== "string" || dedup[env.id]) continue;
    dedup[env.id] = true;
    pulledIds.push(env.id);
    if (known[env.id]) continue; /* replay of an envelope we already have */
    fresh.push(env);
  }
  var cls = DTN.classifyPullEnvelopes(fresh, identity.hint);
  var inboxRecords = [];
  var rejected = 0;
  for (var j = 0; j < cls.mine.length; j++) {
    var res = DTN.decryptEnvelope(cls.mine[j], identity, nowSec());
    if (res.ok) {
      inboxRecords.push({ id: cls.mine[j].id, m: res.m, a: res.a, t: res.t, received_at: nowSec() });
    } else {
      rejected += 1; /* silent reject (§4.3): counted, never surfaced */
    }
  }
  return DTN.addInboxMessages(inboxRecords).then(function () {
    return DTN.addTransitEnvelopes(cls.foreign);
  }).then(function (transitOutcome) {
    return DTN.markSeenIds(pulledIds).then(function () {
      return {
        status: "ok",
        pulled: pulled.length,
        fresh: fresh.length,
        mine: cls.mine.length,
        inboxAdded: inboxRecords.length,
        rejected: rejected,
        transitAdded: transitOutcome.added,
        evicted: transitOutcome.evicted.length
      };
    });
  });
}

function recordSyncMeta(summary) {
  if (!summary) return Promise.resolve();
  if (summary.status === "error" && summary.reason === "no_identity") {
    return Promise.resolve(); /* nothing to record without a mule */
  }
  var meta = {
    status: summary.errors > 0 ? "error" : "ok",
    at: nowSec(),
    pulled: summary.pulled || 0,
    inbox_added: summary.inboxAdded || 0,
    transit_added: summary.transitAdded || 0,
    evicted: summary.evicted || 0,
    rejected: summary.rejected || 0,
    pushed: summary.pushed || 0,
    withheld: summary.withheld || 0 /* §15.6: above the node's ceiling, still carried */
  };
  return DTN.setMeta("last_sync", meta).then(function () {
    if (meta.evicted > 0) {
      return DTN.getMeta("evicted_total").then(function (n) {
        return DTN.setMeta("evicted_total", (typeof n === "number" ? n : 0) + meta.evicted);
      });
    }
  });
}

/* ----- captive mini-browser banner (plan §1.4, spec §13.4) -----
 * Best-effort detection: the iOS CNA marks its user agent with
 * CaptiveNetworkSupport; wispr is the legacy captive-flow marker. Only
 * the wording changes — the banner itself is shown on EVERY load, because
 * mini-browser storage is isolated from the real browser and the identity
 * must live in Chrome/Safari to survive across nodes (same origin). */
function detectCaptiveBrowser() {
  var ua = navigator.userAgent || "";
  return /CaptiveNetworkSupport|wispr/i.test(ua);
}

function setupBanner() {
  var banner = $("banner-captive");
  if (!banner) return;
  if (detectCaptiveBrowser()) {
    setText("banner-title", "You are in the captive-portal mini-browser");
    setText("banner-text", "This restricted browser may wipe your data. Open this in your full browser (Chrome or Safari) so your identity and messages persist across nodes:");
  } else {
    setText("banner-title", "Open this in your full browser");
    setText("banner-text", "If you arrived from the Wi-Fi notice, type this address in Chrome or Safari so your data persists across nodes:");
  }
  showEl(banner);
  $("banner-close").addEventListener("click", function () {
    hideEl(banner);
  });
  $("banner-copy").addEventListener("click", function () {
    copyText(DTN.CANONICAL_URL, function (ok) {
      var btn = $("banner-copy");
      btn.textContent = ok ? "Copied!" : "Could not copy";
      setTimeout(function () { btn.textContent = "Copy"; }, 1500);
    });
  });
}

/* DOM wiring is complete; the guard keeps this file loadable
 * headless from Node, where document does not exist. */
if (typeof document !== "undefined" && document.getElementById("dtn-app")) {
  initUi();
}

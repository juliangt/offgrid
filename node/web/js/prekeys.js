/*
 * Off-grid DTN messaging SPA — prekey bundles: bounded forward secrecy
 * (§4.6, issue #27). Both sides of the scheme:
 *
 *   publisher: generate the stock (one signed medium-term prekey + a batch
 *              of one-time prekeys — fresh crypto.getRandomValues pairs,
 *              NEVER derived from the identity seed), sign the canonical
 *              bundle string with the identity Ed25519 key and publish the
 *              additive `prekeys` member through the ordinary directory
 *              upsert (§10.3). Secrets never leave the device.
 *   sender   : pick the box target from a peer's bundle — a random
 *              one-time prekey when available, else the signed medium-term
 *              prekey — after verifying shape AND signature client-side
 *              (the node is blind and never verifies, §1). No valid bundle
 *              (absent, malformed, tampered) → the legacy identity key.
 *              dest_hint stays derived from the STABLE identity key (§6.1).
 *   recipient: trial-decrypt in the fixed order identity → SPK →
 *              unconsumed OPKs (first success wins, decryptEnvelope's
 *              `prekeySecrets` argument) and WIPE the OPK secret that
 *              opened an envelope — the forward-secrecy event.
 *
 * Zero wire change: the envelope stays §3.1; crypto_box's internal
 * X25519(eph, target) alone provides the FS property once the target
 * prekey secret is wiped — no new KDF, no new primitives (§4.6).
 * Everything here is pure and DOM-free; persistence lives in store.js
 * (the `prekeys` store, §15.6 migration v4) and the wiring in ui.js.
 * Part of the pure protocol engine. ES5 on purpose: captive-portal
 * mini-browsers run the OS WebView.
 */
"use strict";

/* ---------------------------------------------------------------------
 * 5.1b The §4.6 canonical bundle string and its signature.
 * ------------------------------------------------------------------- */

/*
 * §4.6 signed byte string (binding): canonical JSON per §5 — UTF-8, fixed
 * member order b, k, spk, ts, opk, integers in minimal decimal form,
 * minimal string escaping (the members are Base64, so no escaping fires).
 *
 *   {"b":1,"k":<identity Ed25519 public, Base64>,"spk":<spk>,"ts":<ts>,"opk":<count of opks>}
 *
 * The OPK COUNT — not the OPKs — is bound, so one-time-prekey
 * replenishment never invalidates the SPK signature. The flat §5.1,
 * §4.4 and §4.5 inner forms stay byte-identical to their constructions:
 * this string signs a DIRECTORY member, never an inner payload.
 */
function canonicalPrekeyBundleString(identityPubB64, spkPubB64, ts, opkCount) {
  return '{"b":' + String(PREKEY_BUNDLE_VERSION) +
         ',"k":' + jsonEscapeString(identityPubB64) +
         ',"spk":' + jsonEscapeString(spkPubB64) +
         ',"ts":' + String(assertInt(ts, "ts")) +
         ',"opk":' + String(assertInt(opkCount, "opk")) + "}";
}

/* Ed25519 detached signature over the canonical bundle string, made by the
 * identity Ed25519 secret key (the same key that signs inner payloads). */
function prekeySignBundle(signSecret, identityPubB64, spkPubB64, ts, opkCount) {
  var canonical = canonicalPrekeyBundleString(identityPubB64, spkPubB64, ts, opkCount);
  return b64encode(requireNacl().sign.detached(utf8Encode(canonical), signSecret));
}

/*
 * §4.6 bundle shape (client-side mirror of the node's blind §10.3 check —
 * senders enforce it too, because a malformed bundle they nonetheless trust
 * would send mail into a void). Strict on structure: v == 1, spk Base64 of
 * exactly 32 bytes, spk_sig Base64 of exactly 64, ts a positive integer,
 * opks an array of 8..16 Base64 strings of 32 bytes each. Unknown members
 * are ignored (§15.4).
 */
function prekeyBundleShapeOk(bundle) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) return false;
  if (bundle.v !== PREKEY_BUNDLE_VERSION) return false;
  if (typeof bundle.spk !== "string" || bundle.spk.length !== PREKEY_PUBLIC_B64_LEN) return false;
  var spk = b64decode(bundle.spk);
  if (!spk || spk.length !== 32) return false;
  if (typeof bundle.spk_sig !== "string" || bundle.spk_sig.length !== PREKEY_SIG_B64_LEN) return false;
  var sig = b64decode(bundle.spk_sig);
  if (!sig || sig.length !== 64) return false;
  if (typeof bundle.ts !== "number" || !isFinite(bundle.ts) ||
      Math.floor(bundle.ts) !== bundle.ts || bundle.ts <= 0) return false;
  if (!Array.isArray(bundle.opks)) return false;
  if (bundle.opks.length < PREKEY_OPK_MIN || bundle.opks.length > PREKEY_OPK_MAX) return false;
  for (var i = 0; i < bundle.opks.length; i++) {
    if (typeof bundle.opks[i] !== "string") return false;
    var raw = b64decode(bundle.opks[i]);
    if (!raw || raw.length !== 32) return false;
  }
  return true;
}

/*
 * Verify a bundle's spk_sig against the DIRECTORY ENTRY's identity Ed25519
 * public key (§4.6 sender rule 1). This is the doctored-bundle defense:
 * a malicious node serving a bundle it generated itself fails here, and
 * the sender falls back to the identity key (visible as a UI warning).
 * Anything malformed → false (never throws).
 */
function prekeyVerifyBundleSig(bundle, identityPubB64) {
  if (!prekeyBundleShapeOk(bundle)) return false;
  if (typeof identityPubB64 !== "string" || identityPubB64.length !== PUBKEY_B64_LEN) return false;
  try {
    var canonical = canonicalPrekeyBundleString(identityPubB64, bundle.spk, bundle.ts, bundle.opks.length);
    return requireNacl().sign.detached.verify(
      utf8Encode(canonical), b64decode(bundle.spk_sig), b64decode(identityPubB64));
  } catch (e) {
    return false;
  }
}

/* ---------------------------------------------------------------------
 * 5.1c Sender-side target selection (§4.6 sender rules).
 * ------------------------------------------------------------------- */

/* Uniform-random index in [0, n) by rejection sampling over
 * crypto.getRandomValues (§7.2): no modulo bias, no floats. */
function prekeyRandomIndex(n) {
  if (typeof n !== "number" || n < 1 || n > 255) throw new Error("prekeyRandomIndex: n out of range");
  var limit = Math.floor(256 / n) * n;
  for (;;) {
    var buf = randomBytes(1);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/*
 * Pick the box TARGET for a directory entry (§4.6 sender rules, binding):
 *   - entry with a shape-valid, signature-verified bundle → a random OPK
 *     (else, defensively, the SPK);
 *   - entry without prekeys, with a malformed bundle, or with a FAILED
 *     signature → bundle-less: the caller addresses the identity X25519
 *     key (the pre-1.7 construction). `reason` distinguishes "absent"
 *     (nothing published / no usable key material) from "invalid"
 *     (published but tampered or malformed — the UI warns on this one).
 * The result NEVER carries a secret and dest_hint is NOT decided here:
 * the hint stays derived from the entry's stable identity X25519 key
 * (§6.1) — pass it to buildEnvelope as hintIdentityBoxPublic.
 */
function prekeyTargetForEntry(entry) {
  var identityBox = (entry && typeof entry.x25519 === "string") ? b64decode(entry.x25519) : null;
  if (!identityBox || identityBox.length !== 32) return { ok: false, reason: "absent" };
  var bundle = entry.prekeys;
  if (!bundle) return { ok: false, reason: "absent", identityBox: identityBox };
  if (!prekeyBundleShapeOk(bundle) || !prekeyVerifyBundleSig(bundle, entry.pubkey)) {
    return { ok: false, reason: "invalid", identityBox: identityBox };
  }
  if (bundle.opks.length > 0) {
    var pick = bundle.opks[prekeyRandomIndex(bundle.opks.length)];
    return { ok: true, kind: "opk", pub: b64decode(pick), opkPub: pick, identityBox: identityBox };
  }
  return { ok: true, kind: "spk", pub: b64decode(bundle.spk), opkPub: null, identityBox: identityBox };
}

/* ---------------------------------------------------------------------
 * 5.1d Publisher side: stock generation, wire bundle, lifecycle.
 * ------------------------------------------------------------------- */

/*
 * Device-local stock record (one IndexedDB `prekeys` row, §15.6 v4):
 *   { spk: { pubB64, secret, published_at },   // secret: Uint8Array(32)
 *     opks: [ { pubB64, secret } ],            // UNCONSUMED only — the store
 *                                              // IS the local secret stock
 *     tombstones: [ pubB64, ... ] }            // pubs already wiped, never re-added
 * All key pairs are fresh nacl.box.keyPair() draws (§7.2) — none of them is
 * derived from the identity seed, so extracting that seed opens nothing
 * addressed to a prekey.
 */
function prekeyGenerateStock(tsSec, opkCount) {
  var nacl = requireNacl();
  var count = (typeof opkCount === "number" && isFinite(opkCount) &&
               Math.floor(opkCount) === opkCount &&
               opkCount >= PREKEY_OPK_MIN && opkCount <= PREKEY_OPK_MAX)
    ? opkCount : PREKEY_OPK_BATCH_TARGET;
  var spk = nacl.box.keyPair();
  var opks = [];
  for (var i = 0; i < count; i++) {
    var kp = nacl.box.keyPair();
    opks.push({ pubB64: b64encode(kp.publicKey), secret: kp.secretKey });
  }
  return {
    spk: { pubB64: b64encode(spk.publicKey), secret: spk.secretKey, published_at: assertInt(tsSec, "ts") },
    opks: opks,
    tombstones: []
  };
}

/* The wire `prekeys` member for a stock: canonical-string signature bound
 * to the publishing identity (k = the directory entry's Ed25519 public). */
function prekeyBundleForPublish(stock, signSecret, identityPubB64) {
  if (!stock || !stock.spk || typeof stock.spk.pubB64 !== "string" ||
      !Array.isArray(stock.opks) ||
      stock.opks.length < PREKEY_OPK_MIN || stock.opks.length > PREKEY_OPK_MAX) {
    throw new Error("prekeyBundleForPublish: stock outside the §4.6 admission window");
  }
  var pubs = [];
  for (var i = 0; i < stock.opks.length; i++) pubs.push(stock.opks[i].pubB64);
  var sig = prekeySignBundle(signSecret, identityPubB64, stock.spk.pubB64, stock.spk.published_at, pubs.length);
  return {
    v: PREKEY_BUNDLE_VERSION,
    spk: stock.spk.pubB64,
    spk_sig: sig,
    ts: stock.spk.published_at,
    opks: pubs
  };
}

/*
 * The recipient's trial list (§4.6 recipient rules, FIXED order): the
 * current SPK secret first, then each unconsumed OPK secret. The identity
 * secret is NOT in the list — decryptEnvelope always tries it first (the
 * permanent legacy candidate), then these. Pubs sitting in `tombstones`
 * are skipped defensively (they can only appear if a stale write re-added
 * a consumed OPK — the wipe is authoritative).
 */
function prekeyTrialKeys(state) {
  var out = [];
  if (!state) return out;
  var tomb = Array.isArray(state.tombstones) ? state.tombstones : [];
  if (state.spk && state.spk.secret) {
    out.push({ tag: "spk", pub: state.spk.pubB64, secret: state.spk.secret });
  }
  var opks = Array.isArray(state.opks) ? state.opks : [];
  for (var i = 0; i < opks.length; i++) {
    var o = opks[i];
    if (!o || !o.pubB64 || !o.secret) continue;
    if (tomb.indexOf(o.pubB64) >= 0) continue;
    out.push({ tag: "opk", pub: o.pubB64, secret: o.secret });
  }
  return out;
}

/* Pure wipe-on-use (§4.6 recipient rule 2): a NEW state with OPK `pubB64`
 * removed from the stock and its public tombstoned — the caller persists
 * it (store.wipeOpkSecret wraps this in one readwrite transaction). The
 * input is never mutated; wiping an unknown pub is a no-op returning the
 * SAME state (idempotent: a duplicate delivery of a same-OPK batch cannot
 * double-tombstone). */
function prekeyStateWithoutOpk(state, pubB64) {
  if (!state || typeof pubB64 !== "string") return state;
  var opks = Array.isArray(state.opks) ? state.opks : [];
  var kept = [];
  var removed = false;
  for (var i = 0; i < opks.length; i++) {
    if (opks[i] && opks[i].pubB64 === pubB64) { removed = true; continue; }
    kept.push(opks[i]);
  }
  if (!removed) return state;
  var tomb = Array.isArray(state.tombstones) ? state.tombstones.slice() : [];
  if (tomb.indexOf(pubB64) < 0) tomb.push(pubB64);
  var out = {};
  for (var f in state) {
    if (Object.prototype.hasOwnProperty.call(state, f)) out[f] = state[f];
  }
  out.opks = kept;
  out.tombstones = tomb;
  return out;
}

/*
 * Sync-time replenish check (§4.6 lifecycle): SPK stale (30 days on the
 * bundle `ts` anchor) or the unconsumed OPK stock at/below the low-water
 * mark (≤ 4). A missing stock (fresh identity, pre-1.7 record) always
 * needs one — the first sync after the upgrade publishes the first bundle.
 */
function prekeyNeedsReplenish(state, nowSec) {
  if (!state || !state.spk || typeof state.spk.pubB64 !== "string") {
    return { needed: true, spkStale: true, opkLow: true, reason: "no_stock" };
  }
  var now = assertInt(nowSec, "now");
  var spkStale = (now - state.spk.published_at) >= PREKEY_SPK_TTL_SECONDS;
  var count = Array.isArray(state.opks) ? state.opks.length : 0;
  var opkLow = count <= PREKEY_OPK_LOW_WATER;
  return {
    needed: spkStale || opkLow,
    spkStale: spkStale,
    opkLow: opkLow,
    reason: spkStale ? "spk_stale" : (opkLow ? "opk_low" : "ok")
  };
}

/*
 * A replenished stock: a FRESH batch (new SPK pair when rotating, new OPK
 * batch always), carrying over the tombstones and adding every pub of the
 * OLD batch — one batch at a time, the published stock and the local
 * secret stock stay in lockstep (§4.6). The old SECRETS are wiped by the
 * swap itself: the new state simply does not hold them.
 */
function prekeyReplenishedStock(oldState, tsSec, opkCount) {
  var fresh = prekeyGenerateStock(tsSec, opkCount);
  var tomb = (oldState && Array.isArray(oldState.tombstones)) ? oldState.tombstones.slice() : [];
  if (oldState && oldState.spk && typeof oldState.spk.pubB64 === "string" &&
      tomb.indexOf(oldState.spk.pubB64) < 0) {
    tomb.push(oldState.spk.pubB64);
  }
  var opks = (oldState && Array.isArray(oldState.opks)) ? oldState.opks : [];
  for (var i = 0; i < opks.length; i++) {
    if (opks[i] && typeof opks[i].pubB64 === "string" && tomb.indexOf(opks[i].pubB64) < 0) {
      tomb.push(opks[i].pubB64);
    }
  }
  fresh.tombstones = tomb;
  return fresh;
}

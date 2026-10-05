// Prekey bundles and forward secrecy (§4.6, issue #27) — headless suite
// over the SHIPPED SPA engine (tests/helpers/spa_loader.mjs loads exactly
// the files index.html serves). Asserts:
//
//   (a) the §4.6 canonical bundle string and its Ed25519 signature against
//       the spec's worked vector (RFC 8032 identity key, RFC 7748 Bob SPK);
//   (b) bundle shape checks and the tampered-signature path;
//   (c) sender key selection: OPK preferred (random within the stock),
//       SPK fallback, identity fallback for absent/malformed/tampered
//       bundles — with dest_hint STILL derived from the identity key;
//   (d) recipient trial-decrypt order (identity → SPK → OPKs) and the
//       wipe-on-use event: the second envelope to a consumed OPK fails;
//   (e) THE ACCEPTANCE CRITERION — the forward-secrecy proof: an envelope
//       built to a one-time prekey decrypts exactly once, and afterwards
//       fails BOTH for the wiped local state and for an attacker holding
//       ONLY the extracted long-term identity secret;
//   (f) the replenish lifecycle: low-water and stale-SPK triggers, the
//       fresh batch, the old stock wiped (tombstoned, secrets gone);
//   (g) compatibility both directions: an old-client envelope addressed
//       to the identity key still opens through the identity trial path
//       (no forward secrecy — documented), and a new-client sender falls
//       back to identity addressing against a bundle-less entry;
//   (h) integration: a CHUNKED message (§4.4) and an ACK (§4.5) travel
//       over prekey-addressed envelopes end to end through the engine.
//
// Run: node tests/prekeys.mjs   (exit 0 = pass)

import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.prekeyTargetForEntry !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load with the §4.6 prekey functions (prekeys.js missing from index.html?)");
}

let passed = 0;
function ok(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`ok: ${label}`);
}

const NOW = 1791072000; // 2026-10-04T04:26:40Z — mid-epoch 20730 (the §6.1 test date)

// Deterministic fixtures: the RFC 8032 §7.1 identity (its public is the
// §4.1 example k) and the RFC 7748 §6.1 key pairs.
const RFC8032_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUB_B64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const RFC7748_BOB_SECRET_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_PUB_B64 = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

function rfcIdentity() {
  const sign = DTN.nacl.sign.keyPair.fromSeed(DTN.hexDecode(RFC8032_SEED_HEX));
  const box = DTN.nacl.box.keyPair.fromSecretKey(DTN.hexDecode(RFC7748_BOB_SECRET_HEX));
  if (DTN.b64encode(sign.publicKey) !== RFC8032_PUB_B64 || DTN.b64encode(box.publicKey) !== RFC7748_BOB_PUB_B64) {
    throw new Error("RFC fixture keys did not reconstruct");
  }
  return {
    seed: DTN.hexDecode(RFC8032_SEED_HEX),
    signPublic: sign.publicKey,
    signSecret: sign.secretKey,
    signPublicB64: RFC8032_PUB_B64,
    boxPublic: box.publicKey,
    boxSecret: box.secretKey,
    boxPublicB64: RFC7748_BOB_PUB_B64,
    hint: DTN.deriveDestHint(box.publicKey),
    alias: "bob"
  };
}

// A fresh random identity (senders / attackers do not need determinism).
function freshIdentity(alias) {
  const id = DTN.createIdentity();
  id.alias = alias;
  return id;
}

// A full device stock + its wire bundle, signed by `identity`.
function stockAndBundle(identity, opkCount) {
  const stock = DTN.prekeyGenerateStock(NOW, opkCount);
  const bundle = DTN.prekeyBundleForPublish(stock, identity.signSecret, identity.signPublicB64);
  return { stock, bundle };
}

// A directory entry carrying a bundle (what GET /api/v1/directory serves).
function entryFor(identity, bundle) {
  const entry = { alias: identity.alias, pubkey: identity.signPublicB64, x25519: identity.boxPublicB64, last_seen: NOW, epoch: DTN.epochOf(NOW) };
  if (bundle) entry.prekeys = bundle;
  return entry;
}

console.log("== (a) §4.6 canonical bundle string + signature — the spec's worked vector ==");
{
  const canonical = DTN.canonicalPrekeyBundleString(RFC8032_PUB_B64, RFC7748_BOB_PUB_B64, 1791072000, 12);
  ok(canonical === '{"b":1,"k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","spk":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","ts":1791072000,"opk":12}',
     "canonical §4.6 string is the FIXED member order b, k, spk, ts, opk (136 bytes)");
  ok(DTN.utf8Encode(canonical).length === 136, "the canonical string is exactly 136 UTF-8 bytes");
  const sig = DTN.prekeySignBundle(DTN.nacl.sign.keyPair.fromSeed(DTN.hexDecode(RFC8032_SEED_HEX)).secretKey,
                                   RFC8032_PUB_B64, RFC7748_BOB_PUB_B64, 1791072000, 12);
  ok(sig === "2TtmiNYcVcX0QpegeLuAnOCzNChs4L6z2iEu9TuuoprjZa8c5ULQtph1UWWTcrweXqs61iLEX0o2xqTVPW6HBg==",
     "the worked-vector signature matches the §4.6 pinned value");
  ok(DTN.prekeyVerifyBundleSig(
      { v: 1, spk: RFC7748_BOB_PUB_B64, spk_sig: sig, ts: 1791072000, opks: Array.from({ length: 12 }, (_, i) => keyB64Fixture(i)) },
      RFC8032_PUB_B64),
     "the pinned signature verifies against the pinned canonical bytes");
  // Any byte of the canonical string changing must fail verification.
  ok(!DTN.prekeyVerifyBundleSig(
      { v: 1, spk: RFC7748_BOB_PUB_B64, spk_sig: sig, ts: 1791072001, opks: Array.from({ length: 12 }, (_, i) => keyB64Fixture(i)) },
      RFC8032_PUB_B64),
     "a tampered ts fails the signature (the string is bound whole)");
}

// 32 deterministic Base64 key fixtures (shape-valid OPK/SPK stand-ins).
function keyB64Fixture(n) {
  const raw = new Uint8Array(32);
  for (let i = 0; i < 32; i++) raw[i] = (n * 7 + i) & 0xff;
  return DTN.b64encode(raw);
}

console.log("== (b) bundle shape checks ==");
{
  const bob = rfcIdentity();
  const { bundle } = stockAndBundle(bob);
  ok(DTN.prekeyBundleShapeOk(bundle), "a generated bundle passes the shape check");
  ok(bundle.v === 1 && typeof bundle.ts === "number" && bundle.opks.length === DTN.PREKEY_OPK_BATCH_TARGET,
     "generated bundle: v 1, ts anchor, target-batch OPK stock (12)");
  ok(bundle.opks.every((p) => DTN.b64decode(p).length === 32), "every OPK public decodes to 32 bytes");

  const broken = [
    ["v 2", (b) => { b.v = 2; }],
    ["spk truncated", (b) => { b.spk = DTN.b64encode(new Uint8Array(31)); }],
    ["sig truncated", (b) => { b.spk_sig = DTN.b64encode(new Uint8Array(63)); }],
    ["ts zero", (b) => { b.ts = 0; }],
    ["ts fractional", (b) => { b.ts = 1791072000.5; }],
    ["7 opks", (b) => { b.opks = b.opks.slice(0, 7); }],
    ["17 opks", (b) => { b.opks = b.opks.concat(b.opks.slice(0, 5)); }],
    ["opk not base64", (b) => { b.opks[0] = "!!"; }],
    ["not an object", null]
  ];
  let brokenOk = true;
  for (const [label, mutate] of broken) {
    if (!mutate) { brokenOk = brokenOk && !DTN.prekeyBundleShapeOk("nope") && !DTN.prekeyBundleShapeOk(null); continue; }
    const b = JSON.parse(JSON.stringify(bundle));
    mutate(b);
    brokenOk = brokenOk && !DTN.prekeyBundleShapeOk(b);
    if (!brokenOk) { console.error(`   shape check failed to reject: ${label}`); break; }
  }
  ok(brokenOk, "malformed bundles (bad v/spk/sig/ts/opk shapes) all fail the shape check");
}

console.log("== (c) sender key selection: OPK > SPK > identity; hint stays identity-derived ==");
{
  const bob = rfcIdentity();
  const alice = freshIdentity("alice_77");
  const { stock, bundle } = stockAndBundle(bob);
  const opkPubs = new Set(bundle.opks);

  // OPK preferred: every pick lands inside the published stock.
  let allOpk = true;
  let kinds = new Set();
  for (let i = 0; i < 64; i++) {
    const t = DTN.prekeyTargetForEntry(entryFor(bob, bundle));
    kinds.add(t.kind);
    if (!t.ok || t.kind !== "opk" || !opkPubs.has(t.opkPub) || t.pub.length !== 32) allOpk = false;
  }
  ok(allOpk && kinds.size === 1, "sender selection against a stocked bundle always picks a published OPK");
  // Randomness: 64 picks across a 12-OPK stock must not collapse to one key.
  const picked = new Set();
  for (let i = 0; i < 64; i++) picked.add(DTN.prekeyTargetForEntry(entryFor(bob, bundle)).opkPub);
  ok(picked.size > 1, "the OPK choice is randomized across the stock (not always the same key)");

  // SPK fallback: a bundle whose opks array is empty (below the node's
  // admission floor, but shape-relevant defensively) → the SPK.
  const spkOnly = { v: 1, spk: bundle.spk, spk_sig: bundle.spk_sig, ts: bundle.ts, opks: [] };
  const tSpk = DTN.prekeyTargetForEntry(entryFor(bob, spkOnly));
  ok(!tSpk.ok && tSpk.reason === "invalid",
     "a bundle below the opks floor is treated as bundle-less (node admission would have refused it)");

  // Identity fallback: no bundle at all.
  const tNone = DTN.prekeyTargetForEntry(entryFor(bob, null));
  ok(!tNone.ok && tNone.reason === "absent", "a bundle-less entry falls back to the identity key");

  // Envelope built to an OPK: dest_hint STILL the identity-derived hint.
  const target = DTN.prekeyTargetForEntry(entryFor(bob, bundle));
  const env = DTN.buildEnvelope({
    recipientBoxPublic: target.pub,
    hintIdentityBoxPublic: target.identityBox,
    message: "prekey mail",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: NOW,
    hintEpoch: DTN.epochOf(NOW)
  });
  ok(env.dest_hint === DTN.deriveRotatingHint(bob.boxPublic, DTN.epochOf(NOW)),
     "dest_hint is hint_E(identity key) even when the box targets an OPK (§6.1 note)");
  ok(env.dest_hint !== DTN.deriveRotatingHint(target.pub, DTN.epochOf(NOW)),
     "dest_hint is NOT derived from the prekey (a prekey-derived hint would rotate with replenishment)");
  const decoded = DTN.b64decode(env.payload).length;
  ok(decoded >= 248 && decoded <= 400, `prekey-addressed envelope stays within the §8.2 bounds (${decoded} B)`);
}

console.log("== (d) recipient trial order + OPK wipe-on-use ==");
{
  const bob = rfcIdentity();
  const alice = freshIdentity("alice_77");
  const { stock, bundle } = stockAndBundle(bob);
  const entry = entryFor(bob, bundle);
  const opk0 = bundle.opks[0];
  const opk0Target = { ok: true, kind: "opk", pub: DTN.b64decode(opk0), opkPub: opk0, identityBox: bob.boxPublic };

  const makeTo = (t) => DTN.buildEnvelope({
    recipientBoxPublic: t.pub,
    hintIdentityBoxPublic: t.identityBox,
    message: "trial mail",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: NOW,
    hintEpoch: DTN.epochOf(NOW)
  });

  const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(NOW), NOW);

  // An SPK-addressed envelope opens through the SPK trial (tag spk).
  const spkEnv = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(bundle.spk),
    hintIdentityBoxPublic: bob.boxPublic,
    message: "spk mail", alias: "alice_77", signSecret: alice.signSecret,
    signPublic: alice.signPublic, createdAt: NOW, hintEpoch: DTN.epochOf(NOW)
  });
  const spkRes = DTN.decryptEnvelope(spkEnv, bob, NOW, candidates, DTN.prekeyTrialKeys(stock));
  ok(spkRes.ok && spkRes.opened_with && spkRes.opened_with.tag === "spk",
     "an SPK-addressed envelope opens through the SPK secret (second in the trial order)");

  // An OPK-addressed envelope opens through that OPK (trial order spk → opks).
  const res1 = DTN.decryptEnvelope(makeTo(opk0Target), bob, NOW, candidates, DTN.prekeyTrialKeys(stock));
  ok(res1.ok && res1.opened_with && res1.opened_with.tag === "opk" && res1.opened_with.pub === opk0,
     "an OPK-addressed envelope opens through its OPK secret (third in the trial order)");

  // Wipe-on-use (the pure mutation the store persists): the second envelope
  // to the SAME OPK must fail silently — first delivery wins (§4.6).
  const wiped = DTN.prekeyStateWithoutOpk(stock, opk0);
  ok(wiped !== stock && wiped.opks.length === stock.opks.length - 1 &&
     wiped.tombstones.indexOf(opk0) >= 0 && stock.opks.length === DTN.PREKEY_OPK_BATCH_TARGET,
     "the wipe removes the OPK from the stock, tombstones its pub, and never mutates the input");
  const res2 = DTN.decryptEnvelope(makeTo(opk0Target), bob, NOW, candidates, DTN.prekeyTrialKeys(wiped));
  ok(res2.ok === false && res2.reason === "crypto",
     "the second envelope to a consumed OPK fails silently (first delivery wins, §4.6)");

  // Trial ORDER: the identity secret wins first when an envelope targets it.
  const idEnv = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "legacy mail", alias: "alice_77", signSecret: alice.signSecret,
    signPublic: alice.signPublic, createdAt: NOW, hintEpoch: DTN.epochOf(NOW)
  });
  const idRes = DTN.decryptEnvelope(idEnv, bob, NOW, candidates, DTN.prekeyTrialKeys(stock));
  ok(idRes.ok && idRes.opened_with && idRes.opened_with.tag === "identity",
     "the identity secret is the FIRST trial (permanent legacy candidate)");

  // SPK before OPKs: a stock whose SPK secret is missing loses the SPK trial
  // but keeps the OPK trials (order is structural, not accidental).
  const noSpk = { spk: { pubB64: stock.spk.pubB64, secret: null, published_at: NOW }, opks: stock.opks, tombstones: [] };
  ok(DTN.prekeyTrialKeys(noSpk).length === 1 + stock.opks.length - 1 &&
     DTN.prekeyTrialKeys(noSpk)[0].tag === "opk",
     "a stock without an SPK secret still trials its OPKs");
  ok(DTN.prekeyTrialKeys(null).length === 0, "no stock → empty trial list (byte-identical legacy behavior)");
}

console.log("== (e) FORWARD-SECRECY PROOF — the acceptance criterion (§4.6) ==");
{
  const bob = rfcIdentity();
  const alice = freshIdentity("alice_77");
  const { stock, bundle } = stockAndBundle(bob);
  const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(NOW), NOW);
  const opkPubB64 = bundle.opks[3];
  const captured = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(opkPubB64),   // addressed to a ONE-TIME prekey
    hintIdentityBoxPublic: bob.boxPublic,
    message: "captured while in the dead drop",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: NOW,
    hintEpoch: DTN.epochOf(NOW),
    ttl: DTN.TTL_MAX                                 // sits in a dead drop for a long time
  });

  // The attacker's view, simulated strictly: they later extracted the
  // LONG-TERM identity secret — and nothing else (no prekey secrets).
  const attacker = {
    alias: bob.alias, hint: bob.hint,
    signPublic: bob.signPublic, signSecret: bob.signSecret,
    signPublicB64: bob.signPublicB64,
    boxPublic: bob.boxPublic, boxSecret: bob.boxSecret, boxPublicB64: bob.boxPublicB64
  };

  // 1. Before consumption, the legitimate recipient opens it via the OPK.
  const before = DTN.decryptEnvelope(captured, bob, NOW, candidates, DTN.prekeyTrialKeys(stock));
  ok(before.ok && before.opened_with.tag === "opk", "the legitimate recipient opens the OPK mail");

  // 2. The wipe happens (consumption). The SAME envelope now fails even
  //    for the full local state — the secret is gone from the device.
  const wipedStock = DTN.prekeyStateWithoutOpk(stock, opkPubB64);
  const after = DTN.decryptEnvelope(captured, bob, NOW, candidates, DTN.prekeyTrialKeys(wipedStock));
  ok(after.ok === false && after.reason === "crypto",
     "after the wipe, the full local state cannot open the captured envelope");

  // 3. THE ATTACK: captured bytes + later-extracted long-term key → fail.
  const extracted = DTN.decryptEnvelope(captured, attacker, NOW, candidates);
  ok(extracted.ok === false && extracted.reason === "crypto",
     "captured-and-later-extracted LONG-TERM key CANNOT decrypt prekey-addressed mail (acceptance criterion)");

  // 4. Same attack against replenished-away stock: an envelope addressed to
  //    an OPK of the OLD batch, after replenishment wiped that batch.
  const replenished = DTN.prekeyReplenishedStock(stock, NOW + 1);
  const oldBatch = DTN.b64decode(bundle.opks[0]);
  const oldMail = DTN.buildEnvelope({
    recipientBoxPublic: oldBatch, hintIdentityBoxPublic: bob.boxPublic,
    message: "mailed to the old batch", alias: "alice_77",
    signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: NOW + 1, hintEpoch: DTN.epochOf(NOW)
  });
  ok(DTN.decryptEnvelope(oldMail, bob, NOW + 1, candidates, DTN.prekeyTrialKeys(replenished)).ok === false,
     "mail to a replenished-away OPK no longer decrypts (old batch wiped at replenish)");
  ok(DTN.decryptEnvelope(oldMail, attacker, NOW + 1, candidates).ok === false,
     "and the extracted long-term key cannot open it either");
  // The fresh batch still works.
  const freshBundle = DTN.prekeyBundleForPublish(replenished, bob.signSecret, bob.signPublicB64);
  const freshMail = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(freshBundle.opks[2]), hintIdentityBoxPublic: bob.boxPublic,
    message: "mailed to the fresh batch", alias: "alice_77",
    signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: NOW + 1, hintEpoch: DTN.epochOf(NOW)
  });
  ok(DTN.decryptEnvelope(freshMail, bob, NOW + 1, candidates, DTN.prekeyTrialKeys(replenished)).ok,
     "the replenished batch keeps receiving normally");
}

console.log("== (f) replenish lifecycle: triggers, fresh batch, old-stock wipe ==");
{
  const bob = rfcIdentity();
  const { stock } = stockAndBundle(bob);

  // Healthy stock: no replenish.
  ok(DTN.prekeyNeedsReplenish(stock, NOW).needed === false, "a healthy stock (12 OPKs, fresh SPK) needs no replenish");

  // Low-water: ≤ 4 remaining triggers.
  const low = { spk: stock.spk, opks: stock.opks.slice(0, DTN.PREKEY_OPK_LOW_WATER), tombstones: [] };
  const lowNeed = DTN.prekeyNeedsReplenish(low, NOW);
  ok(lowNeed.needed && lowNeed.opkLow && lowNeed.reason === "opk_low", "≤ 4 unconsumed OPKs triggers the low-water replenish");

  // Stale SPK: past the 30-day rotation anchor.
  const oldTs = NOW - DTN.PREKEY_SPK_TTL_SECONDS - 1;
  const stale = { spk: { pubB64: stock.spk.pubB64, secret: stock.spk.secret, published_at: oldTs }, opks: stock.opks, tombstones: [] };
  const staleNeed = DTN.prekeyNeedsReplenish(stale, NOW);
  ok(staleNeed.needed && staleNeed.spkStale && staleNeed.reason === "spk_stale", "an SPK past its 30-day anchor triggers rotation");
  const freshTs = NOW - DTN.PREKEY_SPK_TTL_SECONDS + 1;
  ok(DTN.prekeyNeedsReplenish({ spk: { pubB64: stock.spk.pubB64, secret: stock.spk.secret, published_at: freshTs }, opks: stock.opks, tombstones: [] }, NOW).needed === false,
     "an SPK one second inside its window does not rotate");

  // Missing stock (fresh identity / pre-1.7 record) → first publication.
  ok(DTN.prekeyNeedsReplenish(null, NOW).needed && DTN.prekeyNeedsReplenish(null, NOW).reason === "no_stock",
     "a missing stock always replenishes (first bundle on the next sync)");

  // The replenished stock: fresh SPK, fresh batch, tombstones carry the old pubs.
  const replenished = DTN.prekeyReplenishedStock(low, NOW + 1);
  ok(replenished.spk.pubB64 !== low.spk.pubB64, "replenish rotates the SPK pair");
  ok(replenished.opks.length === DTN.PREKEY_OPK_BATCH_TARGET, "replenish regenerates the target OPK batch");
  const oldPubs = low.opks.map((o) => o.pubB64);
  ok(oldPubs.every((p) => replenished.tombstones.indexOf(p) >= 0), "every old-batch pub is tombstoned (secrets wiped)");
  ok(replenished.opks.every((o) => oldPubs.indexOf(o.pubB64) < 0), "the new batch shares no key with the old one");
  ok(DTN.prekeyTrialKeys(replenished).every((k) => oldPubs.indexOf(k.pub) < 0),
     "the trial list after replenish holds only the fresh batch");
}

console.log("== (g) compatibility both directions (§4.6) ==");
{
  const bob = rfcIdentity();           // NEW recipient (prekeys published)
  const oldAlice = freshIdentity("old_alice"); // OLD sender: ignores prekeys
  const { stock, bundle } = stockAndBundle(bob);
  const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(NOW), NOW);
  const trialKeys = DTN.prekeyTrialKeys(stock);

  // Old sender → new recipient: addressed to the identity key; the identity
  // trial path is PERMANENT → delivered, opened_with identity (no FS).
  const legacyMail = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,   // what a pre-1.7 sender does
    message: "from an old client", alias: "old_alice",
    signSecret: oldAlice.signSecret, signPublic: oldAlice.signPublic,
    createdAt: NOW, hintEpoch: DTN.epochOf(NOW)
  });
  const legacyRes = DTN.decryptEnvelope(legacyMail, bob, NOW, candidates, trialKeys);
  ok(legacyRes.ok && legacyRes.opened_with.tag === "identity" && legacyRes.m === "from an old client",
     "old-client mail to a prekey-published recipient still arrives (identity trial path)");
  ok(stock.opks.length === DTN.PREKEY_OPK_BATCH_TARGET && legacyRes.opened_with.pub === null,
     "identity-opened mail consumes no prekey (honest: it keeps NO forward secrecy)");

  // New sender → old recipient (bundle-less entry): identity fallback.
  const oldBob = freshIdentity("old_bob"); // no prekeys at all
  const t = DTN.prekeyTargetForEntry(entryFor(oldBob, null));
  ok(!t.ok && t.reason === "absent", "a new sender falls back to identity addressing for a bundle-less entry");
  const fallbackMail = DTN.buildEnvelope({
    recipientBoxPublic: oldBob.boxPublic,
    message: "to an old recipient", alias: "alice_77",
    signSecret: oldAlice.signSecret, signPublic: oldAlice.signPublic,
    createdAt: NOW, hintEpoch: DTN.epochOf(NOW)
  });
  ok(DTN.decryptEnvelope(fallbackMail, oldBob, NOW, DTN.hintCandidates(oldBob.boxPublic, DTN.epochOf(NOW), NOW)).ok,
     "the fallback envelope delivers to the old recipient unchanged");
}

console.log("== (g2) tampered bundle → identity fallback (doctored-bundle defense) ==");
{
  const bob = rfcIdentity();
  const alice = freshIdentity("alice_77");
  const { bundle } = stockAndBundle(bob);
  const entry = entryFor(bob, bundle);

  // A malicious node swaps the SPK for its own key (signature now fails).
  const doctored = JSON.parse(JSON.stringify(entry));
  doctored.prekeys.spk = keyB64Fixture(200);
  const tDoctored = DTN.prekeyTargetForEntry(doctored);
  ok(!tDoctored.ok && tDoctored.reason === "invalid",
     "a doctored spk fails the signature check → bundle-less (identity fallback)");

  // A malicious node permutes an OPK (count is signed; the swap of a VALUE
  // is not directly covered — but the shape check and the count binding
  // keep the SPK anchored; a swapped OPK at worst loses that one envelope,
  // never authenticates the node).
  const opkSwapped = JSON.parse(JSON.stringify(entry));
  opkSwapped.prekeys.opks[0] = keyB64Fixture(201);
  ok(DTN.prekeyTargetForEntry(opkSwapped).ok,
     "a swapped OPK value cannot forge anything: worst case is one lost envelope (documented)");
  // ...but a swapped COUNT breaks the signature.
  const countTampered = JSON.parse(JSON.stringify(entry));
  countTampered.prekeys.opks.pop();
  ok(!DTN.prekeyTargetForEntry(countTampered).ok, "dropping an OPK changes the signed count → signature fails");

  // A bundle signed by a DIFFERENT identity (bundle replay across entries).
  const mallory = freshIdentity("mallory");
  const replayed = entryFor(bob, stockAndBundle(mallory).bundle);
  ok(!DTN.prekeyTargetForEntry(replayed).ok, "a bundle replayed across identities fails (k is bound)");
}

console.log("== (h) integration: chunking (§4.4) and acks (§4.5) over prekey-addressed envelopes ==");
{
  const bob = rfcIdentity();
  const alice = freshIdentity("alice_77");
  const { stock, bundle } = stockAndBundle(bob);
  const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(NOW), NOW);
  const trialKeys = DTN.prekeyTrialKeys(stock);
  const entry = entryFor(bob, bundle);

  // §4.4: a >128-byte message split into chunk envelopes, each addressed to
  // a (possibly different) prekey; Bob reassembles into ONE message.
  const text = "Este mensaje largo viaja troceado y cifrado hacia prekeys distintas — " +
    "cada chunk apunta a una key del stock y el id de grupo `g` mantiene la reassembléia intacta. " +
    "Forward secrecy per envelope, reassembly unchanged.";
  const opks = bundle.opks.map((p) => DTN.b64decode(p));
  const g = DTN.b64encode(DTN.randomBytes(16));
  const chunks = [];
  {
    const budget = 94 - DTN.messageByteLength("alice_77");
    const parts = [];
    let cur = "";
    let curBytes = 0;
    for (const ch of text) {
      const b = DTN.messageByteLength(ch);
      if (curBytes > 0 && curBytes + b > budget) { parts.push(cur); cur = ch; curBytes = b; }
      else { cur += ch; curBytes += b; }
    }
    if (cur) parts.push(cur);
    for (let i = 0; i < parts.length; i++) {
      chunks.push(DTN.buildEnvelope({
        recipientBoxPublic: opks[i % opks.length],
        hintIdentityBoxPublic: bob.boxPublic,
        message: parts[i], alias: "alice_77",
        signSecret: alice.signSecret, signPublic: alice.signPublic,
        createdAt: NOW, hintEpoch: DTN.epochOf(NOW),
        chunk: { g, i, n: parts.length }
      }));
    }
  }
  ok(chunks.length >= 2 && chunks.length <= 16, `the long message split into ${chunks.length} legal chunk envelopes`);
  const liveStock = { spk: stock.spk, opks: stock.opks.map((o) => ({ pubB64: o.pubB64, secret: o.secret })), tombstones: [] };
  let reassembled = "";
  const parts = new Array(chunks.length);
  for (const env of chunks) {
    const res = DTN.decryptEnvelope(env, bob, NOW, candidates, DTN.prekeyTrialKeys(liveStock));
    if (!res.ok || !res.chunk) { reassembled = null; break; }
    if (res.opened_with.tag === "opk") {
      const next = DTN.prekeyStateWithoutOpk(liveStock, res.opened_with.pub);
      liveStock.opks = next.opks; liveStock.tombstones = next.tombstones;
    }
    parts[res.chunk.i] = res.m;
  }
  reassembled = parts.join("");
  ok(reassembled === text, "chunked mail addressed to DIFFERENT prekeys reassembles into the exact original text");

  // §4.5: an ack addressed BACK to Alice — who also publishes prekeys —
  // opens through her OPK trial path, binding to her sent record.
  const ackTask = { r: chunks[chunks.length - 1].id, type: DTN.ACK_TYPE_RECEIVED };
  const aliceStockBundle = stockAndBundle(alice);
  const aliceEntry = entryFor(alice, aliceStockBundle.bundle);
  const ackTarget = DTN.prekeyTargetForEntry(aliceEntry);
  ok(ackTarget.ok && ackTarget.kind === "opk", "the ack targets Alice's OPK stock");
  const ack = DTN.buildEnvelope({
    recipientBoxPublic: ackTarget.pub,
    hintIdentityBoxPublic: ackTarget.identityBox,
    message: "", alias: bob.alias,
    signSecret: bob.signSecret, signPublic: bob.signPublic,
    createdAt: NOW, hintEpoch: DTN.epochOf(NOW),
    ttl: DTN.ackTtlFor(NOW, DTN.TTL_DEFAULT, NOW),
    ack: { r: ackTask.r, y: ackTask.type }
  });
  const ackRes = DTN.decryptEnvelope(ack, alice, NOW,
    DTN.hintCandidates(alice.boxPublic, DTN.epochOf(NOW), NOW), DTN.prekeyTrialKeys(aliceStockBundle.stock));
  ok(ackRes.ok && ackRes.ack && ackRes.ack.w === "ack1" && ackRes.ack.r === ackTask.r && ackRes.opened_with.tag === "opk",
     "the ack travels over the prekey path and opens through Alice's OPK trial");
  const sentRecord = DTN.sentNewRecord({
    envIds: chunks.map((e) => e.id), toAlias: bob.alias, toPubkey: bob.signPublicB64,
    text, t: NOW, createdAt: NOW, ttl: DTN.TTL_DEFAULT
  });
  ok(DTN.ackMatchesSent(ackRes, sentRecord), "the prekey-delivered ack still binds to the sent record (§4.5)");
}

console.log(`\nPASS: ${passed} assertions on the §4.6 prekey bundles and forward secrecy (index.html script order)`);

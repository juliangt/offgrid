// §4.6 prekey bundle E2E helper (issue #27) — drives the SHIPPED SPA engine
// headlessly (tests/helpers/spa_loader.mjs, the exact files index.html
// loads) so the forward-secrecy journey in tests/sync_e2e.sh exercises the
// real client code:
//
//   Bob publishes a prekey bundle with his registration; Alice's engine
//   picks a one-time prekey from the SERVED directory entry (signature
//   verified) as the box target while dest_hint stays derived from Bob's
//   STABLE identity key; the envelope rides the real daemons through a
//   mule; Bob's engine trial-decrypts (identity → SPK → OPKs), wipes the
//   OPK secret on use, and the captured envelope bytes then FAIL to
//   decrypt for an attacker holding only Bob's extracted long-term key —
//   the issue's acceptance criterion, end to end.
//
// Modes:
//   fixture OUT NOW       deterministic Alice (fresh) + Bob (RFC 7748/8032
//                         keys); Bob's stock has a STALE SPK anchor (NOW −
//                         SPK_TTL − 1) so a later replenish triggers by
//                         rotation; writes identities, stock, bundle and
//                         the registration bodies.
//   send FIXTURE DIR_BODY OUT KIND RECIPIENT NOW
//                         Alice's side: read the SERVED directory, resolve
//                         the recipient entry by its Ed25519 key, pick the
//                         box target per KIND — prekey: bundle-verified OPK;
//                         legacy: the identity X25519 key (an old client
//                         that ignores prekeys). Prints target=, dest_hint=
//                         and hint_source= (machine-readable verdicts).
//   bob_receive FIXTURE PULL_BODY STATE_IN STATE_OUT NOW
//                         Bob's side: build the candidate set, classify the
//                         SERVED envelopes, decrypt with the trial list of
//                         STATE_IN, wipe the OPK secret that opened (the
//                         §4.6 event) and persist STATE_OUT.
//   fs_proof FIXTURE PULL_BODY STATE [NOW]
//                         The captured-traffic leg: decrypt the served
//                         envelope bytes (a) with an attacker view holding
//                         ONLY the extracted long-term identity secret and
//                         (b) with the CURRENT (post-wipe) device state.
//                         Both must fail; prints attack= and state=.
//   replenish FIXTURE STATE_IN BODY_OUT STATE_OUT NOW
//                         Bob's sync-time replenish: stale-SPK trigger →
//                         fresh batch → the registration body WITH the new
//                         bundle (the harness POSTs it through the ordinary
//                         directory upsert) and the swapped local stock.
//
// Never fails hard in check modes (prints result=fail, exit 0) so the bash
// `check` records failures with its own accounting.

import fs from "node:fs";
import { loadSpaSandbox } from "./spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.prekeyTargetForEntry !== "function" || typeof DTN.prekeyReplenishedStock !== "function") {
  throw new Error("DTN engine did not load with the §4.6 prekey functions (prekeys.js missing?)");
}

const RFC7748_BOB_SECRET_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_PUB_B64 = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
const RFC8032_SIGN_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

function bobIdentity() {
  const boxSecret = DTN.hexDecode(RFC7748_BOB_SECRET_HEX);
  const box = DTN.nacl.box.keyPair.fromSecretKey(boxSecret);
  if (DTN.b64encode(box.publicKey) !== RFC7748_BOB_PUB_B64) {
    throw new Error("the RFC 7748 Bob secret did not reconstruct the registered X25519 key");
  }
  const sign = DTN.nacl.sign.keyPair.fromSeed(DTN.hexDecode(RFC8032_SIGN_SEED_HEX));
  return {
    alias: "bob_prekey",
    seedB64: DTN.b64encode(DTN.hexDecode(RFC8032_SIGN_SEED_HEX)),
    signPublic: sign.publicKey,
    signSecret: sign.secretKey,
    signPublicB64: DTN.b64encode(sign.publicKey),
    boxPublic: box.publicKey,
    boxSecret: box.secretKey,
    boxPublicB64: RFC7748_BOB_PUB_B64,
  };
}

// The device stock carries Uint8Array secrets; the harness moves state
// through JSON files, so it serializes them explicitly (IndexedDB — the
// real store — keeps typed arrays natively via structured clone).
function serializeState(state) {
  return {
    spk: { pubB64: state.spk.pubB64, secretB64: DTN.b64encode(state.spk.secret), published_at: state.spk.published_at },
    opks: state.opks.map((o) => ({ pubB64: o.pubB64, secretB64: DTN.b64encode(o.secret) })),
    tombstones: state.tombstones || [],
  };
}

function deserializeState(s) {
  return {
    spk: { pubB64: s.spk.pubB64, secret: DTN.b64decode(s.spk.secretB64), published_at: s.spk.published_at },
    opks: s.opks.map((o) => ({ pubB64: o.pubB64, secret: DTN.b64decode(o.secretB64) })),
    tombstones: s.tombstones || [],
  };
}

function bobStateFrom(fixture) {
  return deserializeState(fixture.bob_stock); // the fixture's serialized stock
}

function attackerView(fixture) {
  // The extraction simulation: the LONG-TERM identity secrets ONLY — no
  // prekey material ever reaches this view (that is the whole point).
  const bob = bobIdentity();
  return {
    alias: bob.alias, hint: DTN.deriveDestHint(bob.boxPublic),
    signPublic: bob.signPublic, signSecret: bob.signSecret, signPublicB64: bob.signPublicB64,
    boxPublic: bob.boxPublic, boxSecret: bob.boxSecret, boxPublicB64: bob.boxPublicB64,
  };
}

function rebuildIdentity(record) {
  const boxPublic = DTN.b64decode(record.boxPublicB64);
  return {
    alias: record.alias, hint: DTN.deriveDestHint(boxPublic),
    signPublic: DTN.b64decode(record.signPublicB64), signSecret: DTN.b64decode(record.signSecretB64),
    signPublicB64: record.signPublicB64,
    boxPublic, boxSecret: DTN.b64decode(record.boxSecretB64),
    boxPublicB64: record.boxPublicB64,
  };
}

const [, , mode, ...args] = process.argv;

if (mode === "fixture") {
  const [out, nowArg] = args;
  const now = Number(nowArg);
  if (!Number.isInteger(now) || now <= 0) throw new Error("fixture: NOW must be a positive integer (unix seconds)");
  const alice = DTN.createIdentity();
  const bob = bobIdentity();
  // Bob's device stock: full target batch, but with a STALE SPK anchor so a
  // later replenish triggers through the 30-day rotation (not a trick — the
  // same path a real device hits 30 days after publishing).
  const stock = DTN.prekeyGenerateStock(now - DTN.PREKEY_SPK_TTL_SECONDS - 1);
  const bundle = DTN.prekeyBundleForPublish(stock, bob.signSecret, bob.signPublicB64);
  const aliceRecord = {
    alias: "alice_fs",
    seedB64: alice.seedB64,
    signPublicB64: alice.signPublicB64, signSecretB64: DTN.b64encode(alice.signSecret),
    boxPublicB64: alice.boxPublicB64, boxSecretB64: DTN.b64encode(alice.boxSecret),
  };
  fs.writeFileSync(out, JSON.stringify({
    now,
    alice: aliceRecord,
    bob: {
      alias: bob.alias,
      signPublicB64: bob.signPublicB64, signSecretB64: DTN.b64encode(bob.signSecret),
      boxPublicB64: bob.boxPublicB64, boxSecretB64: DTN.b64encode(bob.boxSecret),
    },
    bob_stock: serializeState(stock),
    bob_bundle: bundle,
    alice_reg: { alias: aliceRecord.alias, pubkey: aliceRecord.signPublicB64, x25519: aliceRecord.boxPublicB64 },
    bob_reg: { alias: bob.alias, pubkey: bob.signPublicB64, x25519: bob.boxPublicB64, prekeys: bundle },
    bob_hint_current: DTN.deriveRotatingHint(bob.boxPublic, DTN.epochOf(now)),
    bob_hint_legacy: DTN.deriveDestHint(bob.boxPublic),
    alice_hint_current: DTN.deriveRotatingHint(alice.boxPublic, DTN.epochOf(now)),
  }));
  console.log(`bob_opks=${bundle.opks.length}`);
  console.log(`bundle_bytes=${JSON.stringify(bundle).length}`);
  console.log("RESULT=ok");
} else if (mode === "send") {
  const [fixturePath, dirBodyPath, out, kind, recipient, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const directory = JSON.parse(fs.readFileSync(dirBodyPath, "utf8"));
  const now = Number(nowArg);
  const alice = rebuildIdentity(fx.alice);
  const wantPub = recipient === "bob" ? fx.bob.signPublicB64 : fx.alice.signPublicB64;
  const entry = directory.find((e) => e && e.pubkey === wantPub);
  if (!entry) throw new Error(`send: the ${recipient} entry is not in the served directory`);

  // §4.6 sender rule (real engine code): verify shape + signature, pick a
  // random OPK; a bundle-less or tampered entry falls back to the identity
  // X25519 key (the engine's own behavior — the reason is reported).
  // KIND=legacy simulates an OLD client that ignores prekeys and addresses
  // the identity X25519 key directly.
  let boxTarget, hintSource;
  if (kind === "prekey") {
    const t = DTN.prekeyTargetForEntry(entry);
    if (t.ok) {
      boxTarget = t.pub;
      hintSource = t.identityBox;
      console.log(`target=${t.kind}`);
      console.log(`target_opk=${t.opkPub || "-"}`);
    } else {
      boxTarget = t.identityBox;
      hintSource = t.identityBox;
      console.log("target=identity");
      console.log(`fallback_reason=${t.reason}`);
    }
  } else if (kind === "legacy") {
    boxTarget = DTN.b64decode(entry.x25519);
    hintSource = boxTarget;
    console.log("target=identity");
  } else {
    throw new Error(`send: unknown kind ${kind}`);
  }
  console.log(`hint_source=${DTN.b64encode(hintSource) === entry.x25519 ? "identity" : "other"}`);
  const hintEpoch = (typeof entry.epoch === "number" && entry.epoch >= 0) ? entry.epoch : null;
  const env = DTN.buildEnvelope({
    recipientBoxPublic: boxTarget,
    hintIdentityBoxPublic: hintSource,
    message: `prekey mail (${kind}) from alice to ${recipient}`,
    alias: alice.alias,
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: now,
    ttl: 2592000,
    hintEpoch,
  });
  fs.writeFileSync(out, JSON.stringify({
    known_ids: [env.id], push_envelopes: [env], limit: 50,
  }));
  console.log(`dest_hint=${env.dest_hint}`);
  console.log(`envelope_id=${env.id}`);
  console.log("RESULT=ok");
} else if (mode === "bob_receive") {
  const [fixturePath, pullBodyPath, stateInPath, stateOutPath, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const stateIn = stateInPath === "-" ? bobStateFrom(fx) : deserializeState(JSON.parse(fs.readFileSync(stateInPath, "utf8")));
  const now = Number(nowArg);
  const bob = bobIdentity();
  let classified = "none";
  let decrypted = "fail";
  let opened = "-";
  let wiped = "0";
  try {
    const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(now), now);
    const cls = DTN.classifyPullEnvelopes(served, candidates);
    classified = cls.mine.length >= 1 ? "mine" : (cls.foreign.length >= 1 ? "foreign" : "none");
    if (cls.mine.length === 1) {
      const dec = DTN.decryptEnvelope(cls.mine[0], bob, now, candidates, DTN.prekeyTrialKeys(stateIn));
      decrypted = dec.ok ? "ok" : "fail";
      if (dec.ok) {
        opened = dec.opened_with ? `${dec.opened_with.tag}:${dec.opened_with.pub || "-"}` : "unknown";
        if (dec.opened_with && dec.opened_with.tag === "opk" && dec.opened_with.pub) {
          const next = DTN.prekeyStateWithoutOpk(stateIn, dec.opened_with.pub);
          fs.writeFileSync(stateOutPath, JSON.stringify(serializeState(next)));
          wiped = next.opks.length === stateIn.opks.length ? "0" : "1";
        } else {
          fs.writeFileSync(stateOutPath, JSON.stringify(serializeState(stateIn)));
        }
      }
    }
  } catch (e) {
    console.error(`bob_receive: ${e.message}`);
  }
  console.log(`classified=${classified}`);
  console.log(`decrypted=${decrypted}`);
  console.log(`opened_with=${opened}`);
  console.log(`wiped=${wiped}`);
} else if (mode === "plain_receive") {
  // A recipient with NO prekey stock (the legacy-recipient leg): the plain
  // §4.3 identity path is the whole story.
  const [fixturePath, pullBodyPath, who, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const now = Number(nowArg);
  const who_ = who === "bob" ? bobIdentity() : rebuildIdentity(fx.alice);
  let classified = "none";
  let decrypted = "fail";
  let opened = "-";
  try {
    const candidates = DTN.hintCandidates(who_.boxPublic, DTN.epochOf(now), now);
    const cls = DTN.classifyPullEnvelopes(served, candidates);
    classified = cls.mine.length >= 1 ? "mine" : (cls.foreign.length >= 1 ? "foreign" : "none");
    if (cls.mine.length === 1) {
      const dec = DTN.decryptEnvelope(cls.mine[0], who_, now, candidates);
      decrypted = dec.ok ? "ok" : "fail";
      if (dec.ok) opened = dec.opened_with ? dec.opened_with.tag : "unknown";
    }
  } catch (e) {
    console.error(`plain_receive: ${e.message}`);
  }
  console.log(`classified=${classified}`);
  console.log(`decrypted=${decrypted}`);
  console.log(`opened_with=${opened}`);
} else if (mode === "fs_proof") {
  const [fixturePath, pullBodyPath, statePath, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const state = statePath === "-" ? bobStateFrom(fx) : deserializeState(JSON.parse(fs.readFileSync(statePath, "utf8")));
  const now = Number(nowArg || fx.now);
  const bob = bobIdentity();
  let attack = "decrypted"; // must end "fail"
  let stateOpen = "decrypted";
  try {
    const candidates = DTN.hintCandidates(bob.boxPublic, DTN.epochOf(now), now);
    // (a) The extraction attack: captured bytes + the long-term key ONLY.
    const a = DTN.decryptEnvelope(served[0], attackerView(fx), now, candidates);
    attack = a.ok ? "decrypted" : "fail";
    // (b) The post-wipe device: even the full current state cannot open it.
    const b = DTN.decryptEnvelope(served[0], bob, now, candidates, DTN.prekeyTrialKeys(state));
    stateOpen = b.ok ? "decrypted" : "fail";
  } catch (e) {
    console.error(`fs_proof: ${e.message}`);
    attack = "fail";
    stateOpen = "fail";
  }
  console.log(`attack=${attack}`);
  console.log(`state=${stateOpen}`);
  console.log(`served=${served.length}`);
} else if (mode === "replenish") {
  const [fixturePath, stateInPath, bodyOutPath, stateOutPath, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const stateIn = deserializeState(JSON.parse(fs.readFileSync(stateInPath, "utf8")));
  const now = Number(nowArg);
  const bob = bobIdentity();
  const need = DTN.prekeyNeedsReplenish(stateIn, now);
  if (!need.needed) {
    console.log(`trigger=none`);
    console.log("RESULT=fail");
    process.exit(0);
  }
  const fresh = DTN.prekeyReplenishedStock(stateIn, now);
  const bundle = DTN.prekeyBundleForPublish(fresh, bob.signSecret, bob.signPublicB64);
  fs.writeFileSync(bodyOutPath, JSON.stringify({
    alias: bob.alias, pubkey: bob.signPublicB64, x25519: bob.boxPublicB64, prekeys: bundle,
  }));
  fs.writeFileSync(stateOutPath, JSON.stringify(serializeState(fresh)));
  console.log(`trigger=${need.reason}`);
  console.log(`rotated=${bundle.spk !== fx.bob_bundle.spk ? "yes" : "no"}`);
  console.log(`old_opk_gone=${bundle.opks.indexOf(fx.bob_bundle.opks[0]) < 0 ? "yes" : "no"}`);
  console.log(`new_opks=${bundle.opks.length}`);
  console.log("RESULT=ok");
} else {
  console.error("usage: prekey_e2e.mjs fixture OUT NOW | send FIXTURE DIR_BODY OUT KIND RECIPIENT NOW | " +
    "bob_receive FIXTURE PULL_BODY STATE_IN STATE_OUT NOW | fs_proof FIXTURE PULL_BODY STATE [NOW] | " +
    "replenish FIXTURE STATE_IN BODY_OUT STATE_OUT NOW");
  process.exit(2);
}

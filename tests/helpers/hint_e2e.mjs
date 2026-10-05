// §6.1 rotating dest_hint E2E helper (issue #26) — drives the SHIPPED SPA
// engine headlessly (tests/helpers/spa_loader.mjs, the exact files
// index.html loads) so the rotating-hint journey in tests/sync_e2e.sh
// exercises the real client code:
//
//   Alice's engine derives the dest_hint from the SERVER-SET epoch of the
//   recipient's directory entry (never her device clock), the envelope
//   rides the real daemons through a mule, and Bob's engine recognizes it
//   through his §6.1 candidate set {static legacy, hint(E), hint(E−1)} —
//   including across a simulated epoch boundary and after the simulated
//   transition deadline (injected clocks: the harness passes NOW and the
//   observed epoch explicitly, no wall-clock dependence).
//
// Modes:
//   fixture OUT NOW               deterministic identities (Alice fresh,
//                                 Bob = the RFC 7748 §6.1 key pair) and the
//                                 registration bodies; logs epoch= for NOW.
//   send FIXTURE DIR_BODY OUT KIND NOW
//                                 Alice's side: read the SERVED directory,
//                                 resolve Bob's entry by his Ed25519 key,
//                                 address per KIND — current: the entry's
//                                 server-set epoch; prev: one epoch older
//                                 (envelope minted before a boundary);
//                                 legacy: no hintEpoch (the pre-1.6 static
//                                 hint). Writes the sync body and prints
//                                 machine-readable lines.
//   bob_check FIXTURE PULL_BODY OBSERVED_EPOCH NOW
//                                 Bob's side: build the §6.1 candidate set
//                                 for the OBSERVED epoch at clock NOW,
//                                 classify the SERVED envelopes, decrypt
//                                 the ones that are his; print the verdict
//                                 lines (the harness asserts on them).
//   caps CAPS_BODY                verify the additive §6.1 capabilities
//                                 members on a served document.
//
// Never fails hard in check modes (prints result=fail, exit 0) so the bash
// `check` records failures with its own accounting.

import fs from "node:fs";
import { loadSpaSandbox } from "./spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.deriveRotatingHint !== "function" || typeof DTN.hintCandidates !== "function") {
  throw new Error("DTN engine did not load with the §6.1 functions (envelopes.js/mule.js missing?)");
}

// The registered Bob: the RFC 7748 §6.1 key pair (same fixture key the ack
// E2E registers) — deterministic, so hints are reproducible.
const RFC7748_BOB_SECRET_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_PUB_B64 = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
// Bob's Ed25519 signing key (RFC 8032 §7.1 seed) — the directory identity.
const RFC8032_SIGN_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

function bobIdentity() {
  const boxSecret = DTN.hexDecode(RFC7748_BOB_SECRET_HEX);
  const box = DTN.nacl.box.keyPair.fromSecretKey(boxSecret);
  if (DTN.b64encode(box.publicKey) !== RFC7748_BOB_PUB_B64) {
    throw new Error("the RFC 7748 Bob secret did not reconstruct the registered X25519 key");
  }
  const sign = DTN.nacl.sign.keyPair.fromSeed(DTN.hexDecode(RFC8032_SIGN_SEED_HEX));
  return {
    boxPublic: box.publicKey,
    boxSecret: box.secretKey,
    boxPublicB64: RFC7748_BOB_PUB_B64,
    signPublic: sign.publicKey,
    signPublicB64: DTN.b64encode(sign.publicKey),
  };
}

function aliceSeedFrom(fixture) {
  return DTN.identityFromSeed(DTN.b64decode(fixture.alice_seed));
}

const [, , mode, ...args] = process.argv;

if (mode === "fixture") {
  const [out, nowArg] = args;
  const now = Number(nowArg);
  if (!Number.isInteger(now) || now <= 0) throw new Error("fixture: NOW must be a positive integer (unix seconds)");
  const alice = DTN.createIdentity();
  const bob = bobIdentity();
  const epoch = DTN.epochOf(now);
  fs.writeFileSync(out, JSON.stringify({
    alice_seed: alice.seedB64,
    alice_pub: alice.signPublicB64,
    alice_x25519: alice.boxPublicB64,
    bob_pub: bob.signPublicB64,
    bob_x25519: bob.boxPublicB64,
    bob_hint_legacy: DTN.deriveDestHint(bob.boxPublic),
    bob_hint_current: DTN.deriveRotatingHint(bob.boxPublic, epoch),
    bob_hint_prev: DTN.deriveRotatingHint(bob.boxPublic, epoch - 1),
    epoch,
    alice_reg: { alias: "alice_hint", pubkey: alice.signPublicB64, x25519: alice.boxPublicB64 },
    // The registration body carries a SPOOFED epoch member: the node sets
    // the epoch server-side (§6.1), so this value must never surface.
    bob_reg: { alias: "bob_hint", pubkey: bob.signPublicB64, x25519: bob.boxPublicB64, epoch: 123456789 },
  }));
  console.log(`epoch=${epoch}`);
  console.log(`hint_current=${DTN.deriveRotatingHint(bob.boxPublic, epoch)}`);
  console.log(`hint_prev=${DTN.deriveRotatingHint(bob.boxPublic, epoch - 1)}`);
  console.log(`hint_legacy=${DTN.deriveDestHint(bob.boxPublic)}`);
  console.log("RESULT=ok");
} else if (mode === "send") {
  const [fixturePath, dirBodyPath, out, kind, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const directory = JSON.parse(fs.readFileSync(dirBodyPath, "utf8"));
  const now = Number(nowArg);
  const alice = aliceSeedFrom(fx);
  const entry = directory.find((e) => e && e.pubkey === fx.bob_pub);
  const bobBox = entry ? DTN.b64decode(entry.x25519) : null;
  if (!entry || !bobBox || bobBox.length !== 32) throw new Error("send: Bob's entry not resolvable from the served directory");

  // §6.1 sender rule: the epoch comes from the DIRECTORY ENTRY (the
  // server-set truth), never from the device clock. The kinds:
  //   current — exactly the entry's epoch (the normal 1.6 sender);
  //   prev    — one epoch older (envelope minted before a boundary);
  //   legacy  — no epoch at all (a pre-1.6 sender's static hint).
  let usedEpoch = null;
  if (kind === "current") usedEpoch = entry.epoch;
  else if (kind === "prev") usedEpoch = entry.epoch - 1;
  else if (kind !== "legacy") throw new Error(`send: unknown kind ${kind}`);
  const hintEpoch = (kind === "legacy" || typeof entry.epoch !== "number" || entry.epoch < 1) ? null : usedEpoch;

  const env = DTN.buildEnvelope({
    recipientBoxPublic: bobBox,
    message: `rotating mail (${kind}) from alice to bob`,
    alias: "alice_hint",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: now,
    ttl: 2592000, // TTL_MAX: the mail legitimately outlives an epoch boundary
    hintEpoch,
  });
  fs.writeFileSync(out, JSON.stringify({
    known_ids: [env.id], push_envelopes: [env], limit: 50,
  }));
  console.log(`dest_hint=${env.dest_hint}`);
  console.log(`used_epoch=${hintEpoch === null ? "none" : hintEpoch}`);
  console.log(`kind=${kind}`);
  console.log("RESULT=ok");
} else if (mode === "bob_check") {
  const [fixturePath, pullBodyPath, observedArg, nowArg] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const observed = observedArg === "none" ? null : Number(observedArg);
  const now = Number(nowArg);
  const bob = bobIdentity();
  let classified = "none";
  let decrypted = "fail";
  let reason = "";
  let textOk = "fail";
  try {
    // Bob's real receive path: the candidate set for his freshest observed
    // epoch, then classify + decrypt the served envelopes (§6.1, §11).
    const candidates = DTN.hintCandidates(bob.boxPublic, observed, now);
    const cls = DTN.classifyPullEnvelopes(served, candidates);
    classified = cls.mine.length >= 1 ? "mine" : (cls.foreign.length >= 1 ? "foreign" : "none");
    if (cls.mine.length === 1) {
      const dec = DTN.decryptEnvelope(cls.mine[0], bob, now, candidates);
      decrypted = dec.ok ? "ok" : "fail";
      reason = dec.ok ? "" : String(dec.reason);
      textOk = dec.ok && String(dec.m).startsWith("rotating mail") ? "ok" : "fail";
    }
  } catch (e) {
    console.error(`bob_check: ${e.message}`);
  }
  console.log(`classified=${classified}`);
  console.log(`decrypted=${decrypted}`);
  console.log(`reason=${reason}`);
  console.log(`text_ok=${textOk}`);
  console.log(`served=${served.length}`);
} else if (mode === "caps") {
  const caps = JSON.parse(fs.readFileSync(args[0], "utf8"));
  const okSeconds = caps.hint_epoch_seconds === DTN.HINT_EPOCH_SECONDS;
  const okCurrent = typeof caps.hint_epoch_current === "number" &&
    Number.isInteger(caps.hint_epoch_current) && caps.hint_epoch_current >= 0;
  console.log(`seconds=${caps.hint_epoch_seconds}`);
  console.log(`current=${caps.hint_epoch_current}`);
  console.log(`result=${okSeconds && okCurrent ? "ok" : "fail"}`);
} else {
  console.error("usage: hint_e2e.mjs fixture OUT NOW | send FIXTURE DIR_BODY OUT KIND NOW | " +
    "bob_check FIXTURE PULL_BODY OBSERVED_EPOCH NOW | caps CAPS_BODY");
  process.exit(2);
}

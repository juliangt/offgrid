// §4.7 identity QR E2E helper (issue #28) — drives the SHIPPED SPA engine
// headlessly (tests/helpers/spa_loader.mjs, the exact files index.html
// loads) so the acceptance journey in tests/sync_e2e.sh exercises the real
// client code:
//
//   Two people meet in person and exchange identities via the OFFGRID1 QR
//   payload. Alice imports Bob's payload (engine parse + verify → contact
//   record) and Bob imports Alice's the same way — the node directory is
//   NEVER consulted (it stays empty; the harness proves it). Alice then
//   sends to that CONTACT with the directory endpoint unused: the engine
//   addresses the identity X25519 key with the §6.1 offline-cold static
//   hint and the §4.6 identity fallback; Bob receives, decrypts and
//   replies through his own contact record the same way. A TAMPERED
//   payload (one flipped Base64 character) is rejected with a visible
//   reason and stores nothing.
//
// Modes:
//   fixture OUT NOW       fresh Alice + Bob identities, both QR payloads
//                         (Alice's and Bob's), the contact record each
//                         side saves from the other's payload, a TAMPERED
//                         copy of Bob's payload (one flipped Base64 char)
//                         and the legacy static hints for both.
//   import PAYLOAD_FILE CONTACT_OUT NOW
//                         The engine import path: qrParsePayload (the
//                         same parser the camera scan and the paste box
//                         share) → qrContactRecord. On success writes the
//                         contact record and prints parsed=ok; on failure
//                         prints parsed=fail reason=... and writes NOTHING.
//   send IDENTITY_FILE CONTACT_FILE OUT MESSAGE NOW
//                         The composer path against a CONTACT-ONLY
//                         recipient: no epoch (§6.1 offline-cold static
//                         hint), no prekeys (§4.6 identity fallback).
//                         Prints dest_hint= and envelope_id=, writes the
//                         §10.4 sync body.
//   receive IDENTITY_FILE PULL_BODY NOW
//                         The recipient path: classify the served
//                         envelopes against the §6.1 candidate set
//                         (device clock — offline-cold), decrypt and
//                         verify. Prints classified=, decrypted= and m=.
//
// Never fails hard in check modes (prints result=fail, exit 0) so the bash
// `check` records failures with its own accounting.

import fs from "node:fs";
import { loadSpaSandbox } from "./spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.qrBuildPayload !== "function" || typeof DTN.qrParsePayload !== "function") {
  throw new Error("DTN engine did not load with the §4.7 QR functions (qr.js missing?)");
}

function serializeIdentity(id) {
  return {
    alias: id.alias,
    seedB64: id.seedB64,
    signPublicB64: id.signPublicB64,
    signSecretB64: DTN.b64encode(id.signSecret),
    boxPublicB64: id.boxPublicB64,
    boxSecretB64: DTN.b64encode(id.boxSecret),
  };
}

function rebuildIdentity(record) {
  const id = DTN.identityFromSeed(DTN.b64decode(record.seedB64));
  if (DTN.b64encode(id.signPublic) !== record.signPublicB64 ||
      DTN.b64encode(id.boxPublic) !== record.boxPublicB64) {
    throw new Error("rebuildIdentity: the seed did not reconstruct the recorded keys");
  }
  id.alias = record.alias;
  return id;
}

const [, , mode, ...args] = process.argv;

if (mode === "fixture") {
  const [out, nowArg] = args;
  const now = Number(nowArg);
  if (!Number.isInteger(now) || now <= 0) throw new Error("fixture: NOW must be a positive integer (unix seconds)");
  const alice = DTN.createIdentity();
  alice.alias = "qr_alice";
  const bob = DTN.createIdentity();
  bob.alias = "qr_bob";

  // The QR exchange itself: each side builds its payload (qrBuildPayload)
  // and imports the other's (qrParsePayload + qrContactRecord — the exact
  // engine path the "Add contact" flow runs).
  const alicePayload = DTN.qrBuildPayload(alice, now);
  const bobPayload = DTN.qrBuildPayload(bob, now);
  const aliceParsesBob = DTN.qrParsePayload(bobPayload, now);
  const bobParsesAlice = DTN.qrParsePayload(alicePayload, now);
  if (!aliceParsesBob.ok || !bobParsesAlice.ok) throw new Error("fixture: the freshly built payloads failed to parse");
  const tampered = (() => {
    // Byte-precise tamper, deterministic: decode the payload body, flip
    // ONE bit of one byte in the middle of the X25519 key's value (inside
    // the CRC-covered region, never a JSON structure byte), re-encode.
    // This is exactly the byte-region damage a partial scan/paste leaves —
    // the JSON still parses, one value byte changed, and the CRC-32 must
    // catch it.
    const head = "OFFGRID1:";
    const body = Buffer.from(bobPayload.slice(head.length), "base64");
    const text = body.toString("latin1");
    const marker = text.indexOf('"x":"');
    if (marker < 0) throw new Error("fixture: the payload body has no x member");
    const flipAt = marker + 5 + 20; // middle of the 44-char Base64 x value
    // Swap the byte for a DIFFERENT Base64-alphabet character (never a
    // bit flip that could leave the alphabet and break the JSON member).
    body[flipAt] = body[flipAt] === 0x41 ? 0x42 : 0x41;
    const t = head + body.toString("base64");
    if (t === bobPayload) throw new Error("fixture: the tampered payload equals the original");
    return t;
  })();

  fs.writeFileSync(out, JSON.stringify({
    now,
    alice: serializeIdentity(alice),
    bob: serializeIdentity(bob),
    alice_payload: alicePayload,
    bob_payload: bobPayload,
    tampered_payload: tampered,
    alice_contact_of_bob: DTN.qrContactRecord(aliceParsesBob, "qr", now),
    bob_contact_of_alice: DTN.qrContactRecord(bobParsesAlice, "qr", now),
    alice_hint_legacy: DTN.deriveDestHint(alice.boxPublic),
    bob_hint_legacy: DTN.deriveDestHint(bob.boxPublic),
  }));
  console.log(`payload_chars=${bobPayload.length}`);
  console.log(`tamper_differs=${tampered !== bobPayload ? "yes" : "no"}`);
  console.log("RESULT=ok");
} else if (mode === "import") {
  const [payloadPath, contactOut, nowArg] = args;
  const now = Number(nowArg);
  const payload = fs.readFileSync(payloadPath, "utf8");
  const parsed = DTN.qrParsePayload(payload, now);
  if (!parsed.ok) {
    // §4.7: the rejection is VISIBLE (the reason is reported) and NOTHING
    // is stored — the contact file is never written.
    console.log(`parsed=fail`);
    console.log(`reason=${parsed.reason}`);
    console.log("RESULT=fail");
    process.exit(0);
  }
  fs.writeFileSync(contactOut, JSON.stringify(DTN.qrContactRecord(parsed, "qr", now)));
  console.log(`parsed=ok`);
  console.log(`alias=${parsed.contact.alias}`);
  console.log(`ed=${parsed.contact.ed}`);
  console.log(`x=${parsed.contact.x}`);
  console.log("RESULT=ok");
} else if (mode === "send") {
  const [identityPath, contactPath, out, message, nowArg] = args;
  const now = Number(nowArg);
  const identity = rebuildIdentity(JSON.parse(fs.readFileSync(identityPath, "utf8")));
  const contact = JSON.parse(fs.readFileSync(contactPath, "utf8"));
  // Contact-only recipient: the contact record carries x but NO epoch and
  // NO prekeys — the box targets the identity X25519 key (§4.6 fallback)
  // and dest_hint is the §6.1 offline-cold static hint (no directory read).
  if (!contact || typeof contact.x !== "string") {
    throw new Error("send: the contact record is malformed");
  }
  const env = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(contact.x),
    hintIdentityBoxPublic: DTN.b64decode(contact.x),
    message,
    alias: identity.alias,
    signSecret: identity.signSecret,
    signPublic: identity.signPublic,
    createdAt: now,
    ttl: DTN.TTL_MAX,
    // hintEpoch deliberately absent → the legacy static hint (§6.1)
  });
  fs.writeFileSync(out, JSON.stringify({ known_ids: [env.id], push_envelopes: [env], limit: 50 }));
  console.log(`dest_hint=${env.dest_hint}`);
  console.log(`envelope_id=${env.id}`);
  console.log("RESULT=ok");
} else if (mode === "receive") {
  const [identityPath, pullBodyPath, nowArg] = args;
  const now = Number(nowArg);
  const identity = rebuildIdentity(JSON.parse(fs.readFileSync(identityPath, "utf8")));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  let classified = "none";
  let decrypted = "fail";
  let m = "-";
  try {
    // Offline-cold candidate set: no node epoch observed, the device clock
    // fills in — the static legacy hint stays a candidate inside the
    // §6.1 transition window.
    const candidates = DTN.hintCandidates(identity.boxPublic, null, now);
    const cls = DTN.classifyPullEnvelopes(served, candidates);
    classified = cls.mine.length >= 1 ? "mine" : (cls.foreign.length >= 1 ? "foreign" : "none");
    if (cls.mine.length === 1) {
      const dec = DTN.decryptEnvelope(cls.mine[0], identity, now, candidates);
      decrypted = dec.ok ? "ok" : "fail";
      if (dec.ok) m = dec.m;
    }
  } catch (e) {
    console.error(`receive: ${e.message}`);
  }
  console.log(`classified=${classified}`);
  console.log(`decrypted=${decrypted}`);
  console.log(`m=${m}`);
} else {
  console.error("usage: qr_e2e.mjs fixture OUT NOW | import PAYLOAD_FILE CONTACT_OUT NOW | " +
    "send IDENTITY_FILE CONTACT_FILE OUT MESSAGE NOW | receive IDENTITY_FILE PULL_BODY NOW");
  process.exit(2);
}

// §4.4 chunking E2E helper (issue #24) — drives the SHIPPED SPA engine
// headlessly (tests/helpers/spa_loader.mjs, the exact files index.html
// loads) so the Alice -> node A -> mule -> node B -> Bob journey in
// tests/sync_e2e.sh exercises the real client code, not a reimplementation.
//
// Modes:
//   fixture OUT_JSON     build a 1 KiB UTF-8 text and its chunk envelopes
//                        from a fresh "alice" identity toward the E2E's
//                        registered Bob X25519 key (RFC 7748 §6.1 "Bob",
//                        the same key tests/sync_e2e.sh registers in the
//                        directory). Logs parts=, text_bytes=, text_sha256=.
//   bodies FIXTURE DIR [EXTRA_IDS...]   write alice_push.json (all envelopes
//                        + their ids as known_ids) and known_all.json into
//                        DIR; EXTRA_IDS are appended to both known_ids lists
//                        (e.g. other envelopes already known to be on the
//                        node, so the pulls return only the chunks).
//   carry PULL_BODY OUT  mule hop: turn a pull response body into the next
//                        push body (the mule pushes EXACTLY the bytes it
//                        pulled).
//   verify FIXTURE BODY  Bob's side: decrypt + reassemble the SERVED bytes
//                        of one sync pull response — reversed arrival order
//                        plus one duplicated envelope — and print
//                        machine-readable check lines for the bash harness.
//
// Run by tests/sync_e2e.sh; never fails hard (verify prints RESULT=fail and
// exits 0 so the bash `check` records the failure with its own accounting).

import fs from "node:fs";
import crypto from "node:crypto";
import { loadSpaSandbox } from "./spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.buildMessageEnvelopes !== "function") {
  throw new Error("DTN engine did not load from the index.html script list (chunking.js missing?)");
}

// The E2E's registered Bob (tests/sync_e2e.sh BOB_DIR): RFC 7748 §6.1 keys
// (the X25519 public key the secret below reconstructs deterministically).
const RFC7748_BOB_SECRET_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_PUB_B64 = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

// Synthetic Bob identity for decryptEnvelope: X25519 is deterministic, so
// the RFC 7748 secret reconstructs exactly the registered public key.
function bobIdentity() {
  const boxSecret = DTN.hexDecode(RFC7748_BOB_SECRET_HEX);
  const keyPair = DTN.nacl.box.keyPair.fromSecretKey(boxSecret);
  if (DTN.b64encode(keyPair.publicKey) !== RFC7748_BOB_PUB_B64) {
    throw new Error("the RFC 7748 Bob secret did not reconstruct the registered X25519 key");
  }
  return {
    boxSecret,
    boxPublic: keyPair.publicKey,
    hint: DTN.deriveDestHint(keyPair.publicKey),
  };
}

// Deterministic 1 KiB UTF-8 text: 8 units of exactly 128 bytes with a
// 2-byte "ñ" closing each unit (multi-byte content on chunk boundaries)
// and an emoji + accents inside the units.
function oneKibText() {
  let text = "";
  for (let k = 0; k < 8; k++) {
    const content = `Part ${k + 1}/8 of a long message — la mula lleva trozos ☕ `;
    const pad = 126 - DTN.messageByteLength(content);
    if (pad < 0) throw new Error("fixture: unit content too long");
    const unit = content + "a".repeat(pad) + "ñ";
    if (DTN.messageByteLength(unit) !== 128) throw new Error("fixture: unit is not 128 bytes");
    text += unit;
  }
  if (DTN.messageByteLength(text) !== 1024) throw new Error("fixture: text is not 1 KiB");
  return text;
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(Buffer.from(str, "utf8")).digest("hex");
}

const [, , mode, arg1, arg2] = process.argv;

if (mode === "fixture") {
  const alice = DTN.createIdentity();
  const bob = bobIdentity();
  const text = oneKibText();
  const parts = DTN.chunkPlannedCount(text, "alice");
  if (parts < 2) throw new Error(`fixture: 1 KiB text split into ${parts} envelopes`);
  const envelopes = DTN.buildMessageEnvelopes({
    recipientBoxPublic: bob.boxPublic,
    message: text,
    alias: "alice",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: Math.floor(Date.now() / 1000),
  });
  if (envelopes.length !== parts) throw new Error("fixture: envelope count != planned count");
  fs.writeFileSync(arg1, JSON.stringify({
    text,
    text_sha256: sha256Hex(text),
    alias: "alice",
    parts,
    ids: envelopes.map((e) => e.id),
    envelopes,
  }));
  console.log(`parts=${parts}`);
  console.log(`text_bytes=${DTN.messageByteLength(text)}`);
  console.log(`text_sha256=${sha256Hex(text)}`);
  console.log("RESULT=ok");
} else if (mode === "bodies") {
  const fx = JSON.parse(fs.readFileSync(arg1, "utf8"));
  const extraIds = process.argv.slice(5).filter((s) => /^[0-9a-f]{64}$/.test(s));
  fs.writeFileSync(`${arg2}/alice_push.json`, JSON.stringify({
    known_ids: [...fx.ids, ...extraIds],
    push_envelopes: fx.envelopes,
    limit: 50,
  }));
  fs.writeFileSync(`${arg2}/known_all.json`, JSON.stringify({
    known_ids: [...fx.ids, ...extraIds],
    push_envelopes: [],
    limit: 50,
  }));
  console.log("RESULT=ok");
} else if (mode === "carry") {
  // Mule hop: push exactly what was pulled (byte-faithful cargo).
  const pulled = JSON.parse(fs.readFileSync(arg1, "utf8")).pull_envelopes || [];
  fs.writeFileSync(arg2, JSON.stringify({
    known_ids: pulled.map((e) => e.id),
    push_envelopes: pulled,
    limit: 50,
  }));
  console.log(`carried=${pulled.length}`);
  console.log("RESULT=ok");
} else if (mode === "verify") {
  const fx = JSON.parse(fs.readFileSync(arg1, "utf8"));
  const served = JSON.parse(fs.readFileSync(arg2, "utf8")).pull_envelopes || [];
  const bob = bobIdentity();
  // Every check starts "fail" and is flipped to "ok" only on hard evidence,
  // so ANY early error below keeps the failing verdicts.
  const checks = { served: served.length, bounds: "fail", shapes: "fail", sha: "fail",
                   reassembled: "fail", nocomplete: "fail", duplicates: "fail" };
  let state = null; // hoisted: the final sha256 line reads it outside the try
  try {
    if (served.length !== fx.parts) throw new Error(`served ${served.length} != ${fx.parts} envelopes`);

    // §8.2 bounds + §3.1 shape on every envelope the node served: the node
    // admitted them (200), but assert the bound explicitly anyway.
    for (const env of served) {
      const len = DTN.b64decode(env.payload).length;
      if (len < 248 || len > 400) throw new Error(`payload ${len} outside [248, 400]`);
      if (!DTN.validEnvelopeShape(env)) throw new Error("served envelope failed shape validation");
    }
    checks.bounds = "ok";
    checks.shapes = "ok";

    // Bob's real receive path (the §11/§4.4 logic processPulled runs):
    // decrypt each envelope, merge chunks keyed by the group id g. Feed the
    // chunks REVERSED and with one DUPLICATE — the reassembler must cope
    // with both (the upstream id-dedup already absorbed re-pulls, but a
    // re-delivery must be tolerated anyway).
    const arrivals = [...served].reverse();
    arrivals.push(arrivals[0]); // one duplicated envelope
    let accepted = 0;
    for (const env of arrivals) {
      const res = DTN.decryptEnvelope(env, bob, Math.floor(Date.now() / 1000));
      if (!res.ok || !res.chunk) throw new Error(`decrypt failed: ${res.reason}`);
      if (!state) {
        state = DTN.chunkNewState(res.chunk.g, res.chunk.n, res.a, res.t,
                                  env.created_at, env.ttl, Math.floor(Date.now() / 1000));
      }
      const before = DTN.chunkStateHave(state);
      state = DTN.chunkStateWithPart(state, res.chunk.i, res.m, env.id);
      if (DTN.chunkStateHave(state) > before) accepted += 1;
    }
    checks.duplicates = accepted === fx.parts ? "ok" : "fail";
    checks.reassembled = DTN.chunkStateComplete(state) ? "ok" : "fail";
    checks.sha = DTN.chunkStateText(state) === fx.text &&
                 sha256Hex(DTN.chunkStateText(state)) === fx.text_sha256 ? "ok" : "fail";

    // A partial (one chunk short) must NOT render as a complete message.
    const partial = { ...state, parts: { } };
    let dropped = false;
    for (const k of Object.keys(state.parts)) {
      if (!dropped && Number(k) === fx.parts - 1) { dropped = true; continue; }
      partial.parts[k] = state.parts[k];
    }
    checks.nocomplete = (!DTN.chunkStateComplete(partial) && DTN.chunkStateText(partial) !== fx.text)
      ? "ok" : "fail";
  } catch (e) {
    console.error(`chunk_e2e: ${e.message}`);
  }
  console.log(checks.bounds === "ok" && checks.shapes === "ok" && checks.reassembled === "ok" &&
              checks.sha === "ok" && checks.nocomplete === "ok" && checks.duplicates === "ok"
    ? "RESULT=ok" : "RESULT=fail");
  console.log(`served=${checks.served}`);
  console.log(`bounds=${checks.bounds}`);
  console.log(`shapes=${checks.shapes}`);
  console.log(`reassembled=${checks.reassembled}`);
  console.log(`sha=${checks.sha}`);
  console.log(`nocomplete=${checks.nocomplete}`);
  console.log(`duplicates=${checks.duplicates}`);
  console.log(`reassembled_sha256=${checks.reassembled === "ok" && state ? sha256Hex(DTN.chunkStateText(state)) : "none"}`);
} else {
  console.error(`usage: chunk_e2e.mjs fixture OUT_JSON | bodies FIXTURE DIR | carry PULL_BODY OUT | verify FIXTURE PULL_BODY`);
  process.exit(2);
}

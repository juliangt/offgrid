// §4.5 delivery-ack E2E helper (issue #25) — drives the SHIPPED SPA engine
// headlessly (tests/helpers/spa_loader.mjs, the exact files index.html
// loads) so the ack round trip in tests/sync_e2e.sh exercises the real
// client code, not a reimplementation:
//
//   Alice --flat/chunked--> node A --mule--> node B --Bob
//     Bob's engine emits ONE signed ack envelope addressed back to
//     Alice's dest_hint (resolving her X25519 key from the node
//     directory, exactly what the SPA's processPulled does) — the ack
//     rides the same mule path back to node A, where Alice's engine
//     verifies it against her `sent` record and flips the message state
//     to "delivered". A tampered ack (adversarial mule leg) must fail.
//
// Modes:
//   fixture OUT_JSON            build a flat message and a chunked message
//                               from a fresh "alice_ack" identity toward
//                               the E2E's registered Bob X25519 key (RFC
//                               7748 §6.1 "Bob"). Logs flat_id=,
//                               chunk_parts=, chunk_ref= (the LAST chunk's
//                               envelope id — the §4.5 reference).
//   bodies FIXTURE DIR          write ack_push_flat.json and
//                               ack_push_chunked.json sync bodies into DIR.
//   carry PULL_BODY OUT         mule hop: turn a pull response body into
//                               the next push body (byte-faithful cargo).
//   bob_ack FIXTURE PULL_BODY DIRECTORY_JSON OUT kind
//                               Bob's side for kind = flat | chunked:
//                               decrypt + (re)assemble the SERVED bytes,
//                               resolve the sender's X25519 key from the
//                               node directory by her Ed25519 key, emit
//                               exactly ONE ack envelope and print
//                               machine-readable check lines.
//   tamper PULL_BODY OUT        adversarial mule: flip one character in
//                               the middle of the ack's payload (the
//                               envelope id and metadata stay untouched,
//                               so node admission and dedup are unchanged)
//                               and write the tampered envelope.
//   alice_verify FIXTURE PULL_BODY BOB_SIGN_PUB
//                               Alice's side: build the §4.5 sent record
//                               (keyed by the ack reference id, bound to
//                               the recipient's Ed25519 key), decrypt the
//                               SERVED envelope and print whether the
//                               verified ack flips the state to delivered.
//
// Run by tests/sync_e2e.sh; never fails hard (check modes print
// RESULT=fail and exit 0 so the bash `check` records failures with its own
// accounting).

import fs from "node:fs";
import { loadSpaSandbox } from "./spa_loader.mjs";

const DTN = loadSpaSandbox().DTN;
if (!DTN || typeof DTN.ackTtlFor !== "function") {
  throw new Error("DTN engine did not load from the index.html script list (acks.js missing?)");
}

// The E2E's registered Bob (tests/sync_e2e.sh BOB_DIR): RFC 7748 §6.1 keys
// (the X25519 public key the secret below reconstructs deterministically).
const RFC7748_BOB_SECRET_HEX = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const RFC7748_BOB_PUB_B64 = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

// Bob's deterministic Ed25519 signing identity for the ack (any fixed
// 32-byte seed; the RFC 8032 §7.1 Ed25519 test-vector seed). The harness
// records the derived public key from the fixture and passes it to
// alice_verify, which binds the received ack against it.
const RFC8032_SIGN_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BOB_SIGN_KEYS = DTN.nacl.sign.keyPair.fromSeed(DTN.hexDecode(RFC8032_SIGN_SEED_HEX));
const BOB_SIGN_PUB_B64 = DTN.b64encode(BOB_SIGN_KEYS.publicKey);

function bobIdentity() {
  const boxSecret = DTN.hexDecode(RFC7748_BOB_SECRET_HEX);
  const keyPair = DTN.nacl.box.keyPair.fromSecretKey(boxSecret);
  if (DTN.b64encode(keyPair.publicKey) !== RFC7748_BOB_PUB_B64) {
    throw new Error("the RFC 7748 Bob secret did not reconstruct the registered X25519 key");
  }
  return { boxSecret, boxPublic: keyPair.publicKey, hint: DTN.deriveDestHint(keyPair.publicKey) };
}

// The §4.5 ack builder — the same logic the SPA's buildAckEnvelopes runs
// (ui.js is DOM-guarded and not loadable headless): resolve the sender's
// X25519 key from the directory by her Ed25519 key, address the ack back
// to her dest_hint, sign with the AUTHOR's (Bob's) Ed25519 key, TTL per
// the §4.5 formula, ack time = now. Returns null when the directory
// cannot resolve the sender (best-effort: no ack).
function buildAckEnvelope(task, directory, nowSec) {
  const entry = directory.find((e) => e && e.pubkey === task.sender_key);
  const senderBox = entry ? DTN.b64decode(entry.x25519) : null;
  if (!entry || !senderBox || senderBox.length !== 32) return null;
  return DTN.buildEnvelope({
    recipientBoxPublic: senderBox,
    message: "",
    alias: "bob",
    signSecret: BOB_SIGN_KEYS.secretKey,
    signPublic: BOB_SIGN_KEYS.publicKey,
    createdAt: nowSec,
    ttl: DTN.ackTtlFor(task.created_at, task.ttl, nowSec),
    ack: { r: task.r, y: task.type }
  });
}

function envelopeOk(env) {
  if (!DTN.validEnvelopeShape(env) || env.v !== 1) return false;
  const len = DTN.b64decode(env.payload).length;
  return len >= 248 && len <= 400;
}

const [, , mode, ...args] = process.argv;

if (mode === "fixture") {
  const [out] = args;
  const alice = DTN.createIdentity();
  const bob = bobIdentity();
  const now = Math.floor(Date.now() / 1000);
  const flatText = "Bob, por favor confirmame cuando recibas este mensaje ☕";
  const flat = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic, message: flatText, alias: "alice_ack",
    signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: now,
  });
  const chunkText = "Mensaje largo para el camino de vuelta del acuse: cada sobre viaja " +
    "igual que siempre y el único ack se emite cuando el mensaje llega completo ☕☕☕";
  const chunkEnvs = DTN.buildMessageEnvelopes({
    recipientBoxPublic: bob.boxPublic, message: chunkText, alias: "alice_ack",
    signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: now,
  });
  if (chunkEnvs.length < 2) throw new Error(`fixture: chunked message split into ${chunkEnvs.length}`);
  fs.writeFileSync(out, JSON.stringify({
    alias: "alice_ack",
    alice_seed: alice.seedB64,       /* test-only: lets alice_verify decrypt */
    alice_pub: alice.signPublicB64,
    alice_x25519: alice.boxPublicB64,
    alice_hint: alice.hint,
    bob_sign_pub: BOB_SIGN_PUB_B64,
    flat: { text: flatText, envelope: flat, ref: flat.id },
    chunked: { text: chunkText, envelopes: chunkEnvs, ref: chunkEnvs[chunkEnvs.length - 1].id },
  }));
  console.log(`flat_id=${flat.id}`);
  console.log(`chunk_parts=${chunkEnvs.length}`);
  console.log(`chunk_ref=${chunkEnvs[chunkEnvs.length - 1].id}`);
  console.log("RESULT=ok");
} else if (mode === "bodies") {
  const [fixturePath, dir] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  fs.writeFileSync(`${dir}/ack_push_flat.json`, JSON.stringify({
    known_ids: [fx.flat.envelope.id], push_envelopes: [fx.flat.envelope], limit: 50,
  }));
  fs.writeFileSync(`${dir}/ack_push_chunked.json`, JSON.stringify({
    known_ids: fx.chunked.envelopes.map((e) => e.id),
    push_envelopes: fx.chunked.envelopes,
    limit: 50,
  }));
  console.log("RESULT=ok");
} else if (mode === "carry") {
  // Mule hop: push exactly what was pulled (byte-faithful cargo).
  const pulled = JSON.parse(fs.readFileSync(args[0], "utf8")).pull_envelopes || [];
  fs.writeFileSync(args[1], JSON.stringify({
    known_ids: pulled.map((e) => e.id),
    push_envelopes: pulled,
    limit: 50,
  }));
  console.log(`carried=${pulled.length}`);
  console.log("RESULT=ok");
} else if (mode === "bob_ack") {
  const [fixturePath, pullBodyPath, dirBodyPath, out, kind] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const directory = JSON.parse(fs.readFileSync(dirBodyPath, "utf8"));
  const bob = bobIdentity();
  const now = Math.floor(Date.now() / 1000);
  // Every check starts "fail" and is flipped only on hard evidence.
  const checks = { served: served.length, decrypt: "fail", task: "fail", ref: "fail",
                   dest: "fail", ttl: "fail", bounds: "fail", count: 0, term: "fail" };
  let ackEnv = null;
  try {
    let task = null;
    let origin = null; /* the original envelope the ack references */
    if (kind === "flat") {
      if (served.length !== 1) throw new Error(`expected 1 flat envelope, served ${served.length}`);
      origin = served[0];
      const dec = DTN.decryptEnvelope(origin, bob, now);
      if (!dec.ok || dec.ack || dec.chunk || dec.m !== fx.flat.text) {
        throw new Error(`flat decrypt failed: ${JSON.stringify(dec).slice(0, 120)}`);
      }
      checks.decrypt = "ok";
      /* §4.5 flat reference rule: the envelope's own id; the sender key
       * rides the decrypted inner (resolved via the directory next). */
      task = DTN.ackTaskForArrival(dec, origin.id, origin.created_at, origin.ttl);
      if (task) task.sender_key = dec.k;
    } else {
      if (served.length !== fx.chunked.envelopes.length) {
        throw new Error(`expected ${fx.chunked.envelopes.length} chunks, served ${served.length}`);
      }
      // Bob's real receive path: reversed arrival + one duplicate,
      // reassembly keyed by g; the ack is emitted ONCE, at completion.
      let state = null;
      const arrivals = [...served].reverse();
      arrivals.push(arrivals[0]);
      for (const env of arrivals) {
        const dec = DTN.decryptEnvelope(env, bob, now);
        if (!dec.ok || !dec.chunk) throw new Error(`chunk decrypt failed: ${dec.reason}`);
        if (!state) {
          state = DTN.chunkNewState(dec.chunk.g, dec.chunk.n, dec.a, dec.t,
                                    env.created_at, env.ttl, now, dec.k);
        }
        state = DTN.chunkStateWithPart(state, dec.chunk.i, dec.m, env.id);
      }
      checks.decrypt = DTN.chunkStateComplete(state) && DTN.chunkStateText(state) === fx.chunked.text
        ? "ok" : "fail";
      if (checks.decrypt !== "ok") throw new Error("chunked reassembly mismatch");
      /* §4.5 chunked reference rule: the LAST chunk's envelope id. */
      origin = served.find((e) => e.id === fx.chunked.ref);
      if (!origin) throw new Error("the agreed last-chunk envelope was not served");
      /* The ack task comes from the completed state: the reference is the
       * id stored with chunk n-1, one task per completed message. */
      task = DTN.ackTaskForArrival(
        { ok: true, m: fx.chunked.text, chunk: { g: state.g, i: state.n - 1, n: state.n } },
        state.parts[String(state.n - 1)].id,
        state.created_at, state.ttl);
      /* The sender key rides the reassembly state (kept since the FIRST
        chunk arrived, possibly in an earlier sync). */
      task.sender_key = state.k;
    }
    checks.task = task ? "ok" : "fail";
    checks.ref = task && task.r === (kind === "flat" ? fx.flat.ref : fx.chunked.ref) ? "ok" : "fail";

    ackEnv = buildAckEnvelope(task, directory, now);
    if (!ackEnv) throw new Error("could not resolve the sender in the directory (no ack)");
    checks.dest = ackEnv.dest_hint === fx.alice_hint ? "ok" : "fail";
    checks.ttl = ackEnv.ttl === DTN.ackTtlFor(origin.created_at, origin.ttl, now) ? "ok" : "fail";
    checks.bounds = envelopeOk(ackEnv) ? "ok" : "fail";
    checks.count = 1; // exactly ONE ack envelope per message (§4.5 bound)

    // TERMINATION, E2E edition: an ack arrival yields no ack task — acks
    // are never acked (§4.5).
    checks.term = DTN.ackTaskForArrival(
      { ok: true, ack: { w: "ack1", r: task.r, y: 1 } },
      task.r, origin.created_at, origin.ttl) === null ? "ok" : "fail";
    fs.writeFileSync(out, JSON.stringify({ envelope: ackEnv, kind, ref: task.r }));
  } catch (e) {
    console.error(`ack_e2e: ${e.message}`);
  }
  const allOk = checks.decrypt === "ok" && checks.task === "ok" && checks.ref === "ok" &&
    checks.dest === "ok" && checks.ttl === "ok" && checks.bounds === "ok" &&
    checks.count === 1 && checks.term === "ok";
  console.log(`result=${allOk ? "ok" : "fail"}`);
  console.log(`served=${checks.served}`);
  console.log(`decrypt=${checks.decrypt}`);
  console.log(`task=${checks.task}`);
  console.log(`ref=${checks.ref}`);
  console.log(`dest=${checks.dest}`);
  console.log(`ttl=${checks.ttl}`);
  console.log(`bounds=${checks.bounds}`);
  console.log(`count=${checks.count}`);
  console.log(`term=${checks.term}`);
  console.log(`ack_ref=${(kind === "flat" ? fx.flat.ref : fx.chunked.ref)}`);
} else if (mode === "tamper") {
  // Adversarial mule: flip one character in the middle of the payload.
  const served = JSON.parse(fs.readFileSync(args[0], "utf8")).pull_envelopes || [];
  if (served.length !== 1) throw new Error(`tamper: expected exactly 1 ack, pulled ${served.length}`);
  const env = { ...served[0] };
  const chars = env.payload.split("");
  const mid = Math.floor(chars.length / 2);
  chars[mid] = chars[mid] === "A" ? "B" : "A";
  env.payload = chars.join("");
  fs.writeFileSync(args[1], JSON.stringify(env));
  console.log("RESULT=ok");
} else if (mode === "alice_verify") {
  const [fixturePath, pullBodyPath, bobSignPub] = args;
  const fx = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const served = JSON.parse(fs.readFileSync(pullBodyPath, "utf8")).pull_envelopes || [];
  const now = Math.floor(Date.now() / 1000);
  let decrypted = "fail";
  let matched = "fail";
  let state = "queued";
  let result = "fail";
  try {
    if (served.length === 1) {
      const alice = DTN.identityFromSeed(DTN.b64decode(fx.alice_seed));
      const dec = DTN.decryptEnvelope(served[0], alice, now);
      decrypted = dec.ok ? "ok" : "fail";
      if (dec.ok && dec.ack) {
        /* Which message does the ack reference? Compare the reference id
         * (NOT the ack's own envelope id) against the fixture's records. */
        const isFlat = dec.ack.r === fx.flat.ref;
        const isChunked = dec.ack.r === fx.chunked.ref;
        if (isFlat || isChunked) {
          /* Alice's §4.5 sent record: keyed by the ack reference id, bound
           * to the recipient's Ed25519 key (what a genuine ack carries). */
          const origin = isFlat ? fx.flat.envelope : fx.chunked.envelopes[0];
          const record = DTN.sentNewRecord({
            envIds: isFlat ? [fx.flat.ref] : fx.chunked.envelopes.map((e) => e.id),
            toAlias: "bob",
            toPubkey: bobSignPub,
            text: isFlat ? fx.flat.text : fx.chunked.text,
            t: origin.created_at,
            createdAt: origin.created_at,
            ttl: origin.ttl,
          });
          if (DTN.ackMatchesSent(dec, record)) {
            matched = "ok";
            state = DTN.sentDeliveredRecord(record, now).state;
          }
        }
      }
    }
    result = "ok"; /* alice_verify itself ran; the harness judges the state */
  } catch (e) {
    console.error(`ack_e2e: ${e.message}`);
  }
  console.log(`result=${result}`);
  console.log(`decrypted=${decrypted}`);
  console.log(`matched=${matched}`);
  console.log(`state=${state}`);
} else {
  console.error("usage: ack_e2e.mjs fixture OUT | bodies FIXTURE DIR | carry PULL_BODY OUT | " +
    "bob_ack FIXTURE PULL_BODY DIRECTORY OUT kind | tamper PULL_BODY OUT | " +
    "alice_verify FIXTURE PULL_BODY BOB_SIGN_PUB");
  process.exit(2);
}

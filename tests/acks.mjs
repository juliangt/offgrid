// Delivery-acknowledgment test (§4.5, issue #25).
//
// Loads the shipped scripts in the exact order declared by
// node/web/index.html (via tests/helpers/spa_loader.mjs) and asserts the
// client-side ack convention end to end, headlessly:
//
//   (a) canonical forms: the §4.5 signed byte string and inner_json have
//       the exact fixed member order (worked vector); the §5.1 flat and
//       §4.4 chunked strings stay byte-identical to their pre-§4.5 forms
//   (b) ack construction: an ack is an ORDINARY v1 envelope within the
//       §8.2 bounds, addressed BACK to the sender's dest_hint, carrying
//       m = "" and the ack members inside the signature; the sender
//       decrypts it and gets {ack: {w, r, y}} with the AUTHOR's key
//   (c) forgery resistance: a tampered reference or type fails the
//       signature / structural validation; a third-party signer passes
//       Ed25519 against its own key but fails the sender's bind to the
//       expected recipient (ackMatchesSent); a mule learns nothing
//   (d) termination: acks are never acked (ackTaskForArrival returns null
//       for ack arrivals); one ack per message (chunk completion is
//       one-shot; the reference rule pins the LAST chunk's envelope id)
//   (e) TTL formula: remaining life clamps to [TTL_MIN, TTL_MAX]; the ack
//       never mutates the original's lifetime fields
//   (f) sender state machine: sentNewRecord/ackMatchesSent/
//       sentDeliveredRecord flip queued → delivered only for a verified,
//       bound ack; store-side §15.6 v3 migration is additive (covered in
//       tests/version_migration.mjs)
//   (g) build-time validation: bad r, wrong type, non-empty text, and the
//       chunk+ack combination are rejected before anything is signed
//
// Run: node tests/acks.mjs   (exit 0 = pass)

import crypto from "node:crypto";
import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();

const DTN = sandbox.DTN;
if (!DTN || typeof DTN.ackTtlFor !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (acks.js missing?)");
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

function throws(fn) {
  try { fn(); return false; } catch (e) { return true; }
}

// Decrypt-then-re-encrypt helper: opens one of Bob's ack envelopes as
// Alice, mutates the decrypted inner through `mutate`, re-boxes it toward
// Alice with a FRESH ephemeral key and answers with a well-formed envelope
// whose inner carries the mutation but NO fresh signature — exactly what a
// malicious mule could produce (it cannot sign as the recipient). The
// mutated inner is serialized RAW in canonical member order, skipping
// members the mutation deleted (a 7-member inner has no canonical form —
// that is precisely the corruption under test).
function ackInnerBytesOf(inner) {
  const parts = [];
  const push = (name, val, raw) => {
    if (val === undefined) return;
    parts.push(`"${name}":` + (raw !== undefined ? raw : JSON.stringify(val)));
  };
  push("m", inner.m);
  push("a", inner.a);
  push("k", inner.k);
  push("s", inner.s);
  push("t", inner.t, String(inner.t));
  push("w", inner.w);
  push("r", inner.r);
  push("y", inner.y, String(inner.y));
  return "{" + parts.join(",") + "}";
}

function forgedWithMutatedInner(env, alice, mutate) {
  const raw = DTN.b64decode(env.payload);
  const innerBytes = DTN.nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), alice.boxSecret);
  if (!innerBytes) throw new Error("fixture: could not open the envelope");
  const inner = JSON.parse(DTN.utf8Decode(innerBytes));
  mutate(inner);
  const eph = DTN.nacl.box.keyPair();
  const nonce = DTN.randomBytes(24);
  const box = DTN.nacl.box(DTN.utf8Encode(ackInnerBytesOf(inner)), nonce, alice.boxPublic, eph.secretKey);
  const payload = DTN.b64encode(DTN.concatBytes(eph.publicKey, nonce, box));
  return {
    v: 1,
    /* the strongest forger recomputes the PUBLIC §6.2 id over the doctored
     * payload — what must still stop this tamper is the inner SIGNATURE */
    id: DTN.computeEnvelopeId(1, env.dest_hint, env.created_at, env.ttl, payload),
    dest_hint: env.dest_hint,
    created_at: env.created_at, ttl: env.ttl,
    payload
  };
}

const alice = DTN.createIdentity();
const bob = DTN.createIdentity();
const mule = DTN.createIdentity();
const mallory = DTN.createIdentity();
const NOW = 1759500000;

console.log("== (a) canonical §4.5 forms: worked vector + unchanged flat/chunked forms ==");
{
  const refId = "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f";
  const wantSigned = '{"m":"","a":"bob_1","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001,"w":"ack1","r":"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f","y":1}';
  ok(DTN.canonicalAckSignedString("", "bob_1",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001, "ack1", refId, 1) === wantSigned,
    "§4.5 signed byte string: the §5.1 form gains w,r,y in fixed order after t (worked vector)");
  const wantInner = '{"m":"","a":"bob_1","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","s":"<88-char Base64 Ed25519 signature>","t":1759500001,"w":"ack1","r":"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f","y":1}';
  ok(DTN.canonicalAckInnerJson("", "bob_1",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "<88-char Base64 Ed25519 signature>",
      1759500001, "ack1", refId, 1) === wantInner,
    "§4.5 inner_json: s keeps its §4.1 position, then w,r,y in the same fixed order");

  // The pre-existing forms are UNCHANGED by this feature (binding).
  ok(DTN.canonicalSignedString("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001) ===
     '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001}',
    "plain §5.1 signed byte string stays byte-identical to the pre-§4.5 form");
  const g = "A2aYc0XrQ0mT7oP9wK5v1g==";
  ok(DTN.canonicalChunkedSignedString("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001, "chunk1", g, 0, 2) ===
     '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001,"w":"chunk1","g":"A2aYc0XrQ0mT7oP9wK5v1g==","i":0,"n":2}',
    "§4.4 chunked signed byte string stays byte-identical to the pre-§4.5 form");
  const worstAckMeta = ',"w":"ack1","r":"' + refId + '","y":1';
  ok(DTN.ACK_META_MAX_BYTES === worstAckMeta.length && worstAckMeta.length === 88,
    "ACK_META_MAX_BYTES matches the real worst-case inner footprint (11 + 71 + 6 = 88)");
}

console.log("== (b) ack construction: an ordinary v1 envelope addressed back to the sender ==");
const message = "Hola Bob, confirmame cuando lo recibas";
const original = DTN.buildEnvelope({
  recipientBoxPublic: bob.boxPublic, message, alias: "alice_77",
  signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: NOW,
});
const ackTime = NOW + 7200;
const ackTtl = DTN.ackTtlFor(original.created_at, original.ttl, ackTime);
const ack = DTN.buildEnvelope({
  recipientBoxPublic: alice.boxPublic,   /* addressed BACK to Alice's dest_hint */
  message: "",                           /* acks carry no text (§4.5) */
  alias: "bob_1",                        /* the ACK AUTHOR's alias */
  signSecret: bob.signSecret,
  signPublic: bob.signPublic,            /* signed by the RECIPIENT's Ed25519 key */
  createdAt: ackTime,
  ttl: ackTtl,
  ack: { r: original.id, y: DTN.ACK_TYPE_RECEIVED },
});
{
  ok(DTN.validEnvelopeShape(ack) && ack.v === 1,
    "the ack is an ordinary §3.1 v1 envelope (nodes see nothing new)");
  const decoded = DTN.b64decode(ack.payload).length;
  ok(decoded >= 248 && decoded <= 400,
    `ack decoded payload ${decoded} within the §8.2 bounds [248, 400] (no limit change)`);
  ok(ack.dest_hint === alice.hint,
    "the ack is addressed to the SENDER's dest_hint (travels back like any mail)");
  ok(ack.created_at === ackTime && ack.ttl === ackTtl,
    "ack created_at is the ack time and ttl follows the §4.5 formula");
  ok(ack.id === DTN.computeEnvelopeId(1, ack.dest_hint, ack.created_at, ack.ttl, ack.payload),
    "ack id is a first-class §6.2 envelope id (dedup works unchanged)");

  // Mule blindness on the ack itself.
  const payloadText = Buffer.from(DTN.b64decode(ack.payload)).toString("latin1");
  ok(!payloadText.includes("bob_1") && !payloadText.includes("ack1") && !payloadText.includes(message),
    "a mule cannot see the ack tag, the author alias or the original message (sign-then-encrypt)");
  ok(DTN.decryptEnvelope(ack, mule, ackTime).ok === false,
    "a mule without Alice's key cannot open the ack (§13.1)");

  // The sender's view.
  const dec = DTN.decryptEnvelope(ack, alice, ackTime);
  ok(dec.ok === true && dec.ack && dec.ack.w === "ack1" && dec.ack.y === 1,
    'Alice decrypts the ack: {w: "ack1", y: 1} survives inside her box');
  ok(dec.ack.r === original.id,
    "the ack reference names the original envelope id (flat reference rule)");
  ok(dec.m === "" && dec.a === "bob_1" && dec.t === ackTime,
    "ack inner m is empty; a and t are the AUTHOR's (the recipient's) alias and ack time");
  ok(dec.k === DTN.b64encode(bob.signPublic),
    "the ack signature key is the RECIPIENT's Ed25519 public key (authenticable by the sender)");
}

console.log("== (c) forgery resistance: tampering, wrong signer, mule blindness ==");
{
  const flipR = (inner) => { inner.r = DTN.hexEncode(DTN.sha256(DTN.utf8Encode("other message"))); };
  const flipW = (inner) => { inner.w = "ack2"; };
  const flipY = (inner) => { inner.y = 2; };
  const flipM = (inner) => { inner.m = "smuggled text"; };
  for (const [label, mutate, reason] of [
    ["reference r", flipR, "bad_signature"],
    ["tag w", flipW, "bad_inner"],
    ["type y", flipY, "bad_inner"],
    ["text m", flipM, "bad_inner"],
  ]) {
    const res = DTN.decryptEnvelope(forgedWithMutatedInner(ack, alice, mutate), alice, ackTime);
    ok(res.ok === false && res.reason === reason,
      `a mule-altered ack ${label} is rejected (${reason}) — the member is inside the signature`);
  }
  // A member dropped entirely (seven-member inner) is corrupt by definition.
  const res = DTN.decryptEnvelope(forgedWithMutatedInner(ack, alice, (inner) => { delete inner.y; }), alice, ackTime);
  ok(res.ok === false && res.reason === "bad_inner",
    "an ack inner missing a member is corrupt (exact member set)");

  // Third-party signer: a peer CAN produce a self-consistent ack addressed
  // to Alice (her box key is public in the directory), so the sender must
  // bind the ack to the recipient she actually sent to.
  const forged = DTN.buildEnvelope({
    recipientBoxPublic: alice.boxPublic, message: "", alias: "bob_1",
    signSecret: mallory.signSecret, signPublic: mallory.signPublic,
    createdAt: ackTime, ttl: ackTtl,
    ack: { r: original.id, y: DTN.ACK_TYPE_RECEIVED },
  });
  const fdec = DTN.decryptEnvelope(forged, alice, ackTime);
  const record = DTN.sentNewRecord({
    envIds: [original.id], toAlias: "bob_1", toPubkey: DTN.b64encode(bob.signPublic),
    text: message, t: NOW, createdAt: NOW, ttl: DTN.TTL_DEFAULT,
  });
  ok(fdec.ok === true && fdec.k === DTN.b64encode(mallory.signPublic),
    "a forged ack signed by a third party verifies against ITS OWN key (Ed25519 is honest)");
  ok(DTN.ackMatchesSent(fdec, record) === false,
    "but fails the sender's bind: the signature key is not the recipient the message was sent to");
  ok(DTN.ackMatchesSent(DTN.decryptEnvelope(ack, alice, ackTime), record) === true,
    "the genuine ack binds: reference, type and the recipient's signing key all match");

  // A mule replaying/tampering with the ack envelope bytes fails the MAC.
  const rawAck = DTN.b64decode(ack.payload);
  const flipped = Uint8Array.from(rawAck);
  flipped[70] ^= 0xff;
  const tampered = { ...ack, payload: DTN.b64encode(flipped) };
  ok(DTN.decryptEnvelope(tampered, alice, ackTime).ok === false,
    "a flipped ack payload byte is rejected by the Poly1305 MAC, silently");
}

console.log("== (d) termination and the one-ack-per-message bound ==");
{
  const dec = DTN.decryptEnvelope(ack, alice, ackTime);
  ok(DTN.ackTaskForArrival(dec, original.id, NOW, DTN.TTL_DEFAULT) === null,
    "TERMINATION: an ack arrival yields NO ack task (acks are never acked)");
  ok(DTN.ackTaskForArrival({ ok: true, m: "hi" }, original.id, NOW, DTN.TTL_DEFAULT) !== null,
    "a message arrival yields exactly one ack task");
  ok(DTN.ackTaskForArrival({ ok: false }, original.id, NOW, DTN.TTL_DEFAULT) === null,
    "a failed decrypt yields no ack task");
  ok(DTN.ackTaskForArrival({ ok: true }, "not-hex", NOW, DTN.TTL_DEFAULT) === null,
    "a non-envelope-id reference yields no ack task");

  // Reference rule: flat -> its own id; chunked -> the LAST chunk's id.
  ok(DTN.ackReferenceIdFor([original.id]) === original.id,
    "flat reference: the message's single envelope id");
  const chunkIds = ["aa", "bb", "cc"];
  ok(DTN.ackReferenceIdFor(chunkIds) === "cc",
    "chunked reference: the LAST chunk's envelope id (index n-1)");

  // One-shot completion: the reassembly state machine acks exactly once.
  const parts = DTN.buildMessageEnvelopes({
    recipientBoxPublic: bob.boxPublic,
    message: "Este mensaje largo necesita varios sobres para viajar por la red sin " +
      "internet y un único ack firmado cuando llegue completo a su destino ☕",
    alias: "alice_77", signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: NOW,
  });
  ok(parts.length > 1, `the chunked fixture splits into ${parts.length} envelopes`);
  let state = null;
  const decs = parts.map((e) => DTN.decryptEnvelope(e, bob, NOW));
  const completions = [];
  for (const d of decs) {
    state = DTN.chunkStateWithPart(state || DTN.chunkNewState(d.chunk.g, d.chunk.n, d.a, d.t, NOW, DTN.TTL_DEFAULT, NOW, d.k), d.chunk.i, d.m, "env");
    if (DTN.chunkStateComplete(state)) completions.push(state);
  }
  ok(completions.length === 1,
    "chunk completion happens exactly once (the partial is deleted then) -> exactly ONE ack");
  const lastChunkId = parts[parts.length - 1].id;
  ok(DTN.ackReferenceIdFor(parts.map((e) => e.id)) === lastChunkId,
    "the chunked ack references the LAST chunk's envelope id (§4.5 agreed id)");
  ok(state.k === DTN.b64encode(alice.signPublic),
    "the reassembly state carries the sender's Ed25519 key so the ack can be addressed");
}

console.log("== (e) TTL formula: remaining life clamps, original untouched ==");
{
  ok(DTN.ackTtlFor(NOW, 604800, NOW + 3600) === 604800 - 3600,
    "ack ttl = the original's remaining life when inside [TTL_MIN, TTL_MAX]");
  ok(DTN.ackTtlFor(NOW, 604800, NOW + 604800 - 100) === DTN.TTL_MIN,
    "remaining life below TTL_MIN clamps UP to TTL_MIN (the ack must be servable)");
  ok(DTN.ackTtlFor(NOW, 604800, NOW + 604800 + 5000) === DTN.TTL_MIN,
    "an expired original still yields a TTL_MIN ack (never a TTL outside §8.1)");
  ok(DTN.ackTtlFor(NOW, DTN.TTL_MAX + 1000, NOW) === DTN.TTL_MAX,
    "remaining life above TTL_MAX clamps DOWN to TTL_MAX");
  ok(DTN.ackTtlFor(NOW, 604800, NOW) === 604800,
    "boundary: remaining == ttl when the ack is immediate");
  // The ack never extends the original: its fields are never rewritten.
  const before = JSON.stringify({ c: original.created_at, t: original.ttl });
  DTN.ackTtlFor(original.created_at, original.ttl, ackTime);
  ok(JSON.stringify({ c: original.created_at, t: original.ttl }) === before,
    "the TTL computation never mutates the original's lifetime (no refresh rule)");
}

console.log("== (f) sender state machine: queued → sent → delivered ==");
{
  const record = DTN.sentNewRecord({
    envIds: ["ff".repeat(32), original.id], toAlias: "bob_1",
    toPubkey: DTN.b64encode(bob.signPublic),
    text: message, t: NOW, createdAt: NOW, ttl: DTN.TTL_DEFAULT,
  });
  ok(record.id === original.id && record.env_ids.length === 2 && record.state === "queued",
    "the sent record keys on the ack reference id (the LAST envelope) and starts queued");
  ok(DTN.sentStatusLabel(record.state) === "queued — waiting for the next sync" &&
     DTN.sentStatusLabel("sent") === "sent — carried by a mule" &&
     DTN.sentStatusLabel("delivered") === "delivered — the recipient's device confirmed receipt",
    "state wording is honest: only a verified ack says delivered");

  const delivered = DTN.sentDeliveredRecord(record, ackTime);
  ok(delivered.state === "delivered" && delivered.acked_at === ackTime && delivered.ack_type === 1 &&
     record.state === "queued",
    "the delivered flip creates a NEW record and never mutates the input");

  // Bind failures: wrong reference (another message's ack), wrong key.
  const otherAck = DTN.buildEnvelope({
    recipientBoxPublic: alice.boxPublic, message: "", alias: "bob_1",
    signSecret: bob.signSecret, signPublic: bob.signPublic,
    createdAt: ackTime, ttl: DTN.TTL_MIN,
    ack: { r: DTN.hexEncode(DTN.sha256(DTN.utf8Encode("another message"))), y: 1 },
  });
  const otherDec = DTN.decryptEnvelope(otherAck, alice, ackTime);
  ok(DTN.ackMatchesSent(otherDec, record) === false,
    "an ack referencing another message never matches this record");
  ok(DTN.ackMatchesSent(null, record) === false &&
     DTN.ackMatchesSent(DTN.decryptEnvelope(ack, alice, ackTime), null) === false,
    "null results/records never match");
  ok(DTN.ackMatchesSent(DTN.decryptEnvelope(ack, alice, ackTime),
                        { ...record, to_pubkey: DTN.b64encode(mallory.signPublic) }) === false,
    "an ack from a key other than the recorded recipient pubkey never matches");
}

console.log("== (g) build-time validation of the ack option ==");
{
  const base = {
    recipientBoxPublic: alice.boxPublic, message: "", alias: "bob_1",
    signSecret: bob.signSecret, signPublic: bob.signPublic, createdAt: NOW, ttl: DTN.TTL_MIN,
  };
  ok(throws(() => DTN.buildEnvelope({ ...base, ack: { r: "nothex", y: 1 } })),
    "ack.r outside 64-lowercase-hex rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, ack: { r: "AB".repeat(32), y: 1 } })),
    "ack.r uppercase hex rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, ack: { r: original.id, y: 2 } })),
    "ack.y = 2 rejected at build time (type 1 is the only §4.5 type)");
  ok(throws(() => DTN.buildEnvelope({ ...base, ack: { r: original.id, y: 1.5 } })),
    "non-integer ack.y rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, message: "smuggled", ack: { r: original.id, y: 1 } })),
    "an ack carrying text rejected at build time (m must be empty)");
  ok(throws(() => DTN.buildEnvelope({
    ...base, ack: { r: original.id, y: 1 },
    chunk: { g: DTN.b64encode(DTN.randomBytes(16)), i: 0, n: 2 },
  })), "chunk + ack together rejected at build time (mutually exclusive conventions)");

  // The honest ack still verifies after all this hostility, and the §8.1
  // flat path of the ORIGINAL message is untouched by the ack convention.
  ok(DTN.decryptEnvelope(original, bob, NOW).ok === true &&
     DTN.decryptEnvelope(original, bob, NOW).ack === undefined,
    "a plain message decrypts with NO ack member (flat §4.1 result unchanged)");
}

console.log(`\nPASS: ${passed} assertions on the §4.5 delivery-acknowledgment convention (index.html script order)`);

// Crypto round-trip test for the SPA engine (Sprint 2, plan 2.8).
//
// Loads the shipped scripts in the exact order declared by
// node/web/index.html (via tests/helpers/spa_loader.mjs) and evaluates them
// in a Node vm context (Node 22 provides crypto.getRandomValues; window/self
// are stubbed so the tweetnacl UMD and the window.DTN export land on the
// sandbox), and asserts:
//
//   (a) dest_hint test vector of spec §6.1 (RFC 7748 Alice X25519 key)
//   (b) envelope id test vector of spec §6.2 over the §3.2/§5.2 example
//   (c) full round trip: Alice builds an envelope for Bob; a mule can read
//       dest_hint but learns nothing about sender or message without keys;
//       Bob decrypts, the signature verifies, the message and alias arrive
//   (d) tamper resistance: a flipped payload byte is silently rejected;
//       wrong-recipient envelopes (and the sender's own) cannot be opened
//   (e) transit FIFO eviction at capacity 100 (§8.1)
//
// Run: node tests/crypto_roundtrip.mjs   (exit 0 = pass)

import crypto from "node:crypto";
import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();

const DTN = sandbox.DTN;
if (!DTN || typeof DTN.buildEnvelope !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (nacl or buildEnvelope missing)");
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

function bytesFromHex(hex) {
  const raw = DTN.hexDecode(hex);
  if (!raw) throw new Error(`bad hex fixture: ${hex}`);
  return raw;
}

console.log("== (a) dest_hint derivation — spec §6.1 test vector 1 ==");
const rfc7748AlicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
ok(DTN.hexEncode(DTN.sha256(bytesFromHex(rfc7748AlicePub))) ===
   "300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae",
   "full SHA-256 digest of Alice's X25519 key matches §6.1");
ok(DTN.deriveDestHint(bytesFromHex(rfc7748AlicePub)) === "300c9c9603b92a4b",
   "dest_hint = first 8 bytes as 16 lowercase hex chars (§6.1)");

console.log("== (b) envelope id — spec §6.2 test vector 3 over the §5.2 string ==");
const vectorPayload = "f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2ukrJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEntNfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQrii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84Pyk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE=";
const vectorEnvelopeString = `{"v":1,"dest_hint":"9f3ab02c1d77e4c1","created_at":1759500000,"ttl":604800,"payload":"${vectorPayload}"}`;
ok(DTN.canonicalEnvelopeString(1, "9f3ab02c1d77e4c1", 1759500000, 604800, vectorPayload) === vectorEnvelopeString,
   "canonical §5.2 byte string uses the FIXED member order (not lexicographic)");
ok(DTN.computeEnvelopeId(1, "9f3ab02c1d77e4c1", 1759500000, 604800, vectorPayload) ===
   "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f",
   "envelope id matches §6.2 test vector 2");

ok(DTN.canonicalSignedString("Hola Bob", "alice_77", "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001) ===
   '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001}',
   "canonical §5.1 signed byte string matches the §4.1/§5.1 example");

console.log("== primitives: SHA-256 / UTF-8 / Base64 fuzzed against Node builtins ==");
for (let n = 0; n < 120; n++) {
  const buf = crypto.randomBytes(n);
  const want = crypto.createHash("sha256").update(buf).digest("hex");
  if (DTN.hexEncode(DTN.sha256(new Uint8Array(buf))) !== want) {
    throw new Error(`sha256 mismatch at ${n} bytes`);
  }
}
ok(true, "SHA-256 matches node:crypto for 120 lengths 0..119");

{
  const te = new TextEncoder();
  for (let i = 0; i < 120; i++) {
    let s = "";
    for (let j = 0; j < 40; j++) {
      // any scalar character (no lone surrogates: TextEncoder replaces them
      // and so does the engine, but keep the fuzz comparison simple)
      let cp = crypto.randomBytes(3).readUIntBE(0, 3) % 0x10ffff;
      if (cp >= 0xd800 && cp <= 0xdfff) cp = 0x41;
      s += String.fromCodePoint(cp);
    }
    const a = Buffer.from(DTN.utf8Encode(s)).toString("hex");
    const b = Buffer.from(te.encode(s)).toString("hex");
    if (a !== b) throw new Error("utf8Encode mismatch vs TextEncoder");
    if (DTN.utf8Decode(te.encode(s)) !== s) throw new Error("utf8Decode round trip failed");
  }
  ok(true, "UTF-8 encode/decode matches TextEncoder round trip (120 random strings)");
}

for (let n = 0; n < 150; n++) {
  const buf = crypto.randomBytes(n);
  const enc = DTN.b64encode(new Uint8Array(buf));
  if (enc !== buf.toString("base64")) throw new Error(`b64encode mismatch at ${n}`);
  const dec = DTN.b64decode(enc);
  if (!dec || Buffer.compare(Buffer.from(dec), buf) !== 0) throw new Error(`b64decode mismatch at ${n}`);
}
ok(true, "Base64 (RFC 4648 padded) matches Buffer base64 (150 random lengths)");

ok(DTN.b64decode("a-b_") === null && DTN.b64decode("AB=") === null && DTN.b64decode("AB@C") === null,
   "Base64 decode is strict: Base64url and bad padding rejected (§3.3)");
ok(DTN.hexDecode("ABCDEF") === null && DTN.hexDecode("zz") === null,
   "hex decode is strict lowercase (§3.3)");

console.log("== (c) full round trip: Alice -> node -> mule -> node -> Bob ==");
const bob = DTN.createIdentity();
const alice = DTN.createIdentity();
ok(bob.seedB64.length === 44 && alice.signPublicB64.length === 44 && alice.boxPublicB64.length === 44,
   "identity: 32-byte seed, Ed25519 and X25519 public keys in Base64");
{
  const restored = DTN.identityFromSeed(DTN.b64decode(alice.seedB64));
  ok(DTN.hexEncode(restored.signSecret) === DTN.hexEncode(alice.signSecret) &&
     DTN.hexEncode(restored.boxSecret) === DTN.hexEncode(alice.boxSecret) &&
     restored.hint === alice.hint,
     "seed backup reconstructs the exact identity (deterministic derivation)");
}

const message = "Hola Bob, nos vemos en el nodo 2 — mañana ☕";
const nowSec = 1759500000;
const envelope = DTN.buildEnvelope({
  recipientBoxPublic: bob.boxPublic,
  message: message,
  alias: "alice_77",
  signSecret: alice.signSecret,
  signPublic: alice.signPublic,
  createdAt: nowSec
});

ok(envelope.v === 1 &&
   /^[0-9a-f]{64}$/.test(envelope.id) &&
   /^[0-9a-f]{16}$/.test(envelope.dest_hint) &&
   Number.isInteger(envelope.created_at) && envelope.created_at > 0 &&
   envelope.ttl === 604800 &&
   typeof envelope.payload === "string",
   "envelope shape conforms to §3.1");
ok(envelope.dest_hint === bob.hint, "dest_hint addresses Bob's X25519 key (§6.1)");
ok(envelope.id === DTN.computeEnvelopeId(1, envelope.dest_hint, envelope.created_at, envelope.ttl, envelope.payload),
   "id is the SHA-256 of the canonical §5.2 string (§6.2)");
{
  const decodedLen = DTN.b64decode(envelope.payload).length;
  ok(decodedLen >= 248 && decodedLen <= 400,
     `decoded payload length ${decodedLen} within the §8.2 bounds [248, 400]`);
}

// Mule visibility: it sees dest_hint but no sender/message bytes.
{
  const payloadText = Buffer.from(DTN.b64decode(envelope.payload)).toString("latin1");
  const aliasB64 = Buffer.from("alice_77", "utf8").toString("base64").replace(/[+/=]/g, "");
  ok(!payloadText.includes("alice_77") && !payloadText.includes("Hola Bob"),
     "mule/node cannot see the sender alias or message in the payload (sign-then-encrypt, §4.2)");
  ok(aliasB64.length > 0 && !payloadText.includes(aliasB64),
     "no trivially encoded alias fragment leaks into the payload");
}

// A third party (a mule with its own identity) cannot open it.
const mule = DTN.createIdentity();
const muleAttempt = DTN.decryptEnvelope(envelope, mule, nowSec);
ok(muleAttempt.ok === false, "a mule without Bob's key cannot decrypt (silent reject)");
ok(muleAttempt.reason === "not_mine" || muleAttempt.reason === "crypto",
   `third-party rejection is silent and reason-free for the mule (got "${muleAttempt.reason}")`);

// The sender cannot open her own envelope either (ephemeral key is discarded).
const selfAttempt = DTN.decryptEnvelope(envelope, alice, nowSec);
ok(selfAttempt.ok === false, "Alice cannot open her own envelope (ephemeral secret discarded, §7.3)");

// Bob classifies and decrypts.
ok(DTN.classifyPullEnvelopes([envelope], bob.hint).mine.length === 1,
   "mule classification routes the envelope to Bob (dest_hint match)");
const received = DTN.decryptEnvelope(envelope, bob, nowSec);
ok(received.ok === true, "Bob decrypts the envelope");
ok(received.m === message && received.a === "alice_77" && received.t === nowSec,
   "message, sender alias and timestamp arrive intact after signature verification");

console.log("== (d) tamper resistance and wrong-recipient rejection ==");
{
  const raw = DTN.b64decode(envelope.payload);
  const flipped = Uint8Array.from(raw);
  flipped[60] ^= 0xff; // corrupt inside the box (ciphertext/MAC region)
  const flippedPayload = DTN.b64encode(flipped);
  // The strongest forger recomputes the PUBLIC §6.2 id over the doctored
  // payload — what must still stop this tamper is the Poly1305 MAC.
  const tampered = {
    ...envelope,
    payload: flippedPayload,
    id: DTN.computeEnvelopeId(1, envelope.dest_hint, envelope.created_at, envelope.ttl, flippedPayload)
  };
  const res = DTN.decryptEnvelope(tampered, bob, nowSec);
  ok(res.ok === false && res.reason === "crypto",
     "flipped payload byte is rejected by the Poly1305 MAC, silently");
}
{
  const raw = DTN.b64decode(envelope.payload);
  const flipped = Uint8Array.from(raw);
  flipped[3] ^= 0x01; // corrupt the ephemeral public key
  const tampered = { ...envelope, payload: DTN.b64encode(flipped) };
  const res = DTN.decryptEnvelope(tampered, bob, nowSec);
  ok(res.ok === false, "corrupted ephemeral key is rejected silently");
}
{
  // Signature forgery: valid box, but the inner signature does not match k.
  const forged = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "forgery",
    alias: "mallory",
    signSecret: mule.signSecret,
    signPublic: mule.signPublic,
    createdAt: nowSec
  });
  const res = DTN.decryptEnvelope(forged, bob, nowSec);
  ok(res.ok === true && res.a === "mallory",
     "an honestly signed envelope from a third identity still verifies (signature bound to its own k)");
  // Now swap the inner signature for one made with a different key over the
  // same signed string: must fail verification.
  const innerSigned = DTN.canonicalSignedString("forgery", "mallory",
    DTN.b64encode(mule.signPublic), nowSec);
  const wrongSig = DTN.b64encode(DTN.nacl.sign.detached(
    DTN.utf8Encode(innerSigned), alice.signSecret));
  const victim = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "forgery",
    alias: "mallory",
    signSecret: mule.signSecret,
    signPublic: mule.signPublic,
    createdAt: nowSec
  });
  const rawVictim = DTN.b64decode(victim.payload);
  const boxed = rawVictim.subarray(56);
  const ephPub = rawVictim.subarray(0, 32);
  const nonce = rawVictim.subarray(32, 56);
  const innerBytes = DTN.nacl.box.open(boxed, nonce, ephPub, bob.boxSecret);
  const innerJson = JSON.parse(DTN.utf8Decode(innerBytes));
  innerJson.s = wrongSig;
  // Re-encrypt the forged inner toward Bob with a fresh ephemeral key.
  const eph2 = DTN.nacl.box.keyPair();
  const nonce2 = DTN.randomBytes(24);
  const box2 = DTN.nacl.box(DTN.utf8Encode(DTN.canonicalInnerJson(
    innerJson.m, innerJson.a, innerJson.k, innerJson.s, innerJson.t)),
    nonce2, bob.boxPublic, eph2.secretKey);
  const forged2Payload = DTN.b64encode(DTN.concatBytes(eph2.publicKey, nonce2, box2));
  const forged2 = {
    v: 1,
    id: DTN.computeEnvelopeId(1, victim.dest_hint, nowSec, 604800, forged2Payload),
    dest_hint: victim.dest_hint,
    created_at: nowSec,
    ttl: 604800,
    payload: forged2Payload
  };
  const res2 = DTN.decryptEnvelope(forged2, bob, nowSec);
  ok(res2.ok === false && res2.reason === "bad_signature",
     "a signature made by a different key over the same bytes fails Ed25519 verification");
}
{
  // Inner-field validation: oversize message, bad alias, wrong key lengths.
  const build = (opts) => DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "x",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: nowSec,
    ...opts
  });
  ok((() => { try { build({ message: "x".repeat(129) }); return false; } catch (e) { return true; } })(),
     "129-byte message is rejected at build time (§8.1 byte limit)");
  ok((() => { try { build({ message: "á".repeat(65) }); return false; } catch (e) { return true; } })(),
     "65 two-byte chars (130 bytes) rejected — the limit is UTF-8 bytes, not chars");
  ok(DTN.messageByteLength("á".repeat(64)) === 128,
     "byte counter counts UTF-8 bytes: 64 two-byte chars = 128 bytes");
  ok((() => { try { build({ alias: "bad alias!" }); return false; } catch (e) { return true; } })(),
     "alias outside ^[A-Za-z0-9_.-]{1,24}$ rejected (§8.1)");
  ok((() => { try { build({ ttl: 3599 }); return false; } catch (e) { return true; } })() &&
     (() => { try { build({ ttl: 2592001 }); return false; } catch (e) { return true; } })(),
     "ttl outside [3600, 2592000] rejected at build time (§8.1)");
}
{
  // From-future timestamp is optionally rejected (§4.3 step 6).
  const future = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "from the future",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: nowSec + 400
  });
  const res = DTN.decryptEnvelope(future, bob, nowSec);
  ok(res.ok === false && res.reason === "from_future", "timestamp > 300 s in the future rejected");
}
{
  // Structural noise.
  ok(DTN.decryptEnvelope({ v: 1, id: "x" }, bob, nowSec).ok === false, "garbage envelope rejected");
  ok(DTN.decryptEnvelope(null, bob, nowSec).ok === false, "null envelope rejected");
}

console.log("== (e) transit FIFO eviction at capacity 100 (§8.1) ==");
{
  const queue = [];
  for (let i = 0; i < 105; i++) {
    queue.push({ id: DTN.hexEncode(DTN.sha256(DTN.utf8Encode("e" + i))), created_at: 1759500000 + i });
  }
  const out = DTN.evictTransitQueue(queue, DTN.TRANSIT_CAPACITY);
  ok(out.kept.length === 100 && out.evicted.length === 5, "105 envelopes -> keep 100, evict 5");
  const oldestEvicted = Math.min(...out.evicted.map((r) => r.created_at));
  const newestEvicted = Math.max(...out.evicted.map((r) => r.created_at));
  const oldestKept = Math.min(...out.kept.map((r) => r.created_at));
  ok(oldestEvicted === 1759500000 && newestEvicted === 1759500004,
     "evicted envelopes are the 5 oldest (FIFO by created_at)");
  ok(oldestKept === 1759500005, "kept envelopes are the newest 100");
  ok(out.kept.length + out.evicted.length === queue.length, "no envelope lost by eviction");

  const atCap = DTN.evictTransitQueue(queue.slice(0, 100), DTN.TRANSIT_CAPACITY);
  ok(atCap.kept.length === 100 && atCap.evicted.length === 0, "exactly at capacity nothing is evicted");
  const under = DTN.evictTransitQueue(queue.slice(0, 42), DTN.TRANSIT_CAPACITY);
  ok(under.kept.length === 42 && under.evicted.length === 0, "under capacity nothing is evicted");

  // Ties on created_at break deterministically on id.
  const tied = Array.from({ length: 102 }, (_, i) => ({
    id: DTN.hexEncode(DTN.sha256(DTN.utf8Encode("t" + ((102 - i) % 102)))),
    created_at: 1759500000
  }));
  const tiedOut = DTN.evictTransitQueue(tied, DTN.TRANSIT_CAPACITY);
  ok(tiedOut.kept.length === 100 && tiedOut.evicted.length === 2,
     "tied created_at values still evict exactly 2 deterministically");
}

console.log("== engine exposure ==");
ok(sandbox.window.DTN === DTN && sandbox.self.DTN === DTN,
   "the shipped file exposes window.DTN with the pure engine (DOM-free)");

console.log(`\nPASS: ${passed} assertions against the SPA engine (index.html script order)`);

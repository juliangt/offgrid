// Long-message chunking test (§4.4, issue #24).
//
// Loads the shipped scripts in the exact order declared by
// node/web/index.html (via tests/helpers/spa_loader.mjs) and asserts the
// client-side chunking convention end to end, headlessly:
//
//   (a) splitting (§4.4): UTF-8 code-point boundaries are never split
//       (accents, emoji, surrogate pairs), chunks are equal-ish and every
//       chunk respects the per-sender budget (94 - |alias| bytes, the §8.2
//       payload bound minus the signed metadata footprint), the flat path
//       is untouched for ≤ 128-byte texts, and the N ≤ 16 cap is enforced
//   (b) canonical forms: the §4.4 signed byte string and inner_json have
//       the exact fixed member order (worked vector), and the plain §5.1
//       string for flat messages is byte-identical to the pre-§4.4 form
//   (c) envelope-level round trip: every chunk envelope is an ordinary
//       §3.1 envelope within the §8.2 payload bounds, all chunks share
//       created_at and ttl, out-of-order arrival reassembles, duplicates
//       are absorbed, and ANY tampered metadata member (i, g, n, w) is
//       rejected — the signature covers it
//   (d) reassembly state machine: first-write-wins per index, completion
//       exactly at n parts, TTL-aligned expiry, inbox record shape
//   (e) composer validation: chunk metadata shape at buildEnvelope level
//       (g length, i/n ranges) and the envelope-count cap
//
// Run: node tests/chunking.mjs   (exit 0 = pass)

import crypto from "node:crypto";
import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();

const DTN = sandbox.DTN;
if (!DTN || typeof DTN.buildMessageEnvelopes !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (chunking.js missing?)");
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

// Decrypt-then-re-encrypt helper: opens one of Alice's chunk envelopes as
// Bob, mutates the decrypted inner through `mutate`, re-boxes it toward Bob
// with a FRESH ephemeral key and answers with a well-formed envelope whose
// inner carries the mutation but NO fresh signature (the attacker holds no
// signing key) — exactly what a malicious peer could produce.
function forgedWithMutatedInner(env, bob, mutate) {
  const raw = DTN.b64decode(env.payload);
  const innerBytes = DTN.nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), bob.boxSecret);
  if (!innerBytes) throw new Error("fixture: could not open the envelope");
  const inner = JSON.parse(DTN.utf8Decode(innerBytes));
  mutate(inner);
  const rebuilt = inner.n !== undefined && inner.w !== undefined
    ? DTN.canonicalChunkedInnerJson(inner.m, inner.a, inner.k, inner.s, inner.t, inner.w, inner.g, inner.i, inner.n)
    : DTN.canonicalInnerJson(inner.m, inner.a, inner.k, inner.s, inner.t);
  const eph = DTN.nacl.box.keyPair();
  const nonce = DTN.randomBytes(24);
  const box = DTN.nacl.box(DTN.utf8Encode(rebuilt), nonce, bob.boxPublic, eph.secretKey);
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

console.log("== (a) splitting: code points, budgets, caps ==");
{
  // ASCII 1 KiB, alias alice_77 (budget 94 - 8 = 86): 12 equal-ish chunks.
  const kib = "a".repeat(1024);
  ok(DTN.chunkTextBudget("alice_77") === 86, "budget for alice_77 is 94 - 8 = 86 bytes (§8.2 math)");
  ok(DTN.chunkPlannedCount(kib, "alice_77") === 12, "1 KiB ASCII at budget 86 -> 12 envelopes");
  const kibParts = DTN.chunkSplitText(kib, "alice_77");
  ok(kibParts.join("") === kib, "chunks concatenate back to the original text");
  ok(kibParts.every((p) => DTN.messageByteLength(p) <= 86),
    "every chunk within the sender budget (86 B)");
  ok(Math.max(...kibParts.map((p) => DTN.messageByteLength(p))) === 86,
    "chunks are equal-ish: the largest hits the budget exactly");

  // Accents (2-byte code points): boundaries never split a character.
  const accents = "á".repeat(65); // 130 bytes
  const accentParts = DTN.chunkSplitText(accents, "a");
  ok(accentParts.length >= 2 && accentParts.join("") === accents,
    "65 accented chars (130 B) split into >= 2 whole-character chunks");
  ok(accentParts.every((p) => DTN.utf8Decode(DTN.utf8Encode(p)) === p && !p.includes("\uFFFD")),
    "no accent is split: every chunk re-encodes cleanly (no U+FFFD)");

  // Emoji (4-byte code points, surrogate pairs in JS strings).
  const emoji = "\u{1F600}".repeat(33); // 132 bytes
  const emojiParts = DTN.chunkSplitText(emoji, "a");
  ok(emojiParts.join("") === emoji, "33 emoji (132 B) split without losing any code point");
  ok(emojiParts.every((p) => DTN.messageByteLength(p) <= 93),
    "emoji chunks stay within the budget");
  ok(emojiParts.every((p) => DTN.utf8Decode(DTN.utf8Encode(p)) === p && p.length % 2 === 0),
    "every emoji chunk re-encodes byte-identically (pairs never split)");

  // Mixed script fuzz: nothing ever splits a code point or exceeds bounds.
  // Code POINTS only (no lone surrogates — utf8Encode maps those to U+FFFD
  // by design, matching TextEncoder, and they are not valid message text).
  const poolCodes = [..."abcdefghijklmnopqrstuvwxyz áéíóúñüçßøæ αβγδεζηθικ \u{1F600}\u{1F680}\u{1F4A9} \"\\\n\t"]
    .map((c) => c.codePointAt(0));
  let fuzzRuns = 0;
  for (let trial = 0; trial < 60; trial++) {
    let s = "";
    const targetBytes = 130 + Math.floor(crypto.randomBytes(2).readUIntBE(0, 2) % 1200);
    while (DTN.messageByteLength(s) < targetBytes) {
      s += String.fromCodePoint(poolCodes[crypto.randomBytes(1)[0] % poolCodes.length]);
    }
    for (const alias of ["a", "alice_77", "a".repeat(24)]) {
      const parts = DTN.chunkSplitText(s, alias);
      if (parts.length === 0) continue; // over the 16-envelope cap for this alias
      fuzzRuns++;
      const budget = DTN.chunkTextBudget(alias);
      if (parts.join("") !== s) throw new Error("fuzz: concatenation mismatch");
      if (parts.some((p) => DTN.messageByteLength(p) > budget)) throw new Error("fuzz: chunk over budget");
      if (parts.some((p) => DTN.utf8Decode(DTN.utf8Encode(p)) !== p)) throw new Error("fuzz: split a code point");
      if (parts.length > DTN.CHUNK_MAX_PARTS) throw new Error("fuzz: over the part cap");
    }
  }
  ok(fuzzRuns > 100, `mixed-script fuzz: ${fuzzRuns} splits all respected boundaries, budgets and the cap`);

  // Exact byte-limit cases at the 24-char alias (budget 70): 16 x 70 = 1120.
  ok(DTN.chunkPlannedCount("x".repeat(1120), "a".repeat(24)) === 16,
    "1120 ASCII bytes at a 24-char alias -> exactly 16 envelopes (the cap)");
  ok(DTN.chunkPlannedCount("x".repeat(1121), "a".repeat(24)) === 0,
    "1121 bytes at a 24-char alias -> refused (would exceed 16 envelopes)");
  ok(DTN.chunkPlannedCount("", "alice_77") === 0, "empty text -> 0 envelopes");
  ok(DTN.chunkComposerLimit("a".repeat(24)) === 1120 && DTN.chunkComposerLimit("a") === 16 * 93,
    "composer limit is 16 x budget (alias-dependent, §4.4)");
  ok(throws(() => DTN.buildMessageEnvelopes({
    recipientBoxPublic: new Uint8Array(32), message: "x".repeat(1121),
    alias: "a".repeat(24), signSecret: new Uint8Array(64), signPublic: new Uint8Array(32),
    createdAt: 1759500000,
  })), "buildMessageEnvelopes refuses a message beyond the 16-envelope cap");
}

console.log("== (b) canonical §4.4 forms: worked vector + plain §5.1 byte-identity ==");
{
  const g = "A2aYc0XrQ0mT7oP9wK5v1g=="; // Base64 of 16 bytes (24 chars, §3.3 padding)
  ok(DTN.b64decode(g) !== null && DTN.b64decode(g).length === 16,
    "the worked vector g decodes to exactly 16 bytes");
  const wantSigned = '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001,"w":"chunk1","g":"A2aYc0XrQ0mT7oP9wK5v1g==","i":0,"n":2}';
  ok(DTN.canonicalChunkedSignedString("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001, "chunk1", g, 0, 2) === wantSigned,
    "§4.4 signed byte string: the §5.1 form gains w,g,i,n in fixed order after t (worked vector)");
  const wantInner = '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","s":"<88-char Base64 Ed25519 signature>","t":1759500001,"w":"chunk1","g":"A2aYc0XrQ0mT7oP9wK5v1g==","i":0,"n":2}';
  ok(DTN.canonicalChunkedInnerJson("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "<88-char Base64 Ed25519 signature>",
      1759500001, "chunk1", g, 0, 2) === wantInner,
    "§4.4 inner_json: s keeps its §4.1 position, then w,g,i,n in the same fixed order");

  // The plain §5.1 string is UNCHANGED by this feature (binding): same
  // inputs as the §4.1/§5.1 example produce the exact historical bytes.
  ok(DTN.canonicalSignedString("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001) ===
     '{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001}',
    "plain §5.1 signed byte string stays byte-identical to the pre-§4.4 form");
  ok(DTN.canonicalChunkedSignedString("Hola Bob", "alice_77",
      "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001, "chunk1", g, 0, 2)
     .startsWith(DTN.canonicalSignedString("Hola Bob", "alice_77",
       "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", 1759500001).slice(0, -1)),
    "the chunked string is literally the §5.1 string plus the four members (no other drift)");
}

console.log("== (c) envelope round trip: §8 bounds, shared lifetime, out-of-order, duplicates, tamper ==");
const bob = DTN.createIdentity();
const alice = DTN.createIdentity();
const mule = DTN.createIdentity();
const NOW = 1759500000;
// A 1 KiB text whose accents and emoji cross the chunk boundaries.
const longMessage = ("¡Hola Bob! Esta línea supera el viejo límite de 128 bytes — " +
  "el nodo, la mula y el sobre no cambian; solo el contenido viaja troceado. " +
  "Cada trozo lleva su firma ☕ y llega en cualquier orden. " +
  "Fin del mensaje de prueba con acentos: áéíóú ☕☕☕");
const chunkEnvs = DTN.buildMessageEnvelopes({
  recipientBoxPublic: bob.boxPublic, message: longMessage, alias: "alice_77",
  signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: NOW,
});
{
  ok(chunkEnvs.length > 1, `a ${DTN.messageByteLength(longMessage)}-byte message splits into ${chunkEnvs.length} envelopes`);
  ok(chunkEnvs.every((e) => DTN.validEnvelopeShape(e) && e.v === 1),
    "every chunk envelope is an ordinary v1 §3.1 envelope (nodes see nothing new)");
  ok(chunkEnvs.every((e) => { const l = DTN.b64decode(e.payload).length; return l >= 248 && l <= 400; }),
    "every chunk payload within the §8.2 bounds [248, 400] — nodes reject nothing new");
  ok(new Set(chunkEnvs.map((e) => e.created_at)).size === 1 && new Set(chunkEnvs.map((e) => e.ttl)).size === 1,
    "all chunks share created_at and ttl (§4.4: no per-chunk lifetime games)");
  ok(new Set(chunkEnvs.map((e) => e.id)).size === chunkEnvs.length,
    "chunk ids are distinct (each is a first-class dedupable envelope)");
  const decs = chunkEnvs.map((e) => DTN.decryptEnvelope(e, bob, NOW));
  ok(decs.every((d) => d.ok && d.chunk && d.chunk.n === chunkEnvs.length),
    "Bob decrypts every chunk; the signature covers the metadata (verified implicitly)");
  ok(decs.every((d) => d.chunk.w === DTN.CHUNK_TAG),
    'every chunk carries the "chunk1" schema tag');
  ok(new Set(decs.map((d) => d.chunk.g)).size === 1 && DTN.b64decode(decs[0].chunk.g).length === 16,
    "all chunks share one random 16-byte message id g");
  ok([...decs].map((d) => d.chunk.i).sort((x, y) => x - y).join(",") === decs.map((_, i) => i).join(","),
    "chunk indexes cover 0..n-1 exactly once");
  ok(decs.every((d) => DTN.messageByteLength(d.m) <= 128),
    "every chunk text within the §8.1 128-byte plaintext limit");

  // Out-of-order + duplicate reassembly through the pure state machine.
  let state = null;
  const shuffled = [...decs].reverse(); // worst case: exact reverse arrival
  for (const d of shuffled) {
    if (!state) state = DTN.chunkNewState(d.chunk.g, d.chunk.n, d.a, d.t, NOW, 604800, NOW);
    state = DTN.chunkStateWithPart(state, d.chunk.i, d.m, "env-id");
  }
  ok(!DTN.chunkStateComplete({ ...state, parts: {} }) && DTN.chunkStateComplete(state),
    "out-of-order arrival reassembles: incomplete until the n-th chunk, complete after");
  ok(DTN.chunkStateText(state) === longMessage,
    "reassembled text equals the original (concatenated by index, not arrival order)");
  const heldText = DTN.chunkStateText(state);
  state = DTN.chunkStateWithPart(state, 0, "REPLAYED TEXT", "other-env-id");
  ok(DTN.chunkStateText(state) === heldText,
    "a duplicate chunk (same index) is a no-op: first write wins");
}

console.log("== (c2) tampered chunk metadata is rejected — the signature covers w,g,i,n ==");
{
  const victim = chunkEnvs[0];
  const flipI = (inner) => { inner.i = (inner.i + 1) % inner.n; };
  const flipG = (inner) => { inner.g = DTN.b64encode(DTN.randomBytes(16)); };
  const flipN = (inner) => { inner.n = inner.n === 2 ? 3 : 2; };
  const flipW = (inner) => { inner.w = "chunk2"; };
  for (const [label, mutate, reason] of [
    ["i", flipI, "bad_signature"],
    ["g", flipG, "bad_signature"],
    ["n", flipN, "bad_signature"],
    ["w", flipW, "bad_inner"],
  ]) {
    const res = DTN.decryptEnvelope(forgedWithMutatedInner(victim, bob, mutate), bob, NOW);
    ok(res.ok === false && res.reason === reason,
      `a peer-altered chunk ${label} is rejected (${reason}) — metadata is inside the signature`);
  }
  // A chunk metadata member dropped entirely (5-member inner with w removed).
  const res = DTN.decryptEnvelope(forgedWithMutatedInner(victim, bob, (inner) => { delete inner.w; delete inner.g; delete inner.i; delete inner.n; }), bob, NOW);
  ok(res.ok === false && res.reason === "bad_signature",
    "stripping the metadata fails too (the remaining five members no longer match any signature)");
}

console.log("== (c3) malformed chunk inners are structurally rejected (§4.4) ==");
{
  // Box a RAW inner byte string (no canonical rebuild — extra members and
  // other byte-level oddities must survive to the recipient's parser).
  const boxRawInner = (env, innerJsonString) => {
    const eph = DTN.nacl.box.keyPair();
    const nonce = DTN.randomBytes(24);
    const box = DTN.nacl.box(DTN.utf8Encode(innerJsonString), nonce, bob.boxPublic, eph.secretKey);
    const payload = DTN.b64encode(DTN.concatBytes(eph.publicKey, nonce, box));
    return { v: 1, id: DTN.computeEnvelopeId(1, env.dest_hint, env.created_at, env.ttl, payload), dest_hint: env.dest_hint, created_at: env.created_at, ttl: env.ttl, payload };
  };
  const rawInnerTextOf = (env) => {
    const raw = DTN.b64decode(env.payload);
    return DTN.utf8Decode(DTN.nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), bob.boxSecret));
  };
  const mk = (chunkFields, extraMembers) => {
    const env = chunkEnvs[0];
    return forgedWithMutatedInner(env, bob, (inner) => {
      Object.assign(inner, chunkFields);
      if (extraMembers) for (const k of extraMembers) inner[k] = "x";
    });
  };
  // Structural rejections happen before signature checks, so rebuild with a
  // REAL signature where the shape is legal but the value is out of range.
  const reSign = (env, mutate) => {
    const raw = DTN.b64decode(env.payload);
    const inner = JSON.parse(DTN.utf8Decode(DTN.nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), bob.boxSecret)));
    mutate(inner);
    const signed = DTN.canonicalChunkedSignedString(inner.m, inner.a, inner.k, inner.t, inner.w, inner.g, inner.i, inner.n);
    // Signed by ALICE (the honest sender): shape errors must be caught even
    // under a valid signature; that is the structural validation's job.
    inner.s = DTN.b64encode(DTN.nacl.sign.detached(DTN.utf8Encode(signed), alice.signSecret));
    const eph = DTN.nacl.box.keyPair();
    const nonce = DTN.randomBytes(24);
    const box = DTN.nacl.box(DTN.utf8Encode(DTN.canonicalChunkedInnerJson(inner.m, inner.a, inner.k, inner.s, inner.t, inner.w, inner.g, inner.i, inner.n)), nonce, bob.boxPublic, eph.secretKey);
    const payload = DTN.b64encode(DTN.concatBytes(eph.publicKey, nonce, box));
    return { v: 1, id: DTN.computeEnvelopeId(1, env.dest_hint, env.created_at, env.ttl, payload), dest_hint: env.dest_hint, created_at: env.created_at, ttl: env.ttl, payload };
  };
  ok(DTN.decryptEnvelope(mk({ w: "chunk2" }, null), bob, NOW).reason === "bad_inner",
    'an unknown w tag ("chunk2") is corrupt by definition (§4.4 versioned tag)');
  ok(DTN.decryptEnvelope(reSign(chunkEnvs[0], (inner) => { inner.g = "c2hvcnQ="; }), bob, NOW).reason === "bad_inner",
    "a g that is not Base64-of-16-bytes is rejected even under a valid signature");
  ok(DTN.decryptEnvelope(reSign(chunkEnvs[0], (inner) => { inner.i = inner.n; }), bob, NOW).reason === "bad_inner",
    "i == n (out of range) rejected even under a valid signature");
  ok(DTN.decryptEnvelope(reSign(chunkEnvs[0], (inner) => { inner.n = 17; inner.i = 0; }), bob, NOW).reason === "bad_inner",
    "n = 17 beyond the §4.4 cap rejected even under a valid signature");
  {
    // Use a chunk with payload headroom: the extra member must be rejected
    // on STRUCTURE (exact member set), not merely for lack of §8.2 space.
    const small = DTN.buildMessageEnvelopes({
      recipientBoxPublic: bob.boxPublic, message: "y".repeat(200), alias: "alice_77",
      signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: NOW,
    });
    const last = small[small.length - 1];
    const weird = boxRawInner(last, rawInnerTextOf(last).replace(/\}\s*$/, ',"zz":"x"}'));
    ok(DTN.decryptEnvelope(weird, bob, NOW).reason === "bad_inner",
      "an inner with an extra unknown member is rejected (exact member set)");
  }
  // The honest envelope still verifies after all this hostility.
  ok(DTN.decryptEnvelope(chunkEnvs[0], bob, NOW).ok === true,
    "the untouched chunk still decrypts and verifies");
}

console.log("== (d) reassembly state machine details ==");
{
  const g = DTN.b64encode(DTN.randomBytes(16));
  let state = DTN.chunkNewState(g, 3, "alice_77", NOW, NOW, 604800, NOW);
  ok(state.parts && Object.keys(state.parts).length === 0, "a fresh partial holds zero parts");
  state = DTN.chunkStateWithPart(state, 1, "B", "env1");
  state = DTN.chunkStateWithPart(state, 0, "A", "env0");
  ok(DTN.chunkStateHave(state) === 2 && !DTN.chunkStateComplete(state),
    "2 of 3 held, still incomplete (out-of-order gap on index 2)");
  state = DTN.chunkStateWithPart(state, 2, "C", "env2");
  ok(DTN.chunkStateComplete(state) && DTN.chunkStateText(state) === "ABC",
    "completion at exactly n parts; text is index-ordered, not arrival-ordered");
  const rec = DTN.chunkInboxRecord(state);
  ok(rec.id === "g:" + g && rec.m === "ABC" && rec.a === "alice_77" && rec.t === NOW && rec.parts === 3,
    "the inbox record derives its storage id from the group id (all chunk envelope ids ride in seen_ids)");
  ok(DTN.chunkStateExpired(state, NOW + 604800) === false &&
     DTN.chunkStateExpired(state, NOW + 604800 + 1) === true,
    "partial expiry is TTL-aligned with the exclusive §10.6 boundary (created_at + ttl < now)");
  const snapshot = JSON.stringify(DTN.chunkNewState(g, 3, "alice_77", NOW, NOW, 604800, NOW));
  DTN.chunkStateWithPart(DTN.chunkNewState(g, 3, "alice_77", NOW, NOW, 604800, NOW), 0, "x", "e");
  ok(JSON.stringify(DTN.chunkNewState(g, 3, "alice_77", NOW, NOW, 604800, NOW)) === snapshot,
    "the merge never mutates its input state");
}

console.log("== (e) build-time metadata validation and the flat path ==");
{
  const base = {
    recipientBoxPublic: bob.boxPublic, message: "chunk", alias: "alice_77",
    signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: NOW,
  };
  const g = DTN.b64encode(DTN.randomBytes(16));
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g: "c2hvcnQ=", i: 0, n: 2 } })),
    "chunk.g shorter than 16 bytes rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g, i: -1, n: 2 } })),
    "negative chunk.i rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g, i: 2, n: 2 } })),
    "chunk.i == chunk.n rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g, i: 0, n: 1 } })),
    "chunk.n = 1 rejected (a single-part message is flat, never 'chunked')");
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g, i: 0, n: 17 } })),
    "chunk.n = 17 beyond the §4.4 cap rejected at build time");
  ok(throws(() => DTN.buildEnvelope({ ...base, chunk: { g, i: 0.5, n: 2 } })),
    "non-integer chunk.i rejected at build time");

  // Flat path byte-identity: a ≤128-byte message through the chunking
  // entry point produces the same envelope shape as buildEnvelope always has.
  const flat = DTN.buildMessageEnvelopes({ ...base, message: "Hola Bob, nos vemos mañana ☕" });
  const direct = DTN.buildEnvelope({ ...base, message: "Hola Bob, nos vemos mañana ☕" });
  const dec = DTN.decryptEnvelope(flat[0], bob, NOW);
  const raw = DTN.b64decode(flat[0].payload);
  const inner = JSON.parse(DTN.utf8Decode(DTN.nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), bob.boxSecret)));
  ok(flat.length === 1 && Object.keys(inner).length === 5 && !("w" in inner),
    "a ≤128-byte message stays FLAT: five inner members, no chunk metadata");
  ok(dec.ok && dec.chunk === undefined && dec.m === "Hola Bob, nos vemos mañana ☕",
    "the flat decrypt result carries no chunk member");
  ok(flat[0].v === direct.v && flat[0].dest_hint === direct.dest_hint,
    "flat envelopes are indistinguishable from pre-§4.4 envelopes");
  // The §5.1 string reconstructed from a flat inner equals the historical form.
  ok(DTN.canonicalSignedString(inner.m, inner.a, inner.k, inner.t) ===
     DTN.canonicalSignedString("Hola Bob, nos vemos mañana ☕", "alice_77", inner.k, inner.t),
    "flat signed string construction is unchanged");
  ok(mule.hint !== bob.hint && DTN.decryptEnvelope(chunkEnvs[0], mule, NOW).ok === false,
    "a mule still cannot open chunk envelopes (blind, §13.1)");
}

console.log(`\nPASS: ${passed} assertions on the §4.4 chunking convention (index.html script order)`);

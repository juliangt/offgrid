// Rotating dest_hint test for the SPA engine (issue #26, spec §6.1 — the
// SPA-side rows of the §15.7 matrix g, h, i).
//
// Loads the shipped scripts in the exact order declared by
// node/web/index.html (via tests/helpers/spa_loader.mjs) and asserts:
//
//   (a) the HKDF primitive (hkdf.js, pure ES5 over the vendored SHA-256)
//       against the official RFC 5869 Appendix A test cases 1 and 3
//   (b) the §6.1 worked rotating vector (key, epoch, salt, PRK, OKM, hint)
//       and the previous-epoch hint — the exact values pinned in the spec
//   (c) the §6.1 constants are the pinned ones (epoch 86400, info string,
//       transition deadline 2026-11-30T00:00:00Z) and the salt is the
//       8-byte big-endian epoch
//   (d) the sender derives the hint from the DIRECTORY ENTRY's epoch:
//       buildEnvelope with hintEpoch = entry.epoch addresses hint(E); a
//       chunked message addresses EVERY chunk with the same epoch's hint;
//       the envelope id/dedup construction (§6.2) is unaffected
//   (e) the recipient candidate set is {legacy, hint(E), hint(E−1)} before
//       the deadline, {hint(E), hint(E−1)} after it, and falls back to the
//       device clock offline-cold (§15.7 h, §11)
//   (f) recognition across a simulated epoch boundary (§15.7 g): an
//       envelope minted for E is classified as mine and DECRYPTED with the
//       candidate set of E+1 — no message loss across one rotation
//   (g) the static-candidate drop (§15.7 i): before the deadline a
//       legacy-addressed envelope is delivered; after it, the same
//       envelope is foreign cargo and decryptEnvelope refuses it
//   (h) backward compatibility: the pre-1.6 single-string classification
//       form and the default (no-candidates) decrypt path keep working;
//       envelope-id dedup and the §4.4/§4.5 conventions are untouched
//
// Run: node tests/hint_rotation.mjs   (exit 0 = pass)

import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();

const DTN = sandbox.DTN;
if (!DTN || typeof DTN.buildEnvelope !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (nacl or buildEnvelope missing)");
}
for (const fn of ["hmacSha256", "hkdfSha256", "epochOf", "deriveRotatingHint", "hintCandidates", "observedEpochFromCapabilities"]) {
  if (typeof DTN[fn] !== "function") throw new Error(`DTN.${fn} missing — hkdf.js/envelopes.js/mule.js did not load`);
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

function hexBytes(hex) {
  const raw = DTN.hexDecode(hex);
  if (!raw) throw new Error(`bad hex fixture: ${hex}`);
  return raw;
}

console.log("== (a) HKDF-SHA256 primitive — official RFC 5869 Appendix A cases ==");
{
  // Case 1 (SHA-256): ikm = 0x0b x22, salt = 0x000102...0c, info = 0xf0..f9, L = 42.
  const tc1 = DTN.hkdfSha256(hexBytes("0b".repeat(22)),
    hexBytes("000102030405060708090a0b0c"),
    hexBytes("f0f1f2f3f4f5f6f7f8f9"), 42);
  ok(DTN.hexEncode(tc1) ===
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
     "RFC 5869 Test Case 1 OKM matches (multi-block expansion, info present)");
  // Case 3 (SHA-256): ikm = 0x0b x22, salt and info empty, L = 42.
  const empty = DTN.utf8Encode(""); // an empty sandbox-realm Uint8Array
  const tc3 = DTN.hkdfSha256(hexBytes("0b".repeat(22)), empty, empty, 42);
  ok(DTN.hexEncode(tc3) ===
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
     "RFC 5869 Test Case 3 OKM matches (empty salt/info → HashLen-zero salt)");
  // HMAC-SHA256 smoke (RFC 2104 §2 example over hex data of the RFC).
  const hmac = DTN.hmacSha256(hexBytes("0b".repeat(20)), DTN.utf8Encode("Hi There"));
  ok(DTN.hexEncode(hmac) === "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
     "HMAC-SHA256 matches the RFC 2104 test case");
  ok((() => { try { DTN.hkdfSha256(hexBytes(""), empty, empty, 32); return false; } catch (e) { return true; } })(),
     "HKDF rejects an empty ikm");
  ok((() => { try { DTN.hkdfSha256(hexBytes("0b"), empty, empty, 0); return false; } catch (e) { return true; } })() &&
     (() => { try { DTN.hkdfSha256(hexBytes("0b"), empty, empty, 8161); return false; } catch (e) { return true; } })(),
     "HKDF rejects L outside [1, 255*32]");
}

console.log("== (b) §6.1 worked rotating vector — the spec-pinned values ==");
{
  const alice = hexBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  ok(DTN.epochOf(1791072000) === 20730, "epochOf(2026-10-04T04:26:40Z) = 20730");
  ok(DTN.deriveRotatingHint(alice, 20730) === "cdfbc410643a67f1",
     "dest_hint(E = 20730) matches §6.1 test vector 2");
  ok(DTN.deriveRotatingHint(alice, 20729) === "5459d1d4328608b5",
     "dest_hint(E − 1 = 20729) matches §6.1 test vector 2");
  const legacy = DTN.deriveDestHint(alice);
  ok(legacy === "300c9c9603b92a4b", "the legacy static hint still matches §6.1 test vector 1");
  ok(legacy !== DTN.deriveRotatingHint(alice, 20730),
     "rotating and legacy hints are independent for the same key");
  ok((() => { try { DTN.deriveRotatingHint(alice, 1.5); return false; } catch (e) { return true; } })() &&
     (() => { try { DTN.deriveRotatingHint(alice, -1); return false; } catch (e) { return true; } })(),
     "deriveRotatingHint rejects non-integer and negative epochs");
}

console.log("== (c) pinned §6.1 constants and the big-endian epoch salt ==");
{
  ok(DTN.HINT_EPOCH_SECONDS === 86400, "HINT_EPOCH_SECONDS is the 24 h epoch (§6.1)");
  ok(DTN.HINT_INFO === "offgrid-dest-hint", "HINT_INFO is the exact info string (§6.1)");
  ok(DTN.HINT_LENGTH_BYTES === 8, "HINT_LENGTH_BYTES is 8 (16 hex chars)");
  ok(DTN.HINT_TRANSITION_DEADLINE === 1795996800,
     "HINT_TRANSITION_DEADLINE is 1795996800 = 2026-11-30T00:00:00Z (§6.1)");
  const salt = DTN.epochSalt(20730);
  ok(salt.length === 8 && DTN.hexEncode(salt) === "00000000000050fa",
     "epochSalt renders the 8-byte big-endian epoch (§6.1)");
  ok(DTN.hexEncode(DTN.epochSalt(1)) === "0000000000000001" &&
     DTN.hexEncode(DTN.epochSalt(0)) === "0000000000000000",
     "epochSalt is big-endian from epoch 0 up");
}

console.log("== (d) sender derives the hint from the directory entry's epoch ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const now = 1791072000;
  const entryEpoch = DTN.epochOf(now); // what the node stamped on bob's entry
  const build = (extra) => DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "rotating mail",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: now,
    ...extra
  });
  const env = build({ hintEpoch: entryEpoch });
  ok(env.dest_hint === DTN.deriveRotatingHint(bob.boxPublic, entryEpoch),
     "hintEpoch = entry.epoch addresses the rotating hint for that epoch");
  ok(env.dest_hint !== bob.hint, "the rotating hint differs from the legacy static hint");
  ok(DTN.validEnvelopeShape(env) && /^[0-9a-f]{16}$/.test(env.dest_hint),
     "the envelope keeps its §3.1 shape (same dest_hint admission regex)");
  ok(env.id === DTN.computeEnvelopeId(1, env.dest_hint, env.created_at, env.ttl, env.payload),
     "the §6.2 id construction is unchanged (id covers the hint it was built with)");
  // Dedup unaffected: same core fields, same id; a re-mint for the same epoch
  // differs only by payload (fresh ephemeral key) — dedup stays by id.
  const again = build({ hintEpoch: entryEpoch });
  ok(again.id === DTN.computeEnvelopeId(1, again.dest_hint, again.created_at, again.ttl, again.payload),
     "a re-built envelope still carries a self-consistent §6.2 id");
  ok((() => { try { build({ hintEpoch: "20730" }); return false; } catch (e) { return true; } })(),
     "a non-integer hintEpoch is rejected at build time");
  // A chunked message addresses EVERY chunk with the same epoch's hint.
  const chunkEnvs = DTN.buildMessageEnvelopes({
    recipientBoxPublic: bob.boxPublic, message: "x".repeat(200), alias: "alice_77",
    signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: now, hintEpoch: entryEpoch,
  });
  ok(chunkEnvs.length >= 2 &&
     chunkEnvs.every((e) => e.dest_hint === DTN.deriveRotatingHint(bob.boxPublic, entryEpoch)),
     `all ${chunkEnvs.length} chunks of a chunked message share the entry-epoch hint`);
}

console.log("== (e) recipient candidate set {legacy, E, E-1} / {E, E-1} (§15.7 h) ==");
{
  const bob = DTN.createIdentity();
  const now = 1791072000; // well before the deadline
  const cands = DTN.hintCandidates(bob.boxPublic, 20730, now);
  ok(cands.length === 3 &&
     cands[0] === bob.hint &&
     cands[1] === DTN.deriveRotatingHint(bob.boxPublic, 20730) &&
     cands[2] === DTN.deriveRotatingHint(bob.boxPublic, 20729),
     "before the deadline the set is exactly {legacy, hint(E), hint(E-1)}");
  const post = DTN.hintCandidates(bob.boxPublic, 20730, DTN.HINT_TRANSITION_DEADLINE + 1);
  ok(post.length === 2 &&
     post[0] === DTN.deriveRotatingHint(bob.boxPublic, 20730) &&
     post[1] === DTN.deriveRotatingHint(bob.boxPublic, 20729),
     "after the deadline the legacy candidate is dropped (§15.7 i)");
  const atDeadline = DTN.hintCandidates(bob.boxPublic, 20730, DTN.HINT_TRANSITION_DEADLINE);
  ok(atDeadline.length === 2,
     "exactly AT the deadline the legacy candidate is already dropped (drop is now >= deadline, §6.1)");
  const cold = DTN.hintCandidates(bob.boxPublic, null, now);
  ok(cold.length === 3 && cold[1] === DTN.deriveRotatingHint(bob.boxPublic, DTN.epochOf(now)),
     "offline-cold falls back to the device-clock epoch");
  ok(DTN.observedEpochFromCapabilities({
      api: "v1", envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 2,
      schema_version: 3, build: "dtn-node-dev", hint_epoch_seconds: 86400, hint_epoch_current: 20730,
    }) === 20730,
    "capabilities parsing exposes the additive hint_epoch_current member");
  ok(DTN.observedEpochFromCapabilities({
      api: "v1", envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 2,
      schema_version: 2, build: "old-node",
    }) === null,
    "a pre-1.6 capabilities document (no hint members) observes nothing → null");
}

console.log("== (f) recognition across a simulated epoch boundary (§15.7 g) ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const mintTime = 1791072000;            // mid-epoch 20730
  const afterBoundary = mintTime + 86400; // mid-epoch 20731: a day later
  const env = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic, message: "written yesterday, delivered today",
    alias: "alice_77", signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: mintTime, hintEpoch: DTN.epochOf(mintTime),
  });
  // Bob's session has since observed E+1 (capabilities/directory); the
  // candidate set {hint(E+1), hint(E-1+1)} must still contain hint(E).
  const cls = DTN.classifyPullEnvelopes([env], DTN.hintCandidates(bob.boxPublic, 20731, afterBoundary));
  ok(cls.mine.length === 1 && cls.foreign.length === 0,
     "an E-addressed envelope is still MINE at observed epoch E+1 (one-boundary window)");
  const dec = DTN.decryptEnvelope(env, bob, afterBoundary, DTN.hintCandidates(bob.boxPublic, 20731, afterBoundary));
  ok(dec.ok === true && dec.m === "written yesterday, delivered today" && dec.a === "alice_77",
     "the boundary-crossing envelope decrypts and verifies — no message loss across one rotation");
  // Two boundaries: no longer recognizable (documented decay, §6.1).
  const clsLate = DTN.classifyPullEnvelopes([env], DTN.hintCandidates(bob.boxPublic, 20732, afterBoundary + 86400));
  ok(clsLate.mine.length === 0,
     "two epochs later the E-hint is outside the candidate set (linkability decays)");
}

console.log("== (g) static-candidate drop after the transition deadline (§15.7 i) ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const now = 1791072000;
  // A pre-1.6 sender: no hintEpoch at all → the legacy static derivation.
  const legacyEnv = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic, message: "from a stale pre-1.6 client",
    alias: "alice_77", signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: now,
  });
  ok(legacyEnv.dest_hint === bob.hint, "a pre-1.6 build addresses the static legacy hint");
  const preDeadline = DTN.hintCandidates(bob.boxPublic, 20730, now);
  const postDeadline = DTN.hintCandidates(bob.boxPublic, 20730, DTN.HINT_TRANSITION_DEADLINE + 1);
  ok(DTN.classifyPullEnvelopes([legacyEnv], preDeadline).mine.length === 1,
     "before the deadline the legacy-addressed envelope is delivered (§15.7 h)");
  ok(DTN.decryptEnvelope(legacyEnv, bob, now, preDeadline).ok === true,
     "before the deadline the legacy envelope decrypts");
  const after = DTN.classifyPullEnvelopes([legacyEnv], postDeadline);
  ok(after.mine.length === 0 && after.foreign.length === 1,
     "after the deadline the legacy-addressed envelope is FOREIGN cargo (§15.7 i)");
  ok(DTN.decryptEnvelope(legacyEnv, bob, now, postDeadline).ok === false &&
     DTN.decryptEnvelope(legacyEnv, bob, now, postDeadline).reason === "not_mine",
     "after the deadline decryptEnvelope silently refuses the legacy hint (mail no longer arrives, §6.1)");
  const rotated = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic, message: "current-era mail",
    alias: "alice_77", signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: now, hintEpoch: 20730,
  });
  ok(DTN.classifyPullEnvelopes([rotated], postDeadline).mine.length === 1,
     "after the deadline the ROTATING candidates are unaffected by the drop");
}

console.log("== (h) backward compatibility and dedup invariants ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const now = 1791072000;
  const env = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic, message: "legacy path", alias: "alice_77",
    signSecret: alice.signSecret, signPublic: alice.signPublic, createdAt: now,
  });
  // Pre-1.6 call forms keep working unchanged.
  ok(DTN.classifyPullEnvelopes([env], bob.hint).mine.length === 1,
     "the single-string classification form (pre-1.6 callers) still works");
  ok(DTN.decryptEnvelope(env, bob, now).ok === true,
     "the default decrypt path (no candidates) still uses the legacy identity hint");
  ok(DTN.decryptEnvelope(env, bob, now, env.dest_hint).ok === true,
     "a bare-string candidate set is accepted (pre-1.6 form)");
  ok(DTN.decryptEnvelope(env, bob, now, [env.dest_hint]).ok === true,
     "an array candidate set of one is accepted");
  // Unknown hints classify as foreign cargo (stored, never decrypted).
  const stranger = DTN.classifyPullEnvelopes([env], DTN.hintCandidates(alice.boxPublic, 20730, now));
  ok(stranger.foreign.length === 1 && stranger.mine.length === 0,
     "another identity's candidate set never claims foreign mail");
}

console.log(`\nPASS: ${passed} assertions on the §6.1 rotating dest_hint (index.html script order)`);

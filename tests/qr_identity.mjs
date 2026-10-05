// Identity QR — in-person contact exchange (§4.7, issue #28) — headless
// suite over the SHIPPED SPA engine (tests/helpers/spa_loader.mjs loads
// exactly the files index.html serves). Asserts:
//
//   (a) the CRC-32 primitive (IEEE 802.3) against the standard check value
//       and against the worked-vector CRC — the latter INDEPENDENTLY
//       cross-checked with Python's zlib.crc32 during the development of
//       this suite (the JS table and zlib must agree byte for byte);
//   (b) the §4.7 worked vector: canonical signed string, Ed25519 signature
//       (made by the engine's own vendored nacl, the same RFC 8032 §7.1
//       identity the §4.1/§4.6 vectors pin) and the complete OFFGRID1
//       payload, plus the parse+verify round trip;
//   (c) EVERY tamper class rejected with the exact reason: bit flips in
//       alias/keys/signature, a CRC mismatch alone, a signature swap
//       between two identities, truncated payloads, wrong version, bad
//       Base64, alias regex violations, future timestamps — and nothing
//       stored on any failure;
//   (d) QR encoder validation: for payloads across ALL 15 supported
//       versions the matrix round-trips through an INDEPENDENT minimal
//       decoder (tests/helpers/qr_decode.mjs — its own GF(2^8),
//       Berlekamp-Massey/Chien/Forney, format/version BCH checks, mask
//       formulas, module map and block table; shares no code with the
//       encoder), plus structural checks (finder patterns, timing, format
//       info) and the version-15 size cap;
//   (e) the §4.7 recipient merge: contacts ∪ directory deduped by the
//       Ed25519 key, directory key material wins, the local alias wins,
//       and contacts survive a dead directory (offline-first);
//   (f) the store migration chain: DB_VERSION 5 adds the `contacts` store
//       (keyPath "ed") as an ordered, additive-only, idempotent step.
//
// Run: node tests/qr_identity.mjs   (exit 0 = pass)

import { loadSpaSandbox } from "./helpers/spa_loader.mjs";
import { decodeQR } from "./helpers/qr_decode.mjs";

const sandbox = loadSpaSandbox();
const DTN = sandbox.DTN;
if (!DTN || typeof DTN.qrBuildPayload !== "function" || typeof DTN.qrMakeMatrix !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load with the §4.7 QR functions (qr.js missing from index.html?)");
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

const NOW = 1791072000; // 2026-10-04T04:26:40Z — the spec's test date (mid-epoch 20730)

// Deterministic fixture: the RFC 8032 §7.1 identity (its public is the
// §4.1 example `k` and the §4.6 worked-vector identity key).
const RFC8032_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUB_B64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const WORKED_X_B64 = "/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=";
const WORKED_CANONICAL = '{"v":1,"alias":"alice_77","ed":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","x":"/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=","ts":1791072000}';
const WORKED_CRC = "d76a4d73";
const WORKED_SIG = "g3XAqS73T9xjotQqF3ojXed6E0E1QZHXZESdGrq1ZfHy25VNrUed1+HMaAukFPwA4sHWahn7Ag6c3XsWl4SYAA==";
const WORKED_PAYLOAD = "OFFGRID1:eyJ2IjoxLCJhbGlhcyI6ImFsaWNlXzc3IiwiZWQiOiIxMXFZQVlLeENyZlZTLzdUeVdRSE9nN2hjdlBhcGlNbHJ3SWFhUGNIVVJvPSIsIngiOiIvUjdoSDU5SlVubkJqRExDVUZUUTQ2RjllS2cwa0s4Q2h6ZTFtRVFwcVZnPSIsInRzIjoxNzkxMDcyMDAwLCJzaWciOiJnM1hBcVM3M1Q5eGpvdFFxRjNvalhlZDZFMEUxUVpIWFpFU2RHcnExWmZIeTI1Vk5yVWVkMStITWFBdWtGUHdBNHNIV2FobjdBZzZjM1hzV2w0U1lBQT09IiwiY3JjIjoiZDc2YTRkNzMifQ==";

function workedIdentity() {
  const id = DTN.identityFromSeed(DTN.hexDecode(RFC8032_SEED_HEX));
  if (DTN.b64encode(id.signPublic) !== RFC8032_PUB_B64) throw new Error("RFC 8032 fixture did not reconstruct");
  id.alias = "alice_77";
  return id;
}
function freshIdentity(alias) {
  const id = DTN.createIdentity();
  id.alias = alias;
  return id;
}
function bobIdentity() {
  const id = freshIdentity("bob_the_builder");
  return id;
}

/* ---------------------------------------------------------------------
 * (a) CRC-32 (IEEE 802.3) — the standard check value + the worked vector.
 * ------------------------------------------------------------------- */
console.log("== (a) §4.7 CRC-32 primitive ==");
{
  ok(DTN.qrCrc32Hex(DTN.utf8Encode("123456789")) === "cbf43926",
     "CRC-32 of \"123456789\" is the standard check value cbf43926");
  ok(DTN.qrCrc32(new Uint8Array(0)) === 0, "CRC-32 of the empty string is 0");
  ok(DTN.qrCrc32Hex(DTN.utf8Encode(WORKED_CANONICAL)) === WORKED_CRC,
     "the worked-vector CRC matches (independently cross-checked with Python zlib.crc32)");
  // The §5.1 example canonical string, CRC pinned against zlib as well.
  ok(DTN.qrCrc32Hex(DTN.utf8Encode('{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001}')) === "c15e75fc",
     "the §5.1 example string's CRC matches the zlib-pinned value");
}

/* ---------------------------------------------------------------------
 * (b) The §4.7 worked vector + parse/verify round trip.
 * ------------------------------------------------------------------- */
console.log("== (b) §4.7 worked vector (canonical string, sig, crc, payload) ==");
{
  const id = workedIdentity();
  const canonical = DTN.qrCanonicalPayloadString("alice_77", id.signPublicB64, id.boxPublicB64, NOW);
  ok(canonical === WORKED_CANONICAL, "the canonical signed string is the exact fixed member order v, alias, ed, x, ts");
  ok(DTN.utf8Encode(canonical).length === 145, "the canonical string is exactly 145 UTF-8 bytes");
  ok(DTN.qrCrc32Hex(DTN.utf8Encode(canonical)) === WORKED_CRC, "the canonical string's CRC-32 is the pinned d76a4d73");
  const payload = DTN.qrBuildPayload(id, NOW);
  ok(payload === WORKED_PAYLOAD, "the complete OFFGRID1 payload matches the pinned worked vector");
  ok(payload.length === 357, `the payload is 357 characters (${payload.length})`);
  ok(payload.startsWith("OFFGRID1:"), "the payload carries the OFFGRID1: scanner header");
  // The Base64 body decodes back to the exact canonical object string.
  const obj = JSON.parse(DTN.utf8Decode(DTN.b64decode(payload.slice("OFFGRID1:".length))));
  ok(obj.sig === WORKED_SIG && obj.crc === WORKED_CRC && obj.v === 1 && obj.ts === NOW,
     "the payload object carries sig (engine nacl, RFC 8032 key), crc and v=1");
  ok(DTN.utf8Decode(DTN.b64decode(payload.slice("OFFGRID1:".length))) ===
     DTN.qrCanonicalObjectString("alice_77", RFC8032_PUB_B64, WORKED_X_B64, NOW, WORKED_SIG, WORKED_CRC),
     "the Base64 body is the canonical object string (deterministic serialization)");
  // Determinism: rebuilding gives the identical payload.
  ok(DTN.qrBuildPayload(workedIdentity(), NOW) === WORKED_PAYLOAD, "rebuilding the payload is deterministic (same identity, same ts)");
  // Round trip.
  const parsed = DTN.qrParsePayload(payload, NOW);
  ok(parsed.ok && parsed.contact.alias === "alice_77" && parsed.contact.ed === RFC8032_PUB_B64 &&
     parsed.contact.x === WORKED_X_B64 && parsed.contact.ts === NOW,
     "parse+verify round-trips the payload back to the identity");
  // Whitespace around a paste is tolerated.
  ok(DTN.qrParsePayload("  \n" + payload + "\n  ", NOW).ok, "leading/trailing paste whitespace is stripped before parsing");
  // The stored contact record shape (§4.7).
  const record = DTN.qrContactRecord(parsed, "qr", NOW);
  ok(record.ed === RFC8032_PUB_B64 && record.x === WORKED_X_B64 && record.alias === "alice_77" &&
     record.added_at === NOW && record.source === "qr",
     "qrContactRecord yields {ed, x, alias, added_at, source} keyed by the Ed25519 key");
}

/* ---------------------------------------------------------------------
 * (c) Every tamper class rejected with the exact reason.
 * ------------------------------------------------------------------- */
console.log("== (c) tamper classes — each rejected with its reason, nothing stored ==");
{
  const alice = workedIdentity();
  const bob = bobIdentity();
  const good = WORKED_PAYLOAD;

  // Re-serialize the payload's JSON with a mutated member, keeping the OLD
  // sig and crc (what an attacker flipping bytes can do without the key).
  // Serialization is the fixed member order, by hand (not the engine's
  // builder — that one hardcodes the genuine v=1 shape); mutateFn works on
  // the ordered member list so it can drop or add members wholesale.
  const mutate = (payload, mutateFn) => {
    const obj = JSON.parse(DTN.utf8Decode(DTN.b64decode(payload.slice("OFFGRID1:".length))));
    const esc = (s) => DTN.jsonEscapeString(String(s));
    const members = [
      ["v", String(obj.v)], ["alias", esc(obj.alias)], ["ed", esc(obj.ed)],
      ["x", esc(obj.x)], ["ts", String(obj.ts)], ["sig", esc(obj.sig)], ["crc", esc(obj.crc)],
    ];
    mutateFn(obj, members);
    const body = "{" + members.map(([k, v]) => JSON.stringify(k) + ":" + v).join(",") + "}";
    return "OFFGRID1:" + DTN.b64encode(DTN.utf8Encode(body));
  };
  const dropMember = (name) => (obj, members) => {
    const idx = members.findIndex(([k]) => k === name);
    if (idx >= 0) members.splice(idx, 1);
  };
  const setMember = (name, jsonLiteral) => (obj, members) => {
    const idx = members.findIndex(([k]) => k === name);
    if (idx >= 0) members[idx][1] = jsonLiteral;
  };

  // 1. Bit flip in the alias (CRC covers the canonical string → mismatch).
  ok(DTN.qrParsePayload(mutate(good, setMember("alias", DTN.jsonEscapeString("alice_76"))), NOW).reason === "bad_crc",
     "a flipped alias character fails the CRC first (bad_crc)");
  // 2. Bit flip in the Ed25519 key (also covered by the CRC).
  ok(DTN.qrParsePayload(mutate(good, setMember("ed", DTN.jsonEscapeString("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURp="))), NOW).reason === "bad_crc",
     "a flipped Ed25519 key character fails the CRC first (bad_crc)");
  // 3. Bit flip in the SIGNATURE: outside the CRC's coverage — must reach
  //    and fail the Ed25519 verification (that is why the CRC sits
  //    OUTSIDE the signature, §4.7).
  const flippedSig = WORKED_SIG.slice(0, 10) + (WORKED_SIG[10] === "A" ? "B" : "A") + WORKED_SIG.slice(11);
  ok(DTN.qrParsePayload(mutate(good, setMember("sig", DTN.jsonEscapeString(flippedSig))), NOW).reason === "bad_signature",
     "a flipped signature character passes the CRC and fails the signature (bad_signature)");
  // 4. CRC mismatch alone (everything else intact).
  ok(DTN.qrParsePayload(mutate(good, setMember("crc", '"00000000"')), NOW).reason === "bad_crc",
     "a wrong CRC alone is rejected (bad_crc)");
  // 5. Signature swap between two identities: Bob signs Alice's canonical
  //    string; and Alice's payload carrying Bob's signature wholesale.
  const canonicalBytes = DTN.utf8Encode(DTN.qrCanonicalPayloadString("alice_77", RFC8032_PUB_B64, WORKED_X_B64, NOW));
  const bobSigned = "OFFGRID1:" + DTN.b64encode(DTN.utf8Encode(DTN.qrCanonicalObjectString(
    "alice_77", RFC8032_PUB_B64, WORKED_X_B64, NOW,
    DTN.b64encode(DTN.nacl.sign.detached(canonicalBytes, bob.signSecret)), DTN.qrCrc32Hex(canonicalBytes))));
  ok(DTN.qrParsePayload(bobSigned, NOW).reason === "bad_signature",
     "a payload re-signed by a DIFFERENT identity fails verification (bad_signature)");
  const bobPayload = DTN.qrBuildPayload(bob, NOW);
  const bobSig = JSON.parse(DTN.utf8Decode(DTN.b64decode(bobPayload.slice(9)))).sig;
  ok(DTN.qrParsePayload(mutate(good, setMember("sig", DTN.jsonEscapeString(bobSig))), NOW).reason === "bad_signature",
     "splicing another payload's signature into this one fails (bad_signature)");
  // 6. Truncated payload.
  ok(DTN.qrParsePayload(good.slice(0, good.length - 12), NOW).reason === "bad_base64" ||
     DTN.qrParsePayload(good.slice(0, good.length - 12), NOW).reason === "bad_json",
     "a truncated payload is rejected (bad_base64/bad_json)");
  ok(DTN.qrParsePayload(good.slice(0, 41), NOW).reason === "bad_json",
     "a payload truncated at a Base64 boundary fails the JSON parse (bad_json)");
  // 7. Wrong version.
  ok(DTN.qrParsePayload(mutate(good, setMember("v", "2")), NOW).reason === "bad_version",
     "an unknown payload version is rejected (bad_version)");
  // 8. Bad Base64 / bad prefix.
  ok(DTN.qrParsePayload("OFFGRID1:!!!", NOW).reason === "bad_base64", "invalid Base64 is rejected (bad_base64)");
  ok(DTN.qrParsePayload("OFFGRID2:" + good.slice(9), NOW).reason === "bad_prefix", "a wrong header is rejected (bad_prefix)");
  ok(DTN.qrParsePayload("hello there", NOW).reason === "bad_prefix", "arbitrary text is rejected (bad_prefix)");
  ok(DTN.qrParsePayload("", NOW).reason === "bad_prefix", "an empty payload is rejected (bad_prefix)");
  // 9. Alias regex violation — a FULLY VALID payload (fresh CRC and
  //    signature over the invalid alias) is still rejected structurally.
  const badAlias = (() => {
    const canonical = DTN.utf8Encode(DTN.qrCanonicalPayloadString("bad alias!", RFC8032_PUB_B64, WORKED_X_B64, NOW));
    return "OFFGRID1:" + DTN.b64encode(DTN.utf8Encode(DTN.qrCanonicalObjectString(
      "bad alias!", RFC8032_PUB_B64, WORKED_X_B64, NOW,
      DTN.b64encode(DTN.nacl.sign.detached(canonical, alice.signSecret)), DTN.qrCrc32Hex(canonical))));
  })();
  ok(DTN.qrParsePayload(badAlias, NOW).reason === "bad_alias",
     "an alias violating §8.1 is rejected before any crypto (bad_alias)");
  // 10. Future timestamp: beyond the §4.3 300 s skew allowance.
  ok(DTN.qrParsePayload(DTN.qrBuildPayload(alice, NOW + DTN.QR_TS_SKEW_SECONDS), NOW).ok,
     "a timestamp exactly at the 300 s skew allowance is accepted");
  ok(DTN.qrParsePayload(DTN.qrBuildPayload(alice, NOW + DTN.QR_TS_SKEW_SECONDS + 1), NOW).reason === "bad_ts",
     "a timestamp one second past the skew allowance is rejected (bad_ts)");
  // 11. Member-set violations.
  ok(DTN.qrParsePayload(mutate(good, dropMember("crc")), NOW).reason === "bad_members",
     "a missing member is rejected (bad_members)");
  ok(DTN.qrParsePayload(mutate(good, (obj, members) => { members.push(["extra", "1"]); }), NOW).reason === "bad_members",
     "an extra unknown member is rejected (bad_members)");
  ok(DTN.qrParsePayload("OFFGRID1:" + DTN.b64encode(DTN.utf8Encode("[1,2,3]")), NOW).reason === "bad_json",
     "a non-object JSON body is rejected (bad_json)");
  // 12. Key-length violations.
  const shortKey = DTN.b64encode(new Uint8Array(31)); // 44 Base64 chars, 31 bytes
  ok(DTN.qrParsePayload(mutate(good, setMember("ed", DTN.jsonEscapeString(shortKey))), NOW).reason === "bad_key",
     "an Ed25519 key that decodes to the wrong byte count is rejected (bad_key)");
  ok(DTN.qrParsePayload(mutate(good, setMember("x", '"AAAA"')), NOW).reason === "bad_crc" ||
     DTN.qrParsePayload(mutate(good, setMember("x", '"AAAA"')), NOW).reason === "bad_key",
     "a corrupted X25519 key member is rejected");
  // The strict shape rule, pinned directly (43 chars is not even Base64-clean):
  ok((() => {
    const canonical = DTN.utf8Encode(DTN.qrCanonicalPayloadString("alice_77", shortKey, WORKED_X_B64, NOW));
    const p = "OFFGRID1:" + DTN.b64encode(DTN.utf8Encode(DTN.qrCanonicalObjectString(
      "alice_77", shortKey, WORKED_X_B64, NOW,
      DTN.b64encode(DTN.nacl.sign.detached(canonical, alice.signSecret)), DTN.qrCrc32Hex(canonical))));
    return DTN.qrParsePayload(p, NOW).reason === "bad_key";
  })(), "a 31-byte key in a fully re-signed payload is rejected as bad_key");
  // buildPayload refuses an invalid alias up front.
  let threw = false;
  try { DTN.qrBuildPayload({ ...alice, alias: "no exclamation!" }, NOW); } catch (e) { threw = true; }
  ok(threw, "qrBuildPayload refuses to publish an alias outside the §8.1 regex");
}

/* ---------------------------------------------------------------------
 * (d) QR encoder validation — round trip through the INDEPENDENT decoder
 *     across all 15 supported versions + structural checks.
 * ------------------------------------------------------------------- */
console.log("== (d) QR encoder — byte mode, versions 1..15, ECC M (independent decoder) ==");
{
  const id = workedIdentity();
  // One payload per supported version (ASCII synthetic bodies sized to the
  // published byte-mode capacity table, ECC M).
  const bodies = [5, 15, 30, 50, 72, 92, 110, 135, 160, 200, 240, 275, 315, 345, 390];
  ok(bodies.length === 15, "the version sweep covers all 15 supported versions");
  const seen = new Set();
  let sweepOk = true;
  for (const n of bodies) {
    const text = "OFFGRID1:" + "a".repeat(n);
    const m = DTN.qrMakeMatrix(text);
    const dec = decodeQR(m.modules);
    seen.add(m.version);
    if (dec.text !== text || dec.version !== m.version || dec.eccLevel !== "M" || dec.corrected !== 0) {
      sweepOk = false;
      console.error(`   version sweep failed at n=${n} (v${m.version})`);
      break;
    }
  }
  ok(sweepOk && seen.size === 15, `every version 1..15 encodes and round-trips exactly (${seen.size} distinct versions)`);
  // Version-boundary behavior: one byte past a capacity bumps the version.
  ok(DTN.qrMakeMatrix("OFFGRID1:" + "a".repeat(5)).version === 1, "a 14-character payload fits QR version 1");
  ok(DTN.qrMakeMatrix("OFFGRID1:" + "a".repeat(6)).version === 2, "15 characters need version 2");
  ok(DTN.qrMakeMatrix("OFFGRID1:" + "a".repeat(403)).version === 15, "a 412-character payload fits version 15 (the cap)");
  let tooBig = false;
  try { DTN.qrMakeMatrix("OFFGRID1:" + "a".repeat(404)); } catch (e) { tooBig = /payload too large/.test(e.message); }
  ok(tooBig, "beyond the version-15 capacity the encoder refuses loudly");

  // The three identity payloads of the issue's sizes: min alias, the worked
  // vector (~300 chars), and the 24-character-alias maximum.
  const sizes = [["min", "a"], ["worked", "alice_77"], ["max", "abcdefghijklmnopqrstuvwx"]];
  for (const [label, alias] of sizes) {
    const payload = DTN.qrBuildPayload({ ...id, alias }, NOW);
    const m = DTN.qrMakeMatrix(payload);
    const dec = decodeQR(m.modules);
    ok(dec.text === payload && dec.version === m.version,
       `${label} payload (${payload.length} chars, v${m.version}) round-trips through the independent decoder`);
  }

  // Structural checks on a matrix: finder patterns at the three corners
  // (7x7 dark ring, light ring, 3x3 dark center), alternating timing
  // patterns, valid format info (decoder-verified).
  const payload = WORKED_PAYLOAD;
  const m = DTN.qrMakeMatrix(payload);
  const size = m.size;
  const finderOk = (r0, c0) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const border = r === 0 || r === 6 || c === 0 || c === 6;
        const center = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        if (m.modules[r0 + r][c0 + c] !== (border || center)) return false;
      }
    }
    return true;
  };
  ok(finderOk(0, 0) && finderOk(0, size - 7) && finderOk(size - 7, 0),
     "all three finder patterns are present with the exact 7x7 structure");
  let timingOk = true;
  for (let i = 8; i < size - 8; i++) {
    if (m.modules[6][i] !== (i % 2 === 0) || m.modules[i][6] !== (i % 2 === 0)) timingOk = false;
  }
  ok(timingOk, "the timing patterns alternate dark/light on row 6 and column 6");
  // The independent decoder already BCH-validated BOTH format-info copies
  // and (v >= 7) the version-info copies against the size-derived version.
  const dec = decodeQR(m.modules);
  ok(dec.version === 14 && dec.mask >= 0 && dec.mask <= 7, "format info (ECC M + mask) and version info decode validly");
}

/* ---------------------------------------------------------------------
 * (e) §4.7 recipient merge — contacts ∪ directory, deduped by key.
 * ------------------------------------------------------------------- */
console.log("== (e) recipient merge: contacts ∪ directory, offline-first ==");
{
  const alice = workedIdentity();
  const bob = bobIdentity();
  const carol = freshIdentity("carol");

  const bobContact = { ed: bob.signPublicB64, x: bob.boxPublicB64, alias: "bob_scanned", added_at: NOW - 100, source: "qr" };
  const carolContact = { ed: carol.signPublicB64, x: carol.boxPublicB64, alias: "carol_pasted", added_at: NOW - 50, source: "paste" };
  const dave = freshIdentity("dave");
  const directory = [
    { alias: "bob_directory", pubkey: bob.signPublicB64, x25519: bob.boxPublicB64, last_seen: NOW, epoch: DTN.epochOf(NOW), prekeys: { v: 1, spk: "x", spk_sig: "y", ts: 1, opks: [] } },
    { alias: "dave", pubkey: dave.signPublicB64, x25519: dave.boxPublicB64, last_seen: NOW - 10, epoch: DTN.epochOf(NOW) },
  ];

  const merged = DTN.qrMergeRecipients(directory, [bobContact, carolContact]);
  ok(merged.length === 3, "the merge dedupes by Ed25519 key (bob appears once) and lists everyone");
  const bobRow = merged.find((r) => r.ed === bob.signPublicB64);
  ok(bobRow && bobRow.in_directory && bobRow.contact, "bob is recognized as BOTH a contact and a directory entry");
  ok(bobRow.alias === "bob_scanned", "the LOCAL contact alias wins as the display label (cosmetic, §4.7)");
  ok(bobRow.epoch === DTN.epochOf(NOW) && bobRow.prekeys && bobRow.last_seen === NOW,
     "the DIRECTORY supplies the fresh key material (epoch, prekeys, last_seen)");
  const carolRow = merged.find((r) => r.ed === carol.signPublicB64);
  ok(carolRow && carolRow.contact && !carolRow.in_directory && carolRow.epoch === undefined && carolRow.prekeys === undefined,
     "a contact the directory does not list carries only the QR keys (offline addressing)");
  // Offline-first: a dead directory ([]) still lists every contact.
  const offline = DTN.qrMergeRecipients([], [bobContact, carolContact]);
  ok(offline.length === 2 && offline.every((r) => r.contact && !r.in_directory),
     "with the directory unreachable, the saved contacts are still offered");
  // Deterministic order: alias ASC, then ed ASC.
  const sorted = [...merged].sort((a, b) => (a.alias < b.alias ? -1 : a.alias > b.alias ? 1 : a.ed < b.ed ? -1 : 1));
  ok(JSON.stringify(merged.map((r) => r.ed)) === JSON.stringify(sorted.map((r) => r.ed)),
     "the merged list is deterministically ordered (alias, then ed)");
  // Malformed rows are skipped, not fatal.
  ok(DTN.qrMergeRecipients([null, { pubkey: "x" }], [null, { ed: "y" }]).every((r) => r.x25519),
     "malformed directory/contact rows are skipped");
  // The send path through a CONTACT-ONLY recipient: no epoch (§6.1
  // offline-cold static hint) and no bundle (§4.6 identity fallback).
  const target = DTN.prekeyTargetForEntry(offline[0]);
  ok(!target.ok && target.reason === "absent", "a contact-only recipient addresses the identity key (no bundle, §4.6)");
  const env = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(offline[0].x25519),
    hintIdentityBoxPublic: DTN.b64decode(offline[0].x25519),
    message: "offline hello", alias: alice.alias,
    signSecret: alice.signSecret, signPublic: alice.signPublic,
    createdAt: NOW, ttl: DTN.TTL_MAX  /* no hintEpoch: the §6.1 offline-cold static hint */
  });
  ok(env.dest_hint === DTN.deriveDestHint(DTN.b64decode(offline[0].x25519)),
     "the envelope is addressed with the LEGACY static hint (offline-cold, §6.1)");
  const dec = DTN.decryptEnvelope(env, { ...bob, hint: DTN.deriveDestHint(bob.boxPublic) }, NOW,
    DTN.hintCandidates(bob.boxPublic, null, NOW));
  ok(dec.ok && dec.m === "offline hello", "the recipient recognizes the static-hint envelope inside the transition window");
}

/* ---------------------------------------------------------------------
 * (f) Store migration chain — DB_VERSION 5 adds `contacts` additively.
 * ------------------------------------------------------------------- */
console.log("== (f) store migration chain: additive, idempotent, keyPath ed ==");
{
  ok(DTN.DB_VERSION === 5, "DB_VERSION is 5 (§15.6 chain: v2 inbox_parts, v3 sent, v4 prekeys, v5 contacts)");
  ok(DTN.IDB_MIGRATIONS.length === 5 && DTN.IDB_MIGRATIONS[4].version === 5,
     "the migrations table appends exactly one step for version 5");
  // Apply the chain to a stub database and inspect the created stores.
  const created = [];
  const stubDb = { createObjectStore: (name, opts) => created.push({ name, opts: opts || null }) };
  DTN.runIdbMigrations(stubDb, 0);
  const names = created.map((s) => s.name);
  ok(names[names.length - 1] === DTN.STORE_CONTACTS,
     "the chain's final step creates the contacts store");
  ok((() => {
    const c = [];
    DTN.IDB_MIGRATIONS[4].migrate({ createObjectStore: (n, o) => c.push([n, o]) });
    return c[0][0] === "contacts" && c[0][1] && c[0][1].keyPath === "ed";
  })(),
  "migration v5 creates contacts with keyPath 'ed' (identity = key, §4.7)");
  // Idempotent + resumable: opening at v4 applies ONLY the v5 step.
  created.length = 0;
  DTN.runIdbMigrations(stubDb, 4);
  ok(created.length === 1 && created[0].name === "contacts",
     "a v4 database migrates by exactly one additive step (resumable chain, §15.6)");
  created.length = 0;
  DTN.runIdbMigrations(stubDb, 5);
  ok(created.length === 0, "a v5 database re-runs no migration (idempotent)");
}

/* ---------------------------------------------------------------------
 * (g) Graceful degradation — the scanner feature-detects, headless first.
 * ------------------------------------------------------------------- */
console.log("== (g) degradation: no BarcodeDetector/camera → paste fallback ==");
{
  ok(typeof sandbox.qrScanSupported === "function", "the UI exposes the scan feature-detect (ui.js loads headless)");
  ok(sandbox.qrScanSupported() === false,
     "without BarcodeDetector/getUserMedia (Node, iOS Safari, captive mini-browsers) scanning reports unsupported");
  ok(typeof sandbox.stopQrScan === "function" && typeof sandbox.importContactPayload === "function",
     "scan cleanup and the shared import path exist for the paste flow");
  ok(typeof sandbox.qrReasonLabel === "function" && /corrupted|checksum/i.test(sandbox.qrReasonLabel("bad_crc")),
     "every rejection reason maps to a VISIBLE human message");
}

console.log(`\nPASS: ${passed} assertions on the §4.7 identity QR, contacts and offline exchange (index.html script order)`);

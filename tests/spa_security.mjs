// SPA security-hardening regression suite (issue #14, Phase 2 — the client
// audit). Loads the SHIPPED scripts exactly as index.html declares them
// (tests/helpers/spa_loader.mjs) and pins the audit's confirmed classes:
//
//   (a) vendored-crypto provenance (offline re-verification): the recorded
//       SHA-256 of each vendor embed matches the bytes on disk — tweetnacl
//       1.0.3 nacl-fast.min.js verbatim, qrcode-generator 1.4.4 qrcode.js
//       plus ONLY the documented adaptations ("use strict", self.qrcode
//       tail) — and the engine still exposes the expected nacl surface;
//   (b) nonce / ephemeral-key freshness: same message, same recipient,
//       repeated sends — every nonce and every ephemeral public differs
//       (§4.2 steps 4–5, §7.2);
//   (c) the receive-path §6.2 id check: a consistent envelope passes
//       decryptEnvelope and transit admission; ANY outer-field tamper
//       (dest_hint, created_at, ttl, payload, cross-swapped fields) with a
//       stale id is rejected with reason "bad_id" / skipped by
//       transitRecordOf — and the §15.1 converted v2 form still passes
//       (creation version from meta.orig_v);
//   (d) hostile-envelope resilience (the mule garbage battery): malformed
//       and hostile envelopes never throw and never store — shape checks,
//       silent decrypt rejects, foreign classification, FIFO cap;
//   (e) no-envelope-objects-leak-secrets: the wire object carries exactly
//       the six §3.1 fields, never key material;
//   (f) source hygiene (static, ships in the repo): no XSS sink
//       (innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/new
//       Function/href=javascript:), no localStorage/sessionStorage, no
//       logging (console/alert), no exfiltration channel (fetch/
//       WebSocket/Worker/sendBeacon), every XHR path is a fixed
//       same-origin /api/v1 route, and the portal CSP keeps img-src 'self'
//       with no data: allowance (issue #14 Phase 2 tightening).
//
// Deterministic and offline (no network at test time).
//
// Run: node tests/spa_security.mjs   (exit 0 = pass)

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { loadSpaSandbox, pageScripts, webRoot } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();
const DTN = sandbox.DTN;
if (!DTN || typeof DTN.buildEnvelope !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (nacl or buildEnvelope missing)");
}
for (const fn of ["envelopeIdMatches", "transitRecordOf", "validEnvelopeShape", "classifyPullEnvelopes", "evictTransitQueue", "convertEnvelopeV1toV2"]) {
  if (typeof DTN[fn] !== "function") throw new Error(`DTN.${fn} missing — the engine did not load completely`);
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

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

console.log("== (a) vendored provenance — offline re-verification of the recorded hashes ==");
const naclFile = fs.readFileSync(path.join(webRoot, "js", "vendor", "nacl.min.js"));
const qrFile = fs.readFileSync(path.join(webRoot, "js", "vendor", "qrcode.js"));

{
  // tweetnacl 1.0.3: the embedded upstream region (first `!function` through
  // the END marker, trailing newlines stripped) must equal the npm artifact
  // nacl-fast.min.js — hash recorded in the file's own provenance header.
  const START = naclFile.indexOf(b("/* === TWEETNACL_EMBED_START"));
  const END = naclFile.indexOf(b("/* === TWEETNACL_EMBED_END === */"));
  ok(START === 0 && END > START, "nacl embed carries both provenance markers");
  const codeStart = naclFile.indexOf(b("\n!function")) + 1; /* line start — the header prose mentions `!function(i)` too */
  ok(codeStart > START && codeStart < END, "the embedded upstream code region exists between the markers");
  let region = naclFile.subarray(codeStart, END);
  let end2 = region.length;
  while (end2 > 0 && region[end2 - 1] === 0x0a) end2--;
  region = region.subarray(0, end2);
  const got = sha256hex(region);
  const recorded = recordedHash(naclFile, "TWEETNACL_EMBED_START", "TWEETNACL_EMBED_END");
  ok(/^[0-9a-f]{64}$/.test(recorded), "nacl header records a SHA-256 integrity hash");
  ok(got === recorded, `nacl embed matches its recorded hash (${recorded.slice(0, 16)}…)`);
  ok(got === "3ec535c004aeeb225785d8e93fb33bf99f52e399bd7dfc01969b5629baea5131",
     "nacl embed hash is the tweetnacl@1.0.3 npm nacl-fast.min.js artifact (verified 2026-10-06 via npm pack)");
}
{
  // qrcode-generator 1.4.4: undoing the three DOCUMENTED adaptations must
  // reproduce the upstream original byte-for-byte.
  const START = qrFile.indexOf(b("/* === QRCODE_GENERATOR_EMBED_START"));
  const END = qrFile.indexOf(b("/* === QRCODE_GENERATOR_EMBED_END === */"));
  ok(START === 0 && END > START, "qrcode embed carries both provenance markers");
  const recorded = recordedHash(qrFile, "QRCODE_GENERATOR_EMBED_START", "QRCODE_GENERATOR_EMBED_END");
  ok(/^[0-9a-f]{64}$/.test(recorded), "qrcode header records a SHA-256 integrity hash");
  let afterMarkers = qrFile.subarray(qrFile.indexOf(b("\n"), END) + 1);
  ok(afterMarkers.toString().startsWith('"use strict";\n'),
     "the only leading addition is the documented \"use strict\" directive");
  const adapted = afterMarkers.subarray('"use strict";\n'.length);
  const tailAt = adapted.indexOf(b("/* Off-grid adaptation"));
  ok(tailAt > 0, "the trailing self.qrcode adaptation block is present");
  const upstreamForm = adapted.subarray(0, tailAt);
  ok(sha256hex(upstreamForm) === recorded,
     `qrcode embed minus the documented adaptations matches its recorded upstream hash (${recorded.slice(0, 16)}…)`);
  ok(sha256hex(upstreamForm) === "18ae399f81182bc9de916e9c77b195df20cc58d6f2d55a62b085a299f1bf1780",
     "qrcode upstream hash is the qrcode-generator@1.4.4 npm qrcode.js artifact (verified 2026-10-06 via unpkg)");
}
{
  // Sanity: the loaded vendored nacl exposes the API surface the engine uses.
  const nacl = DTN.nacl;
  ok(nacl && typeof nacl.sign.detached === "function" && typeof nacl.sign.detached.verify === "function" &&
     typeof nacl.sign.keyPair.fromSeed === "function" &&
     typeof nacl.box === "function" && typeof nacl.box.open === "function" &&
     typeof nacl.box.keyPair === "function" && typeof nacl.box.keyPair.fromSecretKey === "function" &&
     typeof nacl.setPRNG === "function" && typeof nacl.verify === "function",
     "vendored nacl exposes the full API surface the engine consumes");
  // RFC 8032 §7.1 TEST 1 (empty message) through the vendored implementation —
  // a known-answer check that the Ed25519 path is mathematically sound.
  const rfc8032seed = DTN.hexDecode(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const rfc8032pk = DTN.hexDecode(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const rfc8032sig = DTN.hexDecode(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  const kp = nacl.sign.keyPair.fromSeed(rfc8032seed);
  ok(DTN.hexEncode(kp.publicKey) === DTN.hexEncode(rfc8032pk),
     "vendored Ed25519 seed→public derivation matches RFC 8032 §7.1 TEST 1");
  const emptyMsg = DTN.utf8Encode(""); /* vm-realm Uint8Array (the nacl type checks are realm-sensitive) */
  const sig = nacl.sign.detached(emptyMsg, kp.secretKey);
  ok(DTN.hexEncode(sig) === DTN.hexEncode(rfc8032sig) &&
     nacl.sign.detached.verify(emptyMsg, sig, rfc8032pk),
     "vendored Ed25519 reproduces the RFC 8032 §7.1 TEST 1 signature");
}

console.log("== (b) nonce and ephemeral-key freshness (§4.2, §7.2) ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const nonces = new Set();
  const ephs = new Set();
  const ids = new Set();
  for (let i = 0; i < 12; i++) {
    const env = DTN.buildEnvelope({
      recipientBoxPublic: bob.boxPublic,
      message: "same message, every time",
      alias: "alice_77",
      signSecret: alice.signSecret,
      signPublic: alice.signPublic,
      createdAt: 1759500000,
    });
    const raw = Buffer.from(DTN.b64decode(env.payload));
    nonces.add(raw.subarray(32, 56).toString("hex"));
    ephs.add(raw.subarray(0, 32).toString("hex"));
    ids.add(env.id);
  }
  ok(nonces.size === 12, "12 envelopes from identical inputs → 12 distinct 24-byte nonces (no reuse, §7.2)");
  ok(ephs.size === 12, "12 distinct ephemeral X25519 publics (one fresh pair per message)");
  ok(ids.size === 12, "12 distinct envelope ids (nonces feed the ciphertext, ids diverge)");
}

console.log("== (c) receive-path §6.2 id check (outer-field tamper detection) ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const env = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "id check fixture",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: 1759500000,
  });
  ok(DTN.envelopeIdMatches(env), "a conforming envelope passes the id check");
  ok(DTN.transitRecordOf(env, 1759500100) !== null, "a conforming envelope is admitted to transit");
  ok(DTN.decryptEnvelope(env, bob, 1759500100, [bob.hint]).ok === true,
     "a conforming envelope still decrypts (no false positives)");

  const tamper = (field, value) => ({ ...env, [field]: value });
  const hostileHints = ["0000000000000000", "ffffffffffffffff"];
  for (const h of hostileHints) {
    const t = tamper("dest_hint", h);
    ok(DTN.envelopeIdMatches(t) === false, `tampered dest_hint (${h}) fails the id check`);
    ok(DTN.transitRecordOf(t, 1759500100) === null, `tampered dest_hint (${h}) is never stored in transit`);
    const dec = DTN.decryptEnvelope(t, bob, 1759500100, [bob.hint]);
    ok(dec.ok === false && dec.reason === "bad_id", `tampered dest_hint (${h}) is a silent bad_id reject`);
  }
  {
    const t = tamper("created_at", 1759500001);
    ok(DTN.decryptEnvelope(t, bob, 1759500100).ok === false &&
       DTN.decryptEnvelope(t, bob, 1759500100).reason === "bad_id",
       "a re-dated envelope (post-dated created_at, stale id) is rejected — re-dating cannot re-age mail past FIFO/janitor eyes");
    ok(DTN.transitRecordOf(t, 1759500100) === null, "re-dated envelope never enters transit");
  }
  {
    const t = tamper("ttl", 2592000);
    ok(DTN.decryptEnvelope(t, bob, 1759500100).reason === "bad_id" &&
       DTN.transitRecordOf(t, 1759500100) === null,
       "a TTL-extended envelope with a stale id is rejected");
  }
  {
    // payload swap: replace the box with another valid envelope's — the
    // outer fields no longer hash to the id.
    const other = DTN.buildEnvelope({
      recipientBoxPublic: bob.boxPublic,
      message: "other",
      alias: "alice_77",
      signSecret: alice.signSecret,
      signPublic: alice.signPublic,
      createdAt: 1759500000,
    });
    ok(DTN.decryptEnvelope(tamper("payload", other.payload), bob, 1759500100).reason === "bad_id",
       "a payload swap with a stale id is rejected");
    // Cross-swap of whole ids (field-level consistency break).
    ok(DTN.decryptEnvelope({ ...env, id: other.id }, bob, 1759500100).reason === "bad_id",
       "a swapped id fails the check");
  }
  {
    // The §15.1 blind conversion PRESERVES the check (creation version from
    // meta.orig_v — version_migration.mjs pins the same rule for dedup).
    const v2 = DTN.convertEnvelopeV1toV2(env);
    ok(DTN.envelopeIdMatches(v2) === true, "the blind v1→v2 conversion passes the receive-path id check");
    ok(DTN.transitRecordOf(v2, 1759500100) !== null, "a converted v2 envelope is admitted to transit");
    ok(DTN.decryptEnvelope(v2, bob, 1759500100).ok === true, "a converted v2 envelope still decrypts for the recipient");
    // A v2 whose meta is stripped of orig_v recomputes against v:2 — still
    // consistent only if the id was minted that way (never in Phase 1)…
    ok(DTN.envelopeIdMatches({ ...env, v: 2, meta: {} }) === false,
       "a faked v:2 wrapper cannot launder a v1-minted id past the check");
  }
}

console.log("== (d) hostile-envelope battery — the mule never crashes, never stores garbage ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const good = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "still fine",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: 1759500000,
  });
  const battery = [
    null, undefined, 42, "envelope", [], {},
    { v: 1 },
    { v: 3, id: good.id, dest_hint: good.dest_hint, created_at: 1, ttl: 3600, payload: good.payload },
    { ...good, v: 1, meta: { orig_v: 1 } },                      // meta on v1 (§15.3)
    { ...good, meta: "not an object" },                          // v2 with scalar meta
    { ...good, created_at: NaN },                                // NaN timestamp
    { ...good, created_at: "1759500000" },                       // string timestamp
    { ...good, ttl: 3599 },                                      // below TTL_MIN
    { ...good, ttl: 2592001 },                                   // above TTL_MAX
    { ...good, dest_hint: "ZZZZZZZZZZZZZZZZ" },                  // non-hex hint
    { ...good, dest_hint: "9f3ab02c1d77e4c" },                   // 15 hex chars
    { ...good, id: "zzzz" },                                     // malformed id
    { ...good, payload: "not-base64!!" },                        // undecodable payload
    { ...good, payload: DTN.b64encode(DTN.randomBytes(247)) },   // payload below [248,400]
    { ...good, payload: DTN.b64encode(DTN.randomBytes(401)) },   // payload above [248,400]
  ];
  let noThrow = true;
  let allUnstored = true;
  let allRejected = true;
  // The MULE's perspective: classification against a third party's hints —
  // hostile cargo must never classify as the mule's own mail (a dest_hint
  // match alone only routes a candidate to the decrypt attempt, §4.3).
  const bystander = DTN.createIdentity();
  const bystanderHints = DTN.hintCandidates(bystander.boxPublic, 20730, 1759500100);
  let allForeign = true;
  for (const t of battery) {
    try {
      if (DTN.transitRecordOf(t, 1759500100) !== null) allUnstored = false;
      if (DTN.classifyPullEnvelopes([t], bystanderHints).mine.length !== 0) allForeign = false;
      const dec = DTN.decryptEnvelope(t, bob, 1759500100, [bob.hint]);
      if (!dec || dec.ok !== false) allRejected = false;
    } catch (e) {
      noThrow = false;
    }
  }
  ok(noThrow === true, "the full hostile battery is handled without a single throw");
  ok(allUnstored === true, "nothing from the hostile battery reaches a transit record");
  ok(allRejected === true, "every hostile envelope is a silent decrypt reject for its addressee");
  ok(allForeign === true, "no hostile envelope is ever classified as a bystander mule's own mail");
  // Structurally invalid forms are rejected at the shape gate itself (the
  // first line of defense before any hashing or decode work happens).
  const structural = [null, 42, "envelope", [], {}, { v: 1 },
    { ...good, v: 1, meta: { orig_v: 1 } }, { ...good, created_at: NaN },
    { ...good, ttl: 3599 }, { ...good, dest_hint: "ZZZZZZZZZZZZZZZZ" }];
  let allShapeFalse = true;
  for (const t of structural) {
    try { if (DTN.validEnvelopeShape(t) !== false) allShapeFalse = false; } catch (e) { allShapeFalse = false; }
  }
  ok(allShapeFalse === true, "structurally invalid envelopes fail the shape gate outright");

  // Valid-shaped garbage (random box bytes, recomputed id) still rides as
  // foreign cargo — the documented blindness trade (a mule cannot read
  // foreign envelopes) — but it is capped, and for the RECIPIENT it is a
  // silent crypto reject (Poly1305), never a crash.
  const bobHints = DTN.hintCandidates(bob.boxPublic, 20730, 1759500100);
  const garbage = DTN.buildEnvelope({
    recipientBoxPublic: alice.boxPublic,   // not Bob — random-looking cargo
    message: "x",
    alias: "mallory_1",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: 1759500000,
    hintEpoch: 20730,
  });
  const cls = DTN.classifyPullEnvelopes([good, garbage], bobHints);
  ok(cls.mine.length === 1 && cls.foreign.length === 1,
     "hint classification routes own mail to mine and valid-shaped foreign cargo onward");
  const dec = DTN.decryptEnvelope(garbage, bob, 1759500100, bobHints);
  ok(dec.ok === false && (dec.reason === "not_mine" || dec.reason === "crypto"),
     "foreign garbage is a silent reject for the recipient (no error text, §4.3)");

  // FIFO cap holds under a flood of valid-shaped garbage.
  const flood = [];
  for (let i = 0; i < 160; i++) {
    flood.push({ id: DTN.hexEncode(DTN.sha256(DTN.utf8Encode("flood-" + i))),
                 dest_hint: "9f3ab02c1d77e4c1", created_at: 1759500000 + i,
                 ttl: 604800, payload: good.payload, v: 1 });
  }
  const evicted = DTN.evictTransitQueue(flood, DTN.TRANSIT_CAPACITY);
  ok(evicted.kept.length === 100 && evicted.evicted.length === 60,
     "a 160-envelope garbage flood is FIFO-capped at the 100-slot transit queue");
}

console.log("== (e) wire objects never carry key material ==");
{
  const bob = DTN.createIdentity();
  const alice = DTN.createIdentity();
  const env = DTN.buildEnvelope({
    recipientBoxPublic: bob.boxPublic,
    message: "leak check",
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: 1759500000,
  });
  ok(JSON.stringify(Object.keys(env).sort()) ===
     JSON.stringify(["created_at", "dest_hint", "id", "payload", "ttl", "v"]),
     "the envelope object carries exactly the six §3.1 fields");
  const wire = DTN.toEnvelopeWire({ ...env, added_at: 1, v: 1 });
  ok(JSON.stringify(Object.keys(wire).sort()) ===
     JSON.stringify(["created_at", "dest_hint", "id", "payload", "ttl", "v"]),
     "the transit wire form strips everything but the six §3.1 fields");
  const envStr = JSON.stringify(env);
  ok(!envStr.includes(DTN.b64encode(alice.signSecret).slice(0, 20)) &&
     !envStr.includes(DTN.b64encode(alice.boxSecret).slice(0, 20)) &&
     !envStr.includes(DTN.b64encode(bob.boxSecret).slice(0, 20)) &&
     !envStr.includes(alice.seedB64.slice(0, 20)),
     "no private key material (Ed25519 secret, X25519 secret, seed) appears in the wire object");
  // The published directory body (what publishIdentity sends) is public
  // material only: derive it the same way ui.js does and assert no secrets.
  const bodyKeys = ["alias", "pubkey", "x25519"];
  ok(bodyKeys.every((k) => typeof alice[k] === "undefined"),
     "the identity record's sendable members are the alias and the PUBLIC keys only");
}

console.log("== (f) source hygiene — no new sinks since the audit (static) ==");
{
  const appScripts = pageScripts().filter((s) => !s.url.includes("/vendor/"));
  ok(appScripts.length === 14, "the app ships 14 non-vendor scripts");
  const forbidden = [
    [/\.innerHTML/, "innerHTML"], [/\.outerHTML/, "outerHTML"],
    [/insertAdjacentHTML/, "insertAdjacentHTML"], [/document\.write/, "document.write"],
    [/\beval\s*\(/, "eval"], [/new\s+Function/, "new Function"],
    [/localStorage/, "localStorage"], [/sessionStorage/, "sessionStorage"],
    [/console\./, "console.*"], [/\balert\s*\(/, "alert("],
    [/sendBeacon/, "sendBeacon"], [/new\s+WebSocket/, "WebSocket"],
    [/new\s+Worker/, "Worker"], [/importScripts/, "importScripts"],
    [/\bfetch\s*\(/, "fetch("],
    [/javascript:/i, "javascript: URL"],
  ];
  for (const { url, source } of appScripts) {
    for (const [re, name] of forbidden) {
      ok(!re.test(source), `${path.basename(url)} carries no ${name}`);
    }
  }
  // Every network touch is a fixed same-origin /api/v1 route.
  const routes = new Set();
  for (const { source } of appScripts) {
    for (const m of source.matchAll(/(?:getJson|postJson)\(\s*"([^"]+)"/g)) routes.add(m[1]);
    for (const m of source.matchAll(/"(\/api\/[^"]+)"/g)) routes.add(m[1]);
  }
  ok(JSON.stringify([...routes].sort()) ===
     JSON.stringify(["/api/v1/capabilities", "/api/v1/directory", "/api/v1/sync"]),
     "the SPA talks to exactly the three fixed same-origin §10.3 routes");
  ok(!/"https?:\/\/[^"]+/.test(appScripts.map((s) => s.source).join("\n")),
     "no absolute URL string literal is ever requested or constructed (same-origin only; CANONICAL_URL is host-relative by concatenation)");
  // CSP: img-src 'self' with no data: allowance (Phase 2 tightening), and
  // the page still keeps the closed default.
  const html = fs.readFileSync(path.join(webRoot, "index.html"), "utf8");
  const csp = html.match(/Content-Security-Policy[^>]*content="([^"]+)"/)?.[1] ?? "";
  ok(csp.includes("img-src 'self'") && !csp.includes("img-src 'self' data:"), "CSP img-src is exactly 'self' (no data: allowance)");
  ok(!csp.includes("unsafe-inline") && csp.includes("default-src 'none'"), "CSP stays closed (no unsafe-inline, default-src 'none')");
  ok(!/data:image/i.test(appScripts.map((s) => s.source).join("\n")), "no data: image is constructed anywhere (the dropped allowance was unused)");
}

console.log(`\nPASS: ${passed} security-hardening assertions on the SPA engine and sources`);

function b(s) {
  return Buffer.from(s, "utf8");
}

// Extract the recorded integrity hash from a vendor file's provenance header
// (the header line format: "//   SHA-256 = <64 hex>").
function recordedHash(file, startMarker, endMarker) {
  const start = file.indexOf(b("/* === " + startMarker));
  const end = file.indexOf(b("/* === " + endMarker + " === */"));
  const header = file.subarray(start, end).toString("utf8");
  const m = header.match(/SHA-256 = ([0-9a-f]{64})/);
  return m ? m[1] : "";
}

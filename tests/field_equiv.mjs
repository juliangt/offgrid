// Issue-#20 field-acceptance equivalents — the software-verifiable half of
// docs/field-test.md, driven through the SHIPPED SPA engine (loaded exactly
// as index.html does, via tests/helpers/spa_loader.mjs) and, where a node is
// needed, against REAL daemons built from this tree:
//
//   A. Seed backup/restore round trip (the headless T3): createIdentity →
//      export seedB64 (the exact text the UI shows under "Save your backup
//      seed") → simulate the device wipe with a FRESH engine instance →
//      import via the ui.js onImport path (DTN.identityFromSeed) → identical
//      Ed25519 + X25519 key pairs, identical §6.1 legacy static hint AND
//      rotating hint(E), identical hintCandidates; the alias is NOT derivable
//      (the import re-asks it); mail built for the pre-wipe identity opens
//      with the restored one.
//   B. The import re-registers (the headless T3 directory half): the same
//      publishIdentity body ui.js builds on import is POSTed to a real
//      daemon; GET /api/v1/directory serves the restored public keys with a
//      fresh epoch stamp; /api/v1/health agrees.
//   C. Cross-node same-origin persistence (the headless T2c + T1 + T10):
//      one client store (identity, inbox, transit, seen — the §11 state,
//      shaped by the store's own DTN.transitRecordOf / DTN.toEnvelopeWire)
//      syncs against node A, then the SAME state against node B (second
//      daemon): the identity survives unchanged, the carried transit queue
//      is delivered, mail addressed to the client via the §4.7 QR-contact
//      path arrives at the new node, and the health envelope/counter figures
//      agree with reality at every phase.
//   D. Fabrication guard on docs/field-test.md: every case T1..T10 present,
//      every Result line an UNCHECKED checkbox, the PENDING markers and the
//      empty sign-off block in place, and NO pre-filled results anywhere
//      (no tick glyphs, no checked boxes, no PASS/FAIL result cells). This
//      keeps the scaffold honest: nothing may be marked as observed until a
//      human observed it. Extended additively for the Phase 3 node-plane
//      session (issue #33 P3.9): §15 exists with cases N1..N14, its honest
//      P3.3-bring-up boundary statement names the enforcing host suites, the
//      Result-line count covers the N-cases too, and the same no-fabrication
//      rules hold across the whole document.
//
// It needs `go` (it builds its own daemon binary into a temp dir) and owns
// 127.0.0.1 ports 18201-18202 (disjoint from the E2E's 18091-18095, the
// chaos suite's 18095-18099 and the upgrade E2E's 18101). Temp files are
// cleaned up on exit.
//
// Run: node tests/field_equiv.mjs   (exit 0 = pass)

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import vm from "node:vm";
import { spawn, execFileSync } from "node:child_process";
import { loadSpaSandbox, repoRoot } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();
const DTN = sandbox.DTN;
if (!DTN || typeof DTN.identityFromSeed !== "function" || typeof DTN.prepareOutgoingBatch !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (envelopes/store/mule missing)");
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

const now = Math.floor(Date.now() / 1000);
// Cross-realm safe: typed arrays from the vm sandbox are not instanceof
// Uint8Array in the host realm, so dispatch on the value type instead.
function hexOf(v) {
  return (typeof v === "string") ? DTN.hexEncode(DTN.b64decode(v)) : DTN.hexEncode(v);
}

/* ======================================================================
 * A. Seed backup/restore round trip — the headless T3 (engine only).
 * ==================================================================== */
console.log("== A. seed backup/restore round trip (fresh engine simulates the wipe) ==");

const alice = DTN.createIdentity();
alice.alias = "alice_field";
alice.registered_at = now;
ok(DTN.validateAlias(alice.alias) && alice.seedB64.length === 44,
   "registered identity with a valid alias and a 44-char Base64 seed");

// The export is exactly what the UI shows: ui.js fills $("reg-seed") and
// $("id-seed") with identity.seedB64 — the paper text of T3.
const seedText = alice.seedB64;

// The wipe: a brand-new engine instance has no state at all.
const DTN2 = loadSpaSandbox().DTN;
ok(DTN2 !== DTN && typeof DTN2.identityFromSeed === "function",
   "fresh engine instance loaded (the simulated wiped device)");

// The import path, line for line as ui.js onImport drives it: trim →
// b64decode → length gate → identityFromSeed.
const parsedSeed = DTN2.b64decode(seedText);
ok(parsedSeed && parsedSeed.length === 32,
   "import: the paper seed decodes to 32 bytes (ui.js onImport gate)");
const restored = DTN2.identityFromSeed(parsedSeed);

ok(hexOf(restored.signPublic) === hexOf(alice.signPublic) &&
   hexOf(restored.signSecret) === hexOf(alice.signSecret),
   "Ed25519 key pair is byte-identical after restore (deterministic fromSeed)");
ok(hexOf(restored.boxPublic) === hexOf(alice.boxPublic) &&
   hexOf(restored.boxSecret) === hexOf(alice.boxSecret),
   "X25519 key pair is byte-identical after restore (SHA-256 stretch, §11)");
ok(restored.hint === alice.hint && restored.hint === DTN.deriveDestHint(alice.boxPublic),
   "legacy static §6.1 hint is identical after restore");

// §6.1 rotating-hint world: hint(E) for several epochs AND the full
// candidate set must match, or restored devices would miss their mail.
// (Restored-side derivations run through DTN2 — the identity's own realm.)
for (const e of [0, DTN.epochOf(now), DTN.epochOf(now) + 1, DTN.epochOf(now) + 30]) {
  ok(DTN2.deriveRotatingHint(restored.boxPublic, e) === DTN.deriveRotatingHint(alice.boxPublic, e),
     `rotating hint(E=${e}) is identical after restore`);
}
{
  const c1 = DTN.hintCandidates(alice.boxPublic, DTN.epochOf(now), now);
  const c2 = DTN2.hintCandidates(restored.boxPublic, DTN.epochOf(now), now);
  ok(c1.join(",") === c2.join(",") && c1.length >= 2,
     "§6.1 hint candidate sets are identical after restore");
}

ok(restored.alias === undefined && restored.registered_at === undefined,
   "alias/registered_at are NOT derivable from the seed (the import re-asks, §11)");

// The import input gates mirror ui.js: bad Base64 is null, wrong length throws.
ok(DTN2.b64decode("not base64!!") === null && DTN2.b64decode("AB=") === null,
   "import: non-Base64 seed text is rejected before any derivation");
{
  let threw = false;
  try { DTN2.identityFromSeed(parsedSeed.subarray(0, 31)); } catch (e) { threw = true; }
  ok(threw, "import: a 31-byte seed is rejected by identityFromSeed");
}

// Determinism: importing the same paper text twice gives the same identity.
const restoredAgain = DTN2.identityFromSeed(DTN2.b64decode(seedText));
ok(hexOf(restoredAgain.signSecret) === hexOf(restored.signSecret) &&
   hexOf(restoredAgain.boxSecret) === hexOf(restored.boxSecret),
   "importing the same seed twice yields the same identity (deterministic)");

// Mail built for the PRE-wipe identity is mail for the restored one: build
// toward alice's key with a rotating hint, open with the restored identity.
{
  const sender = DTN.createIdentity();
  sender.alias = "sender_x";
  const env = DTN.buildEnvelope({
    recipientBoxPublic: alice.boxPublic,
    message: "seed round trip",
    alias: sender.alias,
    signSecret: sender.signSecret,
    signPublic: sender.signPublic,
    createdAt: now,
    hintEpoch: DTN.epochOf(now),
  });
  const candidates = DTN2.hintCandidates(restored.boxPublic, DTN.epochOf(now), now);
  ok(DTN2.classifyPullEnvelopes([env], candidates).mine.length === 1,
     "an envelope addressed to the pre-wipe identity classifies as MINE after restore");
  const dec = DTN2.decryptEnvelope(env, restored, now, candidates);
  ok(dec.ok && dec.m === "seed round trip",
     "the restored identity opens mail addressed to the pre-wipe identity");
}

/* ======================================================================
 * B + C. Real daemons: the import re-registers, then one store crosses
 * nodes. Build the dev binary once, two daemons on 18201/18202.
 * ==================================================================== */
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "field-equiv-"));
const PORT_A = 18201;
const PORT_B = 18202;
const children = [];
let daemonBin = null;

function request(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        headers: Object.assign(
          { Host: "offgrid.local:8080" },
          payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}
        ),
        timeout: 10000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try { json = JSON.parse(text); } catch (e) { /* non-JSON body */ }
          resolve({ status: res.statusCode, text, json });
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("request timeout")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitHealthy(port, label) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const r = await request(port, "GET", "/api/v1/health");
      if (r.status === 200 && r.json && r.json.status === "ok") return r.json;
    } catch (e) { /* not up yet */ }
    await new Promise((res) => setTimeout(res, 150));
  }
  throw new Error(`${label} did not become healthy on 127.0.0.1:${port}`);
}

// The health snapshot is cached in RAM for up to healthCacheTTL (1 s) by
// design (internal/api/health.go — boundedness), so a count that changed
// microseconds ago may still read stale. T10's "agree with reality" is
// therefore checked within that documented window: poll briefly.
async function healthEventually(port, pred, label) {
  const deadline = Date.now() + 5000;
  for (;;) {
    const r = await request(port, "GET", "/api/v1/health");
    const h = r.json;
    if (r.status === 200 && h && pred(h)) return h;
    if (Date.now() > deadline) {
      throw new Error(`${label}: health never matched within the cache window — ${r.text}`);
    }
    await new Promise((res) => setTimeout(res, 150));
  }
}

function startDaemon(port) {
  const dbPath = path.join(workDir, `node-${port}.db`);
  const child = spawn(daemonBin, ["-addr", `127.0.0.1:${port}`, "-db", dbPath], { stdio: "ignore" });
  children.push(child);
  return child;
}

function cleanup() {
  for (const c of children) {
    try { c.kill(); } catch (e) { /* already gone */ }
  }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

try {
  console.log("== B/C setup: build the daemon, start nodes A and B ==");
  daemonBin = path.join(workDir, "dtn-node-field");
  execFileSync("go", ["build", "-trimpath", "-o", daemonBin, "."], { cwd: path.join(repoRoot, "node"), stdio: "pipe" });
  startDaemon(PORT_A);
  startDaemon(PORT_B);
  const healthA0 = await waitHealthy(PORT_A, "node A");
  const healthB0 = await waitHealthy(PORT_B, "node B");
  ok(healthA0.envelopes === 0 && healthB0.envelopes === 0,
     "both daemons healthy on 18201/18202 with empty stores");

  console.log("== B. the import re-registers: directory upsert resent to a real node ==");
  // ui.js onImport → newPrekeyPublication + publishIdentity, verbatim shape.
  const stock = DTN2.prekeyGenerateStock(now);
  const bundle = DTN2.prekeyBundleForPublish(stock, restored.signSecret, restored.signPublicB64);
  const regBody = {
    alias: "alice_field",
    pubkey: restored.signPublicB64,
    x25519: restored.boxPublicB64,
    prekeys: bundle,
  };
  {
    const reg = await request(PORT_A, "POST", "/api/v1/directory", regBody);
    ok(reg.status === 200, "the restored identity's directory upsert is accepted by node A (200)");
    const dir = (await request(PORT_A, "GET", "/api/v1/directory")).json;
    const entry = Array.isArray(dir) ? dir.find((e) => e && e.pubkey === restored.signPublicB64) : null;
    ok(Boolean(entry), "GET /api/v1/directory serves the restored identity's entry");
    ok(entry && entry.alias === "alice_field" && entry.x25519 === restored.boxPublicB64,
       "the served entry re-binds the SAME alias and X25519 key (inbox re-registered)");
    ok(entry && typeof entry.epoch === "number" && entry.epoch >= 0,
       "the served entry carries a fresh §6.1 epoch stamp");
    const h = await healthEventually(PORT_A, (x) => x.directory_entries === 1, "directory_entries=1");
    ok(h.directory_entries === 1 && h.status === "ok",
       "/api/v1/health agrees: 1 directory entry, status ok");
  }

  console.log("== C. one store, two nodes: identity + inbox + transit survive the node change ==");
  // Client state = the §11 same-origin store, shaped by the store's own
  // helpers. Plain objects stand in for IndexedDB (the headless store is
  // never opened anywhere in the shipped code's test surface).
  function deviceState(identity) {
    return { identity, inbox: [], transit: [], seen: new Set() };
  }
  async function registerOnNode(port, identity, opts) {
    const o = opts || {};
    let body = { alias: identity.alias, pubkey: identity.signPublicB64, x25519: identity.boxPublicB64 };
    if (o.stock) {
      body.prekeys = DTN.prekeyBundleForPublish(o.stock, identity.signSecret, identity.signPublicB64);
    }
    const r = await request(port, "POST", "/api/v1/directory", body);
    if (r.status !== 200) throw new Error(`directory upsert failed: ${r.status} ${r.text}`);
  }
  // One mule cycle in miniature, mirroring ui.js runSync: known_ids = inbox ∪
  // transit ∪ seen ∪ pushed ids; the batch gate is the real §15.6 code; the
  // pulled envelopes are classified, stored or decrypted exactly like §11.
  async function syncCycle(port, state, outgoing) {
    outgoing = outgoing || [];
    const outgoingIds = outgoing.map((e) => e.id);
    for (const id of outgoingIds) state.seen.add(id);
    const known = new Set(outgoingIds);
    for (const r of state.inbox) known.add(r.id);
    for (const r of state.transit) known.add(r.id);
    for (const id of state.seen) known.add(id);
    const carried = state.transit.map((r) => DTN.toEnvelopeWire(r));
    const gate = DTN.prepareOutgoingBatch(outgoing.concat(carried), null);
    const resp = await request(port, "POST", "/api/v1/sync", {
      known_ids: [...known],
      push_envelopes: gate.batch,
      limit: 50,
    });
    if (resp.status !== 200) throw new Error(`sync failed: ${resp.status} ${resp.text}`);
    const deliveredIds = new Set(gate.batch.map((e) => e.id));
    state.transit = state.transit.filter((r) => !deliveredIds.has(r.id));
    const pulled = (resp.json && Array.isArray(resp.json.pull_envelopes)) ? resp.json.pull_envelopes : [];
    for (const env of pulled) state.seen.add(env.id);
    return pulled;
  }
  async function pullIntoState(port, state, prekeyStock) {
    const caps = (await request(port, "GET", "/api/v1/capabilities")).json;
    const observedEpoch = DTN.observedEpochFromCapabilities(caps);
    ok(typeof observedEpoch === "number" && observedEpoch >= 0,
       "capabilities advertise hint_epoch_current (the §6.1 node observation)");
    const pulled = await syncCycle(port, state, []);
    const candidates = DTN.hintCandidates(state.identity.boxPublic, observedEpoch, now);
    const cls = DTN.classifyPullEnvelopes(pulled, candidates);
    for (const env of cls.foreign) {
      const rec = DTN.transitRecordOf(env, now);
      if (rec && !state.transit.some((t) => t.id === rec.id)) state.transit.push(rec);
    }
    for (const env of cls.mine) {
      const trial = prekeyStock ? DTN.prekeyTrialKeys(prekeyStock) : undefined;
      const dec = DTN.decryptEnvelope(env, state.identity, now, candidates, trial);
      if (!dec.ok) throw new Error(`own mail failed to decrypt: ${dec.reason}`);
      state.inbox.push({ id: env.id, m: dec.m, a: dec.a, t: dec.t, received_at: now });
    }
    return { cls, candidates };
  }

  // The cast of the walk: Bob (home node B, also walked past A), Alice
  // (sends from A), Cara (the mule whose store we follow).
  const bob = DTN.createIdentity();
  bob.alias = "bob_field";
  const bobStock = DTN.prekeyGenerateStock(now);
  const aliceStock = DTN.prekeyGenerateStock(now);
  const cara = DTN.createIdentity();
  cara.alias = "cara_mule";

  // Bob registers at BOTH nodes (he was at node A in T1 step 1, then walked
  // home to node B with his identity). Alice and Cara register at A.
  await registerOnNode(PORT_A, bob, { stock: bobStock });
  await registerOnNode(PORT_B, bob, { stock: bobStock });
  await registerOnNode(PORT_A, alice, { stock: aliceStock });
  await registerOnNode(PORT_A, cara, {});

  // Alice resolves Bob from node A's SERVED directory and addresses him by
  // the real sender rule (verified bundle → OPK target, rotating hint).
  const dirA = (await request(PORT_A, "GET", "/api/v1/directory")).json;
  const bobEntry = dirA.find((e) => e && e.pubkey === bob.signPublicB64);
  ok(Boolean(bobEntry) && bobEntry.prekeys && typeof bobEntry.prekeys === "object" &&
     Array.isArray(bobEntry.prekeys.opks) && bobEntry.prekeys.opks.length > 0,
     "node A serves Bob's entry with his published prekey bundle");
  const target = DTN.prekeyTargetForEntry(bobEntry);
  ok(target.ok && hexOf(target.identityBox) === hexOf(bob.boxPublic),
     "the sender rule picks a bundle target while the hint stays on the identity key");
  const MESSAGE = "field equiv: two nodes, one store, sha256-stable";
  const aliceEnv = DTN.buildEnvelope({
    recipientBoxPublic: target.pub,
    hintIdentityBoxPublic: target.identityBox,
    message: MESSAGE,
    alias: alice.alias,
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: now,
    hintEpoch: bobEntry.epoch,
  });
  const aliceState = deviceState(alice);
  await syncCycle(PORT_A, aliceState, [aliceEnv]);
  {
    const h = await healthEventually(PORT_A,
      (x) => x.envelopes === 1 && x.directory_entries === 3 && x.counters.pushes_accepted >= 1,
      "node A reality after the send");
    ok(h.envelopes === 1 && h.directory_entries === 3,
       "node A reality: 1 envelope held, 3 directory entries (alice, bob, cara)");
    ok(h.counters.pushes_accepted >= 1, "node A counters.pushes_accepted ticked for the send");
  }

  // Cara syncs at node A: Alice's envelope is FOREIGN to her → transit.
  const caraState = deviceState(cara);
  {
    const before = { inbox: caraState.inbox.length, transit: caraState.transit.length, seen: caraState.seen.size };
    await pullIntoState(PORT_A, caraState);
    ok(caraState.transit.length === 1 && caraState.inbox.length === before.inbox,
       "the mule picks up Alice's envelope as foreign cargo at node A");
    const rec = caraState.transit[0];
    ok(rec.id === aliceEnv.id && rec.payload === aliceEnv.payload &&
       rec.dest_hint === aliceEnv.dest_hint && rec.created_at === aliceEnv.created_at &&
       rec.ttl === aliceEnv.ttl && rec.v === aliceEnv.v,
       "the carried transit record preserves the six §3.1 wire fields byte-identically");
  }

  // Bob, waiting at node B, sends to Cara — she is NOT in node B's directory,
  // so he uses the §4.7 in-person QR contact they exchanged earlier.
  const qrPayload = DTN.qrBuildPayload({ alias: cara.alias, signPublicB64: cara.signPublicB64, boxPublicB64: cara.boxPublicB64, signSecret: cara.signSecret }, now);
  const parsedQr = DTN.qrParsePayload(qrPayload, now);
  ok(parsedQr.ok, "Cara's QR payload parses and verifies (signature + CRC, §4.7)");
  const caraContact = DTN.qrContactRecord(parsedQr, "qr", now);
  ok(caraContact.ed === cara.signPublicB64 && caraContact.x === cara.boxPublicB64,
     "Bob's local contact of Cara holds her exact keys (offline path, §4.7)");
  const capsB = (await request(PORT_B, "GET", "/api/v1/capabilities")).json;
  const epochB = DTN.observedEpochFromCapabilities(capsB);
  const bobToCara = DTN.buildEnvelope({
    recipientBoxPublic: DTN.b64decode(caraContact.x),
    hintIdentityBoxPublic: DTN.b64decode(caraContact.x),
    message: "cara, your cargo arrived with you",
    alias: bob.alias,
    signSecret: bob.signSecret,
    signPublic: bob.signPublic,
    createdAt: now,
    hintEpoch: epochB,
  });
  const bobState = deviceState(bob);
  await syncCycle(PORT_B, bobState, [bobToCara]);
  {
    const h = await healthEventually(PORT_B,
      (x) => x.envelopes === 1 && x.directory_entries === 1, "node B reality before the mule");
    ok(h.envelopes === 1 && h.directory_entries === 1,
       "node B reality before the mule: 1 envelope held (Bob's mail), 1 directory entry (bob)");
  }

  // THE node change: the SAME Cara store now syncs against node B.
  {
    const identitySnapshot = {
      seed: hexOf(cara.seedB64),
      ed: hexOf(cara.signPublicB64),
      x: hexOf(cara.boxPublicB64),
      hint: cara.hint,
    };
    await pullIntoState(PORT_B, caraState);
    ok(hexOf(caraState.identity.signPublicB64) === identitySnapshot.ed &&
       hexOf(caraState.identity.boxPublicB64) === identitySnapshot.x &&
       hexOf(caraState.identity.seedB64) === identitySnapshot.seed &&
       caraState.identity.hint === identitySnapshot.hint,
       "identity unchanged after the node change (same-origin store, T2c)");
    ok(caraState.transit.length === 0,
       "the carried transit queue was delivered to node B (mule drop-off)");
    ok(caraState.inbox.length === 1 && caraState.inbox[0].m === "cara, your cargo arrived with you",
       "mail addressed via the offline QR contact arrived at the NEW node and opened");
    ok(caraState.seen.has(aliceEnv.id) && caraState.seen.has(bobToCara.id),
       "seen_ids dedup memory survived the node change (§11)");
  }
  {
    const h = await healthEventually(PORT_B,
      (x) => x.envelopes === 2 && x.counters.pushes_accepted >= 2, "node B reality after the drop-off");
    ok(h.envelopes === 2, "node B reality after the drop-off: 2 envelopes held");
    ok(h.counters.pushes_accepted >= 2, "node B counters.pushes_accepted ticked for the carried cargo");
  }

  // Bob pulls at node B: Alice's envelope, carried by Cara, opens with HIS
  // stock — payload integrity across two nodes and a walk (the headless T1).
  {
    await pullIntoState(PORT_B, bobState, bobStock);
    ok(bobState.inbox.length === 1 && bobState.inbox[0].id === aliceEnv.id,
       "Bob receives the exact envelope Alice computed (content-addressed id stable)");
    ok(bobState.inbox[0].m === MESSAGE && bobState.inbox[0].a === alice.alias,
       "message text and sender alias arrive byte-identical after the mule walk");
    const h = await healthEventually(PORT_B, (x) => x.envelopes === 2, "node B dead-drop copies");
    ok(h.envelopes === 2, "node B keeps its dead-drop copies after pulls (no pull-deletion)");
    const status = await request(PORT_B, "GET", "/status");
    ok(status.status === 200 && status.text.includes("Node status") &&
       status.text.includes("Counters (since process start)"),
       "GET /status renders the operator view of the same reality (zero-JS HTML)");
  }

  console.log("== D. fabrication guard on docs/field-test.md ==");
  const docPath = path.join(repoRoot, "docs", "field-test.md");
  const doc = fs.readFileSync(docPath, "utf8");
  for (let i = 1; i <= 10; i++) {
    ok(doc.includes(`## T${i} —`), `field-test.md defines case T${i}`);
  }
  ok((doc.match(/\[ \] pass/g) || []).length === 24,
     "all 24 Result lines (T1..T10 + N1..N14) are UNCHECKED checkboxes (nothing pre-observed)");
  const pendingCount = (doc.match(/PENDING/g) || []).length;
  ok(pendingCount >= 20, `results scaffolds carry the PENDING markers (${pendingCount} found)`);
  ok(doc.includes("PROTOCOL READY — EXECUTION PENDING") &&
     doc.includes("prepared as an executable protocol plus an empty report scaffold"),
     "the honest header states the document's machine-prepared, unexecuted status");
  ok(doc.includes("left EMPTY until the physical session happens") &&
     doc.includes("Owner acceptance (name / signature / date): ______"),
     "the sign-off block is present and empty");
  ok(!/✓|✔|☑|✗|✘/.test(doc) && !/\[x\]/i.test(doc),
     "no tick glyphs and no checked boxes anywhere in the report");
  ok(!/\|\s*(pass|fail|passed|failed)\s*\|/i.test(doc),
     "no result table cell is pre-filled with a verdict");
  ok(doc.includes("docs/hardware.md` §10"),
     "T6 cites the channel-planning guidance of docs/hardware.md §10");

  console.log("== D2. the Phase 3 node-plane session, §15 (issue #33 P3.9) — structure + honesty ==");
  ok(doc.includes("## 15. Phase 3 node-plane session"),
     "field-test.md defines the §15 Phase 3 node-plane session");
  ok(doc.includes("protocol; execution pending"),
     "the §15 heading states protocol-only, execution-pending status");
  for (let i = 1; i <= 14; i++) {
    ok(doc.includes(`### N${i} —`), `field-test.md defines node-plane case N${i}`);
  }
  ok((doc.match(/^### N\d+ —/gm) || []).length === 14,
     "the §15 case family counts exactly N1..N14 (nothing extra, nothing missing)");
  for (const sub of [
    "### 15.2 Prerequisites — the Phase 3 kit",
    "### 15.3 Bench tier — cases N1–N5",
    "### 15.4 Field tier — cases N6–N13",
    "### 15.5 Solar repeater soak — case N14 (72 h, unattended)",
    "### 15.6 Results matrices",
    "### 15.7 Defect log (Phase 3 session)",
    "### 15.8 Sign-off — left EMPTY until the Phase 3 physical session happens",
  ]) {
    ok(doc.includes(sub), `§15 subsection present: ${sub}`);
  }
  // The boundary statement: the section's first, load-bearing honesty pin.
  ok(doc.indexOf("**BOUNDARY — read this before planning anything else.**") !== -1 &&
     doc.indexOf("**BOUNDARY — read this before planning anything else.**") < doc.indexOf("### N1 —"),
     "the boundary statement sits at the top of §15, before the first case");
  ok(doc.includes("requires the **P3.3 hardware bring-up**") &&
     doc.includes("dtn_session_store") && doc.includes("dtn_radio"),
     "the boundary names the P3.3 bring-up dependencies (sx126x driver, NVS behind the HAL seams)");
  ok(doc.includes("the C host suite") && doc.includes("tests/node_plane_e2e.sh") &&
     doc.includes("node/internal/forward/integration_test.go") &&
     doc.includes("node/internal/mgmt/integration_test.go"),
     "the boundary names the enforcing host suites while the hardware is pending");
  ok(doc.includes("NOT a claim of results"),
     "the boundary states the section is a protocol, not a claim of results");
  // §4 acceptance items mapped one-to-one into the field tier.
  for (const marker of ["2-hop", "Passive capture", "below its required level", "L3 ceremony",
                        "capsule crosses the plane", "composable from C",
                        "budget bounds a flooding peer", "never starves mail"]) {
    ok(doc.includes(marker), `the §4 acceptance mapping covers: ${marker}`);
  }
  ok(doc.includes("72 h solar soak") && doc.includes("no replay-window rewind"),
     "the soak case pins the 72 h cycle and the persisted-sequence resume criterion");
  ok(doc.includes("left EMPTY until the Phase 3 physical session happens"),
     "the §15.8 sign-off block is present and empty");

  console.log(`\nPASS: ${passed} assertions on the issue-#20 field equivalents (seed restore, cross-node store, status agreement) and the field-test.md guard`);
} finally {
  cleanup();
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
}

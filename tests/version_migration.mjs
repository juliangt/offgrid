// Version-migration test for the SPA side of spec §15 (issue #18, Phase 3).
//
// Loads the shipped scripts in the exact order declared by
// node/web/index.html (via tests/helpers/spa_loader.mjs) and asserts the
// §15.7 conformance rows that live on the mule (Module C side):
//
//   (a) conversion fidelity (§15.7 d, e): the blind v1→v2 transform keeps
//       id/dest_hint/created_at/ttl/payload value-identical, sets
//       meta.orig_v = 1, never mutates its input, and the §6.2 id
//       recomputed over the canonical core fields (creation version from
//       meta.orig_v) equals the original — dedup stays version-agnostic
//       (§15.1 id stability)
//   (b) invertibility (§15.6): dropping meta and setting v = 1 yields the
//       original envelope back
//   (c) negotiation guard (§15.7 f): prepareOutgoingBatch pushes original,
//       unconverted forms when the ceiling is unobtainable (null) or < 2,
//       withholds envelopes above the node's ceiling, converts v1 copies
//       only at a v2 node, and never mutates the stored forms
//   (d) capabilities parsing (§15.5): the example document reduces to its
//       max_envelope_version; the additive §6.1 hint-epoch members (issue
//       #26) ride along ignored, observedEpochFromCapabilities reads
//       hint_epoch_current, anything malformed → null
//   (e) pull path at v2 (§15.3): classification, shape validation and
//       decryption accept envelopes of their stored version, never
//       rejecting or rewriting v2
//   (f) store migrations chain (§15.6): ordered ascending, additive-only,
//       idempotent. store.js is loaded headlessly (it touches indexedDB
//       only inside idbOpen, never at load time), so the shipped chain
//       runner is exercised against a fake database object.
//
// Run: node tests/version_migration.mjs   (exit 0 = pass)

import { loadSpaSandbox } from "./helpers/spa_loader.mjs";

const sandbox = loadSpaSandbox();

const DTN = sandbox.DTN;
if (!DTN || typeof DTN.buildEnvelope !== "function" || !DTN.nacl) {
  throw new Error("DTN engine did not load from the index.html script list (nacl or buildEnvelope missing)");
}
for (const fn of ["convertEnvelopeV1toV2", "maxAdvertisedEnvelopeVersion", "prepareOutgoingBatch", "runIdbMigrations"]) {
  if (typeof DTN[fn] !== "function") throw new Error(`DTN.${fn} missing — mule.js/store.js did not load`);
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

// Real identities and a real v1 envelope, built with the loaded engine
// (same buildEnvelope path as tests/crypto_roundtrip.mjs).
const bob = DTN.createIdentity();
const alice = DTN.createIdentity();
const mule = DTN.createIdentity();
const message = "Carry this across the mesh, please — ☕";
const createdAt = 1759500000;

function buildTo(recipient, text, at) {
  return DTN.buildEnvelope({
    recipientBoxPublic: recipient.boxPublic,
    message: text,
    alias: "alice_77",
    signSecret: alice.signSecret,
    signPublic: alice.signPublic,
    createdAt: at
  });
}

const envelope = buildTo(bob, message, createdAt);       // v1, addressed to Bob
const carried = buildTo(mule, "foreign cargo", createdAt + 5); // v1 cargo for another hop

// A stored v2 envelope as a §15.3 node serves it: natively minted form,
// meta absent (meta is admission-time and never persisted, §15.3).
const carriedV2 = {
  v: 2,
  id: carried.id,
  dest_hint: carried.dest_hint,
  created_at: carried.created_at,
  ttl: carried.ttl,
  payload: carried.payload
};

console.log("== (a) conversion fidelity — §15.7 d, e ==");
{
  const snapshot = JSON.stringify(envelope);
  const converted = DTN.convertEnvelopeV1toV2(envelope);
  ok(converted !== null && converted !== envelope, "conversion returns a NEW object, not the input");
  ok(converted.v === 2, "converted envelope is v2 (§15.1)");
  ok(typeof converted.meta === "object" && converted.meta.orig_v === 1, "meta.orig_v = 1 on the converted form (§15.1)");
  ok(converted.id === envelope.id &&
     converted.dest_hint === envelope.dest_hint &&
     converted.payload === envelope.payload,
     "id, dest_hint and payload preserved bit-for-bit (§15.7 d)");
  ok(converted.created_at === envelope.created_at && converted.ttl === envelope.ttl,
     "created_at/ttl preserved — conversion never refreshes the deadline (§15.7 e)");
  ok(JSON.stringify(envelope) === snapshot, "the input envelope is NOT mutated");
  ok(Object.keys(converted).length === 7,
     "converted form carries exactly the six §3.1 fields plus meta (§15.1 strict superset)");
  ok(DTN.computeEnvelopeId(converted.meta.orig_v, converted.dest_hint,
                           converted.created_at, converted.ttl, converted.payload) === envelope.id,
     "§6.2 id recomputed over the canonical core fields (creation version = meta.orig_v) equals the original id — dedup is version-agnostic (§15.1)");
  ok(DTN.canonicalEnvelopeString(1, converted.dest_hint, converted.created_at,
                                 converted.ttl, converted.payload) ===
     DTN.canonicalEnvelopeString(1, envelope.dest_hint, envelope.created_at,
                                 envelope.ttl, envelope.payload),
     "the §5.2 hashed byte string is unchanged by conversion (meta is outside it)");

  ok(DTN.convertEnvelopeV1toV2(converted) === null, "a v2 envelope is never converted again (no double meta)");
  ok(DTN.convertEnvelopeV1toV2({ ...envelope, v: 3 }) === null, "v3 is never converted (only v == 1 accepted)");
  ok(DTN.convertEnvelopeV1toV2(null) === null && DTN.convertEnvelopeV1toV2({}) === null,
     "null/shapeless inputs convert to null, never throw");
}

console.log("== (b) invertibility — §15.6 ==");
{
  const converted = DTN.convertEnvelopeV1toV2(envelope);
  const inverted = {
    v: 1,
    id: converted.id,
    dest_hint: converted.dest_hint,
    created_at: converted.created_at,
    ttl: converted.ttl,
    payload: converted.payload
  };
  ok(inverted.v === 1 && !("meta" in inverted), "invert: set v = 1, drop meta (§15.6)");
  ok(JSON.stringify(inverted) === JSON.stringify(envelope),
     "the inverted object is deep-equal (byte-level JSON) to the original envelope");
}

console.log("== (c) negotiation guard — §15.7 f ==");
{
  const queue = [envelope, carried, carriedV2];
  const queueSnapshot = JSON.stringify(queue);

  const gNull = DTN.prepareOutgoingBatch(queue, null);
  ok(gNull.batch.length === 3 && gNull.withheld.length === 0,
     "unobtainable capabilities (null): nothing withheld, the whole batch goes out");
  ok(gNull.batch[0] === queue[0] && gNull.batch[1] === queue[1] && gNull.batch[2] === queue[2],
     "null ceiling: the batch is the ORIGINAL forms (same objects), nothing converted (§15.7 f)");
  ok(gNull.batch.every((e) => !("meta" in e)), "null ceiling: no meta anywhere on the batch");

  const g1 = DTN.prepareOutgoingBatch(queue, 1);
  ok(g1.batch.length === 2 && g1.withheld.length === 1,
     "ceiling 1: the two v1 envelopes go out, the carried v2 is withheld");
  ok(g1.batch[0] === queue[0] && g1.batch[0].v === 1 && !("meta" in g1.batch[0]) &&
     g1.batch[1] === queue[1] && g1.batch[1].v === 1,
     "ceiling 1: v1 envelopes unconverted at a v1-only node (§15.7 f)");
  ok(g1.withheld[0] === carriedV2 && !g1.batch.includes(carriedV2),
     "the withheld list names the carried v2 envelope; the batch excludes it (kept in transit_queue, §15.6)");

  const g2 = DTN.prepareOutgoingBatch(queue, 2);
  ok(g2.batch.length === 3 && g2.withheld.length === 0,
     "ceiling 2: nothing withheld");
  ok(g2.batch[0].v === 2 && g2.batch[0].meta.orig_v === 1 && g2.batch[0].id === envelope.id,
     "ceiling 2: v1 envelopes ride as blind v2 conversions with stable ids (§15.1)");
  ok(g2.batch[0] !== queue[0] && g2.batch[1] !== queue[1],
     "converted entries are fresh wire copies — the stored records are not the batched objects");
  ok(g2.batch[2] === queue[2] && g2.batch[2].v === 2 && !("meta" in g2.batch[2]),
     "a stored v2 envelope goes out as-is at a v2 node (never re-converted, §15.6)");
  ok(JSON.stringify(queue) === queueSnapshot,
     "the stored queue (array and records) is never mutated by the gate, in any case");
  ok(g2.batch[0].created_at === envelope.created_at && g2.batch[0].ttl === envelope.ttl,
     "the converted wire copy keeps the original deadline (§15.7 e)");

  const empty = DTN.prepareOutgoingBatch([], 2);
  ok(empty.batch.length === 0 && empty.withheld.length === 0, "an empty queue gates to an empty batch");
  ok(DTN.prepareOutgoingBatch(queue, "2").batch[0] === queue[0],
     "a non-numeric ceiling degrades to the null fallback (defensive)");
}

console.log("== (d) capabilities parsing — §15.5 ==");
{
  const capsDoc = {
    api: "v1",
    envelope_versions: [1, 2],
    min_envelope_version: 1,
    max_envelope_version: 2,
    schema_version: 3,
    build: "dtn-node-dev",
    hint_epoch_seconds: 86400,
    hint_epoch_current: 20730
  };
  ok(DTN.maxAdvertisedEnvelopeVersion(capsDoc) === 2, "the §15.5 document → ceiling 2");
  ok(DTN.maxAdvertisedEnvelopeVersion({ ...capsDoc, envelope_versions: [1], min_envelope_version: 1, max_envelope_version: 1 }) === 1,
     "a v1-only node advertises [1] → ceiling 1");
  ok(DTN.maxAdvertisedEnvelopeVersion({ ...capsDoc, envelope_versions: [1, 2, 3], min_envelope_version: 1, max_envelope_version: 3 }) === 3,
     "a longer ascending set → its last element");
  ok(DTN.maxAdvertisedEnvelopeVersion({ ...capsDoc, future_member: { whatever: 1 } }) === 2,
     "unknown members are ignored (§15.4 additive policy)");
  // §6.1 (issue #26): the additive hint-epoch members ride along ignored by
  // the ceiling reducer, and the §6.1 observer reads the current epoch.
  ok(DTN.maxAdvertisedEnvelopeVersion({
      api: "v1", envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 2, schema_version: 3, build: "b",
      hint_epoch_seconds: 86400, hint_epoch_current: 20730 }) === 2,
     "the §6.1 additive members change nothing for the ceiling (§15.4)");
  ok(DTN.observedEpochFromCapabilities(capsDoc) === 20730,
     "observedEpochFromCapabilities reads hint_epoch_current (§6.1)");
  ok(DTN.observedEpochFromCapabilities({
      api: "v1", envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 2, schema_version: 2, build: "old",
    }) === null,
     "a pre-1.6 capabilities document (no hint members) observes no epoch");
  ok(DTN.observedEpochFromCapabilities({ ...capsDoc, hint_epoch_current: 0 }) === 0 &&
     DTN.observedEpochFromCapabilities({ ...capsDoc, hint_epoch_current: -1 }) === null &&
     DTN.observedEpochFromCapabilities({ ...capsDoc, hint_epoch_current: 1.5 }) === null,
     "the observed epoch must be a non-negative integer");

  const malformed = [
    ["null document", null],
    ["undefined document", undefined],
    ["string document", "v1"],
    ["array document", [1, 2]],
    ["missing envelope_versions", { min_envelope_version: 1, max_envelope_version: 2 }],
    ["empty version set", { envelope_versions: [], min_envelope_version: 0, max_envelope_version: 0 }],
    ["string version set", { envelope_versions: "1,2", min_envelope_version: 1, max_envelope_version: 2 }],
    ["non-integer member", { envelope_versions: [1, 1.5], min_envelope_version: 1, max_envelope_version: 1.5 }],
    ["string member", { envelope_versions: [1, "2"], min_envelope_version: 1, max_envelope_version: 2 }],
    ["non-ascending set", { envelope_versions: [2, 1], min_envelope_version: 2, max_envelope_version: 1 }],
    ["duplicate members", { envelope_versions: [1, 1, 2], min_envelope_version: 1, max_envelope_version: 2 }],
    ["min != first", { envelope_versions: [1, 2], min_envelope_version: 2, max_envelope_version: 2 }],
    ["max != last", { envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 1 }],
    ["missing max", { envelope_versions: [1, 2], min_envelope_version: 1 }],
    ["missing min", { envelope_versions: [1, 2], max_envelope_version: 2 }],
    ["string max", { envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: "2" }],
    ["float max", { envelope_versions: [1, 2], min_envelope_version: 1, max_envelope_version: 2.5 }],
  ];
  for (const [label, doc] of malformed) {
    ok(DTN.maxAdvertisedEnvelopeVersion(doc) === null, `malformed capabilities → null: ${label}`);
  }
}

console.log("== (e) pull path at v2 — §15.3 ==");
{
  const convertedForBob = DTN.convertEnvelopeV1toV2(envelope);
  const foreignV2 = DTN.convertEnvelopeV1toV2(carried);

  const cls = DTN.classifyPullEnvelopes([convertedForBob, foreignV2], bob.hint);
  ok(cls.mine.length === 1 && cls.mine[0].id === envelope.id && cls.mine[0].v === 2,
     "a v2 envelope addressed to Bob classifies as mine — never rejected for its version");
  ok(cls.foreign.length === 1 && cls.foreign[0].id === carried.id,
     "a v2 envelope for another hop classifies as foreign and is carried as-is");

  ok(DTN.validEnvelopeShape(convertedForBob) === true, "shape validation admits converted v2 (meta.orig_v = 1, §15.3)");
  ok(DTN.validEnvelopeShape(carriedV2) === true, "natively-minted v2 (meta absent) admitted (§15.3)");
  ok(DTN.validEnvelopeShape({ ...convertedForBob, meta: { orig_v: 1, future_key: true } }) === true,
     "unknown meta keys are ignored, never validated (§15.1/§15.3)");
  ok(DTN.validEnvelopeShape({ ...envelope, meta: { orig_v: 1 } }) === false, "meta on a v1 envelope is rejected (§15.3)");
  ok(DTN.validEnvelopeShape({ ...carriedV2, meta: { orig_v: 2 } }) === false, "meta.orig_v must be the integer 1 (§15.3)");
  ok(DTN.validEnvelopeShape({ ...carriedV2, meta: "x" }) === false, "meta must be a JSON object (§15.3)");
  ok(DTN.validEnvelopeShape({ ...carriedV2, meta: ["x"] }) === false, "an array is not a meta object (§15.3)");
  ok(DTN.validEnvelopeShape({ ...carriedV2, v: 3 }) === false, "v outside the supported set {1,2} is rejected (§15.3)");

  const dec = DTN.decryptEnvelope(convertedForBob, bob, createdAt);
  ok(dec.ok === true && dec.m === message && dec.a === "alice_77" && dec.t === createdAt,
     "Bob decrypts the CONVERTED v2 form: meta is outside all cryptographic scope (§15.1)");
  ok(DTN.decryptEnvelope(envelope, bob, createdAt).ok === true, "the v1 original still decrypts identically");
}

console.log("== (f) store migrations chain — §15.6 ==");
{
  const chain = DTN.IDB_MIGRATIONS;
  ok(Array.isArray(chain) && chain.length >= 1, "the migrations table exists and is non-empty");
  ok(chain.every((s) => s && typeof s === "object" && Number.isInteger(s.version) && s.version >= 1 && typeof s.migrate === "function"),
     "every step is {version: integer, migrate: function}");
  let ascending = true;
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].version <= chain[i - 1].version) ascending = false;
  }
  ok(ascending && chain[0].version === 1, "versions are strictly ascending starting at 1 (forward-only, §15.6)");
  ok(chain[chain.length - 1].version === DTN.DB_VERSION,
     "the chain top is exactly DB_VERSION — no artificial bumps (§15.6)");

  // Additive-only + order, exercised through the shipped runner against a
  // fake database that records every touched member.
  function fakeDb(log) {
    return new Proxy({}, {
      get(_t, prop) {
        if (prop === "createObjectStore") {
          return (name, options) => log.push({ op: "create", name, options: options || null });
        }
        log.push({ op: "touch", name: String(prop) });
        return undefined;
      }
    });
  }
  const fresh = [];
  DTN.runIdbMigrations(fakeDb(fresh), 0);
  ok(fresh.every((e) => e.op === "create"),
     "the chain only creates — no other database member is ever touched (additive-only, §15.6)");
  ok(fresh.map((e) => e.name).join(",") === "identity,inbox,transit_queue,seen_ids,meta,inbox_parts,sent",
     "the v1 step creates the five §11 stores; v2 adds only inbox_parts (§4.4); v3 adds only sent (§4.5)");
  ok(fresh.find((e) => e.name === "inbox")?.options?.keyPath === "id" &&
     fresh.find((e) => e.name === "transit_queue")?.options?.keyPath === "id" &&
     fresh.find((e) => e.name === "inbox_parts")?.options?.keyPath === "g" &&
     fresh.find((e) => e.name === "sent")?.options?.keyPath === "id",
     "inbox/transit_queue/sent are keyed by envelope id; inbox_parts by the §4.4 group id g");

  const atCurrent = [];
  DTN.runIdbMigrations(fakeDb(atCurrent), DTN.DB_VERSION);
  ok(atCurrent.length === 0, "a database already at DB_VERSION runs no step (idempotent, §15.6)");
  const atV1 = [];
  DTN.runIdbMigrations(fakeDb(atV1), chain[0].version);
  ok(atV1.length === 2 && atV1.every((e) => e.op === "create") &&
     atV1[0].name === "inbox_parts" && atV1[1].name === "sent",
     "a database at version 1 runs exactly the v2+v3 deltas, in order — each step applied once (§15.3 analogue)");
  const atV2 = [];
  DTN.runIdbMigrations(fakeDb(atV2), chain[1].version);
  ok(atV2.length === 1 && atV2[0].op === "create" && atV2[0].name === "sent",
     "a database at version 2 runs exactly the v3 delta — the chain is forward-only (§15.3 analogue)");

  const again = [];
  DTN.runIdbMigrations(fakeDb(again), 0);
  ok(JSON.stringify(again) === JSON.stringify(fresh),
     "chain application is deterministic across runs (idempotent re-run from scratch)");
}

console.log(`\nPASS: ${passed} assertions on the SPA §15 versioning policy (index.html script order)`);

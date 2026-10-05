// Structural contract test for the portal SPA's file layout.
//
// The SPA is a set of same-origin source files under node/web/ embedded into
// the Go binary (go:embed) and served by the node itself. This test pins the
// invariants every other test (and the browser) silently rely on:
//
//   1. index.html references only assets that exist on disk, and every
//      css/js file under node/web/ is referenced (no orphans, no typos).
//   2. No inline scripts or styles: the CSP of the served page is
//      script-src 'self'; style-src 'self' and the page keeps honoring it.
//   3. Scripts load in the documented dependency order and the engine
//      contract (window.DTN API surface) stays intact.
//   4. Every app script is strict-mode ES5 + Promises: it starts with its
//      own "use strict" directive (the vendored tweetnacl stays verbatim).
//
// Run: node tests/spa_structure.mjs   (exit 0 = pass)

import fs from "node:fs";
import path from "node:path";
import { repoRoot, webRoot, referencedAssets, pageScripts, loadSpaSandbox } from "./helpers/spa_loader.mjs";

let passed = 0;
function ok(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`ok: ${label}`);
}

const html = fs.readFileSync(path.join(webRoot, "index.html"), "utf8");

console.log("== 1. referenced assets exist; no orphaned source files ==");
const referenced = referencedAssets();
for (const [url, file] of referenced) {
  ok(fs.existsSync(file), `${url} exists on disk`);
}
ok(referenced.has("/css/app.css"), "the page links exactly one stylesheet");
const onDisk = new Set(
  [...walk(webRoot)]
    .filter((f) => /\.(css|js)$/.test(f))
    .map((f) => "/" + path.relative(webRoot, f).split(path.sep).join("/"))
);
for (const file of onDisk) {
  ok(referenced.has(file), `source file ${file} is referenced by index.html`);
}
ok(referenced.size === onDisk.size, "no referenced asset missing and no orphaned source file");

console.log("== 2. CSP: 'self' only, no inline scripts or styles ==");
const csp = html.match(/Content-Security-Policy[^>]*content="([^"]+)"/)?.[1] ?? "";
for (const directive of ["default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'"]) {
  ok(csp.includes(directive), `CSP keeps ${directive}`);
}
ok(!csp.includes("unsafe-inline"), "CSP drops 'unsafe-inline' (hardening win of the split)");
ok(!/<script(?![^>]*src=)[^>]*>/i.test(html), "no inline <script> blocks (would be blocked by the CSP)");
ok(!/<style[\s>]/i.test(html), "no inline <style> blocks (would be blocked by the CSP)");
ok(/<link rel="stylesheet" href="\/css\/app.css">/.test(html), "stylesheet linked same-origin");

console.log("== 3. script load order and DTN API surface ==");
const expectedOrder = [
  "/js/vendor/nacl.min.js",
  "/js/constants.js",
  "/js/bytes.js",
  "/js/sha256.js",
  "/js/hkdf.js",
  "/js/canonical.js",
  "/js/envelopes.js",
  "/js/prekeys.js",
  "/js/mule.js",
  "/js/chunking.js",
  "/js/acks.js",
  "/js/engine.js",
  "/js/store.js",
  "/js/ui.js",
];
ok(JSON.stringify(pageScripts().map((s) => s.url)) === JSON.stringify(expectedOrder),
   "scripts load in the documented dependency order");

const sandbox = loadSpaSandbox();
const DTN = sandbox.DTN;
const expectedApi = [
  "TRANSIT_CAPACITY", "TTL_DEFAULT", "TTL_MIN", "TTL_MAX", "MESSAGE_MAX_BYTES",
  "ALIAS_REGEX", "CANONICAL_HOST", "CANONICAL_URL",
  "utf8Encode", "utf8Decode", "messageByteLength", "b64encode", "b64decode",
  "hexEncode", "hexDecode", "sha256", "randomBytes", "concatBytes",
  "jsonEscapeString", "canonicalSignedString", "canonicalInnerJson",
  "canonicalEnvelopeString", "validateAlias", "createIdentity",
  "identityFromSeed", "deriveDestHint", "computeEnvelopeId", "buildEnvelope",
  "decryptEnvelope", "validEnvelopeShape", "classifyPullEnvelopes",
  "evictTransitQueue", "nacl",
  // §15 versioning policy on the mule side (issue #18, Phase 3)
  "convertEnvelopeV1toV2", "maxAdvertisedEnvelopeVersion", "prepareOutgoingBatch",
  // §4.4 long-message chunking (issue #24)
  "CHUNK_TAG", "CHUNK_MAX_PARTS", "CHUNK_G_BYTES", "CHUNK_META_MAX_BYTES",
  "CHUNK_TEXT_PLUS_ALIAS_LIMIT", "CHUNK_WARN_PARTS",
  "canonicalChunkedSignedString", "canonicalChunkedInnerJson",
  "chunkTextBudget", "chunkSplitText", "chunkPlannedCount", "chunkComposerLimit",
  "buildMessageEnvelopes", "chunkNewState", "chunkStateWithPart", "chunkStateHave",
  "chunkStateComplete", "chunkStateText", "chunkStateExpired", "chunkInboxRecord",
  // §4.5 delivery acknowledgments (issue #25)
  "ACK_TAG", "ACK_TYPE_RECEIVED", "ACK_META_MAX_BYTES", "SENT_HISTORY_MAX",
  "canonicalAckSignedString", "canonicalAckInnerJson",
  "ackTtlFor", "ackReferenceIdFor", "ackTaskForArrival",
  "sentNewRecord", "ackMatchesSent", "sentDeliveredRecord", "sentStatusLabel",
  // §6.1 rotating dest_hint (issue #26)
  "HINT_EPOCH_SECONDS", "HINT_INFO", "HINT_LENGTH_BYTES", "HINT_TRANSITION_DEADLINE",
  "hmacSha256", "hkdfSha256", "epochOf", "deriveRotatingHint", "hintCandidates",
  "observedEpochFromCapabilities",
  // local store API (section 8)
  "loadIdentity", "saveIdentity", "addInboxMessages", "listInbox",
  "addInboxChunkPart", "listChunkPartials", "removeChunkPartial",
  "purgeExpiredChunkPartials",
  "addSentRecord", "listSent", "markSentPushed", "applyAckToSent", "STORE_SENT",
  "addTransitEnvelopes", "listTransit", "removeTransitIds",
  "markSeenIds", "listSeenIds", "getMeta", "setMeta", "toEnvelopeWire",
  // §15.6 store migrations chain
  "DB_VERSION", "IDB_MIGRATIONS", "runIdbMigrations",
];
for (const member of expectedApi) {
  ok(DTN[member] !== undefined, `DTN.${member} is exported`);
}
ok(sandbox.window.DTN === DTN && sandbox.self.DTN === DTN, "the engine exports window.DTN (DOM-free)");

console.log("== 4. every app script is strict-mode and DOM-guarded ==");
for (const { url, source } of pageScripts()) {
  if (url.endsWith("vendor/nacl.min.js")) continue; // vendored: verbatim, do not touch
  ok(source.trimStart().startsWith("/*") && /"use strict";/.test(source.slice(0, 2000)),
     `${url} declares "use strict"`);
}
// The UI file must not touch the DOM at load time (it only runs from
// initUi, guarded by typeof document + the #dtn-app container).
const ui = fs.readFileSync(path.join(webRoot, "js", "ui.js"), "utf8");
ok(/if \(typeof document !== "undefined" && document\.getElementById\("dtn-app"\)\) \{\s*\n\s*initUi\(\);\s*\n\s*\}\s*$/.test(ui.trimEnd()),
   "ui.js wires the DOM only via the guarded initUi() boot");

console.log(`\nPASS: ${passed} structural assertions on the SPA layout`);

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else yield p;
  }
}

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
// The page may also reference non-code assets (§12.1: the manifest and the
// apple-touch icon); every css/js file on disk must still be referenced and
// no code file may be orphaned.
const referencedCode = [...referenced.keys()].filter((u) => /\.(css|js)$/.test(u));
ok(referencedCode.length === onDisk.size, "no referenced asset missing and no orphaned source file");
ok(referenced.has("/manifest.json") && referenced.has("/icons/icon-180.png"),
   "the §12.1 metadata assets referenced by the page exist on disk");

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
  "/js/vendor/qrcode.js",
  "/js/constants.js",
  "/js/bytes.js",
  "/js/sha256.js",
  "/js/hkdf.js",
  "/js/canonical.js",
  "/js/envelopes.js",
  "/js/prekeys.js",
  "/js/qr.js",
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
  "markSeenIds", "listSeenIds", "getMeta", "setMeta", "toEnvelopeWire", "transitRecordOf",
  // §15.6 store migrations chain
  "DB_VERSION", "IDB_MIGRATIONS", "runIdbMigrations",
  // §4.7 identity QR — in-person contact exchange (issue #28)
  "QR_PAYLOAD_PREFIX", "QR_PAYLOAD_VERSION", "QR_MAX_VERSION", "QR_ECC_LEVEL",
  "QR_TS_SKEW_SECONDS", "QR_QUIET_ZONE_MODULES",
  "qrCrc32", "qrCrc32Hex", "qrCanonicalPayloadString", "qrCanonicalObjectString",
  "qrBuildPayload", "qrParsePayload", "qrContactRecord", "qrMergeRecipients", "qrMakeMatrix",
  "STORE_CONTACTS", "saveContact", "listContacts",
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

console.log("== 5. add-to-home-screen wiring (§12.1, issue #29) ==");
// The manifest/apple-touch-icon hrefs are already existence-checked in
// section 1 via referencedAssets(); here the §12.1 metadata contract and
// the honest hint UI are pinned. Deep manifest/icon assertions live in
// tests/pwa_assets.mjs.
ok(html.includes('<link rel="manifest" href="/manifest.json">'), "the page links the web app manifest (same-origin, §12.1)");
ok(/<meta name="apple-mobile-web-app-capable" content="yes">/.test(html), "iOS standalone metadata present");
ok(html.includes('<link rel="apple-touch-icon" href="/icons/icon-180.png">'), "iOS apple-touch-icon linked (iOS ignores the manifest)");
ok(html.includes('id="banner-install"'), "the install hint banner exists in the page");
ok(html.includes("it is a shortcut, not an offline app"), "the §12.1 honesty note ships verbatim in the hint");
ok(!/<link[^>]*rel="manifest"[^>]*href="https?:/.test(html) && !/<link[^>]*href="https?:[^"]*"[^>]*rel="manifest"/.test(html),
   "the manifest link is never an external URL");
ok(/detectInstallPlatform\(\)/.test(ui) && /install_hint_dismissed/.test(ui),
   "ui.js platform-gates the hint and persists its dismissal in the meta store");

console.log("== 6. /guide quick-start page (issue #23) ==");
// The served guide: script-free HTML with its own stylesheet and the REAL
// SPA screenshots under img/guide/. The master text is docs/quick-start.md;
// this section pins the served page's structure and keeps the binary bloat
// of the embedded screenshots honest.
const guidePath = path.join(webRoot, "guide.html");
ok(fs.existsSync(guidePath), "web/guide.html exists");
const guide = fs.readFileSync(guidePath, "utf8");
const gcsp = guide.match(/Content-Security-Policy[^>]*content="([^"]+)"/)?.[1] ?? "";
for (const directive of ["default-src 'none'", "style-src 'self'", "img-src 'self'", "base-uri 'none'", "form-action 'none'"]) {
  ok(gcsp.includes(directive), `guide CSP keeps ${directive}`);
}
ok(!/<script/i.test(guide), "guide.html carries no JavaScript at all");
ok(!/<style[\s>]/i.test(guide), "guide.html has no inline <style> blocks (CSP style-src 'self')");
ok(guide.includes('<link rel="stylesheet" href="/css/guide.css">'), "guide links its own stylesheet (app.css untouched)");
const guideCss = fs.readFileSync(path.join(webRoot, "css", "guide.css"), "utf8");
ok(guideCss.includes("@page") && guideCss.includes("@media print"), "guide.css carries the print layout (@page + @media print)");
ok(/column-count:\s*2/.test(guideCss), "guide.css prints the core flow in two columns (one-sheet contract)");
for (const marker of ["Ten words you need", "What to expect", "Troubleshooting", "offgrid.local:8080"]) {
  ok(guide.includes(marker), `guide.html carries: ${marker}`);
}
const steps = guide.match(/<li class="step">/g) || [];
ok(steps.length === 10, "the guide carries exactly the 10 numbered steps");
ok(html.includes('<footer class="portal-footer"><a href="/guide">Guide</a></footer>'),
   "portal index links /guide from the footer (labeled \"Guide\"; /status stays unlinked)");
const guideExternals = [...guide.matchAll(/https?:\/\/[^"'<\s)]+/gi)]
  .map((m) => m[0])
  .filter((u) => !u.startsWith("http://offgrid.local:8080"));
ok(guideExternals.length === 0, `guide.html references no external URL beyond the canonical origin (${guideExternals.join(", ") || "none"})`);

// The screenshots: real PNGs of the SPA screens, sized for the guide
// (≤ 720 px wide), with a hard cap on the total embedded bytes.
const imgDir = path.join(webRoot, "img", "guide");
ok(fs.existsSync(imgDir), "web/img/guide/ exists");
const guideImgs = [...guide.matchAll(/src="(\/img\/guide\/[^"]+)"/g)].map((m) => m[1]);
ok(guideImgs.length >= 4, `the guide embeds at least 4 screenshots (${guideImgs.length})`);
ok(new Set(guideImgs).size === guideImgs.length, "no screenshot is referenced twice");
let imgTotal = 0;
for (const url of guideImgs) {
  const p = path.join(webRoot, url.replace(/^\//, ""));
  ok(fs.existsSync(p), `${url} exists on disk`);
  const info = pngInfo(p);
  ok(info !== null, `${url} is a valid PNG (magic + IHDR)`);
  ok(info.width >= 300 && info.width <= 720, `${url} width ${info.width} px is readable but ≤ 720 (guide size cap)`);
  ok(info.height >= 100 && info.height <= 2600, `${url} height ${info.height} px is sane`);
  ok(info.bytes <= 120 * 1024, `${url} embeds small (${info.bytes} bytes ≤ 120 KiB)`);
  imgTotal += info.bytes;
}
ok(imgTotal < 600 * 1024, `guide screenshots total ${(imgTotal / 1024).toFixed(0)} KiB < 600 KiB (honest binary bloat)`);

console.log(`\nPASS: ${passed} structural assertions on the SPA layout`);

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else yield p;
  }
}

// Independent PNG parse (the pwa_assets.mjs pattern): bytes 0..7 magic, the
// IHDR chunk holds width/height as big-endian uint32 at offsets 16 and 20.
function pngInfo(file) {
  const buf = fs.readFileSync(file);
  const magic = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 8; i++) if (buf[i] !== magic[i]) return null;
  if (buf.toString("ascii", 12, 16) !== "IHDR") return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), bytes: buf.length };
}

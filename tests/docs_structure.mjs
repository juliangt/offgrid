// Structural contract test for the issue-#14 security-audit deliverables.
//
// The audit's phase-5 deliverables are documents, so this suite pins them
// the way the repo pins every other artifact — by file structure, offline
// and deterministically:
//
//   1. docs/security-audit.md exists and is FINAL: v1.0.0 header, executive
//      summary with the findings totals, the complete 30-row findings index
//      (NODE/SPA/PROTO/PI/SUPPLY), the phase-5 deliverables-traceability and
//      deferred/follow-up sections, the disclosure note — and no stale
//      DRAFT/phase-1 wording left behind.
//   2. docs/known-limitations.md exists (the issue's deliverable d): dated,
//      linked to issue #14, with the summary table and a subsection per
//      accepted residual, each citing its authoritative source (asserted on
//      stable heading/anchor strings, not full sentences).
//   3. README wiring: both docs sit in the Documentation table and the
//      status section, the corrected hint-linkability claim is present and
//      the pre-audit overclaim wording ("only within the current epoch") is
//      gone.
//   4. Suite wiring: `make test` runs this file, and docs/BUILD.md §4
//      documents it with consistent step numbering.
//
// Run: node tests/docs_structure.mjs   (exit 0 = pass)

import fs from "node:fs";
import path from "node:path";
import { repoRoot } from "./helpers/spa_loader.mjs";

const docsDir = path.join(repoRoot, "docs");

let passed = 0;
function ok(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`ok: ${label}`);
}

console.log("== 1. security-audit.md is FINAL and internally complete ==");
const auditPath = path.join(docsDir, "security-audit.md");
ok(fs.existsSync(auditPath), "docs/security-audit.md exists");
const audit = fs.readFileSync(auditPath, "utf8");
ok(audit.includes("| **Version** | 1.0.0"), "audit header is version 1.0.0");
ok(audit.includes("| **Status** | **FINAL**"), "audit header status is FINAL");
ok(!audit.includes("DRAFT"), "no stale DRAFT status remains in the audit report");
ok(!audit.includes("0.4.0"), "no stale 0.4.0 version remains in the audit report");
ok(!audit.includes("final consolidation pass is pending"), "no stale pending-consolidation wording remains");
ok(audit.includes("## Executive summary"), "the executive summary section exists");
ok(audit.includes("30 findings: 0 critical, 0 high, 6 medium, 10 low, 14 info"),
   "the executive summary states the findings totals by severity");
ok(audit.includes("no window between fix and disclosure"), "the disclosure note is present");
const allFindings = [
  ...Array.from({ length: 7 }, (_, i) => `NODE-0${i + 1}`),
  ...Array.from({ length: 6 }, (_, i) => `SPA-0${i + 1}`),
  ...Array.from({ length: 8 }, (_, i) => `PROTO-0${i + 1}`),
  ...Array.from({ length: 4 }, (_, i) => `PI-0${i + 1}`),
  ...Array.from({ length: 5 }, (_, i) => `SUPPLY-0${i + 1}`),
];
ok(allFindings.length === 30, "the findings inventory counts 30 IDs");
for (const id of allFindings) {
  ok(audit.includes(id), `findings index covers ${id}`);
}
ok(audit.includes("### 6.1 Deliverables traceability"), "the deliverables-traceability section exists");
for (const deliverable of ["(a) Written report", "(b) Threat-model review", "(c) Regression tests", "(d) Known-limitations"]) {
  ok(audit.includes(deliverable), `traceability maps the issue deliverable: ${deliverable}`);
}
ok(audit.includes("### 6.2 Deferred and follow-up"), "the deferred/follow-up section exists");
for (const deferred of ["PROTO-08", "PROTO-05", "SPA-03", "SPA-04", "SUPPLY-02", "PI-02", "PI-04"]) {
  ok(audit.includes(`| ${deferred} |`), `the deferred register tracks ${deferred}`);
}
ok(audit.includes("known-limitations.md"), "the audit report links the known-limitations digest");

console.log("== 2. known-limitations.md covers every accepted residual ==");
const limitsPath = path.join(docsDir, "known-limitations.md");
ok(fs.existsSync(limitsPath), "docs/known-limitations.md exists");
const limits = fs.readFileSync(limitsPath, "utf8");
ok(limits.includes("issue #14"), "the digest is tied to issue #14");
ok(limits.includes("2026-10-06"), "the digest is dated");
ok(limits.includes("| Limitation | What it means for you | Where it's specified |"),
   "the summary table has the limitation/meaning/source columns");
const requiredSections = [
  "## 1. No TLS: the portal is plain HTTP",
  "## 2. The node serves the app itself (evil-twin trust)",
  "## 3. A directory holder can link envelopes to aliases — permanently",
  "## 4. Directory entries have no proof of ownership",
  "## 5. Replayed mail after expiry",
  "## 6. Filling the store is censorship, and the caps are only partial shields",
  "## 7. A shared or unlocked device is the identity",
  "## 8. An extracted SD card is readable",
  "## 9. Release hashes are unsigned; `curl | bash` trusts the channel",
  "## 10. Mules can withhold or drop mail",
  "## 11. The signed-capsule design is not implemented yet",
];
for (const section of requiredSections) {
  ok(limits.includes(section), `residual section present: ${section}`);
}
// Every entry cites its authoritative source: the spec, the audit finding
// IDs and the design record (stable ID strings, not sentences).
const requiredCitations = [
  "protocol.md",
  "security-audit.md",
  "offline-maintenance.md",
  "NODE-05", "SPA-04", "PROTO-01", "NODE-04", "PROTO-02", "PROTO-03",
  "SPA-05", "PI-03", "SUPPLY-02", "SPA-03", "NODE-01",
];
for (const citation of requiredCitations) {
  ok(limits.includes(citation), `the digest cites its source: ${citation}`);
}
ok(limits.split("\n").length <= 130,
   `the digest stays short (${limits.split("\n").length} lines, need <= 130)`);

console.log("== 3. README wiring and the corrected hint claim ==");
const readme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
const auditRefs = (readme.match(/docs\/security-audit\.md/g) || []).length;
ok(auditRefs >= 2, `README references docs/security-audit.md ${auditRefs}x (docs table + status, need >= 2)`);
const limitsRefs = (readme.match(/docs\/known-limitations\.md/g) || []).length;
ok(limitsRefs >= 2, `README references docs/known-limitations.md ${limitsRefs}x (docs table + status, need >= 2)`);
ok(readme.includes("| [`docs/security-audit.md`](docs/security-audit.md) | **Security audit report**"),
   "the Documentation table row for the security-audit report is present");
ok(readme.includes("| [`docs/known-limitations.md`](docs/known-limitations.md) | **Known limitations**"),
   "the Documentation table row for known-limitations is present");
ok(readme.includes("**Security audit — complete** (issue #14)"),
   "the status section records the audit as complete (issue #14)");
ok(readme.includes("can still link envelopes to aliases permanently (protocol §13.3)"),
   "the key-decisions bullet carries the corrected hint-linkability claim");
ok(!readme.includes("within the current epoch"),
   "the pre-audit overclaim wording is gone from the README");

console.log("== 4. suite wiring: Makefile + docs/BUILD.md §4 ==");
const makefile = fs.readFileSync(path.join(repoRoot, "Makefile"), "utf8");
ok(makefile.includes("node tests/docs_structure.mjs"), "the Makefile test target runs tests/docs_structure.mjs");
const buildPath = path.join(docsDir, "BUILD.md");
const build = fs.readFileSync(buildPath, "utf8");
ok(build.includes("node tests/docs_structure.mjs"), "docs/BUILD.md §4 documents tests/docs_structure.mjs");
const stepsMarker = build.indexOf("The explicit steps");
ok(stepsMarker !== -1, "docs/BUILD.md §4 has the explicit-steps block");
const blockStart = build.indexOf("```", stepsMarker);
const blockEnd = build.indexOf("```", blockStart + 3);
ok(blockStart !== -1 && blockEnd > blockStart, "the explicit-steps code block is intact");
const block = build.slice(blockStart, blockEnd);
const stepNums = [...block.matchAll(/^# (\d+)\./gm)].map((m) => Number(m[1]));
ok(stepNums.length > 0, "the explicit steps carry numbered comments");
const expectedNums = Array.from({ length: stepNums.length }, (_, i) => i + 1);
ok(JSON.stringify(stepNums) === JSON.stringify(expectedNums),
   `§4 step comments are consecutive 1..${stepNums.length} (got ${stepNums.join(", ") || "none"})`);
ok(/# \d+\. Audit-deliverables docs structure \(issue #14\)/.test(block),
   "the §4 step for this suite names the audit deliverables (issue #14)");
ok(build.includes("PASS: <n> assertions on the security-audit and known-limitations docs"),
   "§4 documents this suite's expected PASS line");

console.log("== 5. node-network.md exists (issue #33 P3.0) ==");
const nodeNetPath = path.join(docsDir, "node-network.md");
ok(fs.existsSync(nodeNetPath), "docs/node-network.md exists");
const nodeNet = fs.readFileSync(nodeNetPath, "utf8");
ok(nodeNet.includes("| **Version** | 1.0.0"), "node-network header is version 1.0.0");
ok(nodeNet.includes("| **Date** | 2026-10-07"), "node-network header is dated 2026-10-07");
ok(nodeNet.includes("docs/protocol.md"), "node-network references the user-plane spec");
ok(nodeNet.includes("RFC 9171"), "node-network names its BPv7 profile base (RFC 9171)");
ok(nodeNet.includes("dtn://og."), "node-network pins the self-certifying EID scheme");

console.log("== summary ==");
console.log(`PASS: ${passed} assertions on the security-audit and known-limitations docs, the README wiring and the node-network spec`);

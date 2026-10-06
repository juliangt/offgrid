// Structural contract test for docs/install-node.md (issue #35).
//
// The from-scratch installation guide is a builder's single source of
// instructions; a broken anchor, a dead link or a drifted number sends a
// first-time builder into a wall. This test pins the invariants:
//
//   1. The guide exists and carries every required top-level section (the
//      10 deliverables of issue #35) plus the key subsections (budget
//      tiers, substitution table, chemistry/runtime tables, per-environment
//      deployment, printable checklists, glossary).
//   2. The table of contents matches the real headings — every TOC anchor
//      resolves to a heading and every heading is in the TOC (GitHub's
//      anchor algorithm, computed the same way both sides).
//   3. Every relative doc link points at a file that exists, and every
//      cross-file heading fragment (#2-sizing-math-worked-example …)
//      matches a real heading in the target file.
//   4. The required cross-links exist: hardware.md, pi-models.md, BUILD.md,
//      RUNBOOK.md and quick-start.md are all referenced; README links the
//      guide (docs table + solar paragraph) and hardware.md carries the
//      forward pointer back.
//   5. The guide's numbers agree with hardware.md (the 1 W load, the 0.90
//      buck efficiency, the 0.80 DoD floor, the 12.8 V / 20 W baseline, the
//      14.6 V LiFePO4 profile, the 5.1 V bench check, both fuse ratings,
//      the 0 °C charge ban and the 30% overnight floor).
//   6. Each environment subsection (forest, mountain, desert, coastal)
//      includes at least one ASCII diagram (fenced block), and photo
//      placeholders exist as HTML comments (never as fake content).
//
// Run: node tests/install_node_structure.mjs   (exit 0 = pass)

import fs from "node:fs";
import path from "node:path";
import { repoRoot } from "./helpers/spa_loader.mjs";

const docsDir = path.join(repoRoot, "docs");
const guidePath = path.join(docsDir, "install-node.md");

let passed = 0;
function ok(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`ok: ${label}`);
}

// GitHub's heading-anchor algorithm (lowercase, strip punctuation except
// letters/numbers/underscore/hyphen, every space becomes a hyphen — an
// em dash between spaces therefore leaves a double hyphen behind).
function githubAnchor(title) {
  return title.trim().toLowerCase()
    .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

// Line-wise parse that ignores fenced code blocks (the checklists' ASCII
// art must never be mistaken for headings) and returns { headings, fences }
// where headings is [{ level, text, anchor, line }] and fences is the list
// of code-block start offsets (character positions into the raw text).
function parseMarkdown(raw) {
  const lines = raw.split("\n");
  const headings = [];
  const fences = [];
  let inFence = false;
  let offset = 0;
  for (const line of lines) {
    if (/^```/.test(line)) {
      if (!inFence) fences.push(offset);
      inFence = !inFence;
    } else if (!inFence) {
      const m = line.match(/^(#{1,6})\s+(.+?)\s*$/);
      if (m) headings.push({ level: m[1].length, text: m[2], anchor: githubAnchor(m[2]), line });
    }
    offset += line.length + 1;
  }
  return { headings, fences };
}

function headingAnchors(raw) {
  return new Set(parseMarkdown(raw).headings.map((h) => h.anchor));
}

console.log("== 1. the guide exists with every required section ==");
ok(fs.existsSync(guidePath), "docs/install-node.md exists");
const raw = fs.readFileSync(guidePath, "utf8");
const { headings, fences } = parseMarkdown(raw);
const headingTexts = headings.map((h) => h.text);

const requiredSections = [
  "1. Prerequisites and skill map",
  "2. Component shopping guide",
  "3. Build alternatives: pick your path",
  "4. Batteries: chemistry, compatibility and runtime",
  "5. Solar panels",
  "6. Assembly, step by step",
  "7. Outdoor deployment by environment",
  "8. Maintenance and periodic checks",
  "9. Troubleshooting",
  "10. Appendix: printable checklists and glossary",
];
for (const section of requiredSections) {
  ok(headingTexts.includes(section), `top-level section present: ${section}`);
}

// Key subsections the issue calls out explicitly.
const requiredSubsections = [
  "1.4 Which existing doc covers what",
  "2.1 The three budget tiers",
  "2.2 Substitutions: what can vary, what must never vary",
  "2.3 Where to buy and how to sanity-check a listing",
  "3.1 Comparison table",
  "3.2 Path A: off-the-shelf power station in a box",
  "3.3 Path B: the standard build",
  "3.4 Path C: DIY cell pack with a BMS",
  "4.1 The four chemistries in plain language",
  "4.2 Compatibility rules",
  "4.3 Runtime table: capacity vs days of autonomy",
  "4.4 Safe handling",
  "5.2 Sizing intuition: one worked example",
  "6.5 Bench validation checklist",
  "7.1 Weatherproofing basics",
  "7.2 Forest",
  "7.3 Mountain and alpine",
  "7.4 Desert",
  "7.5 Coastal and wetland",
  "8.1 Inspection schedule",
  "10.1 Printable shopping checklist",
  "10.2 Printable field-deployment checklist",
  "10.3 Glossary: the words you cannot avoid",
];
for (const section of requiredSubsections) {
  ok(headingTexts.includes(section), `subsection present: ${section}`);
}

// The three tiers and both estimate currencies.
for (const tier of ["Tier 1 — minimal", "Tier 2 — recommended", "Tier 3 — robust"]) {
  ok(raw.includes(tier), `budget tier present: ${tier}`);
}
ok(raw.includes("Est. USD") && raw.includes("Est. EUR"),
   "tier tables carry cost ESTIMATES in both USD and EUR");
ok(raw.includes("estimates") && /not quotes/.test(raw),
   "prices are explicitly marked as estimates, not quotes");

// Chemistry comparison, substitution rules, runtime derating, environments.
ok(/NMC/.test(raw) && /lead-acid|Lead-acid/.test(raw) && /NiMH/.test(raw),
   "chemistry comparison covers Li-ion (NMC), lead-acid and NiMH alongside LiFePO4");
ok(/must NEVER be substituted|Must NEVER/.test(raw),
   "substitution table names what must NEVER be substituted");
ok(/low.temp(erature)? charge cutoff/i.test(raw),
   "the low-temperature charge cutoff requirement is stated");
ok(raw.includes("0.90") && raw.includes("0.80"),
   "runtime math uses the buck efficiency 0.90 and the DoD floor 0.80 of hardware.md");

console.log("== 2. table of contents matches the real headings ==");
const anchors = new Set(headings.map((h) => h.anchor));
ok(anchors.size === headings.length, "no duplicate heading anchors");
const tocLinks = [...raw.matchAll(/\]\(#([^)\s]+)\)/g)].map((m) => m[1]);
ok(tocLinks.length > 0, "the guide has in-document anchor links (a TOC)");
for (const anchor of tocLinks) {
  ok(anchors.has(anchor), `TOC anchor #${anchor} matches a real heading`);
}
const tocSet = new Set(tocLinks);
for (const h of headings) {
  if (h.level === 1 || h.text === "Contents") continue; // the title and the TOC heading itself are not TOC entries
  ok(tocSet.has(h.anchor), `heading "${h.text}" is linked from the table of contents`);
}

console.log("== 3. every relative doc link resolves, fragments included ==");
const requiredTargets = ["hardware.md", "pi-models.md", "BUILD.md", "RUNBOOK.md", "quick-start.md"];
const seenTargets = new Set();
const links = [...raw.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
for (const link of links) {
  if (link.startsWith("#")) continue; // internal anchor, already validated above
  const [filePart, fragment] = link.split("#");
  ok(!/^https?:/.test(filePart), `link target ${filePart} is a relative repo link, not an external URL`);
  const target = path.normalize(path.join(docsDir, filePart));
  ok(fs.existsSync(target), `link target exists: ${link}`);
  seenTargets.add(filePart);
  if (fragment) {
    const targetRaw = fs.readFileSync(target, "utf8");
    ok(headingAnchors(targetRaw).has(fragment),
       `fragment #${fragment} of ${filePart} matches a heading in that file`);
  }
}
for (const target of requiredTargets) {
  ok(seenTargets.has(target), `the guide links to ${target} (link, don't duplicate)`);
}

console.log("== 4. README wiring and the hardware.md forward pointer ==");
const readme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
const readmeRefs = (readme.match(/docs\/install-node\.md/g) || []).length;
ok(readmeRefs >= 2, `README references docs/install-node.md ${readmeRefs}x (docs table + solar paragraph, need >= 2)`);
const hardware = fs.readFileSync(path.join(docsDir, "hardware.md"), "utf8");
ok(/install-node\.md/.test(hardware), "docs/hardware.md carries the forward pointer to install-node.md");

console.log("== 5. numbers agree with docs/hardware.md ==");
const numberChecks = [
  ["~1 W", "the ~1 W design load"],
  ["0.90", "the buck efficiency (hardware.md §2.1)"],
  ["0.80", "the DoD floor (hardware.md §2.2)"],
  ["12.8 V", "the 12.8 V LiFePO4 4S pack"],
  ["14.6 V", "the LiFePO4 charge profile"],
  ["20 W", "the recommended 20 W panel"],
  ["5.1 V", "the bench buck-output check"],
  ["15 A", "the battery main fuse"],
  ["2 A", "the load fuse"],
  ["0 °C", "the below-freezing charge ban"],
  ["30%", "the overnight SoC floor (hardware.md §8)"],
];
for (const [needle, why] of numberChecks) {
  ok(raw.includes(needle), `guide states ${needle} (${why})`);
}
ok(/hardware\.md#2-sizing-math-worked-example/.test(raw),
   "the guide links hardware.md §2 for the full math instead of re-deriving it");

console.log("== 6. per-environment diagrams and photo placeholders ==");
const envSections = ["7.2 Forest", "7.3 Mountain and alpine", "7.4 Desert", "7.5 Coastal and wetland"];
for (const env of envSections) {
  const startIdx = headings.findIndex((h) => h.text === env);
  ok(startIdx !== -1, `environment section exists: ${env}`);
  const start = headings[startIdx];
  // the subsection ends at the next heading of its own level or higher
  const nextIdx = headings.findIndex((h, i) => i > startIdx && h.level <= start.level);
  const sectionStartOffset = raw.indexOf(`### ${env}`);
  const sectionEndOffset = nextIdx === -1
    ? raw.length
    : raw.indexOf(`\n${"#".repeat(headings[nextIdx].level)} ${headings[nextIdx].text}`, sectionStartOffset);
  ok(sectionStartOffset !== -1 && sectionEndOffset > sectionStartOffset,
     `environment section located in text: ${env}`);
  const hasFence = fences.some((f) => f > sectionStartOffset && f < sectionEndOffset);
  ok(hasFence, `environment section has an ASCII diagram: ${env}`);
}

const photoPlaceholders = (raw.match(/<!-- PHOTO:/g) || []).length;
ok(photoPlaceholders >= 1, `photo placeholders exist as HTML comments (${photoPlaceholders} found, need >= 1)`);

console.log("== 7. glossary covers the unavoidable terms ==");
const glossaryTerms = ["BMS", "Buck converter", "DoD", "IP rating", "MC4", "MPPT", "PSH", "PWM", "SoC", "Voc"];
for (const term of glossaryTerms) {
  ok(new RegExp(`^- \\*\\*${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "m").test(raw),
     `glossary defines ${term}`);
}

console.log("== summary ==");
console.log(`PASS: ${passed} assertions on docs/install-node.md structure, anchors and cross-links`);

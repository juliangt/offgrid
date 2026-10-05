// PWA-lite asset contract test (issue #29, protocol §12.1).
//
// The portal is installable/pinnable within the no-TLS constraint: a web app
// manifest, maskable icons and the iOS meta tags — every byte embedded in
// the node binary and served same-origin (zero external assets, CSP intact).
// This test pins that contract against the SHIPPED FILES (node/web/):
//
//   1. manifest.json carries exactly the §12.1 members: relative start_url
//      and scope ("/" — the origin is the same on every node; no hardcoded
//      host anywhere), display "standalone", theme/background colors from
//      the portal palette, and icons 192+512 with purpose "any maskable".
//      No service-worker member: on plain HTTP there is no offline shell to
//      promise (the icon is a shortcut, not an offline app).
//   2. The icon files are real PNGs with the exact advertised dimensions
//      (PNG magic + IHDR parsed independently) and stay small enough to
//      embed; the 180 px apple-touch icon ships too (iOS ignores the
//      manifest).
//   3. index.html links the manifest and carries theme-color plus the iOS
//      meta tags and apple-touch-icon.
//   4. NO external URL appears in the manifest, the icons or the portal
//      HTML (only the canonical §12 origin reference that already lives in
//      the captive banner is allowed) — the closed-CSP, zero-external-
//      requests discipline of §1.3 stays intact.
//
// Run: node tests/pwa_assets.mjs   (exit 0 = pass)

import fs from "node:fs";
import path from "node:path";
import { repoRoot, webRoot } from "./helpers/spa_loader.mjs";

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
const css = fs.readFileSync(path.join(webRoot, "css", "app.css"), "utf8");

console.log("== 1. manifest.json: exactly the §12.1 members, relative origin ==");
const manifestPath = path.join(webRoot, "manifest.json");
ok(fs.existsSync(manifestPath), "web/manifest.json exists");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
ok(manifest.name === "Offgrid Messages", "manifest name is \"Offgrid Messages\"");
ok(manifest.short_name === "Offgrid", "manifest short_name is \"Offgrid\"");
ok(manifest.start_url === "/", "start_url is \"/\" (RELATIVE — origin identical on every node, §12)");
ok(manifest.scope === "/", "scope is \"/\"");
ok(manifest.display === "standalone", "display is \"standalone\"");
ok(!("serviceworker" in manifest), "manifest carries NO serviceworker member (no offline shell on plain HTTP, §12.1)");
const members = Object.keys(manifest).sort();
ok(JSON.stringify(members) === JSON.stringify(["background_color", "display", "icons", "name", "scope", "short_name", "start_url", "theme_color"]),
   "manifest member set is exactly the documented eight (additive policy: no surprises)");
ok(!/https?:\/\//i.test(fs.readFileSync(manifestPath, "utf8")), "no absolute URL anywhere in the manifest");

console.log("== 2. palette: manifest colors come from the portal css variables ==");
function cssVar(name) {
  const light = css.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})\\s*;`));
  return light ? light[1].toLowerCase() : null;
}
ok(cssVar("accent") !== null && cssVar("bg") !== null, "app.css defines --accent and --bg (light scheme)");
ok(manifest.theme_color === cssVar("accent"), `manifest theme_color matches css --accent (${cssVar("accent")})`);
ok(manifest.background_color === cssVar("bg"), `manifest background_color matches css --bg (${cssVar("bg")})`);
ok((html.match(/<meta name="theme-color" content="([^"]+)">/) || [])[1] === cssVar("accent"),
   "index.html theme-color meta matches css --accent");

console.log("== 3. icons: real PNGs, exact advertised dimensions ==");
// Independent PNG IHDR parse: bytes 0..7 magic, then the IHDR chunk holds
// width/height as big-endian uint32 at offsets 16 and 20.
function pngSize(file) {
  const buf = fs.readFileSync(file);
  const magic = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 8; i++) if (buf[i] !== magic[i]) return null;
  if (buf.toString("ascii", 12, 16) !== "IHDR") return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), bytes: buf.length };
}
const iconsDir = path.join(webRoot, "icons");
const icons = [
  { file: "icon-192.png", size: 192 }, // manifest icon
  { file: "icon-512.png", size: 512 }, // manifest icon
  { file: "icon-180.png", size: 180 }, // apple-touch-icon (iOS)
];
for (const { file, size } of icons) {
  const p = path.join(iconsDir, file);
  ok(fs.existsSync(p), `web/icons/${file} exists`);
  const info = pngSize(p);
  ok(info !== null, `web/icons/${file} is a PNG (magic + IHDR)`);
  ok(info.width === size && info.height === size, `web/icons/${file} is exactly ${size}x${size}`);
  ok(info.bytes > 0 && info.bytes <= 20 * 1024, `web/icons/${file} embeds small (${info.bytes} bytes ≤ 20 KiB)`);
}

console.log("== 4. manifest icon entries point at the shipped files, maskable ==");
ok(Array.isArray(manifest.icons) && manifest.icons.length === 2, "manifest icons: exactly the two entries (192, 512)");
for (const entry of manifest.icons) {
  const want = entry.sizes === "192x192" ? 192 : entry.sizes === "512x512" ? 512 : null;
  ok(want !== null, `manifest icon size ${entry.sizes} is one of 192x192/512x512`);
  ok(entry.type === "image/png", `manifest icon ${entry.sizes} type is image/png`);
  ok(entry.purpose === "any maskable", `manifest icon ${entry.sizes} purpose is "any maskable"`);
  ok(typeof entry.src === "string" && entry.src.startsWith("/") && !entry.src.startsWith("//"),
     `manifest icon ${entry.sizes} src is an origin-relative absolute path (${entry.src})`);
  const onDisk = path.join(webRoot, entry.src.replace(/^\//, ""));
  const info = fs.existsSync(onDisk) ? pngSize(onDisk) : null;
  ok(info !== null && info.width === want && info.height === want,
     `manifest icon ${entry.sizes} src resolves to a shipped ${want}x${want} PNG`);
}

console.log("== 5. index.html: manifest link, iOS meta tags, apple-touch-icon ==");
ok(html.includes('<link rel="manifest" href="/manifest.json">'), "index.html links /manifest.json (same-origin)");
ok(/<meta name="apple-mobile-web-app-capable" content="yes">/.test(html), "index.html carries apple-mobile-web-app-capable");
ok(/<meta name="apple-mobile-web-app-status-bar-style" content="[^"]+">/.test(html), "index.html carries apple-mobile-web-app-status-bar-style");
ok(/<meta name="apple-mobile-web-app-title" content="Offgrid">/.test(html), "index.html carries apple-mobile-web-app-title (\"Offgrid\")");
ok(html.includes('<link rel="apple-touch-icon" href="/icons/icon-180.png">'), "index.html links the 180 px apple-touch-icon (same-origin)");
ok(/<meta name="mobile-web-app-capable" content="yes">/.test(html), "index.html carries mobile-web-app-capable (legacy Chrome standalone hint)");

console.log("== 6. zero external assets: no external URL in icons or portal HTML ==");
// The only http(s) URL allowed in the portal HTML is the canonical §12
// origin reference already displayed by the §13.4 captive banner.
const canonical = "http://offgrid.local:8080";
let externals = [...html.matchAll(/https?:\/\/[^"'<\s)]+/gi)]
  .map((m) => m[0])
  .filter((u) => !u.startsWith(canonical));
ok(externals.length === 0, `index.html references no external URL beyond the canonical origin (${externals.join(", ") || "none"})`);
for (const { file } of icons) {
  const buf = fs.readFileSync(path.join(iconsDir, file));
  ok(!buf.toString("latin1").includes("http://") && !buf.toString("latin1").includes("https://"),
    `web/icons/${file} carries no embedded URL (deterministic generator output)`);
}

console.log(`\nPASS: ${passed} assertions on the §12.1 PWA-lite assets`);

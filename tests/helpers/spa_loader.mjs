// Shared loader for the SPA's shipped JavaScript (issue: the SPA moved from
// one inline file to same-origin source files under node/web/).
//
// Parses the <script src> list straight out of node/web/index.html — the
// document stays the single source of truth for the load order — resolves
// every entry to a file on disk, and evaluates the concatenation in a Node
// vm context. The UI wiring is guarded behind `typeof document`, so no
// document stub is needed; window/self let the tweetnacl UMD and the
// window.DTN export attach to the sandbox.
//
// Exported for tests/crypto_roundtrip.mjs and tests/spa_structure.mjs.

import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const webRoot = path.join(repoRoot, "node", "web");

/** All local assets referenced by the page: { url → absolute file path }. */
export function referencedAssets() {
  const html = fs.readFileSync(path.join(webRoot, "index.html"), "utf8");
  const assets = new Map();
  for (const m of html.matchAll(/(?:src|href)="(\/[^"]+)"/g)) {
    assets.set(m[1], path.join(webRoot, m[1]));
  }
  return assets;
}

/** The page's scripts, in document order: [{ url, source }]. */
export function pageScripts() {
  const html = fs.readFileSync(path.join(webRoot, "index.html"), "utf8");
  return [...html.matchAll(/<script src="(\/[^"]+)"><\/script>/g)].map((m) => ({
    url: m[1],
    source: fs.readFileSync(path.join(webRoot, m[1]), "utf8"),
  }));
}

/**
 * Loads the shipped scripts in document order into a fresh sandbox and
 * returns it. The sandbox exposes the engine as DTN (window.DTN / self.DTN).
 * Each file is evaluated separately, exactly like separate <script> tags:
 * that keeps every file's own "use strict" directive meaningful.
 */
export function loadSpaSandbox() {
  const sandbox = { crypto: globalThis.crypto, console: { log() {}, error: console.error } };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  const sources = pageScripts();
  if (sources.length === 0) {
    throw new Error("index.html references no scripts — the SPA failed to load");
  }
  for (const s of sources) {
    vm.runInContext(s.source, sandbox, { filename: `node/web${s.url}` });
  }
  return sandbox;
}

#!/usr/bin/env node
// tools/gen_icons.mjs — deterministic generator for the portal's PWA icons
// (issue #29, spec §12.1).
//
// The generated PNGs are COMMITTED (node/web/icons/) and travel inside the
// node binary via go:embed; the node never generates anything at runtime and
// no icon ever comes from the network. This script exists only so the
// committed bytes stay reproducible:
//
//   node tools/gen_icons.mjs            # (re)write the three icons
//
// Design: the portal's deep-green accent (#0b6e4f, css var --accent) fills
// the whole canvas full-bleed (what maskable icons want) and a white
// envelope glyph sits inside the maskable safe zone (centered circle of
// diameter 80 %): the glyph's half-diagonal is ≈ 0.345 < 0.40, so Android's
// circular mask crops background only, never mail. Readable at 48 px: the
// envelope spans 56 % of the canvas width. No gradients, no text.
//
// Determinism: pure integer/float math with fixed inputs + zlib level 9 —
// the same source always yields byte-identical PNGs (the E2E and the
// structure tests pin the exact dimensions; git pins the bytes).

import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const outDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)), "..", "node", "web", "icons");

// Palette (portal css vars, light scheme): --accent background, white glyph.
const BG = [0x0b, 0x6e, 0x4f];
const FG = [0xff, 0xff, 0xff];

// Geometry in unit coordinates (0..1 across the canvas).
const RECT = { cx: 0.5, cy: 0.5, hw: 0.28, hh: 0.20, r: 0.045 }; // envelope body
const STROKE = 0.034;                                            // flap line width
const FLAP = [
  { ax: 0.5 - 0.265, ay: 0.5 - 0.180, bx: 0.5, by: 0.5 - 0.010 },
  { ax: 0.5, ay: 0.5 - 0.010, bx: 0.5 + 0.265, by: 0.5 - 0.180 },
];
const SS = 4; // supersampling factor per axis (16 samples per pixel)

function sampleColor(px, py) {
  // Envelope body: rounded rectangle (signed-distance inside test).
  const qx = Math.abs(px - RECT.cx) - (RECT.hw - RECT.r);
  const qy = Math.abs(py - RECT.cy) - (RECT.hh - RECT.r);
  const ox = Math.max(qx, 0), oy = Math.max(qy, 0);
  const sd = Math.hypot(ox, oy) + Math.min(Math.max(qx, qy), 0) - RECT.r;
  if (sd > 0) return BG;
  // Flap: two stroked segments drawn in the background color on the glyph.
  for (const s of FLAP) {
    const abx = s.bx - s.ax, aby = s.by - s.ay;
    const len2 = abx * abx + aby * aby;
    const t = Math.min(1, Math.max(0, ((px - s.ax) * abx + (py - s.ay) * aby) / len2));
    const dx = px - (s.ax + abx * t), dy = py - (s.ay + aby * t);
    if (Math.hypot(dx, dy) <= STROKE / 2) return BG;
  }
  return FG;
}

function renderIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const unit = 1 / size;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const c = sampleColor((x + (sx + 0.5) / SS) * unit, (y + (sy + 0.5) / SS) * unit);
          r += c[0]; g += c[1]; b += c[2];
        }
      }
      const n = SS * SS, off = (y * size + x) * 4;
      rgba[off] = Math.round(r / n);
      rgba[off + 1] = Math.round(g / n);
      rgba[off + 2] = Math.round(b / n);
      rgba[off + 3] = 0xff;
    }
  }
  return encodePNG(size, size, rgba);
}

// --- Minimal deterministic PNG encoder (RGBA8, no filters, one IDAT). ------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const out = Buffer.alloc(8 + data.length + 4);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

function encodePNG(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter type 0 (None)
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: truecolor + alpha
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // adaptive filtering
  ihdr[12] = 0; // no interlace
  const idat = zlib.deflateSync(raw, { level: 9, memLevel: 9, strategy: zlib.constants.Z_DEFAULT_STRATEGY });
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), // PNG magic
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------------------

const SIZES = [
  { file: "icon-192.png", size: 192 }, // manifest icon (§12.1)
  { file: "icon-512.png", size: 512 }, // manifest icon (§12.1)
  { file: "icon-180.png", size: 180 }, // apple-touch-icon (iOS ignores the manifest)
];

fs.mkdirSync(outDir, { recursive: true });
const { createHash } = await import("node:crypto");
for (const { file, size } of SIZES) {
  const png = renderIcon(size);
  fs.writeFileSync(path.join(outDir, file), png);
  console.log(`${file}: ${size}x${size}, ${png.length} bytes, sha256 ${createHash("sha256").update(png).digest("hex")}`);
}
console.log("icons written to " + outDir);

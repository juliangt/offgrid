// Independent minimal QR decoder for the §4.7 test harness — TEST HARNESS
// ONLY, never shipped. It exists so tests/qr_identity.mjs can validate the
// SHIPPED encoder (node/web/js/vendor/qrcode.js + js/qr.js) the only way
// that matters: its matrix must round-trip back to the original payload
// through a decoder that shares NO code with it.
//
// The read path is implemented from the ISO/IEC 18004 rules on its own:
//   - format information: both 15-bit copies, BCH(15,5) checked (generator
//     0x537, mask 0x5412) → ECC level + mask pattern;
//   - version information for v >= 7: both 18-bit copies, BCH checked
//     (generator 0x1F25) and cross-checked against the size-derived version;
//   - unmasking (own copy of the 8 mask formulas);
//   - the function-module map (finders + separators, timing, alignment
//     patterns from the published per-version center table, format and
//     version areas, dark module);
//   - zigzag codeword collection (right-to-left column pairs, column 6
//     skipped, alternating direction);
//   - Reed-Solomon over GF(2^8) with poly 0x11D: syndromes, and — beyond
//     mere detection — textbook Berlekamp-Massey + Chien + Forney
//     correction with a post-correction syndrome recheck;
//   - block de-interleaving from the published ECC-M block table;
//   - byte-mode segment extraction (mode 0100, 8/16-bit length per version).
//
// Tables were transcribed from the published ISO/IEC 18004 tables (the
// thonky.com tutorial), cross-checked against each version's total
// codewords; they deliberately do NOT read the vendored encoder's tables.

/* ---------- GF(2^8), primitive polynomial 0x11D ---------- */

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function buildGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11D;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}
function gfInv(a) {
  return GF_EXP[255 - GF_LOG[a]];
}
function gfPow2(n) {
  // 2^n in GF(256); n taken mod 255 (n may be any integer within 0..510)
  return GF_EXP[((n % 255) + 255) % 255];
}

/* ---------- published tables (ECC level M) ---------- */

// Reed-Solomon block structure: [ecPerBlock, [[count, dataCW], ...]]
// for versions 1..15; every row must sum to the version's total codewords
// (asserted below against the published totals — table drift fails fast).
const RS_BLOCKS_M = [
  [10, [[1, 16]]],
  [16, [[1, 28]]],
  [26, [[1, 44]]],
  [18, [[2, 32]]],
  [24, [[2, 43]]],
  [16, [[4, 27]]],
  [18, [[4, 31]]],
  [22, [[2, 38], [2, 39]]],
  [22, [[3, 36], [2, 37]]],
  [26, [[4, 43], [1, 44]]],
  [30, [[1, 50], [4, 51]]],
  [22, [[6, 36], [2, 37]]],
  [22, [[8, 37], [1, 38]]],
  [24, [[4, 40], [5, 41]]],
  [24, [[5, 41], [5, 42]]],
];

// Total codewords (data + EC) per version, published in ISO/IEC 18004.
const TOTAL_CODEWORDS = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655];

for (let v = 1; v <= 15; v++) {
  const [ecPerBlock, groups] = RS_BLOCKS_M[v - 1];
  let blocks = 0;
  let dataTotal = 0;
  for (const [count, data] of groups) {
    blocks += count;
    dataTotal += count * data;
  }
  if (blocks * ecPerBlock + dataTotal !== TOTAL_CODEWORDS[v - 1]) {
    throw new Error(`qr_decode: RS block table for v${v} does not sum to the published total`);
  }
}

// Alignment pattern center coordinates per version (v2..v15).
const ALIGN_CENTERS = [
  null,            // v1: none
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
];

/* ---------- format information ---------- */

const FORMAT_GENERATOR = 0x537;  // BCH(15,5) generator polynomial
const FORMAT_MASK = 0x5412;      // fixed XOR mask applied to every format code

function bch15Remainder(bits15) {
  let rem = bits15;
  for (let i = 14; i >= 10; i--) {
    if (rem & (1 << i)) rem ^= FORMAT_GENERATOR << (i - 10);
  }
  return rem & 0x3FF;
}

// Read the two format-info copies MSB-first; returns the first copy whose
// BCH remainder is 0 (both must agree when both are valid). Level bits:
// 00=M, 01=L, 10=H, 11=Q.
function readFormatInfo(matrix, size) {
  const copies = [];
  for (let copy = 0; copy < 2; copy++) {
    let bits = 0;
    for (let i = 0; i < 15; i++) {
      let r;
      let c;
      if (copy === 0) {
        if (i < 6) { r = 8; c = i; }
        else if (i === 6) { r = 8; c = 7; }
        else if (i === 7) { r = 8; c = 8; }
        else if (i === 8) { r = 7; c = 8; }
        else { r = 14 - i; c = 8; }
      } else {
        if (i < 7) { r = size - 1 - i; c = 8; }
        else { r = 8; c = size - 15 + i; }
      }
      bits = (bits << 1) | (matrix[r][c] ? 1 : 0);
    }
    copies.push(bits);
  }
  let found = null;
  for (const bits of copies) {
    const unmasked = bits ^ FORMAT_MASK;
    if (bch15Remainder(unmasked) === 0) {
      const level = (unmasked >> 13) & 0x3;
      const mask = (unmasked >> 10) & 0x7;
      if (found && (found.level !== level || found.mask !== mask)) {
        throw new Error("qr_decode: the two format-info copies disagree");
      }
      found = { level, mask };
    }
  }
  if (!found) throw new Error("qr_decode: no valid format information (BCH check failed on both copies)");
  return found;
}

const ECC_LEVEL_NAMES = { 0: "M", 1: "L", 2: "H", 3: "Q" };

/* ---------- version information (v >= 7) ---------- */

const VERSION_GENERATOR = 0x1F25;  // BCH(18,6) generator polynomial

function bch18Remainder(bits18) {
  let rem = bits18;
  for (let i = 17; i >= 12; i--) {
    if (rem & (1 << i)) rem ^= VERSION_GENERATOR << (i - 12);
  }
  return rem & 0xFFF;
}

function readVersionInfo(matrix, size) {
  const copies = [];
  for (let copy = 0; copy < 2; copy++) {
    let bits = 0;
    for (let i = 5; i >= 0; i--) {
      for (let j = size - 9; j >= size - 11; j--) {
        const bit = copy === 0 ? matrix[j][i] : matrix[i][j];
        bits = (bits << 1) | (bit ? 1 : 0);
      }
    }
    copies.push(bits);
  }
  let found = null;
  for (const bits of copies) {
    if (bch18Remainder(bits) === 0) {
      const version = (bits >> 12) & 0x3F;
      if (found && found !== version) throw new Error("qr_decode: the two version-info copies disagree");
      found = version;
    }
  }
  return found; // null = both copies invalid (a hard failure for v >= 7)
}

/* ---------- mask functions (row i, col j; dark when true) ---------- */

const MASKS = [
  (i, j) => (i + j) % 2 === 0,
  (i, j) => i % 2 === 0,
  (i, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

/* ---------- function-module map ---------- */

function buildFunctionMap(size, version) {
  const f = Array.from({ length: size }, () => new Array(size).fill(false));
  const mark = (r, c) => {
    if (r >= 0 && r < size && c >= 0 && c < size) f[r][c] = true;
  };
  const markBlock = (r0, c0, radius) => {
    for (let r = r0 - radius; r <= r0 + radius; r++) {
      for (let c = c0 - radius; c <= c0 + radius; c++) mark(r, c);
    }
  };
  // Finder patterns + separators: the 8x8 region around each of the three
  // corners (7x7 pattern plus its one-module separator ring).
  markBlock(3, 3, 4);
  markBlock(3, size - 4, 4);
  markBlock(size - 4, 3, 4);
  // Timing patterns.
  for (let i = 0; i < size; i++) {
    f[6][i] = true;
    f[i][6] = true;
  }
  // Alignment patterns: 5x5 at every center pair EXCEPT the pairs whose
  // block would intersect a finder+separator region (the ISO omission
  // rule). Omitting exactly those makes the marked-module count match the
  // published data-region capacity of every version 1..15 exactly — the
  // strongest structural check this map has.
  const centers = ALIGN_CENTERS[version - 1] || [];
  const overlapsFinder = (r, c) =>
    (r - 2 <= 7 && c - 2 <= 7) ||               // top-left region
    (r - 2 <= 7 && c + 2 >= size - 8) ||        // top-right region
    (r + 2 >= size - 8 && c - 2 <= 7);          // bottom-left region
  for (const r of centers) {
    for (const c of centers) {
      if (overlapsFinder(r, c)) continue;
      markBlock(r, c, 2);
    }
  }
  // Format information: both copies' exact coordinate sets.
  for (let i = 0; i < 15; i++) {
    if (i < 6) mark(8, i);
    else if (i === 6) mark(8, 7);
    else if (i === 7) mark(8, 8);
    else if (i === 8) mark(7, 8);
    else mark(14 - i, 8);
    if (i < 7) mark(size - 1 - i, 8);
    else mark(8, size - 15 + i);
  }
  // The dark module (always dark, never data).
  mark(size - 8, 8);
  // Version information (v >= 7): the two 3x6 blocks.
  if (version >= 7) {
    for (let i = 0; i <= 5; i++) {
      for (let j = size - 11; j <= size - 9; j++) {
        mark(j, i);   // bottom-left copy
        mark(i, j);   // top-right copy
      }
    }
  }
  return f;
}

/* ---------- codeword collection (zigzag) ---------- */

function readCodewords(matrix, size, version, maskFn, funcMap) {
  const total = TOTAL_CODEWORDS[version - 1];
  const cw = new Uint8Array(total);
  let cwIdx = 0;
  let bitIdx = 0;
  let upward = true;
  let col = size - 1;
  while (col > 0 && cwIdx < total) {
    if (col === 6) col -= 1; // the timing column is skipped entirely
    for (let i = 0; i < size && cwIdx < total; i++) {
      const r = upward ? size - 1 - i : i;
      for (let cOff = 0; cOff <= 1; cOff++) {
        const c = col - cOff;   // right-hand column of the pair first (ISO 8.7.3)
        if (funcMap[r][c]) continue;
        let bit = matrix[r][c] ? 1 : 0;
        if (maskFn(r, c)) bit ^= 1;
        cw[cwIdx] = ((cw[cwIdx] << 1) | bit) & 0xFF;
        bitIdx += 1;
        if (bitIdx === 8) { bitIdx = 0; cwIdx += 1; }
      }
    }
    upward = !upward;
    col -= 2;
  }
  if (cwIdx !== total) {
    throw new Error(`qr_decode: collected ${cwIdx} of ${total} codewords — function map or placement mismatch`);
  }
  return cw;
}

/* ---------- Reed-Solomon (fcr = 0, α = 2) ----------
 * Conventions (self-consistent, textbook): the codeword array c[0..n-1]
 * holds the polynomial c(x) = Σ c[j]·x^(n-1-j) (c[0] highest degree);
 * syndrome S_i = c(α^i) for i = 0..nsym-1; error at array index p has
 * degree i = n-1-p and locator root X = α^i. Λ(x) = Π (1 − X_k x),
 * Ω(x) = S(x)·Λ(x) mod x^nsym with S(x) = Σ S_i x^i (both lowest-degree
 * first), and the magnitude is e = X·Ω(X⁻¹)/Λ'(X⁻¹) at each error root. */

function rsSyndromes(codeword, nsym) {
  const synd = new Array(nsym).fill(0);
  for (let i = 0; i < nsym; i++) {
    const x = gfPow2(i);
    let s = 0;
    for (let j = 0; j < codeword.length; j++) {
      s = gfMul(s, x) ^ codeword[j];
    }
    synd[i] = s;
  }
  return synd;
}

// Berlekamp-Massey: Λ as an array of lowest-degree-first coefficients.
function rsErrorLocator(synd, nsym) {
  const lambda = [1];
  let B = [1];
  let L = 0;
  let m = 1;
  let b = 1;
  for (let n = 0; n < nsym; n++) {
    let d = synd[n];
    for (let i = 1; i < lambda.length; i++) {
      if (n - i >= 0) d ^= gfMul(lambda[i], synd[n - i]);
    }
    if (d === 0) {
      m += 1;
      continue;
    }
    const coef = gfMul(d, gfInv(b));
    const T = lambda.slice();
    for (let i = 0; i < B.length; i++) {
      const term = gfMul(B[i], coef);
      if (i + m < lambda.length) lambda[i + m] ^= term;
      else lambda[i + m] = term;
    }
    if (2 * L <= n) {
      B = T;
      L = n + 1 - L;
      b = d;
      m = 1;
    } else {
      m += 1;
    }
  }
  if (lambda.length - 1 !== L) throw new Error("qr_decode: locator degree mismatch (uncorrectable)");
  if (2 * L > nsym) throw new Error("qr_decode: too many errors for the block's ECC power");
  return lambda;
}

// Chien search: array index p is an error position iff Λ(α^-(n-1-p)) = 0.
function rsFindErrors(lambda, n) {
  const errs = lambda.length - 1;
  const pos = [];
  for (let p = 0; p < n; p++) {
    const degree = n - 1 - p;
    const xInv = gfPow2(255 - (degree % 255)); // α^-i
    let v = 0;
    let xj = 1; // (α^-i)^j
    for (let j = 0; j < lambda.length; j++) {
      v ^= gfMul(lambda[j], xj);
      xj = gfMul(xj, xInv);
    }
    if (v === 0) pos.push(p);
  }
  if (pos.length !== errs) return null; // uncorrectable
  return pos;
}

// Forney magnitudes at the Chien-found positions.
function rsMagnitudes(synd, lambda, positions, n, nsym) {
  // Ω(x) = S(x)·Λ(x) mod x^nsym, lowest-degree first.
  const omega = new Array(nsym).fill(0);
  for (let i = 0; i < synd.length; i++) {
    for (let j = 0; j < lambda.length; j++) {
      if (i + j < nsym) omega[i + j] ^= gfMul(synd[i], lambda[j]);
    }
  }
  const out = positions.map((p) => {
    const degree = n - 1 - p;
    const x = gfPow2(degree);          // X = α^i
    const xInv = gfInv(x);
    let om = 0;
    let xj = 1;
    for (let j = 0; j < omega.length; j++) {
      om ^= gfMul(omega[j], xj);
      xj = gfMul(xj, xInv);
    }
    // Formal derivative Λ'(x) = Σ over odd j of λ_j·x^(j-1) (char 2).
    let deriv = 0;
    let xp = 1; // (α^-i)^(j-1)
    for (let j = 1; j < lambda.length; j += 2) {
      deriv ^= gfMul(lambda[j], xp);
      if (j + 2 < lambda.length) xp = gfMul(xp, gfMul(xInv, xInv));
    }
    if (deriv === 0) throw new Error("qr_decode: Forney denominator vanished (uncorrectable)");
    return gfMul(gfMul(x, om), gfInv(deriv));
  });
  return out;
}

function rsVerifyAndCorrect(codeword, nsym) {
  const synd = rsSyndromes(codeword, nsym);
  if (synd.every((s) => s === 0)) return { codeword: codeword.slice(), corrected: 0 };
  const lambda = rsErrorLocator(synd, nsym);
  const positions = rsFindErrors(lambda, codeword.length);
  if (!positions) throw new Error("qr_decode: uncorrectable Reed-Solomon block (Chien search)");
  const magnitudes = rsMagnitudes(synd, lambda, positions, codeword.length, nsym);
  const fixed = codeword.slice();
  for (let k = 0; k < positions.length; k++) {
    fixed[positions[k]] ^= magnitudes[k];
  }
  const recheck = rsSyndromes(fixed, nsym);
  if (!recheck.every((s) => s === 0)) {
    throw new Error("qr_decode: Reed-Solomon correction did not settle (uncorrectable block)");
  }
  return { codeword: fixed, corrected: positions.length };
}

/* ---------- de-interleaving ---------- */

function deinterleave(cw, version) {
  const [ecPerBlock, groups] = RS_BLOCKS_M[version - 1];
  const blockLens = [];
  for (const [count, dataLen] of groups) {
    for (let b = 0; b < count; b++) blockLens.push(dataLen);
  }
  const numBlocks = blockLens.length;
  const maxData = Math.max(...blockLens);
  const data = Array.from({ length: numBlocks }, () => []);
  let p = 0;
  for (let col = 0; col < maxData; col++) {
    for (let b = 0; b < numBlocks; b++) {
      if (col < blockLens[b]) data[b].push(cw[p++]);
    }
  }
  const ec = Array.from({ length: numBlocks }, () => []);
  for (let col = 0; col < ecPerBlock; col++) {
    for (let b = 0; b < numBlocks; b++) ec[b].push(cw[p++]);
  }
  if (p !== cw.length) throw new Error("qr_decode: de-interleaving consumed the wrong number of codewords");
  return { data, ec, blockLens, ecPerBlock };
}

/* ---------- byte-mode segment extraction ---------- */

function extractByteSegment(dataCodewords, version) {
  const bits = [];
  for (const byte of dataCodewords) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }
  let pos = 0;
  const readBits = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= bits.length) throw new Error("qr_decode: data ended inside the segment header");
      v = (v << 1) | bits[pos++];
    }
    return v;
  };
  const mode = readBits(4);
  if (mode !== 0b0100) {
    throw new Error(`qr_decode: expected byte mode (0100), got ${mode.toString(2).padStart(4, "0")}`);
  }
  const count = readBits(version <= 9 ? 8 : 16);
  if (pos + count * 8 > bits.length) {
    throw new Error("qr_decode: byte segment length exceeds the data capacity");
  }
  const bytes = new Uint8Array(count);
  for (let i = 0; i < count; i++) bytes[i] = readBits(8);
  // The remainder must be terminator (zero bits) and/or 0xEC/0x11 pad
  // bytes; the version's remainder bits (< 8) at the very end are ignored.
  while (pos + 4 <= bits.length && bits[pos] === 0 && bits[pos + 1] === 0 && bits[pos + 2] === 0 && bits[pos + 3] === 0) {
    pos += 4; // terminator nibbles
  }
  while (bits.length - pos >= 8) {
    let byte = 0;
    for (let i = 0; i < 8; i++) byte = (byte << 1) | bits[pos++];
    if (byte !== 0xEC && byte !== 0x11) {
      throw new Error(`qr_decode: unexpected trailing byte 0x${byte.toString(16)} after the byte segment`);
    }
  }
  return bytes;
}

/* ---------- the decoder entry point ---------- */

/**
 * Decode a QR matrix (plain square boolean[][] with NO quiet zone — exactly
 * what DTN.qrMakeMatrix returns) back to its byte-mode payload. Returns
 * { text, bytes, version, size, eccLevel, mask, corrected }. Throws on any
 * structural, BCH or Reed-Solomon failure.
 */
export function decodeQR(matrix) {
  if (!Array.isArray(matrix) || !matrix.length || !Array.isArray(matrix[0])) {
    throw new Error("qr_decode: a boolean[][] matrix is required");
  }
  const size = matrix.length;
  if (size % 4 !== 1 || size < 21) throw new Error(`qr_decode: impossible matrix size ${size}`);
  const version = (size - 17) / 4;
  if (version < 1 || version > 15) throw new Error(`qr_decode: version ${version} outside the supported 1..15`);

  if (version >= 7) {
    const vInfo = readVersionInfo(matrix, size);
    if (vInfo !== version) {
      throw new Error(`qr_decode: version info says ${vInfo}, the size says ${version}`);
    }
  }

  const fmt = readFormatInfo(matrix, size);
  if (ECC_LEVEL_NAMES[fmt.level] !== "M") {
    throw new Error(`qr_decode: expected ECC level M, got ${ECC_LEVEL_NAMES[fmt.level]}`);
  }
  const maskFn = MASKS[fmt.mask];
  if (!maskFn) throw new Error(`qr_decode: mask ${fmt.mask} out of range`);

  const funcMap = buildFunctionMap(size, version);
  const cw = readCodewords(matrix, size, version, maskFn, funcMap);
  const { data, ec, blockLens, ecPerBlock } = deinterleave(cw, version);

  let corrected = 0;
  const dataCodewords = [];
  for (let b = 0; b < data.length; b++) {
    const full = new Uint8Array(blockLens[b] + ecPerBlock);
    full.set(data[b], 0);
    full.set(ec[b], blockLens[b]);
    const res = rsVerifyAndCorrect(full, ecPerBlock);
    corrected += res.corrected;
    for (let i = 0; i < blockLens[b]; i++) dataCodewords.push(res.codeword[i]);
  }

  const bytes = extractByteSegment(dataCodewords, version);
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return { text, bytes, version, size, eccLevel: "M", mask: fmt.mask, corrected };
}

export default decodeQR;

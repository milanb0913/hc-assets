// Server-side image gate for the hc-assets repo (s182 build 6, brief B list). Runs in the GitHub Action `.github/workflows/verify-images.yml` of
// milanb0913/hc-assets on every push and pull request, and fails the run when an image-like file in the pushed range has no valid signed STAGE ATTESTATION.
// SELF-CONTAINED on purpose: only node built-ins, no import from HC-Capture, because the public CI runner has neither the repo nor any secret. It verifies
// with the Ed25519 PUBLIC key committed in the image repo (.hc-verify/pubkey.pem); the private key never leaves the trusted machine
// (~/.hc-capture-keys/verdict-signing.pem), so nothing secret is needed server-side.
//   node ci-verify.mjs --before <sha|0000..> --after <sha> --pubkey <pem> [--repo <dir>]
// A "verdict manifest" is the set of .hc-attest/*.json files in the repo: each one says, signed, "these exact bytes were staged under this exact path for this
// shot after the frame + panel + shot-binding gate" (qa/lib/stage-gate.mjs stageFile writes it). Hash -> path -> shot -> PASS is therefore committed with the image.
// The workflow runs THIS script and the public key from the commit BEFORE the push (never from the pushed head), so a push cannot swap in its own verifier or
// key. KNOWN LIMITS (also in qa/GUARDRAILS.md): (1) the workflow file itself runs from the pushed head, so a push that deletes or edits the workflow evades it
// until Milan enables branch protection that REQUIRES this check (queued in OPEN-THREADS "Ready to go live"); (2) it cannot re-run the frame/ring check (no sharp on
// the runner) and cannot see the local verdict store or later revocations. Build 8: it no longer trusts the attestation alone: it re-verifies the signed PASS record embedded in it
// and re-runs the render gate (format, single frame, alpha, eXIf orientation, colour-management/unknown chunks) on the pushed bytes; (3) the bootstrap push that
// first adds this script and key is verified with its own copy (nothing exists before it).
// Kept in step with qa/panel/phase1/panel-store.mjs needsPanel and qa/lib/verdict-sign.mjs canonical/attestationRel by test/test-ci-verify.mjs (property tests).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync as realExec } from 'node:child_process';

// ---- copies of the shared rules (equivalence is asserted by test/test-ci-verify.mjs over thousands of generated inputs)
const IMG_EXT = new Set(['png', 'apng', 'jpg', 'jpeg', 'jpe', 'jfif', 'gif', 'webp', 'svg', 'svgz', 'avif', 'avifs', 'bmp', 'dib', 'tif', 'tiff', 'ico', 'cur', 'heic', 'heif', 'jxl', 'jp2', 'psd', 'pdf']);
const TEXT_EXT = new Set(['md', 'txt', 'json', 'csv', 'yml', 'yaml', 'html', 'htm', 'css', 'js', 'mjs', 'gitignore', 'nojekyll', 'gitattributes', 'log', 'tsv', 'sh', 'toml']);
const MARKUP_EXT = new Set(['xml', 'xsl', 'xslt', 'xhtml', 'rdf', 'plist', 'kml', 'xaml']);
export function imageMagic(b) {
  if (!b || b.length < 4) return null;
  const at = (i, s) => b.length >= i + s.length && b.subarray(i, i + s.length).toString('latin1') === s;
  if (b[0] === 0x89 && at(1, 'PNG')) return 'png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpeg';
  if (at(0, 'GIF8')) return 'gif';
  if (at(0, 'RIFF') && at(8, 'WEBP')) return 'webp';
  if (at(0, 'BM') && b.length > 18 && b.readUInt32LE(6) === 0 && [12, 40, 52, 56, 64, 108, 124].includes(b.readUInt32LE(14))) return 'bmp';
  if ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2a && b[3] === 0) || (b[0] === 0x4d && b[1] === 0x4d && b[2] === 0 && b[3] === 0x2a)) return 'tiff';
  if (b[0] === 0 && b[1] === 0 && (b[2] === 1 || b[2] === 2) && b[3] === 0) return 'ico';
  if (at(4, 'ftyp') && /avif|avis|heic|heix|mif1|msf1|hevc|heif/.test(b.subarray(8, 16).toString('latin1'))) return 'avif/heic';
  if (b[0] === 0xff && b[1] === 0x0a) return 'jxl';
  if (at(0, '\0\0\0\x0cJXL ')) return 'jxl';
  if (at(0, '%PDF')) return 'pdf';
  return null;
}
const looksBinary = (b) => b.includes(0) || (() => { try { new TextDecoder('utf-8', { fatal: true }).decode(b); return false; } catch { return true; } })();
const SVG_EL = /<\s*(?:[A-Za-z_][\w.-]*:)?svg(?=[\s/>])/i; const SVG_NS = /www\.w3\.org\/2000\/svg/i; const DATA_IMG = /data\s*:\s*image\s*\//i;
export function hasSvg(b) { const t = b.toString('latin1').replace(/\0/g, ''); return SVG_EL.test(t) || SVG_NS.test(t) || DATA_IMG.test(t); }
export function needsPanel(p, buf) {
  const ext = (path.extname(p).slice(1) || '').toLowerCase();
  if (IMG_EXT.has(ext) || MARKUP_EXT.has(ext)) return true;
  if (!buf || !buf.length) return false;
  if (imageMagic(buf)) return true;
  if (hasSvg(buf)) return true;
  if (/^\s*<\?xml/i.test(buf.subarray(0, 64).toString('latin1').replace(/\0/g, ''))) return true;
  if (TEXT_EXT.has(ext) && !looksBinary(buf)) return false;
  return looksBinary(buf);
}
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
export const attestationRel = (file, sha256) => `.hc-attest/${sha256}.${crypto.createHash('sha256').update(String(file).replace(/\\/g, '/')).digest('hex').slice(0, 10)}.json`;
export const stemOfPath = (file) => String(file).replace(/\\/g, '/').split('/').pop().replace(/^PROD_/, '').replace(/\.(png|gif|apng|webp|jpe?g)$/i, '').replace(/_boxed$/, '');
export function pathBindsShot(file, shot, sharedAs = null) {
  if (typeof shot !== 'string' || !shot) return false;
  const stem = stemOfPath(file);
  if (stem === shot || stem.endsWith('_' + shot)) return true;
  return !!sharedAs && typeof sharedAs === 'string' && stem.endsWith('_SHARED_' + sharedAs);
}
// attestations are recognised by CONTENT (s182 build 7): anything under .hc-attest/ must be a valid signed attestation at its canonical path; an
// attestation-shaped name elsewhere gets no special treatment, and an image hidden under an attestation name fails (it is not a valid attestation).
const inAttestDir = (p) => /^\.hc-attest\//i.test(String(p).replace(/\\/g, '/'));
// s182 build 8 (red-team 7 items 2 and 3): the attestation (v3) carries the SIGNED six-role PASS record (or a frozen flag) it was minted from, and this verifier
// RE-CHECKS it from signed data (valid Ed25519 PASS for these bytes naming a shot in the signed list) AND re-runs the deterministic render gate on the bytes
// themselves (below), instead of trusting that an attestation exists. A signer that was fed a caller-supplied "gate passed" result has no real PASS to embed.
const PASS_ROLES = ['gatekeeper', 'edge-inspector', 'annotation-auditor', 'consistency-auditor', 'subject-state-verifier', 'chair'];
export function validPassRecord(r, pub) {
  if (!r || typeof r !== 'object' || r.overall !== 'PASS' || !/^[0-9a-f]{64}$/.test(r.sha256 || '') || typeof r.at !== 'string' || Number.isNaN(Date.parse(r.at)) || typeof r.shot !== 'string' || !r.shot
    || r.canaryCaught !== true || !r.reviewers || !PASS_ROLES.every((x) => /^PASS(?![A-Za-z])/.test(String(r.reviewers[x] ?? '')))) return false;
  const { sig, ...rest } = r; if (typeof sig !== 'string' || !sig || !pub) return false;
  try { return crypto.verify(null, Buffer.from(canonical(rest)), pub, Buffer.from(sig, 'base64')); } catch { return false; }
}
export const frozenStemOf = (file) => String(file).replace(/\\/g, '/').split('/').pop().replace(/^PROD_/, '').replace(/\.(png|gif)$/i, '');
export function attestationShape(a) {
  return !!a && typeof a === 'object' && a.kind === 'stage' && a.v === 3 && /^[0-9a-f]{64}$/.test(a.sha256 || '') && typeof a.file === 'string' && typeof a.shot === 'string' && !!a.shot
    && Array.isArray(a.shots) && a.shots.length > 0 && a.shots.every((x) => typeof x === 'string' && x) && a.shots.includes(a.shot) && (a.sharedAs === null || typeof a.sharedAs === 'string')
    && (a.pass === null || (typeof a.pass === 'object' && !Array.isArray(a.pass))) && typeof a.frozen === 'boolean' && (a.pass !== null) !== (a.frozen === true);
}
export function verifyAttestation(a, { file, sha256, frozenHas } = {}, pub) {
  if (!attestationShape(a)) return false;
  if (file !== undefined && a.file !== String(file).replace(/\\/g, '/')) return false;
  if (sha256 !== undefined && a.sha256 !== sha256) return false;
  if (typeof a.sig !== 'string' || !a.sig || !pub) return false;
  if (!pathBindsShot(a.file, a.shot, a.sharedAs)) return false;
  if (a.pass !== null) { if (!validPassRecord(a.pass, pub) || a.pass.sha256 !== a.sha256 || !a.shots.includes(a.pass.shot)) return false; }
  else if (typeof frozenHas !== 'function' || !frozenHas(frozenStemOf(a.file), a.sha256)) return false;
  const { sig, ...rest } = a;
  try { return crypto.verify(null, Buffer.from(canonical(rest)), pub, Buffer.from(sig, 'base64')); } catch { return false; }
}
export function validAttestationFile(p, buf, pub, frozenHas) {
  let a; try { a = JSON.parse(buf.toString('utf8')); } catch { return null; }
  if (!a || typeof a.file !== 'string' || typeof a.sha256 !== 'string') return null;
  return p === attestationRel(a.file, a.sha256) && verifyAttestation(a, { file: a.file, sha256: a.sha256, frozenHas }, pub) ? a : null;
}

// ---- BEGIN render-gate (generated copy of qa/lib/render-gate.mjs by sync-ci-verify.mjs; test-ci-verify asserts it is identical)
// Render gate (s182 build 8, red-team 7 item 3): judge the pixels a READER's browser would show, not what one decoder returns.
// Red-team 7 broke frameGate two ways with the real applyFrame output: (a) alpha=0 over the whole content area (RGB untouched; a browser composites it
// onto white, so the reader sees a blank card), (b) a PNG eXIf chunk with Orientation=6 (Chromium rotates the image; sharp ignores it).
// Class: "a decoder differential" - the gate decoded with one pipeline and the reader uses another. Fix: this module decodes the PNG to pixels itself
// (zlib + PNG unfiltering, the same steps a browser performs) and REFUSES anything whose rendering could differ from its raw RGB:
//   - not a PNG at all (GIF/WebP/JPEG/SVG/...: only a single-frame, non-interlaced 8/16-bit PNG is shippable);
//   - any alpha < max (colour types 4 and 6 are decoded and every alpha sample checked; tRNS refused unless every entry is opaque);
//   - eXIf with an Orientation tag other than 1 (an unparseable eXIf is refused too), and any chunk that changes rendering: iCCP, gAMA, cHRM, cICP, mDCV,
//     cLLI, acTL/fcTL/fdAT (animation), sPLT/hIST are harmless but unknown chunks are refused (allowlist; fail closed);
//   - chunk CRC mismatch, bytes after IEND, a missing IEND, a size over the pixel budget, interlace (Adam7).
// SELF-CONTAINED (node:zlib only) on purpose: ci-verify.mjs in the public hc-assets repo carries a copy of this file's logic (test/test-ci-verify.mjs asserts
// the two give the same verdict over a generated corpus), so the server-side check re-runs this on the bytes instead of trusting an attestation.
import zlib from 'node:zlib';

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
// Chunks that cannot change how the pixels render. Everything else is refused.
const ALLOWED = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'tEXt', 'zTXt', 'iTXt', 'pHYs', 'tIME', 'sBIT', 'sRGB', 'bKGD', 'eXIf']);
const MAX_PIXELS = 40_000_000;
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

/** Orientation from an eXIf payload (TIFF structure), or { ok:false } when it cannot be parsed. Returns orientation 1 when the tag is absent. */
export function exifOrientation(p) {
  if (p.length < 8) return { ok: false, why: 'eXIf too short' };
  const le = p[0] === 0x49 && p[1] === 0x49, be = p[0] === 0x4d && p[1] === 0x4d; if (!le && !be) return { ok: false, why: 'eXIf is not TIFF' };
  const u16 = (o) => (le ? p.readUInt16LE(o) : p.readUInt16BE(o)); const u32 = (o) => (le ? p.readUInt32LE(o) : p.readUInt32BE(o));
  if (u16(2) !== 42) return { ok: false, why: 'eXIf has a bad TIFF magic' };
  let off = u32(4); let orientation = 1; const seen = new Set();
  while (off && !seen.has(off)) {                       // every IFD in the chain: the tag may sit in IFD1 or later
    seen.add(off); if (off + 2 > p.length) return { ok: false, why: 'eXIf IFD out of range' };
    const cnt = u16(off); if (off + 2 + cnt * 12 + 4 > p.length) return { ok: false, why: 'eXIf IFD truncated' };
    for (let i = 0; i < cnt; i++) { const e = off + 2 + i * 12; if (u16(e) === 0x0112) { if (u16(e + 2) !== 3 || u32(e + 4) < 1) return { ok: false, why: 'eXIf Orientation has a bad type' }; orientation = u16(e + 8); } }
    off = u32(off + 2 + cnt * 12);
    if (seen.size > 8) return { ok: false, why: 'eXIf IFD chain too long' };
  }
  return { ok: true, orientation };
}

/** @returns {{ok:boolean, reason:string, info?:object}} ok=false means a reader's browser could show something other than the raw RGB, or it is not a plain PNG. */
export function renderGate(buf) {
  const no = (reason) => ({ ok: false, reason });
  if (!Buffer.isBuffer(buf)) return no('render gate needs the file bytes');
  if (buf.length < 8 || !buf.subarray(0, 8).equals(SIG)) return no('not a PNG: only a plain single-frame PNG is shippable (fail closed)');
  let o = 8, ihdr = null, plte = null, trns = null, sawIend = false, seenIdat = false, prevType = 'IHDR?'; const idat = []; let first = true;
  while (o < buf.length) {
    if (sawIend) return no('bytes after IEND (a second image or hidden data)');
    if (o + 12 > buf.length) return no('truncated PNG chunk header');
    const len = buf.readUInt32BE(o); const type = buf.subarray(o + 4, o + 8).toString('latin1');
    if (!/^[A-Za-z]{4}$/.test(type)) return no('PNG chunk with an invalid type');
    if (len > 0x7fffffff || o + 12 + len > buf.length) return no(`truncated PNG chunk ${type}`);
    const data = buf.subarray(o + 8, o + 8 + len); const crc = buf.readUInt32BE(o + 8 + len);
    if (crc32(buf.subarray(o + 4, o + 8 + len)) !== crc) return no(`PNG chunk ${type} has a bad CRC (corrupt or hand-edited)`);
    if (first && type !== 'IHDR') return no('PNG does not start with IHDR'); first = false;
    if (!ALLOWED.has(type)) return no(`PNG chunk ${type} is not on the allowlist (animation, colour-management or unknown chunks can change what a reader sees)`);
    if (type === 'IHDR') { if (ihdr || len !== 13) return no('bad IHDR'); ihdr = { w: data.readUInt32BE(0), h: data.readUInt32BE(4), depth: data[8], ct: data[9], comp: data[10], filt: data[11], inter: data[12] }; }
    else if (type === 'PLTE') { if (plte || seenIdat) return no('PLTE out of place'); plte = data; }
    else if (type === 'tRNS') { if (seenIdat || trns) return no('tRNS out of place'); trns = data; }
    else if (type === 'IDAT') { if (prevType !== 'IDAT' && seenIdat) return no('IDAT chunks are not contiguous'); seenIdat = true; idat.push(data); }
    else if (type === 'eXIf') { const r = exifOrientation(data); if (!r.ok) return no(`eXIf could not be parsed (${r.why}); refusing (fail closed)`); if (r.orientation !== 1) return no(`eXIf Orientation=${r.orientation}: a browser rotates/flips this image, so a reader would not see the pixels that were checked`); }
    else if (type === 'IEND') { if (len !== 0) return no('bad IEND'); sawIend = true; }
    prevType = type; o += 12 + len;
  }
  if (!sawIend) return no('PNG has no IEND (truncated)');
  if (!ihdr || !seenIdat) return no('PNG has no IHDR or no image data');
  if (!(ihdr.ct in CHANNELS) || ![1, 2, 4, 8, 16].includes(ihdr.depth) || ihdr.comp !== 0 || ihdr.filt !== 0) return no('unsupported PNG header');
  if (ihdr.inter !== 0) return no('interlaced (Adam7) PNG: re-export as a plain non-interlaced PNG (fail closed)');
  if (!ihdr.w || !ihdr.h || ihdr.w * ihdr.h > MAX_PIXELS) return no('PNG dimensions out of range');
  if (ihdr.ct === 3 && !plte) return no('palette PNG without PLTE');
  const info = { width: ihdr.w, height: ihdr.h, colorType: ihdr.ct, bitDepth: ihdr.depth };
  // tRNS = transparency for colour types 0/2/3 (type 4/6 forbid it): only an all-opaque palette is fine
  if (trns) { if (ihdr.ct !== 3) return no('tRNS transparency key (a browser makes matching pixels transparent)'); if (trns.some((v) => v !== 255)) return no('palette PNG with transparent entries'); }
  if (ihdr.ct !== 4 && ihdr.ct !== 6) return { ok: true, reason: 'plain opaque PNG', info };
  // decode: alpha must be fully opaque in EVERY pixel
  const bps = ihdr.depth / 8; const ch = CHANNELS[ihdr.ct]; const bpp = ch * bps; const stride = ihdr.w * bpp;
  let raw; try { raw = zlib.inflateSync(Buffer.concat(idat), { maxOutputLength: (stride + 1) * ihdr.h + 16 }); } catch (e) { return no(`image data does not inflate (${String(e.message).slice(0, 60)})`); }
  if (raw.length !== (stride + 1) * ihdr.h) return no('image data has the wrong length');
  let prev = Buffer.alloc(stride); const cur = Buffer.alloc(stride);
  const alphaOff = (ch - 1) * bps;
  for (let y = 0; y < ihdr.h; y++) {
    const ft = raw[y * (stride + 1)]; const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0; let v = line[i];
      if (ft === 0) { /* none */ } else if (ft === 1) v += a; else if (ft === 2) v += b; else if (ft === 3) v += (a + b) >> 1;
      else if (ft === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      else return no('PNG scanline with an invalid filter type');
      cur[i] = v & 255;
    }
    for (let x = 0; x < ihdr.w; x++) for (let k = 0; k < bps; k++) if (cur[x * bpp + alphaOff + k] !== 255) return no(`non-opaque pixel (alpha < max) at ${x},${y}: a browser composites it onto the page, so a reader would not see the checked RGB`);
    prev = Buffer.from(cur);
  }
  return { ok: true, reason: 'opaque PNG (alpha verified per pixel)', info };
}
// ---- END render-gate

// ---- git (every call ignores replace refs, like the local hook)
const gitEnv = () => { const e = { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' }; for (const k of ['GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE']) delete e[k]; return e; };
const run = (repo, args, opts = {}) => realExec('git', ['-C', repo, '--no-replace-objects', ...args], { maxBuffer: 1 << 28, env: gitEnv(), ...opts });
const ZERO = /^0+$/;

/**
 * Verify the pushed range. Returns { checked, bad: [{path, sha8, commit, why}], commits }. Throws on anything it cannot read (the caller exits 1: fail closed).
 * `before` all zeros (a new branch) checks every commit of `after` that is not reachable from `baseRef` when given, else the whole history.
 */
export function verifyRange({ repo = '.', before, after, pub, baseRef = null, frozen = new Set() }) {
  const frozenHas = (stem, sha) => frozen.has(`${stem}|${sha}`);
  const out = (...a) => run(repo, a, { encoding: 'utf8' }).trim();
  const rep = out('for-each-ref', '--format=%(refname)', 'refs/replace/'); if (rep) throw new Error('refs/replace/* exists; refusing (fail closed)');
  const peeled = out('rev-parse', '--verify', `${after}^{commit}`);
  const isNew = !before || ZERO.test(before);
  let notArgs = [];
  if (!isNew) { run(repo, ['cat-file', '-e', `${before}^{commit}`]); notArgs = ['--not', before]; }
  else if (baseRef) { try { run(repo, ['cat-file', '-e', `${baseRef}^{commit}`]); notArgs = ['--not', baseRef]; } catch { /* whole history */ } }
  const commits = out('rev-list', peeled, ...notArgs).split('\n').filter(Boolean);
  const seen = new Map(); const structural = [];
  const add = (p, blob, commit) => { const k = `${p}\0${blob}`; if (!seen.has(k)) seen.set(k, { path: p, blob, commit }); };
  const objs = out('rev-list', '--objects', peeled, ...notArgs).split('\n').filter(Boolean);
  const oids = objs.map((l) => (l.indexOf(' ') < 0 ? l : l.slice(0, l.indexOf(' '))));
  const types = oids.length ? run(repo, ['cat-file', '--batch-check=%(objecttype)'], { input: oids.join('\n') + '\n', encoding: 'utf8' }).split('\n').filter(Boolean) : [];
  if (types.length !== oids.length) throw new Error('cannot type every pushed object');
  objs.forEach((l, i) => { if (types[i] === 'blob') { const sp = l.indexOf(' '); add(sp < 0 ? `(unnamed blob ${oids[i].slice(0, 8)})` : l.slice(sp + 1), oids[i], peeled); } });
  for (const c of commits) {
    const toks = run(repo, ['diff-tree', '-m', '-r', '--root', '--raw', '-z', '--no-abbrev', '--no-renames', '--no-commit-id', c], { encoding: 'utf8' }).split('\0').filter(Boolean);
    for (let i = 0; i + 1 < toks.length; i += 2) {
      const m = /^:(\d+) (\d+) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])/.exec(toks[i]); if (!m) throw new Error(`cannot parse diff-tree output for ${c.slice(0, 8)}`);
      const [, sm, dm, , db, st] = m; const p = toks[i + 1]; if (st === 'D') continue;
      if (sm === '160000' || dm === '160000') structural.push({ path: p, commit: c, why: 'gitlink (mode 160000) not allowed' });
      else if (sm === '120000' || dm === '120000') structural.push({ path: p, commit: c, why: 'symlink (mode 120000) not allowed' });
      else if (st === 'T') structural.push({ path: p, commit: c, why: 'type change (T) not allowed' });
      else if (st === 'M' && sm !== dm) structural.push({ path: p, commit: c, why: `mode change ${sm} -> ${dm} not allowed` });
      if (dm !== '160000') add(p, db, c);
    }
  }
  const blob = (sha) => run(repo, ['cat-file', 'blob', sha]);
  const bad = structural.map((x) => ({ path: x.path, sha8: '--------', commit: x.commit.slice(0, 8), why: x.why }));
  const atts = new Map();
  for (const f of seen.values()) if (inAttestDir(f.path)) { const a = validAttestationFile(f.path, blob(f.blob), pub, frozenHas); if (a) atts.set(`${a.file}|${a.sha256}`, a); }
  const attOf = (p, sha) => {
    const a = atts.get(`${p}|${sha}`); if (a && verifyAttestation(a, { file: p, sha256: sha, frozenHas }, pub)) return a;
    try { const t = JSON.parse(run(repo, ['cat-file', 'blob', `${peeled}:${attestationRel(p, sha)}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })); return verifyAttestation(t, { file: p, sha256: sha, frozenHas }, pub) ? t : null; } catch { return null; }
  };
  let checked = 0;
  for (const f of seen.values()) {
    const buf = blob(f.blob);
    if (inAttestDir(f.path)) { if (!validAttestationFile(f.path, buf, pub, frozenHas)) { checked++; bad.push({ path: f.path, sha8: crypto.createHash('sha256').update(buf).digest('hex').slice(0, 8), commit: f.commit.slice(0, 8), why: 'a file under .hc-attest/ must be a valid signed stage attestation at its canonical path; this one is not (image bytes or garbage hidden under an attestation name)' }); } continue; }
    if (!needsPanel(f.path, buf)) continue;
    checked++; const sha = crypto.createHash('sha256').update(buf).digest('hex');
    // s182 build 8: re-run the deterministic render gate on the BYTES (alpha, eXIf orientation, animation, colour-management chunks, format): an attestation is never evidence about pixels
    const rg = renderGate(buf); if (!rg.ok) { bad.push({ path: f.path, sha8: sha.slice(0, 8), commit: f.commit.slice(0, 8), why: `render gate (re-run on the pushed bytes): ${rg.reason}` }); continue; }
    if (!attOf(f.path, sha)) bad.push({ path: f.path, sha8: sha.slice(0, 8), commit: f.commit.slice(0, 8), why: 'no valid signed stage attestation for this path and these exact bytes (stage through qa/lib/stage-gate.mjs stageFile)' });
  }
  return { checked, bad, commits: commits.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const a = process.argv.slice(2); const val = (k, d) => { const i = a.indexOf(k); return i > -1 ? a[i + 1] : d; };
  const fail = (m) => { console.error(`verify-images: FAIL: ${m}`); process.exit(1); };
  try {
    const pemFile = val('--pubkey', null); if (!pemFile || !fs.existsSync(pemFile)) fail('no public key file (--pubkey)');
    const pub = crypto.createPublicKey(fs.readFileSync(pemFile, 'utf8')); if (pub.asymmetricKeyType !== 'ed25519') fail('public key is not Ed25519');
    const fz = val('--frozen', null); let frozen = new Set(); if (fz) { try { const j = JSON.parse(fs.readFileSync(fz, 'utf8')); if (Array.isArray(j)) frozen = new Set(j.filter((x) => typeof x === 'string')); } catch { /* unreadable: nothing is frozen (fail closed) */ } }
    const r = verifyRange({ repo: val('--repo', '.'), before: val('--before', null), after: val('--after', null), pub, baseRef: val('--base-ref', null), frozen });
    if (r.bad.length) { console.error(`verify-images: ${r.bad.length} image-like file(s) in ${r.commits} pushed commit(s) have no valid signed stage attestation:`); for (const b of r.bad) console.error(`  ${b.path}  [${b.sha8}] in ${b.commit}  ${b.why}`); process.exit(1); }
    console.log(`verify-images: OK, ${r.checked} image-like file(s) in ${r.commits} pushed commit(s), all attested`);
  } catch (e) { fail(`cannot verify (${String(e.message).split('\n')[0]}); treating as failed`); }
}

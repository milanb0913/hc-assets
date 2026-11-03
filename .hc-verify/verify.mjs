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
// until Milan enables branch protection that REQUIRES this check (queued in OPEN-THREADS "Ready to go live"); (2) it cannot re-run the frame check (no sharp on
// the runner) and cannot see the local verdict store: it trusts the attestation, which is only signed after both passed locally; (3) the bootstrap push that
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
export function attestationShape(a) {
  return !!a && typeof a === 'object' && a.kind === 'stage' && a.v === 2 && /^[0-9a-f]{64}$/.test(a.sha256 || '') && typeof a.file === 'string' && typeof a.shot === 'string' && !!a.shot
    && Array.isArray(a.shots) && a.shots.length > 0 && a.shots.every((x) => typeof x === 'string' && x) && a.shots.includes(a.shot) && (a.sharedAs === null || typeof a.sharedAs === 'string');
}
export function verifyAttestation(a, { file, sha256 }, pub) {
  if (!attestationShape(a)) return false;
  if (a.file !== String(file).replace(/\\/g, '/') || a.sha256 !== sha256 || typeof a.sig !== 'string' || !a.sig || !pub) return false;
  if (!pathBindsShot(a.file, a.shot, a.sharedAs)) return false;
  const { sig, ...rest } = a;
  try { return crypto.verify(null, Buffer.from(canonical(rest)), pub, Buffer.from(sig, 'base64')); } catch { return false; }
}
export function validAttestationFile(p, buf, pub) {
  let a; try { a = JSON.parse(buf.toString('utf8')); } catch { return null; }
  if (!a || typeof a.file !== 'string' || typeof a.sha256 !== 'string') return null;
  return p === attestationRel(a.file, a.sha256) && verifyAttestation(a, { file: a.file, sha256: a.sha256 }, pub) ? a : null;
}

// ---- git (every call ignores replace refs, like the local hook)
const gitEnv = () => { const e = { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' }; for (const k of ['GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE']) delete e[k]; return e; };
const run = (repo, args, opts = {}) => realExec('git', ['-C', repo, '--no-replace-objects', ...args], { maxBuffer: 1 << 28, env: gitEnv(), ...opts });
const ZERO = /^0+$/;

/**
 * Verify the pushed range. Returns { checked, bad: [{path, sha8, commit, why}], commits }. Throws on anything it cannot read (the caller exits 1: fail closed).
 * `before` all zeros (a new branch) checks every commit of `after` that is not reachable from `baseRef` when given, else the whole history.
 */
export function verifyRange({ repo = '.', before, after, pub, baseRef = null }) {
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
  for (const f of seen.values()) if (inAttestDir(f.path)) { const a = validAttestationFile(f.path, blob(f.blob), pub); if (a) atts.set(`${a.file}|${a.sha256}`, a); }
  const attOf = (p, sha) => {
    const a = atts.get(`${p}|${sha}`); if (a && verifyAttestation(a, { file: p, sha256: sha }, pub)) return a;
    try { const t = JSON.parse(run(repo, ['cat-file', 'blob', `${peeled}:${attestationRel(p, sha)}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })); return verifyAttestation(t, { file: p, sha256: sha }, pub) ? t : null; } catch { return null; }
  };
  let checked = 0;
  for (const f of seen.values()) {
    const buf = blob(f.blob);
    if (inAttestDir(f.path)) { if (!validAttestationFile(f.path, buf, pub)) { checked++; bad.push({ path: f.path, sha8: crypto.createHash('sha256').update(buf).digest('hex').slice(0, 8), commit: f.commit.slice(0, 8), why: 'a file under .hc-attest/ must be a valid signed stage attestation at its canonical path; this one is not (image bytes or garbage hidden under an attestation name)' }); } continue; }
    if (!needsPanel(f.path, buf)) continue;
    checked++; const sha = crypto.createHash('sha256').update(buf).digest('hex');
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
    const r = verifyRange({ repo: val('--repo', '.'), before: val('--before', null), after: val('--after', null), pub, baseRef: val('--base-ref', null) });
    if (r.bad.length) { console.error(`verify-images: ${r.bad.length} image-like file(s) in ${r.commits} pushed commit(s) have no valid signed stage attestation:`); for (const b of r.bad) console.error(`  ${b.path}  [${b.sha8}] in ${b.commit}  ${b.why}`); process.exit(1); }
    console.log(`verify-images: OK, ${r.checked} image-like file(s) in ${r.commits} pushed commit(s), all attested`);
  } catch (e) { fail(`cannot verify (${String(e.message).split('\n')[0]}); treating as failed`); }
}

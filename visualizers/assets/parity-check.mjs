#!/usr/bin/env node
/**
 * Parity check: the JavaScript in `ecc.js` must produce exactly the same
 * answers as the Rust crate.
 *
 * The visualizers re-implement `FiniteField`, `EllipticCurve` and `Ecdsa` in
 * JavaScript so they can animate the operations. This script recomputes every
 * case the Rust examples dump and diffs the two, so the visualizer cannot
 * silently drift away from the crate.
 *
 *   cargo run --release --example parity_dump_ecc -p ecc
 *   cargo run --release --example parity_dump_ecdsa -p ecdsa
 *   node visualizers/assets/parity-check.mjs
 *
 * Add `--run-rust` to let the script run the two cargo commands itself.
 *
 * The Rust side panics on invalid input; the JavaScript mirrors that as a
 * "PANIC" marker, so both sides are compared panic-for-panic.
 */

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

globalThis.window = globalThis;
await import(pathToFileURL(join(repoRoot, 'visualizers/assets/ecc.js')).href);
const { ff, ec, ecdsa, schnorr, mod, modPow } = globalThis.ECC;

const runRust = process.argv.includes('--run-rust');

if (runRust) {
  for (const pkg of ['ecc', 'ecdsa']) {
    console.log(`running cargo example for ${pkg} …`);
    execFileSync('cargo', ['run', '--release', '--example', 'parity_dump_' + pkg, '-p', pkg], {
      cwd: repoRoot,
      stdio: 'inherit',
    });
  }
}

const B = (n) => BigInt(n);

/* ── the JavaScript side ──────────────────────────────────────────────── */

const js = [];

for (const p of [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]) {
  for (let a = 0; a < p; a += 1) {
    for (let d = 0; d < p; d += 1) {
      const pa = B(a); const pd = B(d); const pp = B(p);
      js.push(`ff ${p} ${a} ${d} add ${ff.add(pa, pd, pp)} sub ${ff.sub(pa, pd, pp)} mul ${ff.mul(pa, pd, pp)} invadd ${ff.inverseAdd(pa, pp)} invmul ${ff.inverseMul(pa, pp)} div ${ff.div(pa, pd, pp)}`);
    }
  }
}

const curves = [[17, 2, 2], [11, 2, 2], [23, 1, 1], [31, 5, 7], [17, 3, 0]];
for (const [p, a, b] of curves) {
  const curve = { p: B(p), a: B(a), b: B(b) };
  const show = (q) => (q === null ? 'O' : (q === 'PANIC' ? 'PANIC' : `${q.x},${q.y}`));
  const safe = (fn) => { try { return fn(); } catch (e) { return 'PANIC'; } };

  for (let x = 0; x < p; x += 1) {
    for (let y = 0; y < p; y += 1) {
      const q = { x: B(x), y: B(y) };
      const on = ec.onCurve(curve, q);
      const doubled = show(safe(() => ec.double(curve, q)));
      js.push(`curve ${p} ${a} ${b} on ${on} double ${doubled}`);
    }
  }
  if (p <= 17) {
    for (let x1 = 0; x1 < p; x1 += 1) {
      for (let y1 = 0; y1 < p; y1 += 1) {
        for (let x2 = 0; x2 < p; x2 += 1) {
          for (let y2 = 0; y2 < p; y2 += 1) {
            const res = show(safe(() => ec.add(curve, { x: B(x1), y: B(y1) }, { x: B(x2), y: B(y2) })));
            js.push(`add ${p} ${a} ${b} ${x1} ${y1} ${x2} ${y2} ${res}`);
          }
        }
      }
    }
  } else {
    for (let x1 = 0; x1 < p; x1 += 1) {
      for (let y1 = 0; y1 < p; y1 += 1) {
        for (let x2 = 0; x2 < p; x2 += 1) {
          const y2 = (x2 * 7 + y1) % p;
          const res = show(safe(() => ec.add(curve, { x: B(x1), y: B(y1) }, { x: B(x2), y: B(y2) })));
          js.push(`add ${p} ${a} ${b} ${x1} ${y1} ${x2} ${y2} ${res}`);
        }
      }
    }
  }
  for (let k = 0; k < 40; k += 1) {
    for (let x = 0; x < p; x += 1) {
      for (let y = 0; y < p; y += 1) {
        const res = show(safe(() => ec.multiply(curve, B(k), { x: B(x), y: B(y) })));
        js.push(`mul ${p} ${a} ${b} ${k} ${x} ${y} ${res}`);
      }
    }
  }
}

{
  const c = ecdsa.smallCurve();
  const order = Number(c.order);
  for (let d = 1; d < order; d += 1) {
    for (let k = 1; k < order; k += 1) {
      for (const message of ['parity', 'Alice sends 1 BTC to Bob', '']) {
        const hash = ecdsa.generateHashLessThan(message, c.order);
        const pubKey = ecdsa.publicKey(c, B(d));
        const sig = ecdsa.sign(c, hash, B(d), B(k));
        // `Ecdsa::verify` calls `EllipticCurve::add`, which asserts that the
        // two points differ. On the teaching curve u1·G and u2·Q sometimes
        // coincide, so verification can panic — the crate does not guard
        // against it. Both sides record "PANIC".
        const check = (h) => {
          try {
            return String(ecdsa.verify(c, h, pubKey, [sig.r, sig.s]).valid);
          } catch (e) {
            return 'PANIC';
          }
        };
        const valid = check(hash);
        const tampered = check(ecdsa.generateHashLessThan('tampered', c.order));
        js.push(`ecdsa ${message.length} ${d} ${k} ${hash} ${sig.r} ${sig.s} ${valid} ${tampered}`);
      }
    }
  }
}

{
  // BIP-340 Schnorr, on the teaching curve and on secp256k1.
  const messages = ['', 'a', 'Alice sends 1 BTC to Bob'];

  for (const [name, params] of [['teaching', schnorr.teaching], ['secp256k1', schnorr.secp256k1]]) {
    const keys = name === 'teaching' ? Array.from({ length: 18 }, (_, i) => i + 1) : [1, 2, 3, 7, 42, 12345];

    for (const d of keys) {
      const secretKey = B(d);
      let publicKey;
      try {
        publicKey = schnorr.publicKey(params, secretKey);
      } catch (e) {
        js.push(`schnorr ${name} ${d} pk PANIC`);
        continue;
      }
      js.push(`schnorr ${name} ${d} pk ${publicKey}`);

      messages.forEach((message, mi) => {
        let signature;
        try {
          signature = schnorr.sign(params, secretKey, message, null);
        } catch (e) {
          js.push(`schnorr ${name} ${d} ${mi} sig PANIC`);
          return;
        }
        js.push(`schnorr ${name} ${d} ${mi} sig ${signature.r} ${signature.s}`);

        const valid = schnorr.verify(params, publicKey, message, signature);
        const tampered = schnorr.verify(params, publicKey, 'different', signature);
        const broken = { r: mod(signature.r + 1n, params.order), s: signature.s };
        const brokenValid = schnorr.verify(params, publicKey, message, broken);
        js.push(`schnorr ${name} ${d} ${mi} ver ${valid} ${tampered} ${brokenValid}`);
      });
    }
  }
}

/* ── diff ─────────────────────────────────────────────────────────────── */

function compare(label, rustPath, jsLines) {
  if (!existsSync(rustPath)) {
    console.error(`\n✗ ${label}: dump not found at ${rustPath}`);
    console.error(`  run: cargo run --release --example parity_dump_${label} -p ${label}`);
    return 1;
  }
  const rust = readFileSync(rustPath, 'utf8').replace(/\n$/, '').split('\n');
  let mismatches = 0;
  const max = Math.max(rust.length, jsLines.length);
  for (let i = 0; i < max; i += 1) {
    if (rust[i] !== jsLines[i]) {
      mismatches += 1;
      if (mismatches <= 15) {
        console.log(`  MISMATCH line ${i + 1}\n    rust: ${rust[i]}\n    js:   ${jsLines[i]}`);
      }
    }
  }
  const status = mismatches === 0 ? '✓' : '✗';
  console.log(`${status} ${label}: ${rust.length} cases, ${mismatches} mismatches`);
  return mismatches;
}

let failures = 0;

// The three dumps are separate files, so split the JS lines the same way.
const eccJs = js.filter((l) => !l.startsWith('ecdsa ') && !l.startsWith('schnorr '));
const ecdsaJs = js.filter((l) => l.startsWith('ecdsa '));
const schnorrJs = js.filter((l) => l.startsWith('schnorr '));

failures += compare('ecc', join(repoRoot, 'target', 'parity-dump-ecc.txt'), eccJs);
failures += compare('ecdsa', join(repoRoot, 'target', 'parity-dump-ecdsa.txt'), ecdsaJs);
failures += compare('schnorr', join(repoRoot, 'target', 'parity-dump-schnorr.txt'), schnorrJs);

console.log(failures === 0 ? '\nALL OK — the visualizer matches the crate.' : `\n${failures} MISMATCHES`);
process.exit(failures === 0 ? 0 : 1);

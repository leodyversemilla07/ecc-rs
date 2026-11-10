#!/usr/bin/env node
/**
 * Regenerates `assets/rust-source.js` from the Rust sources in this repository.
 *
 * The visualizer pages show the real code next to the animation, so they must
 * never drift away from the crate. Run this after changing any `.rs` file:
 *
 *     node visualizers/assets/sync-rs-source.mjs
 *
 * The generated file is committed, so a plain `git clone` + open-in-browser
 * works without running Node.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

/**
 * Each entry lists the file to snapshot and the symbols we want to be able to
 * highlight. The key is the symbol name used by the pages; the value is the
 * literal text that starts the item's signature.
 */
const TARGETS = [
  {
    file: 'ecc/src/point.rs',
    symbols: {
      Point: 'pub enum Point',
    },
  },
  {
    file: 'ecc/src/finite_field.rs',
    symbols: {
      add: 'pub fn add(',
      sub: 'pub fn sub(',
      mul: 'pub fn mul(',
      inverse_add: 'pub fn inverse_add(',
      inverse_mul: 'pub fn inverse_mul(',
      div: 'pub fn div(',
    },
  },
  {
    file: 'ecc/src/elliptic_curve.rs',
    symbols: {
      on_curve: 'pub fn on_curve(',
      add: 'pub fn add(',
      double: 'pub fn double(',
      multiply: 'pub fn multiply(',
      compute_x3_y3: 'fn compute_x3_y3(',
    },
  },
  {
    file: 'ecdsa/src/lib.rs',
    symbols: {
      generate_key_pair: 'pub fn generate_key_pair(',
      generate_private_key: 'pub fn generate_private_key(',
      generate_public_key: 'pub fn generate_public_key(',
      sign: 'pub fn sign(',
      verify: 'pub fn verify(',
      generate_hash_less_than: 'pub fn generate_hash_less_than(',
      secp256k1: 'pub fn secp256k1(',
      small_curve: 'pub fn small_curve(',
    },
  },
  {
    file: 'schnorr/src/lib.rs',
    symbols: {
      public_key: 'pub fn public_key(',
      sign: 'pub fn sign(',
      sign_once: 'fn sign_once(',
      verify: 'pub fn verify(',
      lift_x: 'pub fn lift_x(',
      tagged_hash: 'pub fn tagged_hash(',
      has_even_y: 'pub fn has_even_y(',
    },
  },
];

/**
 * Finds the 1-based, inclusive line range of the item that starts with
 * `signature`, by counting braces from that line until they balance.
 */
function findRegion(lines, signature) {
  const start = lines.findIndex((line) => line.includes(signature));
  if (start === -1) return null;

  let depth = 0;
  let opened = false;
  for (let i = start; i < lines.length; i += 1) {
    for (const ch of lines[i]) {
      if (ch === '{') {
        depth += 1;
        opened = true;
      } else if (ch === '}') {
        depth -= 1;
      }
    }
    if (opened && depth === 0) return [start + 1, i + 1];
  }
  return null;
}

const out = {};
const missing = [];

for (const target of TARGETS) {
  const abs = join(repoRoot, target.file);
  const text = readFileSync(abs, 'utf8');
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();

  const regions = {};
  for (const [name, signature] of Object.entries(target.symbols)) {
    const region = findRegion(lines, signature);
    if (!region) {
      missing.push(`${target.file}: ${signature}`);
      continue;
    }
    regions[name] = region;
  }

  out[target.file] = {
    path: relative(repoRoot, abs).split('\\').join('/'),
    lines,
    regions,
  };
}

if (missing.length) {
  console.error('Could not locate these symbols:');
  for (const m of missing) console.error(`  - ${m}`);
  process.exit(1);
}

const body = `/* GENERATED FILE - do not edit by hand.
 * Run: node visualizers/assets/sync-rs-source.mjs
 * Source of truth: the Rust files in this repository.
 */
window.RS = ${JSON.stringify(out, null, 2)};
`;

const target = join(here, 'rust-source.js');
writeFileSync(target, body, 'utf8');
console.log(`Wrote ${relative(repoRoot, target)}`);
for (const [file, data] of Object.entries(out)) {
  console.log(`  ${file}: ${data.lines.length} lines, ${Object.keys(data.regions).length} symbols`);
}

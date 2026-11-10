#!/usr/bin/env node
/**
 * Publishes the visualizers to GitHub Pages.
 *
 * The site is served from the `gh-pages` branch, whose root is a copy of this
 * folder. GitHub Pages is configured (Settings → Pages) to build from that
 * branch with the `/` folder as the site root, so the hub page is served from
 * the root of the project site:
 *
 *     https://leodyversemilla07.github.io/ecc-rs/
 *
 * Run this after changing anything in `visualizers/`:
 *
 *     node visualizers/assets/publish.mjs
 *
 * It rebuilds the `gh-pages` branch from the current contents of this folder
 * and force-pushes it. The branch history is irrelevant — only its tree is
 * served — so it is rebuilt from scratch every time.
 */

import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const visualizers = join(here, '..');
const repoRoot = join(visualizers, '..');
const branch = 'gh-pages';

const git = (...args) => execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8' }).trim();

function fail(message) {
  console.error(`\n✗ ${message}\n`);
  process.exit(1);
}

if (git('rev-parse', '--abbrev-ref', 'HEAD') !== 'main') {
  fail('Run this from the main branch.');
}

// ── stage what the site should contain ──
// Everything in `visualizers/`, plus a `.nojekyll` at the root so GitHub Pages
// serves the files verbatim instead of running them through Jekyll.
//
// The copy lives outside the directories the build is about to replace, so
// the source is never destroyed by its own build.
const staging = join(repoRoot, 'target', 'pages-staging');
rmSync(staging, { recursive: true, force: true });
mkdirSync(staging, { recursive: true });

for (const entry of readdirSync(visualizers)) {
  if (entry === '.nojekyll') continue;
  const from = join(visualizers, entry);
  if (statSync(from).isDirectory()) cpSync(from, join(staging, entry), { recursive: true });
  else cpSync(from, join(staging, entry));
}
cpSync(join(visualizers, '.nojekyll'), join(staging, '.nojekyll'));

// ── rebuild the branch from scratch ──
git('checkout', '--orphan', 'pages-build');
git('rm', '-rq', '--cached', '.');

// Empty the worktree of everything the site should not contain.
for (const entry of readdirSync(repoRoot)) {
  if (entry === '.git' || entry === 'target') continue;
  rmSync(join(repoRoot, entry), { recursive: true, force: true });
}

// Copy the site in.
for (const entry of readdirSync(staging)) {
  const from = join(staging, entry);
  const to = join(repoRoot, entry);
  if (statSync(from).isDirectory()) cpSync(from, to, { recursive: true });
  else cpSync(from, to);
}

// Keep the build output out of the commit.
writeFileSync(join(repoRoot, '.gitignore'), '/target\n');

git('add', '-A');
git('commit', '-q', '-m', 'Publish the visualizers');
git('branch', '-f', branch, 'pages-build');
git('checkout', '--force', 'main');
git('branch', '-D', 'pages-build');
git('push', '--force', 'origin', branch);

rmSync(staging, { recursive: true, force: true });

console.log(`\n✓ Published ${branch} — https://leodyversemilla07.github.io/ecc-rs/\n`);

#!/usr/bin/env node
/**
 * Publishes the visualizers to GitHub Pages.
 *
 * The site is served from the repository's `gh-pages` branch, whose root is a
 * copy of this folder. GitHub Pages is configured (Settings → Pages) to build
 * from that branch with the `/` folder as the site root, so the hub page is
 * served from the root of the project site:
 *
 *     https://leodyversemilla07.github.io/ecc-rs/
 *
 * Run this after changing anything in `visualizers/`:
 *
 *     node visualizers/assets/publish.mjs
 *
 * The branch is built with git's plumbing commands against a temporary index,
 * so the working tree is never touched: uncommitted work, staged changes and
 * the current branch all stay exactly as they were.
 */

import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
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

// ── what the site should contain ──
// Everything in `visualizers/`, plus a `.nojekyll` at the root so GitHub Pages
// serves the files verbatim instead of running them through Jekyll.
const staging = join(repoRoot, 'target', 'pages-staging');
rmSync(staging, { recursive: true, force: true });
mkdirSync(staging, { recursive: true });

for (const entry of readdirSync(visualizers)) {
  const from = join(visualizers, entry);
  if (statSync(from).isDirectory()) cpSync(from, join(staging, entry), { recursive: true });
  else cpSync(from, join(staging, entry));
}
cpSync(join(visualizers, '.nojekyll'), join(staging, '.nojekyll'));

// ── build the branch without touching the working tree ──
const indexFile = join(repoRoot, 'target', 'pages-index');
rmSync(indexFile, { force: true });

const env = { ...process.env, GIT_INDEX_FILE: indexFile };
const gitDir = join(repoRoot, '.git');

execFileSync(
  'git',
  [`--git-dir=${gitDir}`, `--work-tree=${staging}`, 'add', '-A', '.'],
  { cwd: staging, env, encoding: 'utf8' },
);

const tree = execFileSync('git', ['write-tree'], { cwd: repoRoot, env, encoding: 'utf8' }).trim();

let parent;
try {
  parent = git('rev-parse', branch);
} catch {
  parent = undefined;
}

const commitArgs = ['commit-tree', tree, '-m', 'Publish the visualizers'];
if (parent) commitArgs.splice(2, 0, '-p', parent);

const commit = execFileSync('git', commitArgs, { cwd: repoRoot, encoding: 'utf8' }).trim();

git('update-ref', `refs/heads/${branch}`, commit);
git('push', '--force', 'origin', branch);

rmSync(indexFile, { force: true });
rmSync(staging, { recursive: true, force: true });

console.log(`\n✓ Published ${branch} — https://leodyversemilla07.github.io/ecc-rs/\n`);

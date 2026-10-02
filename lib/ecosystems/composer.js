/**
 * Attestium - PHP packages (Composer)
 *
 * Attester: every package directory under vendor/ (vendor/<vendor>/<name>)
 * is hashed, with git blob ids, and the files Composer generates (the
 * autoloader in vendor/composer and vendor/autoload.php, proxies in
 * vendor/bin) are listed.
 *
 * Verifier: composer.lock pins each package to a commit of its source
 * repository.  A commit names its tree, so the tree is the reference: an
 * install from the dist archive holds the tree minus export-ignored files,
 * an install from source the whole tree.  Either way every installed file
 * must be the file at the commit.
 *
 * The generated autoloader is PHP that runs first in every request; verify
 * it by reproducing the build (`composer install` in the build command,
 * with vendor/composer/** and vendor/autoload.php as build outputs).
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {walkTree} = require('../file-tree');
const {parallelMap, exists, setOwn} = require('../util');
const {GitTrees, exportIgnore} = require('../git-trees');
const {NoLockfileError, collect, scanIssues} = require('./common');

const LOCKFILES = ['composer.lock'];
const GENERATED = /^(?:autoload\.php|autoload_runtime\.php|composer\/.+|bin\/[^/]+)$/;

function detect(root) {
  return exists(path.join(root, 'composer.lock')) && exists(path.join(root, 'vendor', 'composer')) ? [path.join(root, 'vendor')] : [];
}

function installRoot(vendor) {
  return vendor;
}

async function scan(vendor) {
  vendor = path.resolve(vendor);
  const errors = [];
  // A source install keeps the package's .git directory; PHP never loads it.
  const walk = await walkTree(vendor, {exclude: (relative, isDirectory) => isDirectory && relative.split('/').length === 3 && relative.endsWith('/.git')});
  for (const walkError of walk.errors) {
    errors.push(walkError);
  }

  // Packages are the two-level directories that hold a composer.json, or
  // that installed.json names.
  const installedNames = new Set();
  try {
    const installed = JSON.parse(await fs.promises.readFile(path.join(vendor, 'composer', 'installed.json'), 'utf8'));
    for (const item of Array.isArray(installed) ? installed : installed.packages || []) {
      if (item && typeof item.name === 'string' && /^[\w.-]+\/[\w.-]+$/.test(item.name)) {
        installedNames.add(item.name);
      }
    }
  } catch {}

  const byPackage = new Map();
  const generated = {};
  const unaccounted = [];
  for (const entry of walk.entries) {
    const [vendorName, packageName] = entry.path.split('/');
    const name = `${vendorName}/${packageName}`;
    if (GENERATED.test(entry.path) && !installedNames.has(name)) {
      setOwn(generated, entry.path, entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256);
    } else if (entry.path.split('/').length >= 3) {
      if (!byPackage.has(name)) {
        byPackage.set(name, {files: [], blobs: []});
      }

      // Collected as entries: assigning a file named __proto__ to a plain
      // object would drop it.
      const relative = entry.path.split('/').slice(2).join('/');
      byPackage.get(name).files.push([relative, entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256]);
      byPackage.get(name).blobs.push([relative, entry.gitBlobId]);
    } else {
      unaccounted.push(entry.path);
    }
  }

  const packages = [];
  for (const [name, {files, blobs}] of [...byPackage].sort()) {
    let version = null;
    try {
      version = JSON.parse(await fs.promises.readFile(path.join(vendor, ...name.split('/'), 'composer.json'), 'utf8')).version || null;
    } catch {}

    packages.push({
      name, version, path: name, files: Object.fromEntries(files), meta: {blobs: Object.fromEntries(blobs)},
    });
  }

  return {
    packages, unaccounted: unaccounted.sort(), links: [], caches: [], errors, meta: {generated},
  };
}

function readLock(repoDir, options = {}) {
  const file = options.lockfile || 'composer.lock';
  if (!exists(path.join(repoDir, file))) {
    throw new NoLockfileError('No composer.lock found');
  }

  const lock = JSON.parse(fs.readFileSync(path.join(repoDir, file), 'utf8'));
  const packages = new Map();
  for (const item of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) {
    packages.set(item.name, {
      name: item.name, version: item.version, source: item.source || null, dist: item.dist || null,
    });
  }

  return {format: 'composer', file, packages};
}

/**
 * The repository and commit a locked package comes from.
 * @returns {{url: string, commit: string}|null}
 */
function sourceOf(locked) {
  const source = locked.source || {};
  if (source.type === 'git' && /^[\da-f]{40}$/.test(source.reference || '')) {
    return {url: String(source.url).replace(/\.git$/, ''), commit: source.reference};
  }

  const dist = locked.dist || {};
  const github = String(dist.url || '').match(/^https:\/\/api\.github\.com\/repos\/([\w.-]+)\/([\w.-]+)\/zipball\/([\da-f]{40})$/);
  if (github) {
    return {url: `https://github.com/${github[1]}/${github[2]}`, commit: github[3]};
  }

  return null;
}

/**
 * @param {Object} input
 * @param {Object} input.scan
 * @param {Object|null} input.lock
 * @param {Object} input.store - ReferenceStore (its cacheDir holds the clones)
 * @param {GitTrees} [input.gitTrees]
 * @param {(file: string) => boolean} [input.covered] - generated files another reference (a reproduced build) verifies, relative to vendor/
 * @returns {Promise<Object>}
 */
async function compare({scan: installed, lock, store, gitTrees, covered = () => false}) {
  const trees = gitTrees || new GitTrees({cacheDir: path.join(store.cacheDir || require('node:os').tmpdir(), 'composer-git')});
  const issues = [];
  const results = await parallelMap(installed.packages.map(item => async () => {
    const locked = lock ? lock.packages.get(item.name) : null;
    if (!locked) {
      return {status: 'failed', item, reason: lock ? 'installed package is not in composer.lock' : 'no composer.lock pins this package'};
    }

    const source = sourceOf(locked);
    if (!source) {
      return {status: 'unverifiable', item, reason: 'composer.lock pins no source commit for this package'};
    }

    let tree;
    let ignored;
    try {
      tree = await trees.tree(source.url, source.commit);
      const attributes = await trees.file(source.url, source.commit, '.gitattributes');
      ignored = exportIgnore(attributes && attributes.toString('utf8'));
    } catch (error) {
      return {status: 'error', item, reason: `could not read ${source.url} at ${source.commit.slice(0, 12)}: ${error.message}`};
    }

    const modified = [];
    const added = [];
    for (const [file, blob] of Object.entries(item.meta.blobs)) {
      const expected = tree.get(file);
      const isLink = String(item.files[file]).startsWith('symlink:');
      if (!expected) {
        added.push(file);
      } else if (expected.blob !== blob || (expected.mode === '120000') !== isLink) {
        modified.push(file);
      }
    }

    // A dist install leaves out export-ignored files; a source install has them all.
    const missing = [...tree.keys()].filter(file => !Object.hasOwn(item.meta.blobs, file) && !ignored(file));
    if (modified.length > 0 || added.length > 0 || missing.length > 0) {
      return {
        status: 'failed', item, reason: `files differ from ${source.url} at ${source.commit.slice(0, 12)}`, modified: modified.sort(), missing: missing.sort(), added: added.sort(),
      };
    }

    return {status: 'verified', item};
  }), store.concurrency);

  const generated = Object.keys(installed.meta.generated || {});
  const uncovered = generated.filter(file => !covered(file));
  if (uncovered.length > 0) {
    issues.push({severity: 'warn', message: 'Files Composer generates (the autoloader runs first in every request) are not compared; reproduce the build with vendor/composer/** and vendor/autoload.php as build outputs', items: uncovered.sort()});
  }

  if (installed.unaccounted.length > 0) {
    issues.push({severity: 'fail', message: 'Files in vendor/ that belong to no package', items: installed.unaccounted});
  }

  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

module.exports = {
  name: 'composer',
  label: 'Composer',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  sourceOf,
};

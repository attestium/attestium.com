/**
 * Attestium - JavaScript packages (npm, pnpm), in the common plugin shape
 *
 * The work is done by ../release-verification: node_modules is scanned in
 * npm's and pnpm's layouts, and each package compared with the registry
 * tarball (or GitHub archive) whose integrity the lockfile pins, with pnpm
 * patches applied and bundled dependencies matched to their bundling
 * package.  Each link in node_modules must point to the package the
 * lockfile resolves its name to (an npm: alias names another package).
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const ReleaseVerification = require('../release-verification');
const {exists} = require('../util');
const {NoLockfileError, scanIssues} = require('./common');

// In the order npm and pnpm read them: npm prefers npm-shrinkwrap.json
// (package-lock.json's format, published with a package) to package-lock.json.
const LOCKFILES = ['pnpm-lock.yaml', 'npm-shrinkwrap.json', 'package-lock.json'];

/**
 * Read a lockfile: the one named (relative to the root), or the first of
 * LOCKFILES in the root.
 *
 * @param {string} root
 * @param {string} [lockfile]
 * @returns {{file: string, format: string, lockfileVersion: *, packages: Object[]}}
 */
function readLockfile(root, lockfile) {
  for (const file of lockfile ? [lockfile] : LOCKFILES) {
    const full = path.join(root, file);
    if (exists(full)) {
      const format = path.basename(file) === 'pnpm-lock.yaml' ? 'pnpm' : 'npm';
      return {...ReleaseVerification.parseLockfile(fs.readFileSync(full, 'utf8'), format), file};
    }
  }

  throw new Error(lockfile ? `No lockfile at ${lockfile}` : `No ${LOCKFILES.join(', ')} found`);
}

function detect(root) {
  return exists(path.join(root, 'node_modules')) ? [path.join(root, 'node_modules')] : [];
}

function installRoot(directory) {
  return directory;
}

/**
 * @param {string} directory - node_modules
 * @param {Object} [options]
 * @param {string} [options.root] - the project (its lockfile chooses which packages need per-file hashes)
 * @returns {Promise<Object>}
 */
async function scan(directory, options = {}) {
  const root = options.root || path.dirname(directory);
  const rv = new ReleaseVerification({projectRoot: root});
  const policy = rv.readPackagePolicy(root);
  // The local lockfile only chooses which packages to send file hashes
  // for; the verifier compares with the lockfile at the public commit.
  let lock = {packages: []};
  try {
    lock = readLockfile(root);
  } catch {}

  const wanted = ReleaseVerification.filesNeeded(lock, policy);
  return rv.scanInstalledPackages(directory, {
    includeFiles: item => wanted.has(`${item.name}@${item.version}`) || wanted.has(item.name),
  });
}

/**
 * @param {string} repoDir
 * @param {Object} [options]
 * @param {string} [options.lockfile] - relative to the repository (a project in a subdirectory); its package.json is next to it
 * @returns {{file: string, format: string, lockfileVersion: *, packages: Object[], policy: Object}}
 */
function readLock(repoDir, options = {}) {
  let lock;
  try {
    lock = readLockfile(repoDir, options.lockfile);
  } catch (error) {
    throw new NoLockfileError(error.message);
  }

  const projectDir = path.dirname(path.join(repoDir, lock.file));
  return {...lock, policy: new ReleaseVerification({projectRoot: projectDir}).readPackagePolicy(projectDir)};
}

/**
 * @param {Object} input
 * @param {Object} input.scan
 * @param {Object|null} input.lock
 * @param {ReleaseVerification} input.release - configured with the registry and cache
 * @returns {Promise<Object>}
 */
async function compare({scan: installed, lock, release}) {
  const comparison = await release.comparePackages({
    installed: installed.packages,
    references: lock ? lock.packages : [],
    policy: lock ? lock.policy : undefined,
  });
  const issues = [];
  if (installed.links.length > 0) {
    issues.push({severity: 'fail', message: 'Links in node_modules do not resolve to an installed package', items: installed.links.map(link => `${link.path}: ${link.problem}`)});
  }

  // A link to another installed package (itself verified) would load it
  // under the link's name, so each must be the package the lockfile names.
  if (Array.isArray(installed.packageLinks)) {
    const retargeted = ReleaseVerification.retargetedLinks(installed.packageLinks, installed.packages, lock ? lock.links : undefined);
    if (retargeted.length > 0) {
      issues.push({severity: 'fail', message: 'Links in node_modules point to a package other than the one the lockfile names', items: retargeted});
    }
  } else {
    issues.push({severity: 'fail', message: 'The scan does not say where links in node_modules point (an older attester)', items: []});
  }

  const foreign = ReleaseVerification.foreignCacheFiles(installed.caches);
  if (foreign.length > 0) {
    issues.push({severity: 'fail', message: 'Files in Python bytecode cache directories that are not bytecode', items: foreign});
  }

  if (installed.caches.length > 0) {
    issues.push({severity: 'warn', message: 'Python bytecode caches in installed packages are not verified (written when a build tool ran Python; remove them to clear this)', items: installed.caches.map(cache => `${cache.path} (${cache.files.length})`)});
  }

  if (installed.unaccounted.length > 0) {
    issues.push({severity: 'warn', message: 'Files in node_modules that belong to no package', items: installed.unaccounted});
  }

  issues.push(...scanIssues(installed));

  return {...comparison, passed: comparison.passed && !issues.some(issue => issue.severity === 'fail'), issues};
}

module.exports = {
  name: 'npm',
  label: 'npm',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
};

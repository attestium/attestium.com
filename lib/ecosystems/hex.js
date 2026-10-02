/**
 * Attestium - Erlang and Elixir packages (Hex)
 *
 * Attester: Mix fetches dependency sources into deps/<name>.  Each is
 * hashed, with the metadata files Mix writes (.hex, .fetch).
 *
 * Verifier: mix.lock pins each package's outer checksum, the SHA-256 of the
 * tarball repo.hex.pm serves.  The tarball is downloaded, checked, and its
 * contents compared with deps/<name>.
 *
 * What runs is compiled from these sources (_build or a release); verify
 * that with a reproduced build of the commit.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {walkTree} = require('../file-tree');
const {readTar, readGzipTarFiles} = require('../tar');
const {sha256, parallelMap, exists} = require('../util');
const {
  NoLockfileError, compareFiles, collect, scanIssues, hashFiles,
} = require('./common');

const LOCKFILES = ['mix.lock'];
// Written by Mix next to a fetched package.
const MIX_FILES = new Set(['.hex', '.fetch']);

function detect(root) {
  return exists(path.join(root, 'mix.lock')) && exists(path.join(root, 'deps')) ? [path.join(root, 'deps')] : [];
}

function installRoot(deps) {
  return deps;
}

async function scan(deps) {
  deps = path.resolve(deps);
  const errors = [];
  const names = [];
  const unaccounted = [];
  try {
    for (const entry of await fs.promises.readdir(deps, {withFileTypes: true})) {
      // A dependency replaced by a link (or anything else that is neither a
      // directory nor a plain file) is not scanned, so it is listed.
      if (entry.isDirectory()) {
        names.push(entry.name);
      } else if (!entry.isFile()) {
        unaccounted.push(entry.name);
      }
    }
  } catch (error) {
    errors.push({path: '.', error: error.code});
  }

  names.sort();

  const packages = await parallelMap(names.map(name => async () => {
    const walk = await walkTree(path.join(deps, name), {exclude: (relative, isDirectory) => isDirectory && (relative === '_build' || relative === 'ebin')});
    for (const walkError of walk.errors) {
      errors.push({path: `${name}/${walkError.path}`, error: walkError.error});
    }

    let version = null;
    try {
      const metadata = await fs.promises.readFile(path.join(deps, name, 'hex_metadata.config'), 'utf8');
      version = (metadata.match(/{<<"version">>,\s*<<"([^"]+)">>}/) || [])[1] || null;
    } catch {}

    return {
      name, version, path: name, files: Object.fromEntries(walk.entries.map(entry => [entry.path, entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256])),
    };
  }), 8);
  return {
    packages, unaccounted: unaccounted.sort(), links: [], caches: [], errors, meta: {},
  };
}

/**
 * Parse mix.lock (an Elixir map literal).
 * @param {string} text
 * @returns {Map<string, {name: string, package: string, version: string, innerChecksum: string, outerChecksum: string|null, repo: string}>}
 */
function parseMixLock(text) {
  const packages = new Map();
  const pattern = /"([\w.-]+)":\s*{:hex,\s*:"?([\w.-]+)"?,\s*"([^"]+)",\s*"([\da-f]{64})",\s*\[[^\]]*],\s*\[.*?],\s*"([\w.-]+)"(?:,\s*"([\da-f]{64})")?}/g;
  for (const match of text.matchAll(pattern)) {
    packages.set(match[1], {
      name: match[1], package: match[2], version: match[3], innerChecksum: match[4], repo: match[5], outerChecksum: match[6] || null,
    });
  }

  for (const match of text.matchAll(/"([\w.-]+)":\s*{:(git|path),/g)) {
    packages.set(match[1], {name: match[1], source: match[2]});
  }

  return packages;
}

function readLock(repoDir, options = {}) {
  const file = options.lockfile || 'mix.lock';
  if (!exists(path.join(repoDir, file))) {
    throw new NoLockfileError('No mix.lock found');
  }

  return {format: 'mix', file, packages: parseMixLock(fs.readFileSync(path.join(repoDir, file), 'utf8'))};
}

/**
 * A Hex tarball's files as Mix unpacks them (contents plus hex_metadata.config).
 * @param {Buffer} buffer
 * @returns {Object<string, string>}
 */
function readHexTarball(buffer) {
  const members = new Map(readTar(buffer).map(entry => [entry.name, entry.data]));
  const contents = members.get('contents.tar.gz');
  const metadata = members.get('metadata.config');
  if (!contents || !metadata) {
    throw new Error('Not a Hex package tarball');
  }

  const files = hashFiles(readGzipTarFiles(contents));
  files['hex_metadata.config'] = sha256(metadata);
  return files;
}

async function compare({scan: installed, lock, store}) {
  const results = await parallelMap(installed.packages.map(item => async () => {
    const locked = lock ? lock.packages.get(item.name) : null;
    if (!locked) {
      return {status: 'failed', item, reason: lock ? 'dependency is not in mix.lock' : 'no mix.lock pins this dependency'};
    }

    if (locked.source) {
      return {status: 'unverifiable', item, reason: `fetched from ${locked.source}, not Hex`};
    }

    if (locked.repo !== 'hexpm') {
      return {status: 'unverifiable', item, reason: `from the Hex repository "${locked.repo}", not hexpm`};
    }

    if (!locked.outerChecksum) {
      return {status: 'unverifiable', item, reason: 'mix.lock has only the inner checksum (update it with a current Mix)'};
    }

    let expected;
    try {
      expected = await store.memo(`hex-tarball:v1:${locked.package}-${locked.version}:${locked.outerChecksum}`, async () => {
        const buffer = await store.get(`${store.urls.hex}/tarballs/${encodeURIComponent(locked.package)}-${encodeURIComponent(locked.version)}.tar`, {maxBytes: 256 * 1024 * 1024});
        if (sha256(buffer) !== locked.outerChecksum) {
          throw new Error(`Downloaded ${locked.package}-${locked.version}.tar does not match mix.lock`);
        }

        return readHexTarball(buffer);
      });
    } catch (error) {
      return {status: /does not match/.test(error.message) ? 'failed' : 'error', item, reason: error.message};
    }

    const comparison = compareFiles(item.files, expected, {allowExtra: file => MIX_FILES.has(file)});
    if (comparison.modified.length > 0 || comparison.missing.length > 0 || comparison.added.length > 0) {
      return {
        status: 'failed', item, reason: 'files differ from the Hex tarball', ...comparison,
      };
    }

    return {status: 'verified', item};
  }), store.concurrency);
  const issues = [{severity: 'info', message: 'Dependency sources are checked; the compiled code that runs (_build or a release) is checked by reproducing the build', items: []}];
  if ((installed.unaccounted || []).length > 0) {
    issues.push({severity: 'fail', message: 'Entries in deps/ that are links or special files, not dependency directories (not compared with anything)', items: installed.unaccounted});
  }

  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

module.exports = {
  name: 'hex',
  label: 'Hex',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  parseMixLock,
  readHexTarball,
};

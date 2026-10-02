/**
 * Attestium - release and supply-chain verification
 *
 * Three comparisons, each against a source the operator of the machine
 * does not control:
 *
 *   1. Node.js binary on disk vs. the binary inside the official release
 *      archive listed in nodejs.org's SHASUMS256.txt (optionally checked
 *      against the Node.js release signing keys with gpgv).
 *   2. Every installed npm package (npm or pnpm layout) vs. the files in the
 *      registry tarball whose SRI integrity is pinned by the lockfile (or,
 *      for global packages without a lockfile, by registry metadata).
 *   3. Bundled dependencies are matched against the bundling package's
 *      tarball, pnpm patches and install-script output are accounted for
 *      explicitly instead of being ignored.
 *
 * Collection (hashing what is installed) and appraisal (fetching the
 * references and comparing) are separate functions so a remote verifier
 * can appraise evidence collected on another machine.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const yaml = require('js-yaml');
const {httpGet, httpGetJson} = require('./http');
const {gpgStatusProblem} = require('./checksums');
const {readGzipTarFiles} = require('./tar');
const {walkTree, manifestDigest} = require('./file-tree');
const {
  sha256, parallelMap, exists, setOwn,
} = require('./util');

const PACKAGE_NAME = /^(?:@[\w.~-]+\/)?[\w.~-]+$/;
const PACKAGE_VERSION = /^[\w.+-]+$/;
const NODE_VERSION = /^v\d+\.\d+\.\d+$/;
const METADATA_FILES = new Set([
  '.modules.yaml',
  '.package-lock.json',
  '.yarn-integrity',
  '.pnpm-workspace-state.json',
  '.pnpm-workspace-state-v1.json',
  'lock.yaml',
]);

/**
 * @param {string} name
 * @returns {boolean}
 */
function isValidPackageName(name) {
  return typeof name === 'string' && name.length <= 214 && PACKAGE_NAME.test(name)
    && !name.split('/').some(part => part === '.' || part === '..');
}

/**
 * @param {string} version
 * @returns {boolean}
 */
function isValidPackageVersion(version) {
  return typeof version === 'string' && version.length <= 256 && PACKAGE_VERSION.test(version);
}

/**
 * Verify data against a Subresource Integrity string.  Uses the strongest
 * supported algorithm present; fails closed when none is supported.
 *
 * @param {Buffer} data
 * @param {string} integrity
 * @returns {boolean}
 */
function verifyIntegrity(data, integrity) {
  if (typeof integrity !== 'string') {
    return false;
  }

  const byAlgorithm = {};
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf('-');
    if (dash > 0) {
      const algorithm = token.slice(0, dash);
      (byAlgorithm[algorithm] ||= []).push(token.slice(dash + 1).split('?')[0]);
    }
  }

  for (const algorithm of ['sha512', 'sha384', 'sha256', 'sha1']) {
    if (byAlgorithm[algorithm]) {
      const actual = crypto.createHash(algorithm).update(data).digest('base64');
      return byAlgorithm[algorithm].includes(actual);
    }
  }

  return false;
}

/**
 * Map process.platform/arch to Node.js release naming.
 * @param {string} platform
 * @param {string} arch
 * @returns {{platform: string, arch: string}}
 */
function nodeReleaseTarget(platform, arch) {
  const platformMap = {
    linux: 'linux', darwin: 'darwin', win32: 'win', aix: 'aix',
  };
  const archMap = {arm: 'armv7l'};
  return {platform: platformMap[platform] || platform, arch: archMap[arch] || arch};
}

/**
 * Parse SHASUMS256.txt.
 * @param {string} text
 * @returns {Map<string, string>} filename -> sha256
 */
function parseShasums(text) {
  const entries = new Map();
  for (const line of text.split('\n')) {
    const match = line.trim().match(/^([\da-f]{64})\s+\*?(\S+)$/);
    if (match) {
      entries.set(match[2], match[1]);
    }
  }

  return entries;
}

/**
 * Parse a pnpm (v6/v9) or npm (v2/v3) lockfile into registry references.
 *
 * @param {string} text
 * @param {string} format - 'pnpm' | 'npm'
 * @returns {{format: string, lockfileVersion: *, packages: Object[]}}
 */
function parseLockfile(text, format) {
  if (format === 'pnpm') {
    const lock = yaml.load(text, {schema: yaml.FAILSAFE_SCHEMA}) || {};
    const lockfileVersion = String(lock.lockfileVersion || '');
    if (!/^[6-9]/.test(lockfileVersion)) {
      throw new Error(`Unsupported pnpm lockfileVersion: ${lockfileVersion || 'missing'}`);
    }

    const packages = [];
    for (const [key, entry] of Object.entries(lock.packages || {})) {
      const bare = key.replace(/^\//, '').replace(/\(.*$/, '');
      const at = bare.indexOf('@', 1);
      const name = (entry && entry.name) || (at > 0 ? bare.slice(0, at) : bare);
      const version = (entry && entry.version) || (at > 0 ? bare.slice(at + 1) : '');
      const resolution = (entry && entry.resolution) || {};
      packages.push(toReference({
        name,
        version,
        integrity: resolution.integrity,
        tarball: resolution.tarball || (resolution.type === 'git' && resolution.repo && resolution.commit ? `${resolution.repo}#${resolution.commit}` : undefined),
        type: resolution.type || (resolution.directory ? 'directory' : null),
      }));
    }

    return {
      format, lockfileVersion, packages, links: pnpmLinks(lock),
    };
  }

  if (format === 'npm') {
    const lock = JSON.parse(text);
    if (!lock.packages) {
      throw new Error(`Unsupported npm lockfileVersion: ${lock.lockfileVersion}`);
    }

    const packages = [];
    const links = {importer: {}, owners: {}, declared: {}};
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === '' || entry.link || entry.inBundle) {
        continue;
      }

      const linkName = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const name = entry.name || linkName;
      const target = {name, version: entry.version || null};
      declareLink(links.declared, linkName, target);
      if (key === `node_modules/${linkName}`) {
        declareLink(links.importer, linkName, target);
      }

      packages.push({
        ...toReference({
          name, version: entry.version, integrity: entry.integrity, tarball: entry.resolved,
        }),
        path: key,
      });
    }

    return {
      format, lockfileVersion: lock.lockfileVersion, packages, links,
    };
  }

  throw new Error(`Unsupported lockfile format: ${format}`);
}

/**
 * Add a package a link name may resolve to.
 * @param {Object<string, Array<{name: string, version: string|null}>>} map
 * @param {string} linkName
 * @param {{name: string, version: string|null}} target
 */
function declareLink(map, linkName, target) {
  const list = Object.hasOwn(map, linkName) ? map[linkName] : [];
  if (!list.some(item => item.name === target.name && item.version === target.version)) {
    list.push(target);
  }

  setOwn(map, linkName, list);
}

/**
 * The package a pnpm lockfile dependency entry resolves to: "1.2.3"
 * (the name linked), "bar@1.2.3" or "/bar@1.2.3" (an npm: alias), each
 * possibly followed by peer dependencies in parentheses; null for a
 * workspace link ("link:"), which points outside node_modules.
 *
 * @param {string} linkName
 * @param {*} value - a string, or {specifier, version} in importers
 * @returns {{name: string, version: string|null}|null}
 */
function pnpmDependency(linkName, value) {
  const text = String(value && typeof value === 'object' ? value.version : value).replace(/\(.*$/, '').replace(/^\//, '');
  if (text.startsWith('link:')) {
    return null;
  }

  if (/^\d/.test(text)) {
    return {name: linkName, version: text};
  }

  // A version that is a URL, a git source or a file: path names no version.
  const at = text.indexOf('@', 1);
  const name = at > 0 ? text.slice(0, at) : '';
  if (PACKAGE_NAME.test(name)) {
    const version = text.slice(at + 1);
    return {name, version: /^\d/.test(version) ? version : null};
  }

  return {name: linkName, version: null};
}

/**
 * What each package link in a pnpm install may point to, from the
 * lockfile: `importer` for the project's node_modules, `owners` for the
 * dependencies of each package (by name@version, merged over peer
 * variants), and `declared` for every declaration of a name.
 *
 * @param {Object} lock - the parsed pnpm-lock.yaml
 * @returns {{importer: Object, owners: Object, declared: Object}}
 */
function pnpmLinks(lock) {
  const links = {importer: {}, owners: {}, declared: {}};
  const fields = ['dependencies', 'devDependencies', 'optionalDependencies'];
  const add = (map, entry) => {
    for (const field of fields) {
      const dependencies = entry && entry[field];
      if (!dependencies || typeof dependencies !== 'object') {
        continue;
      }

      for (const [linkName, value] of Object.entries(dependencies)) {
        const target = pnpmDependency(linkName, value);
        if (target) {
          declareLink(map, linkName, target);
          declareLink(links.declared, linkName, target);
        }
      }
    }
  };

  // Lockfile v6 lists a single project's dependencies at the top level.
  const importers = lock.importers || {'.': lock};
  add(links.importer, importers['.']);
  for (const [key, entry] of Object.entries(importers)) {
    if (key !== '.') {
      add({}, entry);
    }
  }

  // Lockfile v9 keeps dependencies in snapshots, v6 in packages.
  for (const section of [lock.packages, lock.snapshots]) {
    for (const [key, entry] of Object.entries(section || {})) {
      const owner = key.replace(/^\//, '').replace(/\(.*$/, '');
      const map = Object.hasOwn(links.owners, owner) ? links.owners[owner] : {};
      add(map, entry);
      if (Object.keys(map).length > 0) {
        setOwn(links.owners, owner, map);
      }
    }
  }

  return links;
}

/**
 * Package links (node_modules/<name> pointing at an installed package)
 * that point to a package other than the one the lockfile resolves the
 * name to.  A link in the project's node_modules is resolved by the
 * lockfile's project (importer "."), one in .pnpm/<key>/node_modules by the
 * dependencies of the package installed there; a name declared nowhere
 * there (a hoisted link) may point to any package the lockfile declares
 * for that name, and a name the lockfile never declares only to a package
 * of that name.
 *
 * @param {Array<{path: string, target: string}>} packageLinks - from scanInstalledPackages()
 * @param {Object[]} packages - from scanInstalledPackages()
 * @param {{importer: Object, owners: Object, declared: Object}} [links] - from parseLockfile()
 * @returns {string[]} problems
 */
function retargetedLinks(packageLinks, packages, links = {}) {
  const byPath = new Map(packages.map(item => [item.path, item]));
  const lookup = (map, name) => (map && Object.hasOwn(map, name) ? map[name] : null);
  const problems = [];
  for (const link of packageLinks) {
    const target = byPath.get(link.target);
    const parts = link.path.split('/');
    const scoped = parts.length > 1 && parts.at(-2).startsWith('@');
    const linkName = parts.slice(scoped ? -2 : -1).join('/');
    const directory = parts.slice(0, scoped ? -2 : -1).join('/');
    let expected = null;
    if (directory === '') {
      expected = lookup(links.importer, linkName);
    } else {
      // In .pnpm/<key>/node_modules, the package pnpm installed there owns the link.
      const owner = packages.find(item => item.path.startsWith(`${directory}/`) && PNPM_STORE_PACKAGE.test(item.path) && inPnpmStoreDirectory(item));
      expected = owner ? lookup(lookup(links.owners, `${owner.name}@${owner.version}`), linkName) : null;
    }

    expected ||= lookup(links.declared, linkName) || [{name: linkName, version: null}];
    if (!target) {
      problems.push(`${link.path}: points to ${link.target}, which is not a scanned package`);
    } else if (!expected.some(item => item.name === target.name && (item.version === null || item.version === target.version))) {
      const wanted = expected.map(item => (item.version ? `${item.name}@${item.version}` : item.name)).join(' or ');
      problems.push(`${link.path}: points to ${target.name}@${target.version} (${link.target}), where the lockfile has ${wanted}`);
    }
  }

  return problems.sort();
}

// GitHub sources pinned to a full commit: pnpm's codeload tarballs and git
// resolutions, and npm's git URLs.
const GITHUB_COMMIT_SOURCES = [
  /^https:\/\/codeload\.github\.com\/([\w.-]+)\/([\w.-]+)\/tar\.gz\/([\da-f]{40})$/,
  /^(?:git\+)?(?:ssh:\/\/git@|https:\/\/)github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?#([\da-f]{40})$/,
];

/**
 * The GitHub repository and commit a lockfile source is pinned to.
 * @param {string} source
 * @returns {{owner: string, repo: string, commit: string}|null}
 */
function githubCommitOf(source) {
  for (const pattern of GITHUB_COMMIT_SOURCES) {
    const match = typeof source === 'string' && source.match(pattern);
    if (match && ![match[1], match[2]].some(part => /^\.+$/.test(part))) {
      return {owner: match[1], repo: match[2], commit: match[3]};
    }
  }

  return null;
}

/**
 * Packages whose individual file hashes a comparison needs: patched and
 * built packages, and packages packed from a GitHub archive.
 *
 * @param {{packages: Object[]}} lock
 * @param {{patched: Object, built: string[]}} policy
 * @returns {Set<string>} names and name@version specs
 */
function filesNeeded(lock, policy) {
  const specs = new Set([...Object.keys(policy.patched), ...policy.built]);
  for (const reference of lock.packages) {
    if (reference.source === 'github') {
      specs.add(`${reference.name}@${reference.version}`);
    }
  }

  return specs;
}

/**
 * @returns {Object} normalized lockfile reference
 */
function toReference({name, version, integrity, tarball, type}) {
  const reference = {
    name, version, integrity: integrity || null, tarball: tarball || null,
  };
  const github = integrity ? null : githubCommitOf(tarball);
  if (github && (!type || type === 'git')) {
    // A commit names its content, so the archive GitHub generates for it
    // is the reference (the same trust as the repository itself).
    reference.source = 'github';
    reference.github = github;
  } else if (type && type !== 'registry') {
    reference.source = type;
  } else if (!integrity) {
    reference.source = 'no-integrity';
  } else if (tarball && !/^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\//.test(tarball)) {
    reference.source = 'tarball';
  } else {
    reference.source = 'registry';
  }

  return reference;
}

/**
 * Apply a unified diff (as written by `pnpm patch-commit` or `git diff`)
 * to original file contents, exactly: every context and removed line must
 * match at the stated position.  No fuzz, no offsets.
 *
 * @param {string} patchText
 * @param {Map<string, Buffer>} originals - path -> original content
 * @returns {Map<string, Buffer|null>} path -> patched content (null: deleted)
 */
function applyPatch(patchText, originals) {
  const lines = patchText.split('\n');
  // The text after the final newline is not a line.
  const end = lines.at(-1) === '' ? lines.length - 1 : lines.length;
  const results = new Map();
  const fileName = (value, prefix) => {
    const name = value.split('\t')[0].trim();
    if (name === '/dev/null') {
      return null;
    }

    if (!name.startsWith(prefix)) {
      throw new Error(`Unsupported patch path: ${name}`);
    }

    return name.slice(prefix.length);
  };

  let index = 0;
  while (index < lines.length) {
    if (!lines[index].startsWith('--- ')) {
      if (lines[index].startsWith('GIT binary patch') || lines[index].startsWith('Binary files ')) {
        throw new Error('Binary patches are not supported');
      }

      index++;
      continue;
    }

    if (!lines[index + 1] || !lines[index + 1].startsWith('+++ ')) {
      throw new Error(`Malformed patch header at line ${index + 1}`);
    }

    const oldPath = fileName(lines[index].slice(4), 'a/');
    const newPath = fileName(lines[index + 1].slice(4), 'b/');
    index += 2;
    let old = [];
    if (oldPath !== null) {
      const content = results.has(oldPath) ? results.get(oldPath) : originals.get(oldPath);
      if (!content) {
        throw new Error(`Patched file is not in the package: ${oldPath}`);
      }

      old = content.toString('utf8').match(/[^\n]*\n|[^\n]+$/g) || [];
    }

    const output = [];
    let cursor = 0;
    while (index < lines.length && lines[index].startsWith('@@ ')) {
      const header = lines[index].match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
      if (!header) {
        throw new Error(`Malformed hunk header: ${lines[index]}`);
      }

      const oldLength = header[2] === undefined ? 1 : Number(header[2]);
      const newLength = header[4] === undefined ? 1 : Number(header[4]);
      const start = oldLength === 0 ? Number(header[1]) : Number(header[1]) - 1;
      if (start < cursor || start > old.length) {
        throw new Error(`Hunk out of order or out of range in ${oldPath || newPath}`);
      }

      output.push(...old.slice(cursor, start));
      cursor = start;
      index++;
      let removed = 0;
      let added = 0;
      let last = null;
      while (index < end && (removed < oldLength || added < newLength || lines[index].startsWith('\\'))) {
        const line = lines[index];
        const marker = line[0];
        const text = line.slice(1);
        if (marker === '\\') {
          // "\ No newline at end of file" applies to the previous line.
          if (last === '+' || last === ' ') {
            output[output.length - 1] = output.at(-1).replace(/\n$/, '');
          }

          index++;
          continue;
        }

        if (marker === ' ' || marker === '-') {
          if (cursor >= old.length || old[cursor].replace(/\n$/, '') !== text) {
            throw new Error(`Patch does not apply to ${oldPath} at line ${cursor + 1}`);
          }

          if (marker === ' ') {
            output.push(old[cursor]);
            added++;
          }

          cursor++;
          removed++;
        } else if (marker === '+') {
          output.push(`${text}\n`);
          added++;
        } else {
          throw new Error(`Malformed hunk line in ${oldPath || newPath}: ${line.slice(0, 40)}`);
        }

        last = marker;
        index++;
      }

      if (removed !== oldLength || added !== newLength) {
        throw new Error(`Truncated hunk in ${oldPath || newPath}`);
      }
    }

    output.push(...old.slice(cursor));
    if (newPath === null) {
      results.set(oldPath, null);
    } else {
      if (oldPath !== null && oldPath !== newPath) {
        results.set(oldPath, null);
      }

      results.set(newPath, Buffer.from(output.join(''), 'utf8'));
    }
  }

  return results;
}

/**
 * Files touched by a unified diff (pnpm patch file).
 * @param {string} patchText
 * @returns {string[]}
 */
function filesTouchedByPatch(patchText) {
  const files = new Set();
  for (const line of patchText.split('\n')) {
    const match = line.match(/^(?:-{3}|\+{3}) [ab]\/(.+?)\s*$/);
    if (match && match[1] !== '/dev/null') {
      files.add(match[1]);
    }
  }

  return [...files].sort();
}

/**
 * Check the symbolic links found while scanning node_modules.
 * @returns {Promise<{problems: Array<{path: string, target: string|null, problem: string}>, targets: Array<{path: string, target: string}>}>}
 *   problems, and the package each package link points to
 */
async function checkLinks(root, links, packageDirs, relative) {
  const realRoot = await fs.promises.realpath(root).catch(() => path.resolve(root));
  const byRealPath = new Set();
  for (const directory of packageDirs) {
    byRealPath.add(await fs.promises.realpath(directory).catch(() => directory));
  }

  const problems = [];
  const targets = [];
  for (const link of links) {
    const linkPath = relative(link.full);
    let target;
    try {
      target = await fs.promises.realpath(link.full);
    } catch (error) {
      problems.push({path: linkPath, target: null, problem: `broken link (${error.code})`});
      continue;
    }

    const inside = target.startsWith(realRoot + path.sep);
    const shown = inside ? path.relative(realRoot, target).split(path.sep).join('/') : target;
    if (!inside) {
      problems.push({path: linkPath, target: shown, problem: 'points outside node_modules'});
    } else if (link.bin) {
      if (![...byRealPath].some(directory => target.startsWith(directory + path.sep))) {
        problems.push({path: linkPath, target: shown, problem: 'does not point into an installed package'});
      }
    } else if (byRealPath.has(target)) {
      // The name may differ (npm aliases); the verifier checks the target
      // against the lockfile (retargetedLinks).
      targets.push({path: linkPath, target: shown});
    } else {
      problems.push({path: linkPath, target: shown, problem: 'does not point to an installed package'});
    }
  }

  const byPath = (a, b) => (a.path > b.path) - (a.path < b.path);
  return {problems: problems.sort(byPath), targets: targets.sort(byPath)};
}

/**
 * Split a flat map of package files (paths relative to the package root)
 * into the package's own files and any bundled packages under
 * node_modules/.  Returns digests for each.
 *
 * @param {Map<string, Buffer>|Map<string, string>} fileMap - path -> content (Buffer) or sha256 (string)
 * @returns {{files: Object<string,string>, digest: string, fileCount: number, bundled: Object[]}}
 */
function packageManifestFromFiles(fileMap) {
  const own = {};
  const nested = new Map();
  for (const [filePath, value] of fileMap) {
    // Bytecode caches are listed apart from installed packages, so they
    // are left out of references too.
    if (PYTHON_CACHE.test(filePath)) {
      continue;
    }

    const hash = typeof value === 'string' ? value : sha256(value);
    const match = filePath.match(/^node_modules\/((?:@[^/]+\/)?[^/]+)\/(.+)$/);
    if (match) {
      if (!nested.has(match[1])) {
        nested.set(match[1], new Map());
      }

      nested.get(match[1]).set(match[2], value);
    } else if (!filePath.startsWith('node_modules/')) {
      setOwn(own, filePath, hash);
    }
  }

  const bundled = [];
  for (const [directory, files] of nested) {
    const packageJson = files.get('package.json');
    let name = directory;
    let version = null;
    if (Buffer.isBuffer(packageJson)) {
      try {
        const parsed = JSON.parse(packageJson.toString('utf8'));
        name = parsed.name || directory;
        version = parsed.version || null;
      } catch {}
    }

    const manifest = packageManifestFromFiles(files);
    bundled.push({
      name, version, digest: manifest.digest, fileCount: manifest.fileCount,
    }, ...manifest.bundled);
  }

  const entries = Object.entries(own).map(([filePath, hash]) => ({path: filePath, sha256: hash}));
  const manifest = {
    files: own, digest: manifestDigest(entries), fileCount: entries.length, bundled,
  };

  // Npm and pnpm rewrite a "#!...\r\n" first line of a bin file to end
  // in "\n" when they link it (bin-links' fix-bin), so the installed file
  // may be either version.
  const binFixes = {};
  for (const file of binFiles(fileMap)) {
    const content = fileMap.get(file);
    if (Buffer.isBuffer(content) && WINDOWS_HASHBANG.test(content.subarray(0, 2048).toString())) {
      setOwn(binFixes, file, sha256(Buffer.from(content.toString('utf8').replace(/^(#![^\n]+)\r\n/, '$1\n'), 'utf8')));
    }
  }

  if (Object.keys(binFixes).length > 0) {
    manifest.binFixes = binFixes;
    manifest.fixedDigest = manifestDigest(entries.map(entry => ({path: entry.path, sha256: binFixes[entry.path] || entry.sha256})));
  }

  // The npm installer writes a tarball's .gitignore files as .npmignore when it installs
  // a package (unless the package also has that file).
  const renamed = entry => {
    const target = entry.path.replace(/(^|\/)\.gitignore$/, '$1.npmignore');
    return target !== entry.path && !Object.hasOwn(own, target) ? target : entry.path;
  };

  if (entries.some(entry => renamed(entry) !== entry.path)) {
    manifest.npmDigest = manifestDigest(entries.map(entry => ({path: renamed(entry), sha256: binFixes[entry.path] || entry.sha256})));
  }

  return manifest;
}

const WINDOWS_HASHBANG = /^#![^\n]+\r\n/;
const PNPM_STORE_PACKAGE = /^\.pnpm\/([^/]+)\/node_modules\/((?:@[^/]+\/)?[^/]+)$/;

/**
 * Whether a package in pnpm's store layout (.pnpm/<key>/node_modules/<name>)
 * is the package its directory is named for: pnpm names the directory by
 * the package's own name, and the key by its name and version (followed by
 * peer dependencies, or a hash when the key is long or has capitals).
 * Keys of packages from a URL or git name no version.  Other layouts are
 * not judged here.
 *
 * @param {{name: string, version: string, path: string}} item
 * @returns {boolean}
 */
function inPnpmStoreDirectory(item) {
  const match = item.path.match(PNPM_STORE_PACKAGE);
  if (!match) {
    return true;
  }

  const [, key, directory] = match;
  const prefix = `${item.name.replace('/', '+')}@`;
  if (directory !== item.name || !key.startsWith(prefix)) {
    return false;
  }

  const rest = key.slice(prefix.length);
  if (!/^\d/.test(rest) || rest === item.version || rest.startsWith(`${item.version}_`)) {
    return true;
  }

  // Truncated before a hash: what is left must begin the name and version.
  const hashed = key.match(/^(.+)_[\da-z]{26,64}$/);
  return Boolean(hashed) && `${prefix}${item.version}`.startsWith(hashed[1]);
}

const PYTHON_CACHE = /(?:^|\/)__pycache__\//;

/**
 * Files in Python bytecode cache directories that are not bytecode.
 * @param {Array<{path: string, files: string[]}>} caches - from scanInstalledPackages()
 * @returns {string[]}
 */
function foreignCacheFiles(caches = []) {
  return caches.flatMap(cache => cache.files.filter(file => !/^[^/]+\.pyc$/.test(file)).map(file => `${cache.path}/${file}`)).sort();
}

/**
 * The package's own files that its package.json declares as executables
 * ("bin", or every file under "directories.bin").
 *
 * @param {Map<string, Buffer|string>} fileMap
 * @returns {string[]}
 */
function binFiles(fileMap) {
  const packageJson = fileMap.get('package.json');
  let parsed;
  try {
    parsed = JSON.parse(packageJson.toString('utf8'));
  } catch {
    return [];
  }

  const normalize = file => (typeof file === 'string' ? path.posix.normalize(file).replace(/^\.\//, '') : '');
  const files = new Set();
  const {bin, directories} = parsed || {};
  if (typeof bin === 'string') {
    files.add(normalize(bin));
  } else if (bin && typeof bin === 'object') {
    for (const target of Object.values(bin)) {
      files.add(normalize(target));
    }
  } else if (directories && typeof directories.bin === 'string') {
    const prefix = `${normalize(directories.bin).replace(/\/$/, '')}/`;
    for (const file of fileMap.keys()) {
      if (file.startsWith(prefix)) {
        files.add(file);
      }
    }
  }

  return [...files].filter(file => file && !file.startsWith('../') && !file.startsWith('node_modules/') && fileMap.has(file));
}

class ReleaseVerification {
  /**
   * @param {Object} [options]
   * @param {string} [options.projectRoot=process.cwd()]
   * @param {string} [options.nodeDistUrl='https://nodejs.org/dist']
   * @param {string} [options.registryUrl='https://registry.npmjs.org']
   * @param {string} [options.cacheDir] - directory for cached reference manifests
   * @param {string} [options.nodeKeyring] - keyring of Node.js release keys; when set, SHASUMS256.txt must be signed
   * @param {number} [options.timeout=30000]
   * @param {number} [options.concurrency=8]
   * @param {number} [options.maxRetries=3]
   * @param {number} [options.retryDelay=1000]
   */
  constructor(options = {}) {
    this.projectRoot = path.resolve(options.projectRoot || process.cwd());
    this.nodeDistUrl = (options.nodeDistUrl || 'https://nodejs.org/dist').replace(/\/+$/, '');
    this.registryUrl = (options.registryUrl || 'https://registry.npmjs.org').replace(/\/+$/, '');
    this.githubArchiveUrl = (options.githubArchiveUrl || 'https://codeload.github.com').replace(/\/+$/, '');
    this.cacheDir = options.cacheDir || null;
    this.nodeKeyring = options.nodeKeyring || null;
    this.concurrency = options.concurrency || 8;
    this.httpOptions = {
      timeout: options.timeout ?? 30_000,
      maxRetries: options.maxRetries ?? 3,
      retryDelay: options.retryDelay ?? 1000,
    };
    this._manifestCache = new Map();
  }

  // ─── cache ────────────────────────────────────────────────────────

  _cachePath(key) {
    return this.cacheDir ? path.join(this.cacheDir, `${sha256(key)}.json`) : null;
  }

  _readCache(key) {
    const file = this._cachePath(key);
    if (!file) {
      return null;
    }

    try {
      const cached = JSON.parse(fs.readFileSync(file, 'utf8'));
      return cached.key === key ? cached.value : null;
    } catch {
      return null;
    }
  }

  _writeCache(key, value) {
    const file = this._cachePath(key);
    if (!file) {
      return;
    }

    fs.mkdirSync(this.cacheDir, {recursive: true, mode: 0o700});
    const temporary = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(temporary, JSON.stringify({key, value}), {mode: 0o600});
    fs.renameSync(temporary, file);
  }

  // ─── 1. Node.js binary ────────────────────────────────────────────

  /**
   * Fetch SHASUMS256.txt for a release, optionally verifying its signature.
   * @param {string} version - e.g. "v18.20.8"
   * @returns {Promise<Map<string,string>>}
   */
  async getNodeShasums(version) {
    if (!NODE_VERSION.test(version)) {
      throw new TypeError(`Invalid Node.js version: ${version}`);
    }

    const base = `${this.nodeDistUrl}/${version}`;
    const text = await httpGet(`${base}/SHASUMS256.txt`, {...this.httpOptions, maxBytes: 1024 * 1024});
    if (this.nodeKeyring) {
      const signature = await httpGet(`${base}/SHASUMS256.txt.sig`, {...this.httpOptions, maxBytes: 64 * 1024});
      await this._gpgVerify(text, signature);
    }

    return parseShasums(text.toString('utf8'));
  }

  async _gpgVerify(data, signature) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-gpg-'));
    try {
      const dataPath = path.join(directory, 'SHASUMS256.txt');
      const sigPath = path.join(directory, 'SHASUMS256.txt.sig');
      fs.writeFileSync(dataPath, data);
      fs.writeFileSync(sigPath, signature);
      // Its own home directory, and gpgv's status lines checked: it exits
      // with 0 for a signature by a revoked or expired key.
      await new Promise((resolve, reject) => {
        execFile('gpgv', ['--homedir', directory, '--status-fd', '1', '--keyring', path.resolve(this.nodeKeyring), sigPath, dataPath], {timeout: 30_000}, (error, stdout) => {
          const problem = error ? error.message.split('\n')[0] : gpgStatusProblem(String(stdout));
          if (problem) {
            reject(new Error(`SHASUMS256.txt signature verification failed: ${problem}`));
            return;
          }

          resolve();
        });
      });
    } finally {
      fs.rmSync(directory, {recursive: true, force: true});
    }
  }

  /**
   * SHA-256 of the official Node.js binary for a release/platform/arch.
   *
   * Windows: SHASUMS256.txt lists win-<arch>/node.exe directly.
   * Linux/macOS: the official .tar.gz is downloaded, checked against
   * SHASUMS256.txt, and bin/node is extracted and hashed.
   *
   * @param {Object} target
   * @param {string} target.version
   * @param {string} target.platform - process.platform value
   * @param {string} target.arch - process.arch value
   * @returns {Promise<{sha256: string, source: string, archive: string, archiveSha256: string}>}
   */
  async getOfficialNodeBinary({version, platform, arch}) {
    const target = nodeReleaseTarget(platform, arch);
    const shasums = await this.getNodeShasums(version);

    if (target.platform === 'win') {
      const entry = `win-${target.arch}/node.exe`;
      const hash = shasums.get(entry);
      if (!hash) {
        throw new Error(`No ${entry} entry in SHASUMS256.txt for ${version}`);
      }

      return {
        sha256: hash, source: 'shasums', archive: entry, archiveSha256: hash,
      };
    }

    const archive = `node-${version}-${target.platform}-${target.arch}.tar.gz`;
    const manifest = await this.getOfficialNodeArchive({version, platform, arch}, shasums);
    const hash = manifest.files['bin/node'];
    if (!hash) {
      throw new Error(`bin/node not found in ${archive}`);
    }

    return {
      sha256: hash, source: 'archive', archive, archiveSha256: manifest.archiveSha256,
    };
  }

  /**
   * Manifest (path -> sha256, first path component stripped) of the
   * official Linux/macOS release archive.  Used for the Node.js binary and
   * for the npm and corepack copies that ship inside the archive.
   *
   * @param {{version: string, platform: string, arch: string}} target
   * @param {Map<string,string>} [shasums] - already fetched SHASUMS256.txt
   * @returns {Promise<{archive: string, archiveSha256: string, files: Object<string,string>}>}
   */
  async getOfficialNodeArchive({version, platform, arch}, shasums) {
    const target = nodeReleaseTarget(platform, arch);
    if (target.platform === 'win') {
      throw new Error('Windows releases are verified from SHASUMS256.txt, not an archive');
    }

    shasums ||= await this.getNodeShasums(version);
    const archive = `node-${version}-${target.platform}-${target.arch}.tar.gz`;
    const archiveSha256 = shasums.get(archive);
    if (!archiveSha256) {
      throw new Error(`No ${archive} entry in SHASUMS256.txt for ${version}`);
    }

    const cacheKey = `node-archive:${archive}:${archiveSha256}`;
    const cached = this._readCache(cacheKey);
    if (cached) {
      return cached;
    }

    const buffer = await httpGet(`${this.nodeDistUrl}/${version}/${archive}`, {...this.httpOptions, maxBytes: 256 * 1024 * 1024});
    if (sha256(buffer) !== archiveSha256) {
      throw new Error(`Downloaded ${archive} does not match SHASUMS256.txt`);
    }

    const files = {};
    const versions = {};
    for (const [filePath, content] of readGzipTarFiles(buffer, {stripFirstComponent: true})) {
      setOwn(files, filePath, sha256(content));
      if (filePath.startsWith('lib/node_modules/') && filePath.endsWith('/package.json')) {
        try {
          const {version: packageVersion} = JSON.parse(content.toString('utf8'));
          if (typeof packageVersion === 'string') {
            versions[filePath.slice(0, -'/package.json'.length)] = packageVersion;
          }
        } catch {}
      }
    }

    const result = {
      archive, archiveSha256, files, versions,
    };
    this._writeCache(cacheKey, result);
    return result;
  }

  /**
   * Verify a Node.js binary on disk against the official release.
   *
   * @param {Object} [options]
   * @param {string} [options.execPath=process.execPath]
   * @param {string} [options.version=process.version]
   * @param {string} [options.platform=process.platform]
   * @param {string} [options.arch=process.arch]
   * @param {string} [options.sha256] - precomputed hash (e.g. from remote evidence)
   * @returns {Promise<{name: string, passed: boolean, details: Object}>}
   */
  async verifyNodeRelease(options = {}) {
    const details = {
      version: options.version || process.version,
      platform: options.platform || process.platform,
      arch: options.arch || process.arch,
      execPath: options.execPath || process.execPath,
    };
    const result = {name: 'node-release', passed: false, details};
    try {
      details.sha256 = options.sha256 || (await require('./file-tree').hashFile(details.execPath)).sha256;
      const official = await this.getOfficialNodeBinary(details);
      details.officialSha256 = official.sha256;
      details.officialSource = `${this.nodeDistUrl}/${details.version}/${official.archive}`;
      details.matched = details.sha256 === official.sha256;
      result.passed = details.matched;
      if (!details.matched) {
        details.error = 'Binary differs from the official release (repackaged by a distribution, or modified)';
      }
    } catch (error) {
      details.error = error.message;
    }

    return result;
  }

  // ─── 2. installed packages ────────────────────────────────────────

  /**
   * Find and hash every installed package under a node_modules directory
   * (npm nested/flat layout and pnpm's .pnpm store layout).
   *
   * Symbolic links are not followed while scanning, so pnpm's links are not
   * counted twice; instead every link is checked afterwards.  A package link
   * must resolve to a scanned package, and a link in .bin must resolve into
   * one; anything else (a link to a directory outside node_modules, to a
   * directory that is not a package, or a broken link) is listed in
   * `links`.  The top-level .cache directory (tool caches) is skipped.
   *
   * @param {string} [nodeModulesDir=<projectRoot>/node_modules]
   * @param {Object} [options]
   * @param {boolean|((pkg: {name: string, version: string}) => boolean)} [options.includeFiles=false]
   * Python bytecode caches (__pycache__ directories) are not hashed with
   * their package; they are listed in `caches`.
   *
   * @returns {Promise<{packages: Object[], unaccounted: string[], links: Object[], caches: Array<{path: string, files: string[]}>, errors: Object[]}>}
   */
  async scanInstalledPackages(nodeModulesDir = path.join(this.projectRoot, 'node_modules'), options = {}) {
    const root = path.resolve(nodeModulesDir);
    const includeFiles = options.includeFiles || false;
    const packages = [];
    const unaccounted = [];
    const errors = [];
    const packageDirs = [];
    const links = [];
    const caches = [];

    const relative = target => path.relative(root, target).split(path.sep).join('/');

    const scanModulesDir = async directory => {
      let dirents;
      try {
        dirents = await fs.promises.readdir(directory, {withFileTypes: true});
      } catch (error) {
        errors.push({path: relative(directory) || '.', error: error.code});
        return;
      }

      for (const dirent of dirents) {
        const full = path.join(directory, dirent.name);
        if (dirent.isSymbolicLink()) {
          links.push({full, bin: false});
          continue;
        }

        if (dirent.name === '.cache' && directory === root) {
          continue;
        }

        if (dirent.name === '.bin') {
          // Executables for package scripts: links into packages (npm) or
          // generated shims (pnpm).  The links are checked below.
          try {
            for (const bin of await fs.promises.readdir(full, {withFileTypes: true})) {
              if (bin.isSymbolicLink()) {
                links.push({full: path.join(full, bin.name), bin: true});
              }
            }
          } catch (error) {
            errors.push({path: relative(full), error: error.code});
          }

          continue;
        }

        if (!dirent.isDirectory()) {
          if (!METADATA_FILES.has(dirent.name)) {
            unaccounted.push(relative(full));
          }

          continue;
        }

        if (dirent.name === '.pnpm') {
          const stores = await fs.promises.readdir(full, {withFileTypes: true});
          for (const store of stores) {
            const storePath = path.join(full, store.name);
            const storeModules = path.join(storePath, 'node_modules');
            if (store.isDirectory() && store.name === 'node_modules') {
              // Hoisted packages, which Node.js can resolve.
              await scanModulesDir(storePath);
            } else if (store.isDirectory() && exists(storeModules)) {
              await scanModulesDir(storeModules);
            } else if (store.isSymbolicLink()) {
              links.push({full: storePath, bin: false});
            } else if (store.isDirectory()) {
              unaccounted.push(`${relative(storePath)}/`);
            } else if (!METADATA_FILES.has(store.name)) {
              unaccounted.push(relative(storePath));
            }
          }

          continue;
        }

        if (dirent.name.startsWith('@')) {
          await scanModulesDir(full);
          continue;
        }

        if (dirent.name.startsWith('.')) {
          unaccounted.push(`${relative(full)}/`);
          continue;
        }

        packageDirs.push(full);
        const nested = path.join(full, 'node_modules');
        if (exists(nested)) {
          await scanModulesDir(nested);
        }
      }
    };

    await scanModulesDir(root);

    const scanned = await parallelMap(packageDirs.map(directory => async () => {
      let name = null;
      let version = null;
      try {
        const packageJson = JSON.parse(await fs.promises.readFile(path.join(directory, 'package.json'), 'utf8'));
        name = typeof packageJson.name === 'string' ? packageJson.name : null;
        version = typeof packageJson.version === 'string' ? packageJson.version : null;
      } catch (error) {
        errors.push({path: relative(directory), error: `package.json: ${error.code || error.message}`});
      }

      // Python writes bytecode caches next to the modules it imports (for
      // example node-gyp's gyp during a native build).  They are not part of
      // the package, so they are listed instead of hashed with it.
      const cacheDirs = [];
      const {entries, errors: walkErrors} = await walkTree(directory, {
        exclude(relativePath, isDirectory) {
          if (isDirectory && path.posix.basename(relativePath) === '__pycache__') {
            cacheDirs.push(relativePath);
            return true;
          }

          return isDirectory && relativePath === 'node_modules';
        },
      });
      for (const walkError of walkErrors) {
        errors.push({path: `${relative(directory)}/${walkError.path}`, error: walkError.error});
      }

      for (const cacheDir of cacheDirs) {
        const cache = await walkTree(path.join(directory, ...cacheDir.split('/')));
        caches.push({path: `${relative(directory)}/${cacheDir}`, files: cache.entries.map(entry => entry.path).sort()});
        for (const walkError of cache.errors) {
          errors.push({path: `${relative(directory)}/${cacheDir}/${walkError.path}`, error: walkError.error});
        }
      }

      const item = {
        name: name || path.basename(directory),
        version,
        path: relative(directory),
        digest: manifestDigest(entries),
        fileCount: entries.length,
      };
      if (!name || !version) {
        item.invalid = true;
      }

      const wantFiles = typeof includeFiles === 'function' ? includeFiles(item) : includeFiles;
      if (wantFiles) {
        item.files = Object.fromEntries(entries.map(entry => [entry.path, entry.sha256]));
      }

      return item;
    }), this.concurrency);

    packages.push(...scanned);
    packages.sort((a, b) => (a.path > b.path) - (a.path < b.path));
    unaccounted.sort();
    caches.sort((a, b) => (a.path > b.path) - (a.path < b.path));
    const {problems, targets} = await checkLinks(root, links, packageDirs, relative);
    return {
      packages, unaccounted, links: problems, packageLinks: targets, caches, errors,
    };
  }

  /**
   * Registry metadata integrity for name@version.
   * @param {string} name
   * @param {string} version
   * @returns {Promise<{integrity: string, tarball: string}>}
   */
  async getRegistryReference(name, version) {
    if (!isValidPackageName(name) || !isValidPackageVersion(version)) {
      throw new TypeError(`Invalid package reference: ${name}@${version}`);
    }

    const metadata = await httpGetJson(`${this.registryUrl}/${name.replace('/', '%2f')}/${encodeURIComponent(version)}`, {...this.httpOptions, maxBytes: 16 * 1024 * 1024});
    const integrity = metadata.dist && (metadata.dist.integrity || (metadata.dist.shasum && `sha1-${Buffer.from(metadata.dist.shasum, 'hex').toString('base64')}`));
    if (!integrity) {
      throw new Error(`Registry metadata for ${name}@${version} has no integrity`);
    }

    return {integrity, tarball: metadata.dist.tarball};
  }

  /**
   * Download the reference tarball for a lockfile entry: the registry
   * tarball, checked against its pinned integrity, or the archive GitHub
   * generates for a pinned commit.
   *
   * @param {Object} reference
   * @returns {Promise<Buffer>}
   */
  async _referenceTarball({name, version, integrity, github}) {
    const options = {...this.httpOptions, maxBytes: 512 * 1024 * 1024};
    if (github) {
      return httpGet(`${this.githubArchiveUrl}/${github.owner}/${github.repo}/tar.gz/${github.commit}`, options);
    }

    // Always the configured registry: the integrity check below is what
    // authenticates the content, so a URL taken from a lockfile would only
    // add another host to trust.
    const buffer = await httpGet(`${this.registryUrl}/${name}/-/${name.split('/').pop()}-${version}.tgz`, options);
    if (!verifyIntegrity(buffer, integrity)) {
      throw new Error(`Tarball for ${name}@${version} does not match integrity ${integrity.slice(0, 20)}...`);
    }

    return buffer;
  }

  /**
   * Reference manifest (path -> sha256) of a registry tarball.  The tarball
   * must match `integrity`, so the registry itself cannot substitute content
   * for a version pinned by a lockfile.
   *
   * @param {Object} reference
   * @param {string} reference.name
   * @param {string} reference.version
   * @param {string} reference.integrity
   * @param {string} [reference.tarball]
   * @returns {Promise<{files: Object, digest: string, fileCount: number, bundled: Object[]}>}
   */
  async getPackageManifest(reference) {
    const {name, version, integrity, github} = reference;
    if (!isValidPackageName(name) || !isValidPackageVersion(version)) {
      throw new TypeError(`Invalid package reference: ${name}@${version}`);
    }

    const cacheKey = github ? `github-manifest:v3:${github.owner}/${github.repo}@${github.commit}` : `npm-manifest:v4:${name}@${version}:${integrity}`;
    if (this._manifestCache.has(cacheKey)) {
      return this._manifestCache.get(cacheKey);
    }

    const promise = (async () => {
      const cached = this._readCache(cacheKey);
      if (cached) {
        return cached;
      }

      const manifest = packageManifestFromFiles(readGzipTarFiles(await this._referenceTarball(reference), {stripFirstComponent: true}));
      this._writeCache(cacheKey, manifest);
      return manifest;
    })();
    this._manifestCache.set(cacheKey, promise);
    try {
      return await promise;
    } catch (error) {
      this._manifestCache.delete(cacheKey);
      throw error;
    }
  }

  /**
   * Selected files of a registry tarball, verified against its integrity.
   * @param {{name: string, version: string, integrity: string}} reference
   * @param {string[]} paths
   * @returns {Promise<Map<string, Buffer>>}
   */
  async getPackageFiles(reference, paths) {
    const {name, version} = reference;
    if (!isValidPackageName(name) || !isValidPackageVersion(version)) {
      throw new TypeError(`Invalid package reference: ${name}@${version}`);
    }

    const wanted = new Set(paths);
    const files = new Map();
    for (const [filePath, content] of readGzipTarFiles(await this._referenceTarball(reference), {stripFirstComponent: true})) {
      if (wanted.has(filePath)) {
        files.set(filePath, content);
      }
    }

    return files;
  }

  /**
   * Read the lockfile in a project root.
   * @param {string} [root=this.projectRoot]
   * @returns {{format: string, lockfileVersion: *, packages: Object[]}}
   */
  readLockfile(root = this.projectRoot) {
    const pnpmLock = path.join(root, 'pnpm-lock.yaml');
    if (exists(pnpmLock)) {
      return parseLockfile(fs.readFileSync(pnpmLock, 'utf8'), 'pnpm');
    }

    const npmLock = path.join(root, 'package-lock.json');
    if (exists(npmLock)) {
      return parseLockfile(fs.readFileSync(npmLock, 'utf8'), 'npm');
    }

    throw new Error('No pnpm-lock.yaml or package-lock.json found');
  }

  /**
   * Read the package policy (patched and built dependencies) from a
   * project's package.json and patch files.
   *
   * @param {string} [root=this.projectRoot]
   * @returns {{patched: Object<string, {files: string[], text: string}|null>, built: string[]}}
   */
  readPackagePolicy(root = this.projectRoot) {
    const policy = {patched: {}, built: []};
    let packageJson;
    try {
      packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    } catch {
      return policy;
    }

    const pnpm = packageJson.pnpm || {};
    for (const [spec, patchFile] of Object.entries(pnpm.patchedDependencies || {})) {
      const resolved = path.resolve(root, patchFile);
      if (!resolved.startsWith(path.resolve(root) + path.sep)) {
        continue;
      }

      try {
        const text = fs.readFileSync(resolved, 'utf8');
        policy.patched[spec] = {files: filesTouchedByPatch(text), text};
      } catch {
        policy.patched[spec] = null;
      }
    }

    policy.built = Array.isArray(pnpm.onlyBuiltDependencies) ? [...pnpm.onlyBuiltDependencies] : [];
    return policy;
  }

  /**
   * Compare installed packages with reference tarballs.
   *
   * Packages are appraised from the shallowest to the deepest path, so a
   * package's bundled dependencies (shipped inside its own tarball) are
   * matched against that tarball before anything else is consulted.
   *
   * @param {Object} input
   * @param {Object[]} input.installed - from scanInstalledPackages() (files required for patched/built packages)
   * @param {Object[]} [input.references] - lockfile references; when omitted every package is looked up in the registry
   * @param {{patched: Object, built: string[]}} [input.policy]
   * @param {(item: Object) => Promise<Object|null>} [input.manifestProvider]
   *   Optional source of a reference manifest for a package; return null to fall back to the registry.
   * @param {(item: Object) => Promise<Object<string,string>|null>} [input.resolveFiles]
   *   Optional loader of per-file hashes, used to explain a digest mismatch.
   * @returns {Promise<{passed: boolean, summary: Object, findings: Object[], files: Map<string, Object<string,string>>}>}
   *   `files`: for each package that matched its reference (verified, patched
   *   or built), by its path, the hash of each of its files.
   */
  async comparePackages({installed, references, policy = {patched: {}, built: []}, manifestProvider, resolveFiles}) {
    const referenceMap = new Map();
    // An npm lockfile pins what is installed at each path; Node.js resolves
    // a name by path, so a package must be the one pinned where it is.
    const referencePaths = new Map();
    for (const reference of references || []) {
      referenceMap.set(`${reference.name}@${reference.version}`, reference);
      if (reference.path) {
        referencePaths.set(reference.path, reference);
      }
    }

    const built = new Set(policy.built || []);
    const bundledDigests = new Map();
    const summary = {
      total: installed.length, verified: 0, bundled: 0, patched: 0, built: 0, failed: 0, unverifiable: 0, error: 0,
    };

    const resolveManifest = async (item, spec) => {
      if (manifestProvider) {
        const provided = await manifestProvider(item);
        if (provided) {
          return {manifest: provided};
        }
      }

      let reference = referenceMap.get(spec);
      if (referencePaths.size > 0) {
        reference = referencePaths.get(`node_modules/${item.path}`);
        if (!reference) {
          return {result: {status: 'failed', reason: 'the lockfile pins no package at this path'}};
        }

        if (`${reference.name}@${reference.version}` !== spec) {
          return {result: {status: 'failed', reason: `the lockfile pins ${reference.name}@${reference.version} at this path`}};
        }
      }

      if (!reference && !references) {
        try {
          reference = {
            name: item.name, version: item.version, source: 'registry', ...(await this.getRegistryReference(item.name, item.version)),
          };
        } catch (error) {
          return {result: {status: 'unverifiable', reason: error.message}};
        }
      }

      if (!reference) {
        return {result: {status: 'failed', reason: 'installed package is not in the lockfile or any bundle'}};
      }

      if (reference.source !== 'registry' && reference.source !== 'github') {
        return {result: {status: 'unverifiable', reason: `resolved from ${reference.source}, not the registry`}};
      }

      try {
        return {manifest: await this.getPackageManifest(reference), reference};
      } catch (error) {
        // Only content that contradicts its pin is evidence of tampering;
        // a reference that cannot be downloaded leaves the package unchecked.
        return {result: {status: /does not match integrity/.test(error.message) ? 'failed' : 'error', reason: error.message}};
      }
    };

    const appraise = async item => {
      const spec = `${item.name}@${item.version}`;
      if (item.invalid) {
        return {status: 'failed', item, reason: 'missing or invalid package.json'};
      }

      // A package that matches its reference by digest keeps its file list
      // (native modules and bin scripts it may run are explained by it),
      // so that list must be the one the digest was computed from.
      const unbound = item.files && manifestDigest(Object.entries(item.files).map(([filePath, hash]) => ({path: filePath, sha256: hash}))) !== item.digest
        ? {status: 'failed', item, reason: 'the file list does not match the package digest'}
        : null;
      if (!inPnpmStoreDirectory(item)) {
        return {status: 'failed', item, reason: 'installed where pnpm keeps another package'};
      }

      // A bundled dependency is installed inside the package that bundles it.
      const bundle = bundledDigests.get(`${spec}:${item.digest}`);
      const bundledBy = bundle && item.path.startsWith(`${bundle.path}/node_modules/`) ? bundle.spec : null;
      if (bundledBy) {
        return unbound || {status: 'bundled', item, bundledBy};
      }

      const {manifest, reference, result} = await resolveManifest(item, spec);
      if (result) {
        return {...result, item};
      }

      for (const bundled of manifest.bundled) {
        bundledDigests.set(`${bundled.name}@${bundled.version}:${bundled.digest}`, {spec, path: item.path});
      }

      if (item.digest === manifest.digest || (manifest.fixedDigest && item.digest === manifest.fixedDigest) || (manifest.npmDigest && item.digest === manifest.npmDigest)) {
        if (!unbound) {
          verifiedFiles.push({name: item.name, files: manifest.files});
        }

        return unbound || {status: 'verified', item, files: manifest.files};
      }

      // Pnpm keys patches by name@version, or by name for every version.
      const patched = policy.patched || {};
      const patch = reference ? patched[spec] ?? patched[item.name] : undefined;
      const isBuilt = built.has(item.name);
      if (!item.files && resolveFiles) {
        item.files = await resolveFiles(item);
      }

      if (!item.files) {
        return {status: 'failed', item, reason: 'files differ from reference tarball'};
      }

      // With a pnpm patch, the reference is the tarball with the patch
      // applied, exactly; any other difference is a failure.
      let expected = manifest.files;
      if (patch) {
        try {
          const originals = await this.getPackageFiles(reference, patch.files);
          expected = {...manifest.files};
          for (const [filePath, content] of applyPatch(patch.text, originals)) {
            if (content === null) {
              delete expected[filePath];
            } else {
              setOwn(expected, filePath, sha256(content));
            }
          }
        } catch (error) {
          return {status: 'failed', item, reason: `patch could not be applied to the reference: ${error.message}`};
        }
      }

      // The npm installer writes a tarball's .gitignore files as .npmignore when it
      // installs a package: the same content under that name matches.
      for (const filePath of Object.keys(expected)) {
        const renamed = filePath.replace(/(^|\/)\.gitignore$/, '$1.npmignore');
        if (renamed !== filePath && !Object.hasOwn(item.files, filePath) && !Object.hasOwn(expected, renamed) && item.files[renamed] === expected[filePath]) {
          expected = {...expected};
          delete expected[filePath];
          setOwn(expected, renamed, item.files[renamed]);
        }
      }

      // A package installed from a repository archive is packed from it
      // (its "files" list and .npmignore leave some out), so files may be
      // missing, but whatever is installed must be in the archive unchanged.
      const packed = reference && reference.source === 'github';
      const modified = [];
      const missing = [];
      for (const [filePath, hash] of Object.entries(expected)) {
        if (!Object.hasOwn(item.files, filePath)) {
          if (!packed || filePath === 'package.json') {
            missing.push(filePath);
          }
        } else if (item.files[filePath] !== hash && item.files[filePath] !== (manifest.binFixes || {})[filePath]) {
          modified.push(filePath);
        }
      }

      // Packages allowed to run install scripts may add build output, but
      // may not change what they shipped.
      const added = isBuilt ? [] : Object.keys(item.files).filter(filePath => !Object.hasOwn(expected, filePath));
      if ((patch || isBuilt || packed) && modified.length === 0 && missing.length === 0 && added.length === 0) {
        return {status: patch ? 'patched' : (isBuilt ? 'built' : 'verified'), item};
      }

      // Files only added, to a package not allowed to build: most often an
      // install script's output (a downloaded or compiled native addon).
      const onlyAdded = !patch && !packed && added.length > 0 && modified.length === 0 && missing.length === 0;
      return {
        status: 'failed', item, reason: onlyAdded ? 'files differ from reference tarball (install script output is allowed only for packages in pnpm.onlyBuiltDependencies)' : 'files differ from reference tarball', modified, missing, added, replaceable: isBuilt && !patch && !packed && missing.length === 0 && reference,
      };
    };

    // An install script may replace a file it shipped with the same file
    // of one of its optional dependencies (esbuild copies the platform
    // package's bin/esbuild over its own launcher script): allowed for a
    // built package, when that dependency is installed and verified.
    const verifiedFiles = [];
    const replacedByDependency = async result => {
      let manifest;
      try {
        manifest = JSON.parse((await this.getPackageFiles(result.replaceable, ['package.json'])).get('package.json'));
      } catch {
        return false;
      }

      const {optionalDependencies} = {...manifest};
      const optional = {...optionalDependencies};
      return result.modified.every(filePath => verifiedFiles.some(dependency => Object.hasOwn(optional, dependency.name)
        && Object.hasOwn(dependency.files, filePath) && dependency.files[filePath] === result.item.files[filePath]));
    };

    const depthOf = item => item.path.split('/node_modules/').length;
    const depths = [...new Set(installed.map(item => depthOf(item)))].sort((a, b) => a - b);
    const results = [];
    for (const depth of depths) {
      const level = installed.filter(item => depthOf(item) === depth);
      results.push(...await parallelMap(level.map(item => () => appraise(item)), this.concurrency));
    }

    const rechecked = await parallelMap(results.map(result => async () => (result.replaceable && await replacedByDependency(result) ? {status: 'built', item: result.item} : result)), this.concurrency);

    const findings = [];
    // The reference's file hashes of each package that matched it, by
    // path, so a verifier can compare other records of those files (such
    // as the kernel's IMA measurements) with the reference, not with the
    // attester's report.
    const files = new Map();
    for (const result of rechecked) {
      summary[result.status]++;
      const own = result.files || result.item.files;
      if ((result.status === 'verified' || result.status === 'patched' || result.status === 'built') && own) {
        files.set(result.item.path, own);
      }

      if (result.status === 'failed' || result.status === 'unverifiable' || result.status === 'error') {
        const finding = {
          status: result.status,
          package: `${result.item.name}@${result.item.version}`,
          path: result.item.path,
          reason: result.reason,
        };
        for (const key of ['modified', 'missing', 'added']) {
          if (result[key] && result[key].length > 0) {
            finding[key] = result[key].slice(0, 50);
          }
        }

        findings.push(finding);
      }
    }

    findings.sort((a, b) => (a.path > b.path) - (a.path < b.path));
    // A package that could not be checked is not a pass.
    return {
      passed: summary.failed === 0 && summary.unverifiable === 0 && summary.error === 0, summary, findings, files,
    };
  }

  /**
   * Verify the project's installed node_modules against its lockfile.
   * @returns {Promise<{name: string, passed: boolean, details: Object}>}
   */
  async verifyModules() {
    const result = {name: 'module-integrity', passed: false, details: {}};
    try {
      const lock = this.readLockfile();
      const policy = this.readPackagePolicy();
      const needsFiles = filesNeeded(lock, policy);
      const scan = await this.scanInstalledPackages(undefined, {
        includeFiles: item => needsFiles.has(`${item.name}@${item.version}`) || needsFiles.has(item.name),
      });
      const nodeModulesDir = path.join(this.projectRoot, 'node_modules');
      const comparison = await this.comparePackages({
        installed: scan.packages,
        references: lock.packages,
        policy,
        async resolveFiles(item) {
          const {entries} = await walkTree(path.join(nodeModulesDir, ...item.path.split('/')), {
            exclude: (relativePath, isDirectory) => isDirectory && relativePath === 'node_modules',
          });
          return Object.fromEntries(entries.map(entry => [entry.path, entry.sha256]));
        },
      });
      result.details = {
        lockfile: `${lock.format} ${lock.lockfileVersion}`,
        ...comparison.summary,
        findings: comparison.findings,
        unaccounted: scan.unaccounted,
        links: scan.links,
        retargetedLinks: retargetedLinks(scan.packageLinks, scan.packages, lock.links),
        caches: scan.caches,
        errors: scan.errors,
      };
      // Stray files outside packages are reported but do not fail: nothing
      // verified loads them.  Links that swap in other code do.
      result.passed = comparison.passed && scan.errors.length === 0 && scan.links.length === 0 && result.details.retargetedLinks.length === 0 && foreignCacheFiles(scan.caches).length === 0;
    } catch (error) {
      result.details.error = error.message;
    }

    return result;
  }

  /**
   * Verify a globally installed package directory (e.g. npm or pm2 under
   * <prefix>/lib/node_modules) and every dependency installed beneath it.
   *
   * Packages that ship inside the official Node.js archive (npm, corepack)
   * are compared with that archive when the installed version is the one
   * the release shipped; everything else is compared with the registry
   * tarball named by registry metadata.
   *
   * @param {string} packageDir
   * @param {Object} [options]
   * @param {{version: string, platform: string, arch: string}} [options.node]
   *   Release whose archive is the reference for bundled npm/corepack (default: the running Node.js).
   * @returns {Promise<{name: string, passed: boolean, details: Object}>}
   */
  async verifyGlobalPackage(packageDir, options = {}) {
    const result = {name: `${path.basename(packageDir)}-release`, passed: false, details: {packageDir}};
    try {
      if (!exists(path.join(packageDir, 'package.json'))) {
        result.details.installed = false;
        result.details.error = 'not installed';
        return result;
      }

      const realDir = fs.realpathSync(packageDir);
      if (realDir !== path.resolve(packageDir)) {
        result.details.linkedTo = realDir;
      }

      packageDir = realDir;
      const name = path.basename(packageDir);
      const belongs = relativePath => relativePath === name || relativePath.startsWith(`${name}/`);
      const scan = await this.scanInstalledPackages(path.dirname(packageDir), {includeFiles: item => belongs(item.path)});
      // The parent directory holds other global packages; judge only this one.
      const installed = scan.packages.filter(item => belongs(item.path));
      const errors = scan.errors.filter(error => belongs(error.path));
      const links = scan.links.filter(link => belongs(link.path));
      const caches = scan.caches.filter(cache => belongs(cache.path));
      const self = installed.find(item => item.path === name);
      if (!self) {
        throw new Error('Not a package directory');
      }

      const node = options.node || {version: process.version, platform: process.platform, arch: process.arch};
      let archive = null;
      if (nodeReleaseTarget(node.platform, node.arch).platform !== 'win') {
        try {
          archive = await this.getOfficialNodeArchive(node);
        } catch (error) {
          result.details.nodeArchiveError = error.message;
        }
      }

      const manifestProvider = async item => {
        const prefix = `lib/node_modules/${item.path}`;
        if (!archive || archive.versions[prefix] !== item.version) {
          return null;
        }

        const files = new Map();
        for (const [filePath, hash] of Object.entries(archive.files)) {
          if (filePath.startsWith(`${prefix}/`)) {
            const relativePath = filePath.slice(prefix.length + 1);
            if (!relativePath.startsWith('node_modules/')) {
              files.set(relativePath, hash);
            }
          }
        }

        return packageManifestFromFiles(files);
      };

      const comparison = await this.comparePackages({installed, manifestProvider});
      result.details = {
        ...result.details, version: self.version, ...comparison.summary, findings: comparison.findings, links, caches, errors,
      };
      result.passed = comparison.passed && errors.length === 0 && links.length === 0 && foreignCacheFiles(caches).length === 0;
    } catch (error) {
      result.details.error = error.message;
    }

    return result;
  }

  /**
   * Global package directory for a Node.js installation.
   * @param {string} [execPath=process.execPath]
   * @param {string} [platform=process.platform]
   * @returns {string}
   */
  static globalModulesDir(execPath = process.execPath, platform = process.platform) {
    const prefix = platform === 'win32' ? path.dirname(execPath) : path.dirname(path.dirname(execPath));
    return platform === 'win32' ? path.join(prefix, 'node_modules') : path.join(prefix, 'lib', 'node_modules');
  }

  // ─── 3. everything ────────────────────────────────────────────────

  /**
   * @param {Object} [options]
   * @param {boolean} [options.checkNode=true]
   * @param {Object} [options.node] - {execPath, version, platform, arch} of the Node.js to verify (default: this process)
   * @param {string} [options.globalDir] - global node_modules directory (default: derived from node.execPath)
   * @param {string[]} [options.globalPackages=['npm','pnpm','pm2']]
   * @param {boolean} [options.modules=true]
   * @returns {Promise<Object>}
   */
  async verifyAll(options = {}) {
    const node = {
      execPath: process.execPath,
      version: process.version,
      platform: process.platform,
      arch: process.arch,
      ...options.node,
    };
    const report = {
      timestamp: new Date().toISOString(),
      platform: node.platform,
      arch: node.arch,
      nodeVersion: node.version,
      checks: {},
    };

    if (options.checkNode !== false) {
      report.checks.nodeRelease = await this.verifyNodeRelease(node);
    }

    const globalDir = options.globalDir || ReleaseVerification.globalModulesDir(node.execPath, node.platform);
    for (const name of options.globalPackages || ['npm', 'pnpm', 'pm2']) {
      if (!isValidPackageName(name)) {
        throw new TypeError(`Invalid package name: ${name}`);
      }

      const check = await this.verifyGlobalPackage(path.join(globalDir, name), {node});
      if (check.details.installed !== false) {
        report.checks[`${name}Release`] = check;
      }
    }

    if (options.modules !== false) {
      report.checks.moduleIntegrity = await this.verifyModules();
    }

    const checks = Object.values(report.checks);
    report.passed = checks.length > 0 && checks.every(check => check.passed);
    report.summary = `${checks.filter(check => check.passed).length}/${checks.length} release checks passed`;
    return report;
  }
}

ReleaseVerification.parseLockfile = parseLockfile;
ReleaseVerification.parseShasums = parseShasums;
ReleaseVerification.githubCommitOf = githubCommitOf;
ReleaseVerification.filesNeeded = filesNeeded;
ReleaseVerification.retargetedLinks = retargetedLinks;
ReleaseVerification.foreignCacheFiles = foreignCacheFiles;
ReleaseVerification.verifyIntegrity = verifyIntegrity;
ReleaseVerification.filesTouchedByPatch = filesTouchedByPatch;
ReleaseVerification.applyPatch = applyPatch;
ReleaseVerification.packageManifestFromFiles = packageManifestFromFiles;
ReleaseVerification.nodeReleaseTarget = nodeReleaseTarget;
ReleaseVerification.isValidPackageName = isValidPackageName;

module.exports = ReleaseVerification;

/**
 * Attestium - .NET packages (NuGet)
 *
 * Attester: a published .NET application (the directory holding
 * <app>.deps.json and <app>.runtimeconfig.json) is hashed file by file.
 *
 * Verifier: packages.lock.json (RestorePackagesWithLockFile) pins each
 * package's content hash, the SHA-512 of the .nupkg.  Every locked package
 * is downloaded and checked, and each assembly or native library in the
 * published directory must be a file one of them ships, unchanged.  Files
 * the build produces (the application's own assembly, its apphost,
 * deps.json and runtimeconfig.json, which decide what the runtime loads)
 * are verified by reproducing the build.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {walkTree} = require('../file-tree');
const {readZipFiles, listZip} = require('../zip');
const {
  sha256, parallelMap, exists, setOwn,
} = require('../util');
const {NoLockfileError, collect, scanIssues} = require('./common');

// Case does not matter: the runtime loads Evil.DLL as it loads evil.dll.
const CODE = /\.(?:dll|exe|so|dylib|a)$|\.so\.\d/i;
const NOT_CODE = /\.(?:pdb|xml|md|txt)$/i;

/**
 * Published application directories under a project root.
 * @param {string} root
 * @returns {string[]}
 */
function detect(root) {
  const found = [];
  const visit = (directory, depth) => {
    let entries = [];
    try {
      entries = fs.readdirSync(directory, {withFileTypes: true});
    } catch {
      return;
    }

    if (entries.some(entry => entry.isFile() && entry.name.endsWith('.runtimeconfig.json')) && entries.some(entry => entry.isFile() && entry.name.endsWith('.deps.json'))
      && (/(?:^|\/)(?:publish|out)$/.test(directory.split(path.sep).join('/')) || depth === 0)) {
      found.push(directory);
      return;
    }

    // Deep enough for <repo>/src/<project>/bin/Release/<tfm>/<rid>/publish.
    if (depth >= 8) {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory() && !['.git', 'node_modules', 'obj', '.venv'].includes(entry.name)) {
        visit(path.join(directory, entry.name), depth + 1);
      }
    }
  };

  visit(root, 0);
  return found.filter(directory => directory !== root);
}

function installRoot(directory) {
  return directory;
}

async function scan(directory) {
  directory = path.resolve(directory);
  const walk = await walkTree(directory);
  const packages = [];
  const other = {};
  for (const entry of walk.entries) {
    const hash = entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256;
    if (CODE.test(entry.path)) {
      packages.push({
        name: path.posix.basename(entry.path), version: null, path: entry.path, files: {[entry.path]: hash},
      });
    } else {
      setOwn(other, entry.path, hash);
    }
  }

  return {
    packages, unaccounted: [], links: [], caches: [], errors: walk.errors, meta: {other},
  };
}

/**
 * Locked packages from every packages.lock.json in a repository (one per
 * project).
 */
function readLock(repoDir, options = {}) {
  const files = [];
  if (options.lockfile) {
    files.push(options.lockfile);
  } else {
    const visit = (relative, depth) => {
      let entries = [];
      try {
        entries = fs.readdirSync(path.join(repoDir, relative), {withFileTypes: true});
      } catch {
        return;
      }

      for (const entry of entries) {
        const child = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isFile() && entry.name === 'packages.lock.json') {
          files.push(child);
        } else if (entry.isDirectory() && depth < 4 && !['.git', 'node_modules', 'bin', 'obj'].includes(entry.name)) {
          visit(child, depth + 1);
        }
      }
    };

    visit('', 0);
  }

  if (files.length === 0 || !files.every(file => exists(path.join(repoDir, file)))) {
    throw new NoLockfileError('No packages.lock.json found (set RestorePackagesWithLockFile)');
  }

  const packages = new Map();
  for (const file of files) {
    const lock = JSON.parse(fs.readFileSync(path.join(repoDir, file), 'utf8'));
    for (const target of Object.values(lock.dependencies || {})) {
      for (const [id, entry] of Object.entries(target || {})) {
        if (entry && entry.type !== 'Project' && typeof entry.resolved === 'string' && typeof entry.contentHash === 'string') {
          packages.set(`${id.toLowerCase()}/${entry.resolved.toLowerCase()}`, {id, version: entry.resolved, contentHash: entry.contentHash});
        }
      }
    }
  }

  return {format: 'nuget', file: files.join(', '), packages};
}

/**
 * NuGet's content hash of a package: SHA-512 (base64) of the .nupkg, or,
 * for a signed package, of the archive as it would be without its
 * signature file (.signature.p7s), with the zip directory adjusted to
 * match (NuGet's SignedPackageArchiveUtility.GetPackageContentHash).
 *
 * @param {Buffer} buffer
 * @returns {string}
 */
function contentHash(buffer) {
  const entries = listZip(buffer);
  const signature = entries.find(entry => entry.name === '.signature.p7s');
  if (!signature) {
    return crypto.createHash('sha512').update(buffer).digest('base64');
  }

  // Where each central directory record is, and how long each local entry is.
  let end = -1;
  for (let index = buffer.length - 22; index >= 0; index--) {
    if (buffer.readUInt32LE(index) === 0x06_05_4B_50) {
      end = index;
      break;
    }
  }

  const centralStart = buffer.readUInt32LE(end + 16);
  const records = [];
  let cursor = centralStart;
  for (const entry of entries) {
    const headerSize = 46 + buffer.readUInt16LE(cursor + 28) + buffer.readUInt16LE(cursor + 30) + buffer.readUInt16LE(cursor + 32);
    const flags = buffer.readUInt16LE(cursor + 8);
    const local = entry.localOffset;
    let total = 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28) + entry.compressedSize;
    if (flags & 0x08) {
      // Data descriptor, with or without its optional signature.
      total += buffer.readUInt32LE(local + total) === 0x08_07_4B_50 ? 16 : 12;
    }

    records.push({
      entry, position: cursor, headerSize, total, offset: local,
    });
    cursor += headerSize;
  }

  const signed = records.find(record => record.entry === signature);
  const others = records.filter(record => record !== signed).sort((a, b) => a.offset - b.offset);
  const hash = crypto.createHash('sha512');
  const u16 = value => {
    const bytes = Buffer.alloc(2);
    bytes.writeUInt16LE(value);
    return bytes;
  };

  const u32 = value => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value >>> 0);
    return bytes;
  };

  hash.update(buffer.subarray(0, others[0].offset));
  for (const record of others) {
    hash.update(buffer.subarray(record.offset, record.offset + record.total));
  }

  for (const record of [...others].sort((a, b) => a.position - b.position)) {
    hash.update(buffer.subarray(record.position, record.position + 42));
    const change = record.offset > signed.offset ? -signed.total : 0;
    hash.update(u32(buffer.readUInt32LE(record.position + 42) + change));
    hash.update(buffer.subarray(record.position + 46, record.position + record.headerSize));
  }

  hash.update(buffer.subarray(end, end + 8));
  hash.update(u16(buffer.readUInt16LE(end + 8) - 1));
  hash.update(u16(buffer.readUInt16LE(end + 10) - 1));
  hash.update(u32(buffer.readUInt32LE(end + 12) - signed.headerSize));
  hash.update(u32(buffer.readUInt32LE(end + 16) - signed.total));
  hash.update(buffer.subarray(end + 20));
  return hash.digest('base64');
}

/**
 * Runtime code a package ships (assemblies and native libraries under lib/
 * and runtimes/), by file name.  Only code names are indexed, which also
 * keeps names such as __proto__ or constructor out of the plain object.
 * @param {Buffer} buffer - .nupkg
 * @returns {Object<string, string[]>} basename -> SHA-256 values
 */
function packageFiles(buffer) {
  const index = {};
  for (const [file, content] of readZipFiles(buffer, {filter: name => /^(?:lib|runtimes)\//i.test(name) && CODE.test(name)})) {
    const base = path.posix.basename(file);
    (index[base] ||= []).push(sha256(content));
  }

  return index;
}

async function compare({scan: installed, lock, store, covered = () => false}) {
  const issues = [];
  if (!lock) {
    return collect(installed.packages.filter(item => !covered(item.path)).map(item => ({status: 'failed', item, reason: 'no packages.lock.json pins the application\'s packages'})), scanIssues(installed));
  }

  const indexes = await parallelMap([...lock.packages.values()].map(locked => async () => {
    try {
      return await store.memo(`nuget-package:v1:${locked.id.toLowerCase()}/${locked.version.toLowerCase()}:${locked.contentHash}`, async () => {
        const id = locked.id.toLowerCase();
        const version = locked.version.toLowerCase();
        const buffer = await store.get(`${store.urls.nuget}/${encodeURIComponent(id)}/${encodeURIComponent(version)}/${encodeURIComponent(id)}.${encodeURIComponent(version)}.nupkg`, {maxBytes: 1024 * 1024 * 1024});
        if (contentHash(buffer) !== locked.contentHash) {
          throw new Error(`Downloaded ${locked.id} ${locked.version} does not match its content hash`);
        }

        return {package: `${locked.id}@${locked.version}`, files: packageFiles(buffer)};
      });
    } catch (error) {
      return {package: `${locked.id}@${locked.version}`, error: error.message};
    }
  }), store.concurrency);
  const failedDownloads = indexes.filter(index => index.error);
  if (failedDownloads.length > 0) {
    issues.push({severity: failedDownloads.some(index => /does not match/.test(index.error)) ? 'fail' : 'error', message: 'Locked packages that could not be checked', items: failedDownloads.map(index => `${index.package}: ${index.error}`)});
  }

  const results = installed.packages.filter(item => !covered(item.path)).map(item => {
    const base = path.posix.basename(item.path);
    const hash = item.files[item.path];
    const source = indexes.find(index => index.files && (index.files[base] || []).includes(hash));
    if (source) {
      return {status: 'verified', item: {...item, name: base, version: source.package}};
    }

    return {status: 'failed', item, reason: indexes.some(index => index.files && index.files[base]) ? 'differs from the file of the same name in the locked packages' : 'no locked package ships this file, and no build reproduces it'};
  });

  const uncovered = Object.keys(installed.meta.other || {}).filter(file => !covered(file) && !NOT_CODE.test(file));
  if (uncovered.length > 0) {
    issues.push({severity: 'warn', message: 'Build output that decides what the runtime loads (deps.json, runtimeconfig.json) is not compared; reproduce the build to verify it', items: uncovered.sort()});
  }

  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

module.exports = {
  name: 'nuget',
  label: 'NuGet',
  lockfiles: ['packages.lock.json'],
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  packageFiles,
  contentHash,
};

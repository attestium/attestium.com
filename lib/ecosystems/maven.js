/**
 * Attestium - Java libraries (Maven Central; Gradle and Maven builds)
 *
 * Attester: directories of jars a JVM application loads (Gradle's
 * build/install/<app>/lib, Maven's target/lib or target/dependency, a
 * web application's WEB-INF/lib) are hashed jar by jar, and each jar's
 * Maven coordinates are read from its META-INF/maven/.../pom.properties.
 *
 * Verifier: jars are copied unchanged from the repository, so each jar's
 * SHA-256 must be one the build pinned: Gradle's dependency verification
 * metadata (gradle/verification-metadata.xml) or a Maven lockfile
 * (lockfile.json from maven-lockfile).  A jar the build does not pin is
 * compared with the one Maven Central serves for its coordinates, which
 * trusts the registry instead of the repository.
 *
 * The application's own jar is build output: verify it by reproducing the
 * build.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {hashFile} = require('../file-tree');
const {readZipFiles} = require('../zip');
const {sha256, parallelMap, exists} = require('../util');
const {NoLockfileError, collect, scanIssues} = require('./common');

const LOCKFILES = ['gradle/verification-metadata.xml', 'lockfile.json'];
// The JVM's lib/* class path wildcard takes .jar and .JAR alike.
const JAR = /\.(?:jar|war)$/i;

function detect(root) {
  // Where builds and deployments put dependency jars: Maven's copy and
  // assembly plugins, Gradle's installDist, unpacked wars, and plain lib/.
  const candidates = [path.join(root, 'target', 'lib'), path.join(root, 'target', 'dependency'), path.join(root, 'lib'), path.join(root, 'libs')];
  for (const base of [path.join(root, 'build', 'install')]) {
    try {
      for (const name of fs.readdirSync(base)) {
        candidates.push(path.join(base, name, 'lib'));
      }
    } catch {}
  }

  for (const base of [path.join(root, 'target'), path.join(root, 'build', 'libs')]) {
    try {
      for (const name of fs.readdirSync(base)) {
        candidates.push(path.join(base, name, 'WEB-INF', 'lib'));
      }
    } catch {}
  }

  return candidates.filter(directory => {
    try {
      return fs.readdirSync(directory).some(name => JAR.test(name));
    } catch {
      return false;
    }
  });
}

function installRoot(directory) {
  return directory;
}

/**
 * The Maven coordinates a jar declares for itself (only when it declares
 * exactly one: a jar with several shades other artifacts in).
 * @param {Buffer} buffer
 * @returns {{groupId: string, artifactId: string, version: string}|null}
 */
function coordinates(buffer) {
  let files;
  try {
    files = readZipFiles(buffer, {filter: name => /^META-INF\/maven(?:\/[^/]+){2}\/pom\.properties$/.test(name), maxUncompressedBytes: 1024 * 1024});
  } catch {
    return null;
  }

  if (files.size !== 1) {
    return null;
  }

  const properties = {};
  for (const line of [...files.values()][0].toString('utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*(groupId|artifactId|version)\s*[=:]\s*(\S+)\s*$/);
    if (match) {
      properties[match[1]] = match[2];
    }
  }

  return properties.groupId && properties.artifactId && properties.version ? properties : null;
}

async function scan(directory) {
  directory = path.resolve(directory);
  const errors = [];
  const unaccounted = [];
  let names = [];
  try {
    names = (await fs.promises.readdir(directory, {withFileTypes: true})).sort((a, b) => (a.name > b.name) - (a.name < b.name));
  } catch (error) {
    errors.push({path: '.', error: error.code});
  }

  const jars = names.filter(entry => entry.isFile() && JAR.test(entry.name)).map(entry => entry.name);
  for (const entry of names) {
    if (!jars.includes(entry.name)) {
      unaccounted.push(entry.isDirectory() ? `${entry.name}/` : entry.name);
    }
  }

  const packages = await parallelMap(jars.map(name => async () => {
    const file = path.join(directory, name);
    try {
      const {sha256: hash} = await hashFile(file);
      const found = coordinates(await fs.promises.readFile(file));
      return {
        name: found ? `${found.groupId}:${found.artifactId}` : name, version: found ? found.version : null, path: name, files: {[name]: hash}, meta: found ? {coordinates: found} : {},
      };
    } catch (error) {
      errors.push({path: name, error: error.code || error.message});
      return null;
    }
  }), 8);
  return {
    packages: packages.filter(Boolean), unaccounted, links: [], caches: [], errors, meta: {},
  };
}

/**
 * Pinned artifacts from Gradle's verification metadata.
 * @param {string} text
 * @returns {Map<string, Set<string>>} artifact file name -> SHA-256 values
 */
function parseVerificationMetadata(text) {
  const pinned = new Map();
  let artifact = null;
  for (const match of text.matchAll(/<(\/?)([\w-]+)((?:\s+[\w:-]+="[^"]*")*)\s*(\/?)>/g)) {
    const [, closing, tag, attributes, selfClosing] = match;
    const attribute = name => (attributes.match(new RegExp(`\\s${name}="([^"]*)"`)) || [])[1];
    if (tag === 'artifact') {
      artifact = closing ? null : attribute('name');
      if (artifact && !pinned.has(artifact)) {
        pinned.set(artifact, new Set());
      }

      if (selfClosing) {
        artifact = null;
      }
    } else if (artifact && (tag === 'sha256' || tag === 'also-trust') && !closing) {
      const value = attribute('value');
      if (/^[\da-f]{64}$/i.test(value || '')) {
        pinned.get(artifact).add(value.toLowerCase());
      }
    }
  }

  return pinned;
}

/**
 * Pinned artifacts from maven-lockfile's lockfile.json.
 * @param {Object} lock
 * @returns {Map<string, Set<string>>}
 */
function parseMavenLockfile(lock) {
  const pinned = new Map();
  const visit = dependency => {
    if (!dependency || typeof dependency !== 'object') {
      return;
    }

    if (dependency.artifactId && dependency.version && /^sha-?256$/i.test(dependency.checksumAlgorithm || '') && /^[\da-f]{64}$/i.test(dependency.checksum || '')) {
      const name = `${dependency.artifactId}-${dependency.version}${dependency.classifier ? `-${dependency.classifier}` : ''}.${dependency.type || 'jar'}`;
      if (!pinned.has(name)) {
        pinned.set(name, new Set());
      }

      pinned.get(name).add(dependency.checksum.toLowerCase());
    }

    for (const child of dependency.children || []) {
      visit(child);
    }
  };

  for (const dependency of lock.dependencies || []) {
    visit(dependency);
  }

  return pinned;
}

function readLock(repoDir, options = {}) {
  const candidates = options.lockfile ? [options.lockfile] : LOCKFILES;
  const file = candidates.find(name => exists(path.join(repoDir, name)));
  if (!file) {
    throw new NoLockfileError(`No pinned Java dependencies found (${candidates.join(', ')})`);
  }

  const text = fs.readFileSync(path.join(repoDir, file), 'utf8');
  return file.endsWith('.xml')
    ? {format: 'gradle-verification-metadata', file, pinned: parseVerificationMetadata(text)}
    : {format: 'maven-lockfile', file, pinned: parseMavenLockfile(JSON.parse(text))};
}

function centralHash(store, found) {
  const {groupId, artifactId, version} = found;
  return store.memo(`maven-central:v1:${groupId}:${artifactId}:${version}`, async () => {
    const url = `${store.urls.maven}/${groupId.split('.').map(part => encodeURIComponent(part)).join('/')}/${encodeURIComponent(artifactId)}/${encodeURIComponent(version)}/${encodeURIComponent(artifactId)}-${encodeURIComponent(version)}.jar`;
    return sha256(await store.get(url, {maxBytes: 512 * 1024 * 1024}));
  });
}

/**
 * @param {Object} input
 * @param {Object} input.scan
 * @param {Object|null} input.lock
 * @param {Object} input.store
 * @param {(file: string) => boolean} [input.covered] - jars another reference verifies (the application's own)
 * @returns {Promise<Object>}
 */
async function compare({scan: installed, lock, store, covered = () => false}) {
  const unpinned = [];
  const results = await parallelMap(installed.packages.filter(item => !covered(item.path)).map(item => async () => {
    const hash = item.files[item.path];
    const pinned = lock ? lock.pinned.get(item.path) : null;
    if (pinned) {
      return pinned.has(hash) ? {status: 'verified', item} : {status: 'failed', item, reason: 'the jar differs from the one the build pinned'};
    }

    if (!item.meta.coordinates) {
      return {status: 'failed', item, reason: 'the build pins no jar of this name, and the jar names no Maven coordinates'};
    }

    try {
      const central = await centralHash(store, item.meta.coordinates);
      if (central === hash) {
        unpinned.push(item.path);
        return {status: 'verified', item};
      }

      return {status: 'failed', item, reason: 'the jar differs from Maven Central\'s for its coordinates'};
    } catch (error) {
      return {status: 'error', item, reason: `could not fetch it from Maven Central: ${error.message}`};
    }
  }), store.concurrency);
  const issues = [];
  if (unpinned.length > 0) {
    issues.push({severity: 'warn', message: 'Jars the build does not pin were compared with Maven Central (pin them with Gradle dependency verification or maven-lockfile)', items: unpinned.sort()});
  }

  // A link named like a jar is loaded like one (java -cp 'lib/*').
  const jarLike = installed.unaccounted.filter(name => JAR.test(name));
  if (jarLike.length > 0) {
    issues.push({severity: 'fail', message: 'Links or other entries named like jars, which the JVM may load, that are not regular files', items: jarLike});
  }

  const other = installed.unaccounted.filter(name => !JAR.test(name));
  if (other.length > 0) {
    issues.push({severity: 'warn', message: 'Other files next to the jars', items: other});
  }

  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

module.exports = {
  name: 'maven',
  label: 'Maven',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  coordinates,
  parseVerificationMetadata,
  parseMavenLockfile,
};

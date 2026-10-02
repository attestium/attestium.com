/**
 * Attestium - a TUF client for Sigstore's trust roots
 *
 * Sigstore publishes its trusted root (certificate authorities and
 * transparency log keys) and npm's registry signing keys through The Update
 * Framework, so they can be rotated without trusting whoever serves them:
 * every root version is signed by a threshold of the previous root's keys
 * and its own, and every other file is reached through timestamp, snapshot
 * and targets metadata signed by the roles the root names.
 *
 * This client implements the TUF 1.0 update workflow for a repository with
 * consistent snapshots: root rotation, expiry, rollback and threshold
 * checks, length and hash checks, and delegated targets (one level, as
 * Sigstore's repository uses).  Every verified root version, and the newest
 * timestamp and snapshot, are cached.  An initial root is shipped with the
 * library, and a cached root is used only when it chains from it.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {httpGet} = require('./http');

const MAX_ROOT_ROTATIONS = 256;

class TufError extends Error {}

/**
 * OLPC canonical JSON, which TUF signs: sorted keys, no whitespace, strings
 * with only backslash and double quote escaped.
 * @param {*} value
 * @returns {string}
 */
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') {
    return String(value);
  }

  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new TufError('canonical JSON has no floating point numbers');
    }

    return String(value);
  }

  if (typeof value === 'string') {
    return `"${value.replaceAll('\\', '\\\\').replaceAll('"', String.raw`\"`)}"`;
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalJson(item)).join(',')}]`;
  }

  return `{${Object.keys(value).sort().map(key => `${canonicalJson(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

/**
 * A TUF public key as a KeyObject.
 */
function publicKey(key) {
  const value = key.keyval && key.keyval.public;
  if (typeof value !== 'string') {
    throw new TufError('key has no public value');
  }

  if (value.includes('BEGIN PUBLIC KEY')) {
    return crypto.createPublicKey(value);
  }

  // Early Sigstore roots give P-256 keys as hex-encoded uncompressed points.
  if (key.keytype.startsWith('ecdsa') && /^04[\da-f]{128}$/i.test(value)) {
    return crypto.createPublicKey({key: Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Buffer.from(value, 'hex')]), format: 'der', type: 'spki'});
  }

  if (key.keytype === 'ed25519' && /^[\da-f]{64}$/i.test(value)) {
    return crypto.createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(value, 'hex')]), format: 'der', type: 'spki'});
  }

  throw new TufError(`unsupported key ${key.keytype}/${key.scheme}`);
}

/**
 * Verify that `metadata` is signed by a threshold of a role's keys.
 * @param {Object} metadata - {signed, signatures}
 * @param {Object<string, Object>} keys - keyid -> key
 * @param {{keyids: string[], threshold: number}} role
 * @param {string} name
 */
function verifyThreshold(metadata, keys, role, name) {
  if (!Number.isInteger(role.threshold) || role.threshold < 1) {
    throw new TufError(`${name} has an invalid threshold`);
  }

  const data = Buffer.from(canonicalJson(metadata.signed), 'utf8');
  const valid = new Set();
  // Distinct keys, not key ids: one key listed under two ids counts once.
  const signers = new Set();
  for (const signature of metadata.signatures || []) {
    if (!role.keyids.includes(signature.keyid) || valid.has(signature.keyid) || !Object.hasOwn(keys, signature.keyid)) {
      continue;
    }

    const key = keys[signature.keyid];
    try {
      const algorithm = key.scheme === 'ed25519' ? null : 'sha256';
      const object = publicKey(key);
      const material = object.export({type: 'spki', format: 'der'}).toString('hex');
      if (!signers.has(material) && crypto.verify(algorithm, data, object, Buffer.from(signature.sig, 'hex'))) {
        valid.add(signature.keyid);
        signers.add(material);
      }
    } catch {}
  }

  if (valid.size < role.threshold) {
    throw new TufError(`${name} has ${valid.size} valid signature(s), needs ${role.threshold}`);
  }
}

class TufClient {
  /**
   * @param {Object} options
   * @param {string} options.metadataUrl
   * @param {string} [options.targetsUrl] - default: <metadataUrl>/targets
   * @param {Object} options.initialRoot - a root.json trusted to start from
   * @param {string} [options.cacheDir] - keeps the newest verified metadata
   * @param {Object} [options.httpOptions]
   * @param {() => Date} [options.now]
   */
  constructor(options) {
    this.metadataUrl = options.metadataUrl.replace(/\/+$/, '');
    this.targetsUrl = (options.targetsUrl || `${this.metadataUrl}/targets`).replace(/\/+$/, '');
    this.initialRoot = options.initialRoot;
    this.cacheDir = options.cacheDir || null;
    this.httpOptions = options.httpOptions || {};
    this.now = options.now || (() => new Date());
    this._refresh = null;
  }

  _cached(name) {
    if (!this.cacheDir) {
      return null;
    }

    try {
      return JSON.parse(fs.readFileSync(path.join(this.cacheDir, name), 'utf8'));
    } catch {
      return null;
    }
  }

  _store(name, metadata) {
    if (this.cacheDir) {
      fs.mkdirSync(this.cacheDir, {recursive: true, mode: 0o700});
      fs.writeFileSync(path.join(this.cacheDir, name), JSON.stringify(metadata), {mode: 0o600});
    }
  }

  async _fetch(url, maxBytes) {
    return httpGet(url, {...this.httpOptions, maxBytes});
  }

  _checkExpiry(metadata, name) {
    if (Date.parse(metadata.signed.expires) <= this.now().getTime()) {
      throw new TufError(`${name} metadata has expired`);
    }
  }

  _checkType(metadata, type) {
    if (!metadata || !metadata.signed || metadata.signed._type !== type) {
      throw new TufError(`expected ${type} metadata`);
    }
  }

  /**
   * Run the update workflow once; later calls reuse the result.
   * @returns {Promise<{root: Object, targets: Object, delegated: Map<string, Object>}>}
   */
  refresh() {
    this._refresh ||= this._update();
    this._refresh.catch(() => {
      this._refresh = null;
    });
    return this._refresh;
  }

  /**
   * Check a new root against the root it follows (TUF 5.3.4 to 5.3.6).
   */
  _verifyRoot(next, root) {
    this._checkType(next, 'root');
    verifyThreshold(next, root.signed.keys, root.signed.roles.root, `root v${next.signed.version} (by the previous root)`);
    verifyThreshold(next, next.signed.keys, next.signed.roles.root, `root v${next.signed.version} (by itself)`);
    if (next.signed.version !== root.signed.version + 1) {
      throw new TufError('root version did not increase by one');
    }
  }

  /**
   * Cached metadata of a role, or null when there is none or it is not
   * signed by the role's current keys (a rotated key invalidates it).  Its
   * expiry does not matter: it only serves rollback checks.
   */
  _trusted(name, type, keys, role) {
    const metadata = this._cached(name);
    try {
      this._checkType(metadata, type);
      verifyThreshold(metadata, keys, role, name);
      return metadata;
    } catch {
      return null;
    }
  }

  async _update() {
    // ── root ──
    // Every root follows from the shipped one: each next version is taken
    // from the cache when it verifies against the root before it, and
    // fetched otherwise.  A cached root is never trusted on its own.
    let root = this.initialRoot;
    for (let rotation = 0; rotation < MAX_ROOT_ROTATIONS; rotation++) {
      const name = `${root.signed.version + 1}.root.json`;
      const cached = this._cached(name);
      if (cached) {
        try {
          this._verifyRoot(cached, root);
          root = cached;
          continue;
        } catch {}
      }

      let next;
      try {
        next = JSON.parse((await this._fetch(`${this.metadataUrl}/${name}`, 512 * 1024)).toString('utf8'));
      } catch (error) {
        if (error.statusCode === 404 || error.statusCode === 403) {
          break;
        }

        throw error;
      }

      this._verifyRoot(next, root);
      root = next;
      this._store(name, root);
    }

    this._checkExpiry(root, 'root');
    const {keys, roles} = root.signed;

    // ── timestamp ──
    const timestamp = JSON.parse((await this._fetch(`${this.metadataUrl}/timestamp.json`, 64 * 1024)).toString('utf8'));
    this._checkType(timestamp, 'timestamp');
    verifyThreshold(timestamp, keys, roles.timestamp, 'timestamp');
    const snapshotMeta = timestamp.signed.meta['snapshot.json'];
    const trustedTimestamp = this._trusted('timestamp.json', 'timestamp', keys, roles.timestamp);
    if (trustedTimestamp) {
      if (timestamp.signed.version < trustedTimestamp.signed.version) {
        throw new TufError('timestamp version went backwards');
      }

      if (snapshotMeta.version < trustedTimestamp.signed.meta['snapshot.json'].version) {
        throw new TufError('snapshot version went backwards');
      }
    }

    this._checkExpiry(timestamp, 'timestamp');
    this._store('timestamp.json', timestamp);

    // ── snapshot ──
    const snapshotRaw = await this._fetch(`${this.metadataUrl}/${snapshotMeta.version}.snapshot.json`, snapshotMeta.length || 2 * 1024 * 1024);
    checkHashes(snapshotRaw, snapshotMeta, 'snapshot');
    const snapshot = JSON.parse(snapshotRaw.toString('utf8'));
    this._checkType(snapshot, 'snapshot');
    verifyThreshold(snapshot, keys, roles.snapshot, 'snapshot');
    if (snapshot.signed.version !== snapshotMeta.version) {
      throw new TufError('snapshot version does not match the timestamp');
    }

    const trustedSnapshot = this._trusted('snapshot.json', 'snapshot', keys, roles.snapshot);
    if (trustedSnapshot) {
      if (snapshot.signed.version < trustedSnapshot.signed.version) {
        throw new TufError('snapshot version went backwards');
      }

      // Targets metadata listed before stays listed, at no older version.
      for (const [file, meta] of Object.entries(trustedSnapshot.signed.meta)) {
        const listed = snapshot.signed.meta[file];
        if (!listed) {
          throw new TufError(`snapshot no longer lists ${file}`);
        }

        if (listed.version < meta.version) {
          throw new TufError(`${file} version went backwards`);
        }
      }
    }

    this._checkExpiry(snapshot, 'snapshot');
    this._store('snapshot.json', snapshot);

    // ── targets ──
    const targetsMeta = snapshot.signed.meta['targets.json'];
    const targetsRaw = await this._fetch(`${this.metadataUrl}/${targetsMeta.version}.targets.json`, targetsMeta.length || 8 * 1024 * 1024);
    checkHashes(targetsRaw, targetsMeta, 'targets');
    const targets = JSON.parse(targetsRaw.toString('utf8'));
    this._checkType(targets, 'targets');
    verifyThreshold(targets, keys, roles.targets, 'targets');
    if (targets.signed.version !== targetsMeta.version) {
      throw new TufError('targets version does not match the snapshot');
    }

    this._checkExpiry(targets, 'targets');

    return {
      root, snapshot, targets, delegated: new Map(),
    };
  }

  /**
   * Download a target file, verified against its targets metadata.
   *
   * @param {string} name - e.g. "trusted_root.json" or "registry.npmjs.org/keys.json"
   * @returns {Promise<Buffer>}
   */
  async target(name) {
    const state = await this.refresh();
    let info = state.targets.signed.targets[name];
    if (!info) {
      // One level of delegation: the first role whose paths match.
      const delegations = state.targets.signed.delegations || {roles: [], keys: {}};
      const role = delegations.roles.find(candidate => (candidate.paths || []).some(pattern => matchPath(pattern, name)));
      if (!role) {
        throw new TufError(`no target named ${name}`);
      }

      if (!state.delegated.has(role.name)) {
        const meta = state.snapshot.signed.meta[`${role.name}.json`];
        if (!meta) {
          throw new TufError(`snapshot does not list ${role.name}`);
        }

        const raw = await this._fetch(`${this.metadataUrl}/${meta.version}.${encodeURIComponent(role.name)}.json`, meta.length || 8 * 1024 * 1024);
        checkHashes(raw, meta, role.name);
        const metadata = JSON.parse(raw.toString('utf8'));
        this._checkType(metadata, 'targets');
        verifyThreshold(metadata, delegations.keys, role, role.name);
        if (metadata.signed.version !== meta.version) {
          throw new TufError(`${role.name} version does not match the snapshot`);
        }

        this._checkExpiry(metadata, role.name);
        state.delegated.set(role.name, metadata);
      }

      info = state.delegated.get(role.name).signed.targets[name];
      if (!info) {
        throw new TufError(`no target named ${name}`);
      }
    }

    const directory = name.includes('/') ? `${name.slice(0, name.lastIndexOf('/'))}/` : '';
    const base = name.slice(name.lastIndexOf('/') + 1);
    const content = await this._fetch(`${this.targetsUrl}/${directory}${info.hashes.sha256}.${base}`, info.length);
    checkHashes(content, info, name);
    return content;
  }
}

/**
 * Length and hashes (sha256, sha512) listed for a file must match.
 */
function checkHashes(content, meta, name) {
  if (meta.length !== undefined && content.length !== meta.length) {
    throw new TufError(`${name} has the wrong length`);
  }

  for (const [algorithm, expected] of Object.entries(meta.hashes || {})) {
    if (!['sha256', 'sha512'].includes(algorithm)) {
      continue;
    }

    if (crypto.createHash(algorithm).update(content).digest('hex') !== expected) {
      throw new TufError(`${name} does not match its ${algorithm} hash`);
    }
  }
}

/**
 * TUF path pattern (shell-style, "*" does not cross "/").
 */
function matchPath(pattern, name) {
  const source = pattern.replaceAll(/[$()+.[\\\]^{|}]/g, String.raw`\$&`).replaceAll('*', '[^/]*').replaceAll('?', '[^/]');
  return new RegExp(`^${source}$`).test(name);
}

module.exports = {
  TufClient, TufError, canonicalJson, verifyThreshold, checkHashes, matchPath,
};

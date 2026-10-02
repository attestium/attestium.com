/**
 * Attestium - container images (verifier side)
 *
 * Reads images from an OCI registry by digest: manifests and layers are
 * content-addressed, so every byte is checked against the digest that
 * names it.  The layers are applied in order (whiteouts included) to give
 * the image's root filesystem as a map of file hashes, which is compared
 * with the files a container is running from.
 *
 * Also lists the Sigstore bundles attached to an image as OCI referrers
 * (cosign --new-bundle-format, actions/attest-build-provenance with
 * push-to-registry).
 *
 * Anonymous pulls with the registry's token flow; credentials can be passed
 * per registry.
 *
 * @license MIT
 */

'use strict';

const buffer = require('node:buffer');
const zlib = require('node:zlib');
const {spawnSync} = require('node:child_process');
const {httpGet} = require('./http');
const {readTar} = require('./tar');
const {sha256} = require('./util');

const INDEX_TYPES = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);
const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');
const BUNDLE_TYPE = /^application\/vnd\.dev\.sigstore\.bundle(?:\.v0\.3\+json|\+json;version=0\.[123])$/;

/**
 * Parse an image reference ("nginx:1.27", "ghcr.io/o/r@sha256:...").
 * @param {string} reference
 * @returns {{registry: string, repository: string, tag: string|null, digest: string|null}}
 */
function parseReference(reference) {
  const match = String(reference).match(/^(?:([\w.-]+(?::\d+)?)\/)?([\w./-]+?)(?::(\w[\w.-]{0,127}))?(?:@(sha256:[\da-f]{64}))?$/);
  if (!match) {
    throw new Error(`Invalid image reference: ${String(reference).slice(0, 200)}`);
  }

  let [, registry, repository] = match;
  // "library/nginx": the first part is a registry only if it looks like a host.
  if (registry && !/[.:]/.test(registry) && registry !== 'localhost') {
    repository = `${registry}/${repository}`;
    registry = undefined;
  }

  registry ||= 'docker.io';
  if (registry === 'docker.io' && !repository.includes('/')) {
    repository = `library/${repository}`;
  }

  return {
    registry, repository, tag: match[3] || null, digest: match[4] || null,
  };
}

class Registry {
  /**
   * @param {Object} [options]
   * @param {Object} [options.httpOptions] - denyPrivateAddresses defaults to true for a
   *   registry with no configured endpoint (a name taken from evidence), and its token service
   * @param {Object<string, string>} [options.endpoints] - registry name -> base URL (default https://<name>; docker.io -> registry-1.docker.io)
   * @param {Object<string, {username: string, password: string}|{token: string}>} [options.credentials]
   */
  constructor(options = {}) {
    this.httpOptions = options.httpOptions || {};
    this.endpoints = {'docker.io': 'https://registry-1.docker.io', ...options.endpoints};
    this.credentials = options.credentials || {};
    this._tokens = new Map();
  }

  _base(registry) {
    return this.endpoints[registry] || `https://${registry}`;
  }

  /**
   * HTTP options for a registry: one evidence names (no endpoint
   * configured) is never reached at a private address, so evidence cannot
   * point the verifier at its own network.
   */
  _httpOptions(registry) {
    return {denyPrivateAddresses: !Object.hasOwn(this.endpoints, registry), ...this.httpOptions};
  }

  /**
   * GET with the registry's bearer token flow.
   */
  async _get(registry, repository, urlPath, {accept, maxBytes}) {
    const url = `${this._base(registry)}/v2/${urlPath}`;
    const key = `${registry}/${repository}`;
    const headers = {accept: accept || '*/*'};
    const credential = this.credentials[registry];
    if (this._tokens.has(key)) {
      headers.authorization = `Bearer ${this._tokens.get(key)}`;
    } else if (credential && credential.token) {
      headers.authorization = `Bearer ${credential.token}`;
    }

    try {
      return await httpGet(url, {
        ...this._httpOptions(registry), headers, maxBytes, maxRetries: 2,
      });
    } catch (error) {
      if (error.statusCode !== 401) {
        throw error;
      }
    }

    // Anonymous (or basic-credentialed) token for pulling this repository;
    // a new one when the one held has expired.
    const challenge = await this._challenge(registry);
    if (!challenge) {
      throw new Error(`${registry} requires authentication`);
    }

    const tokenUrl = `${challenge.realm}?service=${encodeURIComponent(challenge.service || '')}&scope=${encodeURIComponent(`repository:${repository}:pull`)}`;
    const tokenHeaders = {};
    if (credential && credential.username) {
      tokenHeaders.authorization = `Basic ${Buffer.from(`${credential.username}:${credential.password}`).toString('base64')}`;
    }

    const body = JSON.parse((await httpGet(tokenUrl, {...this._httpOptions(registry), headers: tokenHeaders, maxBytes: 1024 * 1024})).toString('utf8'));
    const token = body.token || body.access_token;
    if (!token) {
      throw new Error(`${registry} issued no token`);
    }

    this._tokens.set(key, token);
    return httpGet(url, {
      ...this._httpOptions(registry), headers: {...headers, authorization: `Bearer ${token}`}, maxBytes, maxRetries: 2,
    });
  }

  /**
   * The Bearer challenge of a registry's /v2/ endpoint.
   */
  async _challenge(registry) {
    const url = `${this._base(registry)}/v2/`;
    const header = await new Promise(resolve => {
      const {request} = url.startsWith('https:') ? require('node:https') : require('node:http');
      const {assertAllowedUrl, connectOptions} = require('./http');
      const options = this._httpOptions(registry);
      assertAllowedUrl(new URL(url), options);
      const client = request(url, {
        method: 'GET', timeout: options.timeout ?? 30_000, ca: options.ca, ...connectOptions(options),
      }, response => {
        response.resume();
        resolve(response.headers['www-authenticate'] || null);
      });
      client.on('timeout', () => client.destroy());
      client.on('error', () => resolve(null));
      client.end();
    });
    const match = String(header || '').match(/^bearer\s+(.*)$/i);
    if (!match) {
      return null;
    }

    const fields = {};
    for (const part of match[1].matchAll(/(\w+)="([^"]*)"/g)) {
      fields[part[1]] = part[2];
    }

    return fields.realm ? fields : null;
  }

  /**
   * A manifest or index by digest, checked against the digest.
   * @param {Object} reference - from parseReference, with digest
   * @param {string} [digest] - defaults to reference.digest
   * @returns {Promise<Object>}
   */
  async manifest(reference, digest = reference.digest) {
    if (!/^sha256:[\da-f]{64}$/.test(digest || '')) {
      throw new Error('A manifest is fetched only by digest');
    }

    const body = await this._get(reference.registry, reference.repository, `${reference.repository}/manifests/${digest}`, {accept: MANIFEST_ACCEPT, maxBytes: 8 * 1024 * 1024});
    if (`sha256:${sha256(body)}` !== digest) {
      throw new Error(`Manifest ${digest} does not match its digest`);
    }

    return JSON.parse(body.toString('utf8'));
  }

  /**
   * A blob by digest, checked.
   */
  async blob(reference, digest, maxBytes = 2 * 1024 * 1024 * 1024) {
    if (!/^sha256:[\da-f]{64}$/.test(digest || '')) {
      throw new Error(`Invalid blob digest ${String(digest).slice(0, 80)}`);
    }

    const body = await this._get(reference.registry, reference.repository, `${reference.repository}/blobs/${digest}`, {maxBytes});
    if (`sha256:${sha256(body)}` !== digest) {
      throw new Error(`Blob ${digest} does not match its digest`);
    }

    return body;
  }

  /**
   * The platform manifest of an image: the manifest itself, or the entry of
   * an index for this platform.
   *
   * @param {Object} reference - with digest
   * @param {{os: string, architecture: string, variant?: string}} platform
   * @returns {Promise<{digest: string, manifest: Object, index: string|null}>}
   */
  async platformManifest(reference, platform) {
    const top = await this.manifest(reference);
    if (!INDEX_TYPES.has(top.mediaType) && !Array.isArray(top.manifests)) {
      return {digest: reference.digest, manifest: top, index: null};
    }

    const entry = top.manifests.find(item => item.platform && item.platform.os === platform.os && item.platform.architecture === platform.architecture
      && (!platform.variant || item.platform.variant === platform.variant));
    if (!entry) {
      throw new Error(`The image has no ${platform.os}/${platform.architecture} manifest`);
    }

    return {digest: entry.digest, manifest: await this.manifest(reference, entry.digest), index: reference.digest};
  }

  /**
   * Sigstore bundles attached to a manifest as referrers.
   * @param {Object} reference
   * @param {string} digest - subject manifest digest
   * @returns {Promise<Object[]>}
   */
  async referrerBundles(reference, digest) {
    let index;
    try {
      index = JSON.parse((await this._get(reference.registry, reference.repository, `${reference.repository}/referrers/${digest}`, {accept: 'application/vnd.oci.image.index.v1+json', maxBytes: 4 * 1024 * 1024})).toString('utf8'));
    } catch (error) {
      if (error.statusCode === 404) {
        return [];
      }

      throw error;
    }

    const bundles = [];
    for (const descriptor of index.manifests || []) {
      if (!BUNDLE_TYPE.test(descriptor.artifactType || '')) {
        continue;
      }

      const manifest = await this.manifest(reference, descriptor.digest);
      for (const layer of manifest.layers || []) {
        if (BUNDLE_TYPE.test(layer.mediaType || '')) {
          bundles.push(JSON.parse((await this.blob(reference, layer.digest, 16 * 1024 * 1024)).toString('utf8')));
        }
      }
    }

    return bundles;
  }
}

// Layers are held in memory; an image expanding beyond this is refused.
const MAX_IMAGE_BYTES = 4 * 1024 * 1024 * 1024;

/**
 * Decompress a layer by its media type.
 * @param {Buffer} blob
 * @param {string} mediaType
 * @param {number} [maxBytes=4 GiB] - the most it may expand to
 * @returns {Buffer} tar
 */
function decompressLayer(blob, mediaType, maxBytes = MAX_IMAGE_BYTES) {
  const limit = Math.max(1, Math.min(maxBytes, buffer.constants.MAX_LENGTH));
  const tooLarge = () => new Error(`The layer expands to more than ${maxBytes} bytes`);
  // A registry serves whatever layer the image names: a few megabytes can
  // expand to more memory than the verifier has.
  const bounded = decompress => {
    try {
      return decompress();
    } catch (error) {
      throw error.code === 'ERR_BUFFER_TOO_LARGE' ? tooLarge() : error;
    }
  };

  let output = blob;
  if (/\+gzip$|\.tar\.gzip$|tar\.gzip|diff\.tar\.gzip/.test(mediaType) || (blob[0] === 0x1F && blob[1] === 0x8B)) {
    output = bounded(() => zlib.gunzipSync(blob, {maxOutputLength: limit}));
  } else if (/\+zstd$/.test(mediaType) || (blob.length >= 4 && blob.readUInt32LE(0) === 0xFD_2F_B5_28)) {
    if (typeof zlib.zstdDecompressSync === 'function') {
      output = bounded(() => zlib.zstdDecompressSync(blob, {maxOutputLength: limit}));
    } else {
      const result = spawnSync('zstd', ['-d', '-c', '-q'], {input: blob, maxBuffer: limit});
      if (result.error && result.error.code === 'ENOBUFS') {
        throw tooLarge();
      }

      if (result.status !== 0) {
        throw new Error('zstd layers need Node.js 22.15 or later, or the zstd program');
      }

      output = result.stdout;
    }
  }

  if (output.length > maxBytes) {
    throw tooLarge();
  }

  return output;
}

/**
 * Apply layers (tar archives, in order) to get the root filesystem.
 *
 * Each path is also kept in a tree of directories, so replacing or
 * whiting out a directory costs what is under it, not the whole image.  An
 * opaque directory hides what lower layers put in it, not what its own
 * layer adds; a hard link takes the contents its target has at that point.
 *
 * @param {Buffer[]} tars
 * @returns {Map<string, [string, string]>} path -> [sha256 or "symlink:<target>", mode]
 */
function applyLayers(tars) {
  const files = new Map();
  // Directory ('' for the root) -> the paths directly in it.
  const children = new Map();
  const parentOf = name => (name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '');
  const add = (name, value) => {
    files.set(name, value);
    for (let child = name; ;) {
      const parent = parentOf(child);
      if (!children.has(parent)) {
        children.set(parent, new Set());
      }

      if (children.get(parent).has(child)) {
        break;
      }

      children.get(parent).add(child);
      if (parent === '') {
        break;
      }

      child = parent;
    }
  };

  // Remove a path and everything under it, except the paths in `keep`.
  const remove = (target, keep) => {
    const stack = [target];
    while (stack.length > 0) {
      const name = stack.pop();
      const below = children.get(name);
      if (keep && keep.has(name)) {
        stack.push(...(below || []));
        continue;
      }

      files.delete(name);
      if (below) {
        stack.push(...below);
        children.delete(name);
      }

      const siblings = children.get(parentOf(name));
      if (siblings) {
        siblings.delete(name);
      }
    }
  };

  for (const tar of tars) {
    // What this layer has put down so far (with its directories).
    const unpacked = new Set();
    const mark = name => {
      for (let current = name; current !== '' && !unpacked.has(current); current = parentOf(current)) {
        unpacked.add(current);
      }
    };

    for (const entry of readTar(tar)) {
      const name = entry.name.replace(/^\.?\//, '').replace(/\/$/, '');
      if (!name || name.split('/').includes('..')) {
        continue;
      }

      const base = name.slice(name.lastIndexOf('/') + 1);
      const directory = parentOf(name);
      if (base === '.wh..wh..opq') {
        // Deleting from a Set while iterating it visits every remaining entry.
        for (const child of children.get(directory) || []) {
          remove(child, unpacked);
        }

        continue;
      }

      if (base.startsWith('.wh.')) {
        remove(directory ? `${directory}/${base.slice(4)}` : base.slice(4));
        continue;
      }

      const mode = entry.mode !== undefined && entry.mode & 0o111 ? '100755' : '100644';
      switch (entry.type) {
        case '0':
        case '\0':
        case '7': {
          remove(name);
          add(name, [sha256(entry.data), mode]);
          mark(name);
          break;
        }

        case '2': {
          remove(name);
          add(name, [`symlink:${entry.linkName}`, '120000']);
          mark(name);
          break;
        }

        case '1': {
          const target = entry.linkName.replace(/^\.?\//, '');
          if (files.has(target)) {
            const value = files.get(target);
            remove(name);
            add(name, value);
            mark(name);
          }

          break;
        }

        case '5': {
          // A directory replacing a file.
          files.delete(name);
          mark(name);
          break;
        }
        // No default
      }
    }
  }

  return files;
}

/**
 * The root filesystem of an image's platform manifest.
 *
 * @param {Registry} registry
 * @param {Object} reference
 * @param {Object} manifest - platform manifest
 * @param {Object} [options]
 * @param {number} [options.maxBytes=4 GiB] - the most all layers together may expand to
 * @returns {Promise<Map<string, [string, string]>>}
 */
async function imageFiles(registry, reference, manifest, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_IMAGE_BYTES;
  const tars = [];
  let total = 0;
  for (const layer of manifest.layers || []) {
    const tar = decompressLayer(await registry.blob(reference, layer.digest), layer.mediaType || '', maxBytes - total);
    total += tar.length;
    tars.push(tar);
  }

  return applyLayers(tars);
}

/**
 * Compare a container's files with its image's.
 *
 * @param {Object<string, [string, string]>} actual - from containers.walkRootfs
 * @param {Map<string, [string, string]>} expected
 * @param {Object} [options]
 * @param {(file: string) => boolean} [options.ignore] - paths the runtime writes (/etc/hostname, ...)
 * @returns {{modified: string[], missing: string[], added: string[], modeChanged: string[]}}
 */
function compareRootfs(actual, expected, options = {}) {
  const ignore = options.ignore || (() => false);
  const modified = [];
  const missing = [];
  const added = [];
  const modeChanged = [];
  for (const [file, [hash, mode]] of expected) {
    if (ignore(file)) {
      continue;
    }

    const found = actual[file];
    if (!found) {
      missing.push(file);
    } else if (found[0] !== hash) {
      modified.push(file);
    } else if (found[1] !== mode) {
      modeChanged.push(file);
    }
  }

  for (const file of Object.keys(actual)) {
    if (!expected.has(file) && !ignore(file)) {
      added.push(file);
    }
  }

  return {
    modified: modified.sort(), missing: missing.sort(), added: added.sort(), modeChanged: modeChanged.sort(),
  };
}

module.exports = {
  Registry,
  parseReference,
  decompressLayer,
  applyLayers,
  imageFiles,
  compareRootfs,
};

/**
 * Attestium - build attestations as references
 *
 * Where an artifact came from, as its builder signed it:
 *
 *   GitHub artifact attestations  the SLSA provenance or other statement a
 *                                 workflow signed for a file or image digest
 *                                 (actions/attest-build-provenance)
 *   npm provenance                the SLSA provenance the registry stores
 *                                 for a package version published from CI
 *
 * Trust comes from Sigstore's public-good instance: its trusted root and
 * npm's registry keys are fetched through TUF (./tuf) starting from the
 * root shipped in ./data, and each bundle is verified by ./sigstore.
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const {httpGetJson, httpGet} = require('./http');
const {TufClient} = require('./tuf');
const {verifyBundle, SigstoreError} = require('./sigstore');

const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
const SLSA_PROVENANCE = /\/slsa\.dev\/provenance\//;
const NPM_PUBLISH = /\/npm\/attestation\/.+\/publish\//;

class SigstoreTrust {
  /**
   * @param {Object} [options]
   * @param {string} [options.cacheDir]
   * @param {Object} [options.httpOptions]
   * @param {string} [options.tufUrl='https://tuf-repo-cdn.sigstore.dev']
   * @param {Object} [options.initialRoot] - TUF root to start from (default: shipped)
   * @param {Object} [options.trustedRoot] - use this trusted_root.json instead of TUF (tests, private instances)
   * @param {Object} [options.npmKeys] - registry.npmjs.org/keys.json contents instead of TUF
   */
  constructor(options = {}) {
    this.options = options;
    this.tuf = new TufClient({
      metadataUrl: options.tufUrl || 'https://tuf-repo-cdn.sigstore.dev',
      initialRoot: options.initialRoot || require('./data/sigstore-root.json'),
      cacheDir: options.cacheDir ? path.join(options.cacheDir, 'sigstore-tuf') : null,
      httpOptions: options.httpOptions,
    });
    this._root = null;
    this._npmKeys = null;
  }

  /**
   * @returns {Promise<Object>} trusted_root.json
   */
  trustedRoot() {
    this._root ||= this.options.trustedRoot
      ? Promise.resolve(this.options.trustedRoot)
      : this.tuf.target('trusted_root.json').then(content => JSON.parse(content.toString('utf8')));
    this._root.catch(() => {
      this._root = null;
    });
    return this._root;
  }

  /**
   * Npm's registry signing keys, as {hint: {pem, validUntil}}.
   * @returns {Promise<Object>}
   */
  npmKeys() {
    this._npmKeys ||= (async () => {
      const json = this.options.npmKeys || JSON.parse((await this.tuf.target('registry.npmjs.org/keys.json')).toString('utf8'));
      const keys = {};
      for (const key of json.keys || []) {
        const der = Buffer.from(key.publicKey.rawBytes, 'base64');
        keys[key.keyId] = {
          pem: crypto.createPublicKey({key: der, format: 'der', type: 'spki'}).export({type: 'spki', format: 'pem'}),
          validUntil: key.publicKey.validFor && key.publicKey.validFor.end ? Date.parse(key.publicKey.validFor.end) : Infinity,
        };
      }

      return keys;
    })();
    this._npmKeys.catch(() => {
      this._npmKeys = null;
    });
    return this._npmKeys;
  }
}

/**
 * The certificate identity a GitHub Actions workflow signs with.
 *
 * The subject alternative name names the workflow file that signed; for a
 * reusable workflow that is the called workflow, while the repository the
 * run built is the source repository claim.  A public repository's
 * reusable workflows can be called by any other repository, so both are
 * required: the workflow, and the repository whose code it ran on.
 *
 * @param {Object} signer
 * @param {string} signer.repository - owner/name of the repository the workflow ran for (its code was built)
 * @param {string} [signer.workflow] - path of the workflow file (.github/workflows/release.yml); any when omitted
 * @param {string} [signer.ref] - git ref of the workflow file (refs/heads/main); any when omitted
 * @param {string} [signer.workflowRepository] - owner/name holding the workflow file, for a reusable workflow of another repository (default: repository)
 * @returns {Object} identity for verifyBundle
 */
function githubIdentity({
  repository, workflow, ref, workflowRepository,
}) {
  const escape = value => value.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);
  const file = workflow ? escape(workflow.replace(/^\/+/, '')) : String.raw`\.github/workflows/[^@]+`;
  const at = ref ? escape(ref) : '.+';
  return {
    issuer: GITHUB_ISSUER,
    subjectAlternativeName: new RegExp(`^https://github\\.com/${escape(workflowRepository || repository)}/${file}@${at}$`),
    sourceRepositoryURI: `https://github.com/${repository}`,
  };
}

/**
 * Snappy (raw block format) decompression, for bundles GitHub serves
 * compressed.
 * @param {Buffer} input
 * @returns {Buffer}
 */
function snappyDecompress(input) {
  let position = 0;
  let length = 0;
  let shift = 0;
  for (;;) {
    const byte = input[position++];
    if (byte === undefined || shift > 28) {
      throw new Error('Malformed snappy length');
    }

    length += (byte & 0x7F) * (2 ** shift);
    if ((byte & 0x80) === 0) {
      break;
    }

    shift += 7;
  }

  if (length > 256 * 1024 * 1024) {
    throw new Error('Snappy data too large');
  }

  const output = Buffer.alloc(length);
  let written = 0;
  while (position < input.length) {
    const tag = input[position++];
    const type = tag & 0x03;
    if (type === 0) {
      let literal = tag >> 2;
      if (literal >= 60) {
        const bytes = literal - 59;
        literal = input.readUIntLE(position, bytes);
        position += bytes;
      }

      literal += 1;
      if (position + literal > input.length || written + literal > length) {
        throw new Error('Malformed snappy literal');
      }

      input.copy(output, written, position, position + literal);
      position += literal;
      written += literal;
      continue;
    }

    let copyLength;
    let offset;
    if (type === 1) {
      copyLength = ((tag >> 2) & 0x07) + 4;
      offset = ((tag >> 5) << 8) | input[position++];
    } else if (type === 2) {
      copyLength = (tag >> 2) + 1;
      offset = input.readUInt16LE(position);
      position += 2;
    } else {
      copyLength = (tag >> 2) + 1;
      offset = input.readUInt32LE(position);
      position += 4;
    }

    if (offset === 0 || offset > written || written + copyLength > length) {
      throw new Error('Malformed snappy copy');
    }

    for (let index = 0; index < copyLength; index++) {
      output[written] = output[written - offset];
      written++;
    }
  }

  if (written !== length) {
    throw new Error('Snappy data is truncated');
  }

  return output;
}

/**
 * Attestations GitHub stores for a digest, as Sigstore bundles.
 *
 * @param {Object} input
 * @param {string} input.repository - owner/name
 * @param {string} input.digest - sha256 hex
 * @param {Object} [input.httpOptions] - headers may carry a token
 * @param {string} [input.apiUrl='https://api.github.com']
 * @returns {Promise<Object[]>}
 */
async function githubAttestations({repository, digest, httpOptions = {}, apiUrl = 'https://api.github.com'}) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !/^[\da-f]{64}$/.test(digest)) {
    throw new TypeError('Invalid repository or digest');
  }

  let response;
  try {
    response = await httpGetJson(`${apiUrl}/repos/${repository}/attestations/sha256:${digest}`, {
      ...httpOptions, headers: {accept: 'application/vnd.github+json', ...httpOptions.headers}, maxBytes: 64 * 1024 * 1024,
    });
  } catch (error) {
    if (error.statusCode === 404) {
      return [];
    }

    throw error;
  }

  const bundles = [];
  for (const attestation of response.attestations || []) {
    if (attestation.bundle) {
      bundles.push(attestation.bundle);
    } else if (typeof attestation.bundle_url === 'string') {
      const raw = await httpGet(attestation.bundle_url, {...httpOptions, headers: {}, maxBytes: 64 * 1024 * 1024});
      bundles.push(JSON.parse(snappyDecompress(raw).toString('utf8')));
    }
  }

  return bundles;
}

/**
 * Verify that a GitHub workflow attested a digest.  The first bundle that
 * verifies wins; every failure is reported when none does.
 *
 * @param {Object} input
 * @param {Object[]} input.bundles
 * @param {string} input.digest - sha256 hex of the artifact
 * @param {Object} input.signer - see githubIdentity()
 * @param {SigstoreTrust} input.trust
 * @param {string} [input.predicateType] - required statement type (default: any)
 * @returns {Promise<{statement: Object, claims: Object, signedAt: Date}>}
 */
async function verifyGithubAttestation({bundles, digest, signer, trust, predicateType}) {
  const trustedRoot = await trust.trustedRoot();
  const errors = [];
  for (const bundle of bundles) {
    try {
      const result = verifyBundle(bundle, {trustedRoot, identity: githubIdentity(signer), subject: {algorithm: 'sha256', digest}});
      if (predicateType && result.statement.predicateType !== predicateType) {
        throw new SigstoreError(`statement type is ${result.statement.predicateType}`);
      }

      return result;
    } catch (error) {
      errors.push(error.message);
    }
  }

  throw new SigstoreError(bundles.length === 0 ? 'no attestation found for this digest' : `no attestation verified: ${[...new Set(errors)].join('; ')}`);
}

/**
 * The listed predicate type is the registry's label; the signed statement
 * must say the same.
 */
function checkType(verified, pattern) {
  if (!pattern.test(String(verified.statement.predicateType))) {
    throw new SigstoreError(`statement type is ${String(verified.statement.predicateType).slice(0, 80)}`);
  }
}

/**
 * Npm provenance for a package version: which repository, commit and
 * workflow built the tarball whose integrity the lockfile pins.
 *
 * @param {Object} input
 * @param {string} input.name
 * @param {string} input.version
 * @param {string} input.integrity - the lockfile's SRI (sha512)
 * @param {SigstoreTrust} input.trust
 * @param {string} [input.registryUrl='https://registry.npmjs.org']
 * @param {Object} [input.httpOptions]
 * @returns {Promise<{provenance: boolean, reason?: string, repository?: string|null, commit?: string|null, workflow?: string, signedAt?: string, published?: boolean}>}
 */
async function npmProvenance({name, version, integrity, trust, registryUrl = 'https://registry.npmjs.org', httpOptions = {}}) {
  const match = String(integrity || '').match(/(?:^|\s)sha512-([\w+/=]+)/);
  if (!match) {
    return {provenance: false, reason: 'no sha512 integrity'};
  }

  const digest = Buffer.from(match[1], 'base64').toString('hex');
  let response;
  try {
    response = await httpGetJson(`${registryUrl.replace(/\/+$/, '')}/-/npm/v1/attestations/${name.replace('/', '%2f')}@${encodeURIComponent(version)}`, {...httpOptions, maxBytes: 16 * 1024 * 1024});
  } catch (error) {
    if (error.statusCode === 404) {
      return {provenance: false};
    }

    throw error;
  }

  const trustedRoot = await trust.trustedRoot();
  const subject = {algorithm: 'sha512', digest};
  const result = {provenance: false};
  for (const attestation of response.attestations || []) {
    if (SLSA_PROVENANCE.test(attestation.predicateType || '')) {
      const verified = verifyBundle(attestation.bundle, {trustedRoot, subject});
      checkType(verified, SLSA_PROVENANCE);
      result.provenance = true;
      result.repository = verified.claims.sourceRepositoryURI || null;
      result.commit = verified.claims.sourceRepositoryDigest || null;
      result.workflow = verified.claims.subjectAlternativeName;
      result.signedAt = verified.signedAt.toISOString();
    } else if (NPM_PUBLISH.test(attestation.predicateType || '')) {
      verifyPublishAttestation(attestation.bundle, await trust.npmKeys(), {trustedRoot, subject});
      result.published = true;
    }
  }

  return result;
}

/**
 * A publish attestation: signed by one of the registry's keys, while it
 * was valid.
 */
function verifyPublishAttestation(bundle, keys, options) {
  const hint = bundle && bundle.verificationMaterial && bundle.verificationMaterial.publicKey && bundle.verificationMaterial.publicKey.hint;
  const key = keys[hint];
  const verified = verifyBundle(bundle, {...options, publicKeys: key ? {[hint]: key.pem} : {}});
  // A bundle carrying a certificate is verified with it, whatever key it
  // names: any Fulcio certificate would do.
  if (verified.claims !== null) {
    throw new SigstoreError('the publish attestation is not signed by a registry key');
  }

  checkType(verified, NPM_PUBLISH);
  if (verified.signedAt.getTime() > key.validUntil) {
    throw new SigstoreError(`the registry key ${hint} had expired when the publish attestation was signed`);
  }
}

module.exports = {
  SigstoreTrust,
  githubIdentity,
  githubAttestations,
  verifyGithubAttestation,
  npmProvenance,
  snappyDecompress,
  GITHUB_ISSUER,
};

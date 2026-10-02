/**
 * Attestium - the evidence format
 *
 * Evidence is what an attester reports about a machine; a verifier checks
 * it against references.  The format is specified in SPEC.md and published
 * as a JSON Schema (../schema/evidence.schema.json), so attesters and
 * verifiers in any language can produce and check it.
 *
 * Also: release manifests, the file list a CI build publishes (and attests)
 * for an artifact deployed without git.
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');
const {compile} = require('./schema');
const {digestOf, setOwn} = require('./util');
const {walkTree, createMatcher} = require('./file-tree');

const TYPE = 'attestium-evidence';
const VERSION = 2;
const MANIFEST_TYPE = 'attestium-manifest';
const MANIFEST_NAME = '.attestium-manifest.json';

let validator = null;

/**
 * Check evidence against the published schema.
 * @param {*} evidence
 * @returns {{valid: boolean, errors: string[]}}
 */
function validateEvidence(evidence) {
  validator ||= compile(require('../schema/evidence.schema.json'));
  return validator(evidence);
}

/**
 * The digest an attester computes over its evidence: everything except
 * the digest itself and what is added after it (hardware reports that
 * sign the digest, and the IMA log, which is authenticated by replay).
 *
 * @param {Object} evidence
 * @returns {string}
 */
function evidenceDigest(evidence) {
  const {
    evidenceDigest: _digest, tpm, ima, confidential, ...rest
  } = evidence;
  return digestOf(rest);
}

/**
 * Create a release manifest for a directory: every file's SHA-256 and mode.
 *
 * @param {string} directory
 * @param {Object} options
 * @param {string} options.repository - owner/name
 * @param {string} options.commit - the commit the release was built from
 * @param {string[]} [options.exclude] - glob patterns
 * @returns {Promise<Object>}
 */
async function createManifest(directory, {repository, commit, exclude = []}) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository || '') || !/^[\da-f]{40}$/.test(commit || '')) {
    throw new TypeError('A manifest needs repository (owner/name) and a full commit id');
  }

  const skip = createMatcher(exclude);
  const {entries, errors} = await walkTree(path.resolve(directory), {
    exclude: relative => relative === '.git' || relative === MANIFEST_NAME || skip(relative),
  });
  if (errors.length > 0) {
    throw new Error(`Could not read ${errors.length} file(s): ${errors.slice(0, 3).map(error => `${error.path} (${error.error})`).join(', ')}`);
  }

  const files = {};
  for (const entry of entries) {
    setOwn(files, entry.path, [entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256, entry.mode]);
  }

  return {
    type: MANIFEST_TYPE, version: 1, repository, commit, files,
  };
}

/**
 * Parse and check a manifest's shape.
 * @param {string|Buffer} text
 * @returns {Object}
 */
function parseManifest(text) {
  const manifest = JSON.parse(String(text));
  const ok = manifest && manifest.type === MANIFEST_TYPE && manifest.version === 1
    && /^[\w.-]+\/[\w.-]+$/.test(manifest.repository || '') && /^[\da-f]{40}$/.test(manifest.commit || '')
    && manifest.files && typeof manifest.files === 'object' && !Array.isArray(manifest.files)
    && Object.values(manifest.files).every(entry => Array.isArray(entry) && entry.length === 2 && entry.every(item => typeof item === 'string'));
  if (!ok) {
    throw new Error('Not an Attestium manifest');
  }

  return manifest;
}

module.exports = {
  TYPE,
  VERSION,
  MANIFEST_TYPE,
  MANIFEST_NAME,
  validateEvidence,
  evidenceDigest,
  createManifest,
  parseManifest,
};

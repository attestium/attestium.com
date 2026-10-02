/**
 * Attestium - published checksums as references
 *
 * Many projects publish a list of SHA-256 checksums with their releases
 * (SHA256SUMS, checksums.txt), usually signed.  A binary installed from such
 * a release is explained when its hash is in the list and the list's
 * signature verifies:
 *
 *   gpg        detached OpenPGP signature, checked with gpgv and a keyring
 *   minisign   Ed25519 signature (minisign, and signify-compatible keys)
 *   sigstore   a Sigstore bundle over the list, with a required identity
 *
 * Without a signature the list is trusted as far as HTTPS and its host.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const {verifyBundle} = require('./sigstore');
const {sha256} = require('./util');

/**
 * Parse a checksum list: GNU coreutils ("<hash>  <file>", "<hash> *<file>")
 * and BSD ("SHA256 (<file>) = <hash>") lines.
 *
 * @param {string} text
 * @returns {Map<string, string>} file name -> sha256
 */
function parseChecksums(text) {
  const entries = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const gnu = line.match(/^([\da-fA-F]{64})\s+\*?(.+)$/);
    const bsd = line.match(/^SHA256\s*\((.+)\)\s*=\s*([\da-fA-F]{64})$/);
    if (gnu) {
      entries.set(gnu[2].trim().replace(/^\.\//, ''), gnu[1].toLowerCase());
    } else if (bsd) {
      entries.set(bsd[1].replace(/^\.\//, ''), bsd[2].toLowerCase());
    }
  }

  return entries;
}

/**
 * Verify a minisign signature.
 *
 * @param {Buffer} data
 * @param {string} signatureText - the .minisig file
 * @param {string} publicKey - base64 key (the second line of a .pub file)
 * @returns {boolean}
 */
function verifyMinisign(data, signatureText, publicKey) {
  const lines = signatureText.split(/\r?\n/);
  const key = Buffer.from(publicKey.trim(), 'base64');
  const signature = Buffer.from(lines[1] || '', 'base64');
  const trusted = (lines[2] || '').match(/^trusted comment: (.*)$/);
  const global = Buffer.from(lines[3] || '', 'base64');
  if (key.length !== 42 || signature.length !== 74 || !trusted || global.length !== 64) {
    return false;
  }

  const algorithm = signature.subarray(0, 2).toString('latin1');
  if (key.subarray(0, 2).toString('latin1') !== 'Ed' || !key.subarray(2, 10).equals(signature.subarray(2, 10)) || !['Ed', 'ED'].includes(algorithm)) {
    return false;
  }

  const ed25519 = crypto.createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key.subarray(10)]), format: 'der', type: 'spki'});
  // "ED": the file's BLAKE2b-512 digest is signed; "Ed" (legacy): the file.
  const message = algorithm === 'ED' ? crypto.createHash('blake2b512').update(data).digest() : data;
  const signed = signature.subarray(10);
  return crypto.verify(null, message, ed25519, signed)
    && crypto.verify(null, Buffer.concat([signed, Buffer.from(trusted[1], 'utf8')]), ed25519, global);
}

const GPG_REFUSED = {
  BADSIG: 'a signature is bad',
  ERRSIG: 'a signature could not be checked',
  EXPSIG: 'the signature has expired',
  EXPKEYSIG: 'the signing key has expired',
  REVKEYSIG: 'the signing key is revoked',
};

/**
 * Why gpgv's status output (--status-fd) does not show only good signatures
 * by valid keys, or null.  gpgv exits with 0 for a signature by a revoked
 * or expired key, so its exit status alone is not enough.
 *
 * @param {string} status
 * @returns {string|null}
 */
function gpgStatusProblem(status) {
  const keywords = status.split('\n').filter(line => line.startsWith('[GNUPG:] ')).map(line => line.split(' ')[1]);
  const refused = keywords.find(keyword => Object.hasOwn(GPG_REFUSED, keyword));
  if (refused) {
    return GPG_REFUSED[refused];
  }

  const count = keyword => keywords.filter(item => item === keyword).length;
  const signatures = count('NEWSIG');
  return signatures > 0 && count('GOODSIG') === signatures && count('VALIDSIG') === signatures ? null : 'no good signature';
}

function gpgVerify(data, signature, keyring) {
  return new Promise((resolve, reject) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-checksums-'));
    const dataFile = path.join(directory, 'data');
    const signatureFile = path.join(directory, 'data.sig');
    fs.writeFileSync(dataFile, data);
    fs.writeFileSync(signatureFile, signature);
    // Its own home directory: only the given keyring, no user configuration.
    execFile('gpgv', ['--homedir', directory, '--status-fd', '1', '--keyring', path.resolve(keyring), signatureFile, dataFile], {timeout: 30_000}, (error, stdout) => {
      fs.rmSync(directory, {recursive: true, force: true});
      const problem = error ? error.message.split('\n')[0] : gpgStatusProblem(String(stdout));
      if (problem) {
        reject(new Error(`checksum list signature does not verify (gpgv): ${problem}`));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Fetch, verify and parse a published checksum list.
 *
 * @param {Object} source
 * @param {string} source.url
 * @param {Object} [source.signature]
 * @param {'gpg'|'minisign'|'sigstore'} source.signature.type
 * @param {string} [source.signature.url] - default: url + .sig / .minisig / .sigstore.json
 * @param {string} [source.signature.keyring] - gpg
 * @param {string} [source.signature.publicKey] - minisign
 * @param {Object} [source.signature.identity] - sigstore (required): certificate claims to require
 * @param {Object} context
 * @param {import('./ecosystems/common').ReferenceStore} context.store
 * @param {() => Promise<Object>} [context.trustedRoot] - sigstore
 * @returns {Promise<{checksums: Map<string, string>, signed: boolean}>}
 */
async function fetchChecksums(source, {store, trustedRoot}) {
  const {signature} = source;
  // Any Fulcio certificate verifies; only the identity says whose it is.
  if (signature && signature.type === 'sigstore' && Object.keys(signature.identity || {}).length === 0) {
    throw new Error('a Sigstore signature needs an identity: the certificate claims to require (issuer, subjectAlternativeName, ...)');
  }

  const entries = await store.memo(`checksums:v1:${source.url}:${JSON.stringify(source.signature || null)}`, async () => {
    const data = await store.get(source.url, {maxBytes: 16 * 1024 * 1024});
    if (signature) {
      const suffix = {gpg: '.sig', minisign: '.minisig', sigstore: '.sigstore.json'}[signature.type];
      if (!suffix) {
        throw new Error(`unknown signature type ${signature.type}`);
      }

      const signatureBody = await store.get(signature.url || `${source.url}${suffix}`, {maxBytes: 4 * 1024 * 1024});
      if (signature.type === 'gpg') {
        await gpgVerify(data, signatureBody, signature.keyring);
      } else if (signature.type === 'minisign') {
        if (!verifyMinisign(data, signatureBody.toString('utf8'), signature.publicKey)) {
          throw new Error('checksum list signature does not verify (minisign)');
        }
      } else {
        // A signature over the file itself, or a statement naming it.
        verifyBundle(JSON.parse(signatureBody.toString('utf8')), {
          trustedRoot: await trustedRoot(), artifact: data, subject: {algorithm: 'sha256', digest: sha256(data)}, identity: toIdentity(signature.identity),
        });
      }
    }

    return [...parseChecksums(data.toString('utf8'))];
  }, {persist: false});
  return {checksums: new Map(entries), signed: Boolean(source.signature)};
}

/**
 * Identity requirements from configuration: strings, or /regex/ strings.
 */
function toIdentity(identity = {}) {
  const result = {};
  for (const [name, value] of Object.entries(identity)) {
    const regex = String(value).match(/^\/(.+)\/$/);
    result[name] = regex ? new RegExp(regex[1]) : value;
  }

  return result;
}

module.exports = {
  parseChecksums, verifyMinisign, fetchChecksums, toIdentity, gpgStatusProblem,
};

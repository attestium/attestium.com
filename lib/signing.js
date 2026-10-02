/**
 * Attestium - Ed25519 signing
 *
 * Signed envelopes over canonical JSON.  A signature proves that the
 * holder of a specific private key produced the payload; it says nothing
 * about how well that key is protected.  Keys held in software on the
 * attesting machine can be read by anyone with root on that machine, which
 * is why hardware quotes (see ./tpm.js) exist.
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const {canonicalize, sha256} = require('./util');

const ALGORITHM = 'ed25519';

/**
 * Generate an Ed25519 key pair.
 * @returns {{publicKey: string, privateKey: string}} PEM encoded keys
 */
function generateKeyPair() {
  const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {type: 'spki', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
  });
  return {publicKey, privateKey};
}

/**
 * @param {string|Buffer|crypto.KeyObject} key
 * @returns {crypto.KeyObject}
 */
function toPublicKey(key) {
  let object = key instanceof crypto.KeyObject ? key : crypto.createPublicKey(key);
  if (object.type === 'private') {
    object = crypto.createPublicKey(object);
  }

  if (object.asymmetricKeyType !== ALGORITHM) {
    throw new TypeError(`Expected an ${ALGORITHM} key, got ${object.asymmetricKeyType}`);
  }

  return object;
}

/**
 * @param {string|Buffer|crypto.KeyObject} key
 * @returns {crypto.KeyObject}
 */
function toPrivateKey(key) {
  const object = key instanceof crypto.KeyObject ? key : crypto.createPrivateKey(key);
  if (object.asymmetricKeyType !== ALGORITHM) {
    throw new TypeError(`Expected an ${ALGORITHM} key, got ${object.asymmetricKeyType}`);
  }

  return object;
}

/**
 * SHA-256 fingerprint of a public key's SPKI DER encoding.
 * @param {string|Buffer|crypto.KeyObject} key
 * @returns {string}
 */
function fingerprint(key) {
  return sha256(toPublicKey(key).export({type: 'spki', format: 'der'}));
}

/**
 * Sign a payload.
 *
 * @param {*} payload - any value accepted by canonicalize()
 * @param {string|Buffer|crypto.KeyObject} privateKey
 * @returns {{alg: string, keyId: string, publicKey: string, payload: *, signature: string}}
 */
function sign(payload, privateKey) {
  const key = toPrivateKey(privateKey);
  const publicKey = crypto.createPublicKey(key);
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload)), key);
  return {
    alg: ALGORITHM,
    keyId: fingerprint(publicKey),
    publicKey: publicKey.export({type: 'spki', format: 'pem'}),
    payload,
    signature: signature.toString('base64'),
  };
}

/**
 * Verify a signed envelope.
 *
 * The public key embedded in the envelope is only a convenience; trust
 * comes from `trustedPublicKey`.  When it is omitted, the result can only
 * say the envelope is self-consistent, so `trusted` is false.
 *
 * @param {Object} envelope
 * @param {string|Buffer|crypto.KeyObject} [trustedPublicKey]
 * @returns {{valid: boolean, trusted: boolean, keyId: string|null, error?: string}}
 */
function verify(envelope, trustedPublicKey) {
  try {
    if (!envelope || envelope.alg !== ALGORITHM || typeof envelope.signature !== 'string') {
      return {
        valid: false, trusted: false, keyId: null, error: 'Malformed envelope',
      };
    }

    const key = toPublicKey(trustedPublicKey || envelope.publicKey);
    const keyId = fingerprint(key);
    if (envelope.keyId !== keyId) {
      return {
        valid: false, trusted: false, keyId, error: 'Key id does not match the verifying key',
      };
    }

    const valid = crypto.verify(
      null,
      Buffer.from(canonicalize(envelope.payload)),
      key,
      Buffer.from(envelope.signature, 'base64'),
    );
    return valid
      ? {valid: true, trusted: Boolean(trustedPublicKey), keyId}
      : {
        valid: false, trusted: false, keyId, error: 'Signature does not verify',
      };
  } catch (error) {
    return {
      valid: false, trusted: false, keyId: null, error: error.message,
    };
  }
}

module.exports = {
  ALGORITHM,
  generateKeyPair,
  fingerprint,
  sign,
  verify,
  toPublicKey,
  toPrivateKey,
};

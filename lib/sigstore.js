/**
 * Attestium - Sigstore bundle verification
 *
 * Verifies the signed statements CI systems and registries publish about
 * what they built: GitHub artifact attestations (actions/attest,
 * actions/attest-build-provenance), npm provenance, and container image
 * attestations.  All are Sigstore bundles (v0.1 to v0.3) holding a DSSE
 * envelope with an in-toto statement.
 *
 * A bundle is accepted only when:
 *
 *   1. the signing certificate chains to a certificate authority in the
 *      trusted root (Fulcio), and was valid when the entry was logged
 *   2. the transparency log entry is authentic (the log's signed entry
 *      timestamp, or an inclusion proof to a signed checkpoint) and matches
 *      this signature, certificate and payload
 *   3. the DSSE signature over the statement verifies with the certificate
 *   4. the certificate's identity (the workflow that signed, its issuer,
 *      repository, commit and ref) is what the caller requires
 *   5. the statement names the artifact's digest as a subject
 *
 * Bundles signed with a known public key instead of a certificate (npm's
 * publish attestations) are accepted when the key is one of those passed
 * in `publicKeys`.
 *
 * Signing time comes from the log's signed entry timestamp (Rekor v1) or
 * from RFC 3161 timestamps by a trusted timestamp authority (required for
 * Rekor v2, whose entries carry no time).
 *
 * Not verified: certificate transparency SCTs in the signing certificate
 * (the certificate is itself in the transparency log entry, which is
 * verified).
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const asn1 = require('./asn1');
const {canonicalize, sha256} = require('./util');

// Fulcio certificate extensions (github.com/sigstore/fulcio/docs/oid-info.md).
const FULCIO_OIDS = {
  '1.3.6.1.4.1.57264.1.1': 'issuerV1',
  '1.3.6.1.4.1.57264.1.8': 'issuer',
  '1.3.6.1.4.1.57264.1.9': 'buildSignerURI',
  '1.3.6.1.4.1.57264.1.10': 'buildSignerDigest',
  '1.3.6.1.4.1.57264.1.11': 'runnerEnvironment',
  '1.3.6.1.4.1.57264.1.12': 'sourceRepositoryURI',
  '1.3.6.1.4.1.57264.1.13': 'sourceRepositoryDigest',
  '1.3.6.1.4.1.57264.1.14': 'sourceRepositoryRef',
  '1.3.6.1.4.1.57264.1.15': 'sourceRepositoryIdentifier',
  '1.3.6.1.4.1.57264.1.16': 'sourceRepositoryOwnerURI',
  '1.3.6.1.4.1.57264.1.17': 'sourceRepositoryOwnerIdentifier',
  '1.3.6.1.4.1.57264.1.18': 'buildConfigURI',
  '1.3.6.1.4.1.57264.1.19': 'buildConfigDigest',
  '1.3.6.1.4.1.57264.1.20': 'buildTrigger',
  '1.3.6.1.4.1.57264.1.21': 'runInvocationURI',
  '1.3.6.1.4.1.57264.1.22': 'sourceRepositoryVisibilityAtSigning',
};
const V1_TEXT_OIDS = new Set(['1.3.6.1.4.1.57264.1.1']);

class SigstoreError extends Error {}

const b64 = value => Buffer.from(String(value || ''), 'base64');

/**
 * The key a DER SubjectPublicKeyInfo describes.
 */
function spkiKey(der) {
  return crypto.createPublicKey({key: der, format: 'der', type: 'spki'});
}

/**
 * Verify a signature with the digest that suits the key.
 */
function verifySignature(key, data, signature) {
  const details = key.asymmetricKeyDetails;
  let algorithm = 'sha256';
  if (key.asymmetricKeyType === 'ed25519') {
    algorithm = null;
  } else if (details.namedCurve === 'secp384r1') {
    algorithm = 'sha384';
  } else if (details.namedCurve === 'secp521r1') {
    algorithm = 'sha512';
  }

  try {
    return crypto.verify(algorithm, data, key, signature);
  } catch {
    return false;
  }
}

/**
 * DSSE pre-authentication encoding.
 * @param {string} payloadType
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${payload.length} `), payload]);
}

/**
 * Merkle root from an RFC 9162 inclusion proof.
 * @param {bigint} index
 * @param {bigint} size
 * @param {Buffer} leafHash
 * @param {Buffer[]} proof
 * @returns {Buffer}
 */
function rootFromInclusionProof(index, size, leafHash, proof) {
  if (index >= size) {
    throw new SigstoreError('inclusion proof index is outside the tree');
  }

  const node = (left, right) => crypto.createHash('sha256').update(Buffer.from([1])).update(left).update(right).digest();
  let fn = index;
  let sn = size - 1n;
  let hash = leafHash;
  for (const sibling of proof) {
    if (sn === 0n) {
      throw new SigstoreError('inclusion proof is too long');
    }

    if ((fn & 1n) === 1n || fn === sn) {
      hash = node(sibling, hash);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      hash = node(hash, sibling);
    }

    fn >>= 1n;
    sn >>= 1n;
  }

  if (sn !== 0n) {
    throw new SigstoreError('inclusion proof is too short');
  }

  return hash;
}

/**
 * Parse and verify a signed checkpoint (a signed note) with a log's key.
 * @param {string} envelope
 * @param {Object} log - trusted log {key, keyId}
 * @returns {{origin: string, size: bigint, root: Buffer}}
 */
function verifyCheckpoint(envelope, log) {
  const split = envelope.indexOf('\n\n');
  if (split === -1) {
    throw new SigstoreError('malformed checkpoint');
  }

  const body = envelope.slice(0, split + 1);
  const [origin, size, root] = body.split('\n');
  const signatures = envelope.slice(split + 2).split('\n').filter(Boolean);
  const verified = signatures.some(line => {
    const match = line.match(/^— (\S+) (\S+)$/);
    if (!match) {
      return false;
    }

    // The first four bytes name the key; the signature itself decides.
    const bytes = b64(match[2]);
    return bytes.length > 4 && verifySignature(log.key, Buffer.from(body, 'utf8'), bytes.subarray(4));
  });
  if (!verified) {
    throw new SigstoreError('checkpoint signature does not verify with the log\'s key');
  }

  if (!/^\d+$/.test(size || '')) {
    throw new SigstoreError('malformed checkpoint size');
  }

  return {origin, size: BigInt(size), root: b64(root)};
}

/**
 * Load a trusted root (Sigstore's trusted_root.json).
 * @param {Object} json
 * @returns {{authorities: Object[], logs: Object[]}}
 */
function loadTrustedRoot(json) {
  const window = validFor => ({
    start: validFor && validFor.start ? Date.parse(validFor.start) : -Infinity,
    end: validFor && validFor.end ? Date.parse(validFor.end) : Infinity,
  });
  return {
    authorities: (json.certificateAuthorities || []).map(authority => ({
      uri: authority.uri,
      chain: authority.certChain.certificates.map(certificate => new crypto.X509Certificate(b64(certificate.rawBytes))),
      ...window(authority.validFor),
    })),
    logs: (json.tlogs || []).map(log => ({
      baseUrl: log.baseUrl,
      keyId: b64(log.logId.keyId),
      key: spkiKey(b64(log.publicKey.rawBytes)),
      ...window(log.publicKey.validFor),
    })),
  };
}

/**
 * The identity claims of a Fulcio certificate.
 * @param {crypto.X509Certificate} certificate
 * @returns {Object}
 */
function certificateClaims(certificate) {
  const claims = {subjectAlternativeName: null};
  const extensions = asn1.certificateExtensions(certificate.raw);
  const san = extensions.get('2.5.29.17');
  if (san) {
    for (const name of asn1.parse(san.value).children) {
      // UniformResourceIdentifier [6] or rfc822Name [1]
      if (name.tagClass === 2 && (name.tag === 6 || name.tag === 1)) {
        claims.subjectAlternativeName = asn1.content(name).toString('utf8');
        break;
      }
    }
  }

  for (const [oid, name] of Object.entries(FULCIO_OIDS)) {
    const extension = extensions.get(oid);
    if (extension) {
      claims[name] = V1_TEXT_OIDS.has(oid) ? extension.value.toString('utf8') : asn1.text(asn1.parse(extension.value));
    }
  }

  claims.issuer ||= claims.issuerV1 || null;
  delete claims.issuerV1;
  return claims;
}

/**
 * Check a transparency log entry; returns its log and the time it was
 * logged (null when the entry records none).
 */
function verifyTlogEntry(entry, trusted, material, envelope) {
  const keyId = b64(entry.logId && entry.logId.keyId);
  const log = trusted.logs.find(item => item.keyId.equals(keyId));
  if (!log) {
    throw new SigstoreError('the transparency log is not in the trusted root');
  }

  const bodyText = String(entry.canonicalizedBody || '');
  const body = b64(bodyText);
  const integratedTime = Number(entry.integratedTime || 0);
  let authentic = false;
  if (entry.inclusionPromise && entry.inclusionPromise.signedEntryTimestamp) {
    const payload = canonicalize({
      body: bodyText, integratedTime, logID: keyId.toString('hex'), logIndex: Number(entry.logIndex),
    });
    if (!verifySignature(log.key, Buffer.from(payload, 'utf8'), b64(entry.inclusionPromise.signedEntryTimestamp))) {
      throw new SigstoreError('the log\'s signed entry timestamp does not verify');
    }

    authentic = true;
  }

  if (entry.inclusionProof) {
    const proof = entry.inclusionProof;
    const checkpoint = verifyCheckpoint(String(proof.checkpoint && proof.checkpoint.envelope), log);
    const leaf = crypto.createHash('sha256').update(Buffer.from([0])).update(body).digest();
    const root = rootFromInclusionProof(BigInt(proof.logIndex), BigInt(proof.treeSize), leaf, (proof.hashes || []).map(hash => b64(hash)));
    if (!root.equals(b64(proof.rootHash)) || !root.equals(checkpoint.root) || checkpoint.size !== BigInt(proof.treeSize)) {
      throw new SigstoreError('the inclusion proof does not lead to the signed checkpoint');
    }

    authentic = true;
  }

  if (!authentic) {
    throw new SigstoreError('the log entry has neither a signed entry timestamp nor an inclusion proof');
  }

  // The entry must be this signature, by this key, over this payload.
  const parsed = JSON.parse(body.toString('utf8'));
  const kind = `${entry.kindVersion && entry.kindVersion.kind}/${entry.kindVersion && entry.kindVersion.version}`;
  if (`${parsed.kind}/${parsed.apiVersion}` !== kind) {
    throw new SigstoreError('the log entry\'s kind does not match its body');
  }

  const payloadHash = sha256(b64(envelope.payload));
  const signature = String(envelope.signatures[0].sig);
  let signatures;
  let recordedHash;
  switch (kind) {
    case 'dsse/0.0.1': {
      signatures = (parsed.spec.signatures || []).map(item => ({signature: item.signature, key: b64(item.verifier).toString('utf8')}));
      recordedHash = parsed.spec.payloadHash;

      break;
    }

    case 'intoto/0.0.2': {
      const content = parsed.spec.content || {};
      signatures = ((content.envelope && content.envelope.signatures) || []).map(item => ({signature: b64(item.sig).toString('utf8'), key: b64(item.publicKey).toString('utf8')}));
      recordedHash = content.payloadHash;

      break;
    }

    case 'hashedrekord/0.0.1': {
      const spec = parsed.spec || {};
      signatures = [{signature: (spec.signature || {}).content, key: b64(((spec.signature || {}).publicKey || {}).content).toString('utf8')}];
      recordedHash = spec.data && spec.data.hash;

      break;
    }

    case 'dsse/0.0.2': {
    // Rekor v2: binary fields are base64, keys are DER.
      const spec = (parsed.spec && parsed.spec.dsseV002) || {};
      signatures = (spec.signatures || []).map(item => {
        const verifier = item.verifier || {};
        const der = verifier.x509Certificate ? b64(verifier.x509Certificate.rawBytes) : b64(verifier.publicKey && verifier.publicKey.rawBytes);
        return {signature: item.content, der};
      });
      const hash = spec.payloadHash || {};
      recordedHash = {algorithm: hash.algorithm === 'SHA2_256' ? 'sha256' : hash.algorithm, value: b64(hash.digest).toString('hex')};

      break;
    }

    default: {
      throw new SigstoreError(`unsupported log entry kind ${kind}`);
    }
  }

  if (!recordedHash || recordedHash.algorithm !== 'sha256' || recordedHash.value !== payloadHash) {
    throw new SigstoreError('the log entry is for a different payload');
  }

  const materialDer = material.der;
  const matches = signatures.some(item => {
    if (item.signature !== signature) {
      return false;
    }

    try {
      const der = item.der || (item.key.includes('BEGIN CERTIFICATE') ? new crypto.X509Certificate(item.key).raw : crypto.createPublicKey(item.key).export({type: 'spki', format: 'der'}));
      return der.equals(materialDer);
    } catch {
      return false;
    }
  });
  if (!matches) {
    throw new SigstoreError('the log entry records a different signature or signing key');
  }

  // Rekor v2 records no time; a timestamp authority provides it instead.
  return {log, time: entry.inclusionPromise ? integratedTime * 1000 : null};
}

const HASHES = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

/**
 * Verify an RFC 3161 timestamp over the bundle's signature with a timestamp
 * authority in the trusted root; returns the time it certifies.
 *
 * @param {Buffer} der - TimeStampToken (or a TimeStampResp holding one)
 * @param {Buffer} signature - the signature bytes the timestamp covers
 * @param {Object} json - trusted_root.json (its timestampAuthorities)
 * @returns {number} milliseconds since the epoch
 */
function verifyTimestamp(der, signature, json) {
  let token = asn1.parse(der);
  if (token.children && token.children[0] && token.children[0].tag === 16) {
    // TimeStampResp: status, then the token.
    token = token.children[1];
  }

  if (!token || asn1.oid(token.children[0]) !== '1.2.840.113549.1.7.2') {
    throw new SigstoreError('the timestamp is not CMS signed data');
  }

  const signedData = token.children[1].children[0];
  const encapsulated = signedData.children.find(child => child.tag === 16 && child.tagClass === 0 && child.children[0].tag === 6);
  if (asn1.oid(encapsulated.children[0]) !== '1.2.840.113549.1.9.16.1.4') {
    throw new SigstoreError('the timestamp does not hold TSTInfo');
  }

  const tstInfoDer = asn1.content(encapsulated.children[1].children[0]);
  const tstInfo = asn1.parse(tstInfoDer);
  const messageImprint = tstInfo.children[2];
  const genTime = tstInfo.children[4];
  const imprintHash = HASHES[asn1.oid(messageImprint.children[0].children[0])];
  if (!imprintHash || !asn1.content(messageImprint.children[1]).equals(crypto.createHash(imprintHash).update(signature).digest())) {
    throw new SigstoreError('the timestamp is for a different signature');
  }

  const time = asn1.time(genTime).getTime();
  const signerInfo = signedData.children.at(-1).children[0];
  const signedAttributes = signerInfo.children.find(child => child.tagClass === 2 && child.tag === 0);
  const digestAlgorithm = HASHES[asn1.oid(signerInfo.children[2].children[0])];
  if (!signedAttributes || !digestAlgorithm) {
    throw new SigstoreError('the timestamp has no signed attributes');
  }

  const messageDigest = signedAttributes.children.find(attribute => asn1.oid(attribute.children[0]) === '1.2.840.113549.1.9.4');
  if (!messageDigest || !asn1.content(messageDigest.children[1].children[0]).equals(crypto.createHash(digestAlgorithm).update(tstInfoDer).digest())) {
    throw new SigstoreError('the timestamp\'s signed digest does not match its content');
  }

  // The signature covers the attributes encoded as a SET.
  const attributes = Buffer.from(asn1.raw(signedAttributes));
  attributes[0] = 0x31;
  const signatureValue = asn1.content(signerInfo.children.find(child => child.tag === 4 && child.tagClass === 0 && child !== signerInfo.children[0]));
  const authorities = (json.timestampAuthorities || []).map(authority => ({
    chain: authority.certChain.certificates.map(certificate => new crypto.X509Certificate(b64(certificate.rawBytes))),
    start: authority.validFor && authority.validFor.start ? Date.parse(authority.validFor.start) : -Infinity,
    end: authority.validFor && authority.validFor.end ? Date.parse(authority.validFor.end) : Infinity,
  }));
  const trusted = authorities.some(authority => {
    const [leaf, ...rest] = authority.chain;
    if (time < authority.start || time > authority.end || time < Date.parse(leaf.validFrom) || time > Date.parse(leaf.validTo)) {
      return false;
    }

    for (const [index, link] of authority.chain.entries()) {
      const parent = rest[index] || link;
      if (!link.checkIssued(parent) || !link.verify(parent.publicKey)) {
        return false;
      }
    }

    try {
      return crypto.verify(digestAlgorithm, attributes, leaf.publicKey, signatureValue);
    } catch {
      return false;
    }
  });
  if (!trusted) {
    throw new SigstoreError('the timestamp is not signed by a trusted timestamp authority');
  }

  return time;
}

/**
 * Require certificate claims (each a string, exact, or a RegExp).
 */
function checkIdentity(claims, identity = {}) {
  for (const [name, expected] of Object.entries(identity)) {
    // An unset requirement would match a claim the certificate lacks.
    if (typeof expected !== 'string' && !(expected instanceof RegExp)) {
      throw new SigstoreError(`identity requirement ${name} must be a string or a RegExp`);
    }

    const actual = claims ? claims[name] : null;
    const ok = expected instanceof RegExp ? typeof actual === 'string' && expected.test(actual) : actual === expected;
    if (!ok) {
      throw new SigstoreError(`certificate ${name} is ${JSON.stringify(actual)}, expected ${String(expected)}`);
    }
  }
}

/**
 * Verify a Sigstore bundle.
 *
 * @param {Object} bundle
 * @param {Object} options
 * @param {Object} options.trustedRoot - trusted_root.json contents
 * @param {Object<string, string>} [options.publicKeys] - key hint -> PEM, for key-signed bundles
 * @param {Object} [options.identity] - required certificate claims: each value a string (exact) or RegExp
 * @param {{algorithm: string, digest: string}} [options.subject] - the artifact digest a subject must name (hex)
 * @param {string} [options.payloadType='application/vnd.in-toto+json']
 * @param {Buffer} [options.artifact] - the signed file, for bundles that sign an artifact directly
 * @returns {{statement: Object, claims: Object|null, signedAt: Date, keyHint: string|null}}
 * @throws {SigstoreError}
 */
function verifyBundle(bundle, options) {
  if (!bundle || typeof bundle !== 'object' || !/^application\/vnd\.dev\.sigstore\.bundle(?:\+json;version=0\.[12]|\.v0\.3\+json)$/.test(bundle.mediaType || '')) {
    throw new SigstoreError(`unsupported bundle media type ${String(bundle && bundle.mediaType).slice(0, 80)}`);
  }

  // A DSSE envelope (a signed statement), or a signature over an artifact
  // (cosign sign-blob), which is represented here the same way.
  let envelope = bundle.dsseEnvelope;
  let message = null;
  if (!envelope && bundle.messageSignature) {
    if (!options.artifact) {
      throw new SigstoreError('the bundle signs an artifact; pass its contents to verify it');
    }

    message = bundle.messageSignature;
    envelope = {payload: Buffer.from(options.artifact).toString('base64'), payloadType: '', signatures: [{sig: message.signature}]};
  }

  if (!envelope || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    throw new SigstoreError('only bundles with one signature are supported');
  }

  const trusted = loadTrustedRoot(options.trustedRoot);
  const verification = bundle.verificationMaterial || {};
  let certificate = null;
  let material;
  if (verification.certificate || verification.x509CertificateChain) {
    const raw = verification.certificate ? verification.certificate.rawBytes : verification.x509CertificateChain.certificates[0].rawBytes;
    certificate = new crypto.X509Certificate(b64(raw));
    material = {der: certificate.raw, key: certificate.publicKey};
  } else if (verification.publicKey && options.publicKeys && options.publicKeys[verification.publicKey.hint]) {
    const key = crypto.createPublicKey(options.publicKeys[verification.publicKey.hint]);
    material = {der: key.export({type: 'spki', format: 'der'}), key};
  } else {
    throw new SigstoreError('the bundle is signed with a key that is not trusted');
  }

  const entries = verification.tlogEntries || [];
  if (entries.length === 0) {
    throw new SigstoreError('the bundle has no transparency log entry');
  }

  // When the signature was made: the log's signed entry time (Rekor v1),
  // and any RFC 3161 timestamps.  The certificate must be valid at each.
  const times = [];
  const logged = verifyTlogEntry(entries[0], trusted, material, envelope);
  if (logged.time !== null) {
    times.push(logged.time);
  }

  for (const timestamp of (verification.timestampVerificationData && verification.timestampVerificationData.rfc3161Timestamps) || []) {
    times.push(verifyTimestamp(b64(timestamp.signedTimestamp), b64(envelope.signatures[0].sig), options.trustedRoot));
  }

  if (times.length === 0) {
    throw new SigstoreError('the bundle has no verifiable signing time (no signed entry timestamp or RFC 3161 timestamp)');
  }

  // The log key signed the entry's proof or promise: it must have been valid
  // then, whether the time comes from the log or from a timestamp authority
  // (a retired key must not vouch for entries made later).
  if (times.some(time => time < logged.log.start || time > logged.log.end)) {
    throw new SigstoreError('the entry was logged outside the log key\'s validity');
  }

  const signedAt = Math.min(...times);

  if (certificate) {
    if (times.some(time => time < Date.parse(certificate.validFrom) || time > Date.parse(certificate.validTo))) {
      throw new SigstoreError('the certificate was not valid when the entry was logged');
    }

    const chained = trusted.authorities.some(authority => {
      if (times.some(time => time < authority.start || time > authority.end)) {
        return false;
      }

      const [issuer, ...rest] = authority.chain;
      if (!certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey)) {
        return false;
      }

      for (const [index, link] of authority.chain.entries()) {
        const parent = rest[index] || link;
        if (!link.checkIssued(parent) || !link.verify(parent.publicKey)) {
          return false;
        }
      }

      return true;
    });
    if (!chained) {
      throw new SigstoreError('the certificate does not chain to a trusted certificate authority');
    }
  }

  const payload = b64(envelope.payload);
  const payloadType = String(envelope.payloadType || '');
  if (message) {
    // Signed over the artifact itself; the claims are all there is.
    const digest = message.messageDigest || {};
    if (digest.algorithm !== 'SHA2_256' || !b64(digest.digest).equals(require('node:crypto').createHash('sha256').update(payload).digest())) {
      throw new SigstoreError('the bundle signs a different artifact');
    }

    if (!verifySignature(material.key, payload, b64(envelope.signatures[0].sig))) {
      throw new SigstoreError('the signature over the artifact does not verify');
    }

    const claims = certificate ? certificateClaims(certificate) : null;
    checkIdentity(claims, options.identity);
    return {
      statement: null, claims, signedAt: new Date(signedAt), keyHint: verification.publicKey ? verification.publicKey.hint : null,
    };
  }

  if (!verifySignature(material.key, pae(payloadType, payload), b64(envelope.signatures[0].sig))) {
    throw new SigstoreError('the DSSE signature does not verify');
  }

  if (payloadType !== (options.payloadType || 'application/vnd.in-toto+json')) {
    throw new SigstoreError(`unexpected payload type ${payloadType.slice(0, 80)}`);
  }

  const claims = certificate ? certificateClaims(certificate) : null;
  checkIdentity(claims, options.identity);

  let statement;
  try {
    statement = JSON.parse(payload.toString('utf8'));
  } catch {
    throw new SigstoreError('the statement is not JSON');
  }

  if (options.subject) {
    const {algorithm, digest} = options.subject;
    const named = (statement.subject || []).some(subject => subject && subject.digest && subject.digest[algorithm] === digest);
    if (!named) {
      throw new SigstoreError(`the statement does not name the artifact (${algorithm}:${digest.slice(0, 16)}...)`);
    }
  }

  return {
    statement, claims, signedAt: new Date(signedAt), keyHint: verification.publicKey ? verification.publicKey.hint : null,
  };
}

module.exports = {
  verifyBundle,
  loadTrustedRoot,
  certificateClaims,
  rootFromInclusionProof,
  verifyCheckpoint,
  verifyTimestamp,
  pae,
  SigstoreError,
  FULCIO_OIDS,
};

'use strict';

/**
 * A private Sigstore for tests: a certificate authority (root and
 * intermediate) standing in for Fulcio, transparency log keys standing in
 * for Rekor v1 (ECDSA P-256) and Rekor v2 (Ed25519), a timestamp authority,
 * and bundles signed the way GitHub Actions, npm and cosign sign them.
 * Certificates and timestamps are made with the openssl command.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {canonicalize} = require('../../lib/util');
const {pae} = require('../../lib/sigstore');
const helpers = require('../helpers');

const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
const OIDS = {
  issuerV1: '1.3.6.1.4.1.57264.1.1',
  issuer: '1.3.6.1.4.1.57264.1.8',
  sourceRepositoryURI: '1.3.6.1.4.1.57264.1.12',
  sourceRepositoryDigest: '1.3.6.1.4.1.57264.1.13',
  sourceRepositoryRef: '1.3.6.1.4.1.57264.1.14',
};
const IN_TOTO = 'application/vnd.in-toto+json';
const BUNDLE_V3 = 'application/vnd.dev.sigstore.bundle.v0.3+json';

let authority = null;
let counter = 0;

function openssl(args, directory) {
  return helpers.openssl(args, {cwd: directory});
}

const unique = () => `${process.pid}-${++counter}-${crypto.randomBytes(3).toString('hex')}`;

/**
 * A certificate made with openssl.  `issuer` is another result of this
 * function (self-signed when omitted); `extensions` are openssl extension
 * lines.
 */
function makeCertificate(directory, {subject, curve = 'prime256v1', issuer, extensions = [], days = 3650, algorithm}) {
  const name = unique();
  const keyFile = `${name}.key`;
  const pemFile = `${name}.pem`;
  if (algorithm === 'ed25519') {
    openssl(['genpkey', '-algorithm', 'ed25519', '-out', keyFile], directory);
  } else {
    openssl(['ecparam', '-name', curve, '-genkey', '-noout', '-out', keyFile], directory);
  }

  if (issuer) {
    openssl(['req', '-new', '-key', keyFile, '-out', `${name}.csr`, '-subj', subject], directory);
    const args = ['x509', '-req', '-in', `${name}.csr`, '-CA', issuer.pemFile, '-CAkey', issuer.keyFile, '-set_serial', String(Date.now() + counter), '-out', pemFile, '-days', String(days)];
    if (extensions.length > 0) {
      fs.writeFileSync(path.join(directory, `${name}.ext`), `${extensions.join('\n')}\n`);
      args.push('-extfile', `${name}.ext`);
    }

    openssl(args, directory);
  } else {
    const args = ['req', '-new', '-x509', '-key', keyFile, '-out', pemFile, '-days', String(days), '-subj', subject];
    for (const extension of extensions) {
      args.push('-addext', extension);
    }

    openssl(args, directory);
  }

  const pem = fs.readFileSync(path.join(directory, pemFile), 'utf8');
  return {
    pem,
    der: new crypto.X509Certificate(pem).raw,
    key: crypto.createPrivateKey(fs.readFileSync(path.join(directory, keyFile))),
    keyFile,
    pemFile,
  };
}

const CA_EXTENSIONS = ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,keyCertSign,cRLSign'];

/**
 * A certificate authority with an intermediate, as Fulcio has.
 */
function makeAuthority(label = 'test') {
  const {directory} = getAuthority();
  const root = makeCertificate(directory, {subject: `/O=${label}/CN=${label} fulcio`, curve: 'secp384r1', extensions: CA_EXTENSIONS});
  const intermediate = makeCertificate(directory, {
    subject: `/O=${label}/CN=${label} fulcio intermediate`, curve: 'secp384r1', issuer: root, extensions: CA_EXTENSIONS,
  });
  return {root, intermediate};
}

/**
 * A timestamp authority: a root and a leaf allowed to sign timestamps.
 */
function makeTsa(label = 'test', directory = getAuthority().directory) {
  const root = makeCertificate(directory, {subject: `/O=${label}/CN=${label} tsa root`, extensions: CA_EXTENSIONS});
  const leaf = makeCertificate(directory, {
    subject: `/O=${label}/CN=${label} tsa`, issuer: root, extensions: ['basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature', 'extendedKeyUsage=critical,timeStamping'],
  });
  fs.writeFileSync(path.join(directory, `${leaf.pemFile}.chain`), root.pem);
  return {root, leaf};
}

const certificateEntry = certificate => ({rawBytes: certificate.der.toString('base64')});

/**
 * A trusted root naming certificate authorities, logs and timestamp
 * authorities (a root of logs alone needs no openssl).
 */
function trustedRootFor({ca, logs, tsa}) {
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    certificateAuthorities: ca
      ? [{
        uri: 'https://fulcio.test', certChain: {certificates: [certificateEntry(ca.intermediate), certificateEntry(ca.root)]}, validFor: {start: '2000-01-01T00:00:00Z'},
      }]
      : [],
    tlogs: logs.map(log => ({
      baseUrl: log.baseUrl,
      hashAlgorithm: 'SHA2_256',
      publicKey: {rawBytes: log.der.toString('base64'), keyDetails: log.keyDetails, validFor: {start: '2000-01-01T00:00:00Z'}},
      logId: {keyId: log.logId.toString('base64')},
    })),
    timestampAuthorities: tsa
      ? [{
        subject: {organization: 'test', commonName: 'test tsa'}, uri: 'https://tsa.test', certChain: {certificates: [certificateEntry(tsa.leaf), certificateEntry(tsa.root)]}, validFor: {start: '2000-01-01T00:00:00Z'},
      }]
      : [],
  };
}

/**
 * A transparency log key: ECDSA P-256 (Rekor v1) or Ed25519 (Rekor v2).
 */
function makeLog(type = 'ecdsa', baseUrl = 'https://rekor.test') {
  const pair = type === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const der = pair.publicKey.export({type: 'spki', format: 'der'});
  return {
    ...pair,
    der,
    logId: crypto.createHash('sha256').update(der).digest(),
    keyDetails: type === 'ed25519' ? 'PKIX_ED25519' : 'PKIX_ECDSA_P256_SHA_256',
    baseUrl,
    origin: new URL(baseUrl).host,
    algorithm: type === 'ed25519' ? null : 'sha256',
  };
}

/**
 * The certificate authority, log keys and timestamp authority (made once
 * per process).
 */
function getAuthority() {
  if (authority) {
    return authority;
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sigstore-fixture-'));
  process.once('exit', () => {
    fs.rmSync(directory, {recursive: true, force: true});
  });
  authority = {directory};
  const ca = makeAuthority();
  const log = makeLog('ecdsa', 'https://rekor.test');
  const log2 = makeLog('ed25519', 'https://log2.rekor.test');
  const tsa = makeTsa('test', directory);
  Object.assign(authority, {
    ca,
    caPem: ca.root.pem,
    log,
    log2,
    logId: log.logId,
    tsa,
    trustedRoot: trustedRootFor({ca, logs: [log, log2], tsa}),
  });
  return authority;
}

/**
 * A Fulcio-style signing certificate.  `claims` maps a claim name (see
 * OIDS) to its value: null omits it, and issuerV1 is stored as raw text as
 * Fulcio's deprecated extensions are.  `san` is an openssl name
 * ("URI:...", "email:...", "DNS:...") or null for none.
 */
function signingCertificate({repository = 'octo/app', workflow = '.github/workflows/release.yml', ref = 'refs/heads/main', commit = 'a'.repeat(40), issuer = GITHUB_ISSUER, san, claims = {}, curve = 'prime256v1', ca} = {}) {
  const {directory, ca: defaultCa} = getAuthority();
  const values = {
    issuer,
    sourceRepositoryURI: `https://github.com/${repository}`,
    sourceRepositoryDigest: commit,
    sourceRepositoryRef: ref,
    ...claims,
  };
  const extensions = [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=codeSigning',
  ];
  const name = san === undefined ? `URI:https://github.com/${repository}/${workflow}@${ref}` : san;
  if (name) {
    extensions.push(`subjectAltName=critical,${name}`);
  }

  for (const [claim, value] of Object.entries(values)) {
    if (value !== null && value !== undefined) {
      extensions.push(claim === 'issuerV1' ? `${OIDS[claim]}=DER:${Buffer.from(value).toString('hex')}` : `${OIDS[claim]}=ASN1:UTF8String:${value}`);
    }
  }

  const certificate = makeCertificate(directory, {
    subject: '/O=sigstore.dev', curve, issuer: (ca || defaultCa).intermediate, extensions, days: 1,
  });
  return {pem: certificate.pem, der: certificate.der, key: certificate.key};
}

/**
 * RFC 6962 Merkle tree helpers.
 */
const leafHash = data => crypto.createHash('sha256').update(Buffer.from([0])).update(data).digest();
const nodeHash = (left, right) => crypto.createHash('sha256').update(Buffer.from([1])).update(left).update(right).digest();
const largestPowerBelow = n => {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }

  return k;
};

function treeHash(leaves) {
  if (leaves.length === 1) {
    return leaves[0];
  }

  const k = largestPowerBelow(leaves.length);
  return nodeHash(treeHash(leaves.slice(0, k)), treeHash(leaves.slice(k)));
}

function auditPath(index, leaves) {
  if (leaves.length === 1) {
    return [];
  }

  const k = largestPowerBelow(leaves.length);
  return index < k
    ? [...auditPath(index, leaves.slice(0, k)), treeHash(leaves.slice(k))]
    : [...auditPath(index - k, leaves.slice(k)), treeHash(leaves.slice(0, k))];
}

/**
 * A tree of `size` leaves with `data` at `index`; the others are filler.
 * @returns {{root: Buffer, hashes: Buffer[], leaf: Buffer}}
 */
function merkleTree(data, {size = 7, index = 5} = {}) {
  const leaves = Array.from({length: size}, (_, position) => leafHash(position === index ? data : Buffer.from(`leaf ${position}`)));
  return {root: treeHash(leaves), hashes: auditPath(index, leaves), leaf: leaves[index]};
}

/**
 * A signed note (checkpoint) by a log.
 */
function checkpoint(log, {size, root, origin = log.origin}) {
  const body = `${origin}\n${size}\n${root.toString('base64')}\n`;
  const signature = crypto.sign(log.algorithm, Buffer.from(body), log.privateKey);
  const hint = log.logId.subarray(0, 4);
  return `${body}\n— ${origin} ${Buffer.concat([hint, signature]).toString('base64')}\n`;
}

/**
 * An RFC 3161 timestamp over `data` by the timestamp authority.
 *
 * @param {Buffer} data
 * @param {Object} [options]
 * @param {string} [options.hash='sha256'] - message imprint hash
 * @param {string} [options.signerDigest='sha256']
 * @param {boolean} [options.token=false] - the bare token instead of a TimeStampResp
 * @param {Object} [options.tsa] - another authority from makeTsa()
 * @returns {Buffer}
 */
function timestamp(data, {hash = 'sha256', signerDigest = 'sha256', token = false, tsa} = {}) {
  const {directory, tsa: defaultTsa} = getAuthority();
  const {leaf} = tsa || defaultTsa;
  const name = unique();
  fs.writeFileSync(path.join(directory, `${name}.data`), data);
  fs.writeFileSync(path.join(directory, `${name}.cnf`), [
    '[tsa]',
    'default_tsa = tsa_config',
    '[tsa_config]',
    `serial = ${name}.serial`,
    `signer_digest = ${signerDigest}`,
    'default_policy = 1.2.3.4.1',
    'digests = sha1, sha256, sha384, sha512',
    'accuracy = secs:1',
    'ordering = no',
    'tsa_name = yes',
    'ess_cert_id_chain = no',
    'ess_cert_id_alg = sha256',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(directory, `${name}.serial`), '01\n');
  openssl(['ts', '-query', '-data', `${name}.data`, `-${hash}`, '-cert', '-out', `${name}.tsq`], directory);
  const args = ['ts', '-reply', '-config', `${name}.cnf`, '-queryfile', `${name}.tsq`, '-signer', leaf.pemFile, '-inkey', leaf.keyFile, '-chain', `${leaf.pemFile}.chain`, '-out', `${name}.tsr`];
  if (token) {
    args.push('-token_out');
  }

  openssl(args, directory);
  return fs.readFileSync(path.join(directory, `${name}.tsr`));
}

const HASH_FOR_CURVE = {prime256v1: 'sha256', secp384r1: 'sha384', secp521r1: 'sha512'};

/**
 * The transparency log entry body recording a signature.
 */
function entryBody(kind, {payloadHash, signature, keyPem, keyDer, isCertificate}) {
  const verifier = Buffer.from(keyPem).toString('base64');
  switch (kind) {
    case 'dsse/0.0.1': {
      return {
        apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: payloadHash}, signatures: [{signature, verifier}]},
      };
    }

    case 'intoto/0.0.2': {
      return {
        apiVersion: '0.0.2',
        kind: 'intoto',
        spec: {
          content: {
            envelope: {payloadType: IN_TOTO, signatures: [{sig: Buffer.from(signature).toString('base64'), publicKey: verifier}]},
            payloadHash: {algorithm: 'sha256', value: payloadHash},
          },
        },
      };
    }

    case 'hashedrekord/0.0.1': {
      return {
        apiVersion: '0.0.1', kind: 'hashedrekord', spec: {data: {hash: {algorithm: 'sha256', value: payloadHash}}, signature: {content: signature, publicKey: {content: verifier}}},
      };
    }

    case 'dsse/0.0.2': {
      const verifierField = isCertificate ? {x509Certificate: {rawBytes: keyDer.toString('base64')}} : {publicKey: {rawBytes: keyDer.toString('base64')}};
      return {
        apiVersion: '0.0.2',
        kind: 'dsse',
        spec: {
          dsseV002: {
            payloadHash: {algorithm: 'SHA2_256', digest: Buffer.from(payloadHash, 'hex').toString('base64')},
            signatures: [{content: signature, verifier: {...verifierField, keyDetails: 'PKIX_ECDSA_P256_SHA_256'}}],
          },
        },
      };
    }

    default: {
      const [name, version] = kind.split('/');
      return {apiVersion: version, kind: name, spec: {}};
    }
  }
}

/**
 * A transparency log entry for a body: with a signed entry timestamp
 * (Rekor v1) and/or an inclusion proof to a signed checkpoint.
 */
function logEntry(body, {kind, log, integratedTime = Math.floor(Date.now() / 1000), promise = true, proof = false, logIndex = 1234}) {
  const canonicalizedBody = Buffer.from(JSON.stringify(body)).toString('base64');
  const [name, version] = kind.split('/');
  const entry = {
    logIndex: String(logIndex),
    logId: {keyId: log.logId.toString('base64')},
    kindVersion: {kind: name, version},
    integratedTime: promise ? String(integratedTime) : '0',
    canonicalizedBody,
  };
  if (promise) {
    const payload = canonicalize({
      body: canonicalizedBody, integratedTime, logID: log.logId.toString('hex'), logIndex,
    });
    entry.inclusionPromise = {signedEntryTimestamp: crypto.sign(log.algorithm, Buffer.from(payload), log.privateKey).toString('base64')};
  }

  if (proof) {
    const size = 7;
    const index = 5;
    const tree = merkleTree(Buffer.from(canonicalizedBody, 'base64'), {size, index});
    entry.inclusionProof = {
      logIndex: String(index),
      rootHash: tree.root.toString('base64'),
      treeSize: String(size),
      hashes: tree.hashes.map(hash => hash.toString('base64')),
      checkpoint: {envelope: checkpoint(log, {size, root: tree.root})},
    };
  }

  return entry;
}

const DEFAULT_STATEMENT = {
  _type: 'https://in-toto.io/Statement/v1', subject: [{name: 'app.tgz', digest: {sha256: 'ab'.repeat(32)}}], predicateType: 'https://slsa.dev/provenance/v1', predicate: {},
};

/**
 * A Sigstore bundle.
 *
 * @param {Object} [input]
 * @param {Object} [input.statement] - the in-toto statement (DSSE bundles)
 * @param {Buffer} [input.payload] - raw DSSE payload instead of a statement
 * @param {string} [input.payloadType]
 * @param {Buffer} [input.artifact] - sign this file directly (messageSignature, as cosign sign-blob)
 * @param {'certificate'|'chain'|'publicKey'} [input.material='certificate']
 * @param {Object} [input.certificate] - options for signingCertificate()
 * @param {string} [input.curve='prime256v1'] - signing key curve
 * @param {string} [input.kind] - log entry kind (default dsse/0.0.1, hashedrekord/0.0.1 for artifacts, dsse/0.0.2 for Rekor v2)
 * @param {'v1'|'v2'} [input.rekor='v1'] - v2: Ed25519 log, inclusion proof only, time from a TSA
 * @param {boolean} [input.promise] - include a signed entry timestamp (default: Rekor v1)
 * @param {boolean} [input.proof] - include an inclusion proof (default: Rekor v2)
 * @param {number} [input.timestamps] - RFC 3161 timestamps to add (default 1 for Rekor v2)
 * @param {number} [input.integratedTime] - seconds (default now)
 * @param {string} [input.mediaType]
 * @param {string} [input.hint='test-key'] - key hint for publicKey material
 * @returns {{bundle: Object, trustedRoot: Object, certificate: Object|null, publicKeyPem: string, key: crypto.KeyObject, body: Object}}
 */
function makeBundle({
  statement = DEFAULT_STATEMENT,
  payload,
  payloadType = IN_TOTO,
  artifact,
  material = 'certificate',
  certificate: certificateOptions = {},
  curve = 'prime256v1',
  kind,
  rekor = 'v1',
  promise = rekor === 'v1',
  proof = rekor === 'v2',
  timestamps = rekor === 'v2' ? 1 : 0,
  integratedTime,
  mediaType = BUNDLE_V3,
  hint = 'test-key',
} = {}) {
  const {log, log2, trustedRoot} = getAuthority();
  let certificate = null;
  let key;
  let publicKeyPem;
  if (material === 'publicKey') {
    const pair = crypto.generateKeyPairSync('ec', {namedCurve: curve});
    key = pair.privateKey;
    publicKeyPem = pair.publicKey.export({type: 'spki', format: 'pem'});
  } else {
    certificate = signingCertificate({curve, ...certificateOptions});
    key = certificate.key;
    publicKeyPem = crypto.createPublicKey(certificate.pem).export({type: 'spki', format: 'pem'});
  }

  const algorithm = HASH_FOR_CURVE[curve];
  let content;
  let signed;
  let entryKind = kind;
  if (artifact) {
    entryKind ||= 'hashedrekord/0.0.1';
    const bytes = Buffer.from(artifact);
    const signature = crypto.sign(algorithm, bytes, key).toString('base64');
    content = {
      messageSignature: {messageDigest: {algorithm: 'SHA2_256', digest: crypto.createHash('sha256').update(bytes).digest('base64')}, signature},
    };
    signed = {signature, payloadHash: crypto.createHash('sha256').update(bytes).digest('hex')};
  } else {
    entryKind ||= rekor === 'v2' ? 'dsse/0.0.2' : 'dsse/0.0.1';
    const bytes = payload || Buffer.from(JSON.stringify(statement));
    const signature = crypto.sign(algorithm, pae(payloadType, bytes), key).toString('base64');
    content = {dsseEnvelope: {payload: bytes.toString('base64'), payloadType, signatures: [{sig: signature}]}};
    signed = {signature, payloadHash: crypto.createHash('sha256').update(bytes).digest('hex')};
  }

  const body = entryBody(entryKind, {
    ...signed,
    keyPem: certificate ? certificate.pem : publicKeyPem,
    keyDer: certificate ? certificate.der : crypto.createPublicKey(publicKeyPem).export({type: 'spki', format: 'der'}),
    isCertificate: Boolean(certificate),
  });
  const entry = logEntry(body, {
    kind: entryKind, log: rekor === 'v2' ? log2 : log, integratedTime: integratedTime ?? Math.floor(Date.now() / 1000), promise, proof,
  });
  const verificationMaterial = {tlogEntries: [entry]};
  if (material === 'certificate') {
    verificationMaterial.certificate = {rawBytes: certificate.der.toString('base64')};
  } else if (material === 'chain') {
    verificationMaterial.x509CertificateChain = {certificates: [{rawBytes: certificate.der.toString('base64')}]};
  } else {
    verificationMaterial.publicKey = {hint};
  }

  if (timestamps > 0) {
    const signatureBytes = Buffer.from(signed.signature, 'base64');
    verificationMaterial.timestampVerificationData = {
      rfc3161Timestamps: Array.from({length: timestamps}, () => ({signedTimestamp: timestamp(signatureBytes).toString('base64')})),
    };
  }

  return {
    bundle: {mediaType, verificationMaterial, ...content},
    trustedRoot,
    certificate,
    publicKeyPem,
    key,
    body,
  };
}

/**
 * A bundle attesting subjects (GitHub artifact attestation shape).
 *
 * @param {Object} input
 * @param {Array<{name: string, digest: Object<string, string>}>} input.subjects
 * @param {string} input.repository - owner/name
 * @param {string} [input.workflow='.github/workflows/release.yml']
 * @param {string} [input.ref='refs/heads/main']
 * @param {string} input.commit
 * @param {string} [input.predicateType='https://slsa.dev/provenance/v1']
 * @param {string} [input.issuer]
 * @param {string} [input.san] - certificate URI instead of the workflow's
 * @returns {{bundle: Object, trustedRoot: Object}}
 */
function attest({subjects, repository, workflow = '.github/workflows/release.yml', ref = 'refs/heads/main', commit, predicateType = 'https://slsa.dev/provenance/v1', issuer, san}) {
  const {bundle, trustedRoot} = makeBundle({
    statement: {
      _type: 'https://in-toto.io/Statement/v1', subject: subjects, predicateType, predicate: {},
    },
    certificate: {
      repository, workflow, ref, commit, issuer, san: san ? `URI:${san}` : undefined,
    },
  });
  return {bundle, trustedRoot};
}

module.exports = {
  attest,
  makeBundle,
  getAuthority,
  signingCertificate,
  makeCertificate,
  makeAuthority,
  makeTsa,
  makeLog,
  trustedRootFor,
  merkleTree,
  leafHash,
  checkpoint,
  timestamp,
  logEntry,
  entryBody,
  GITHUB_ISSUER,
  IN_TOTO,
  BUNDLE_V3,
};

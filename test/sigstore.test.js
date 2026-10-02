'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const asn1 = require('../lib/asn1');
const sigstore = require('../lib/sigstore');
const fixture = require('./fixtures/sigstore');

const {verifyBundle, SigstoreError} = sigstore;
const DATA = path.join(__dirname, 'fixtures/sigstore-data');
const readJson = name => JSON.parse(fs.readFileSync(path.join(DATA, name), 'utf8'));
const realRoot = readJson('trusted_root.json');
const clone = value => structuredClone(value);
const b64json = value => Buffer.from(JSON.stringify(value)).toString('base64');
const fromB64json = value => JSON.parse(Buffer.from(value, 'base64').toString('utf8'));

/**
 * The npm registry's signing keys (from its keys endpoint), by key id.
 */
function npmPublicKeys() {
  const keys = {};
  for (const key of readJson('npm-keys.json').keys) {
    keys[key.keyid] = `-----BEGIN PUBLIC KEY-----\n${key.key}\n-----END PUBLIC KEY-----\n`;
  }

  return keys;
}

function rejects(fn, pattern) {
  assert.throws(fn, error => {
    assert.ok(error instanceof SigstoreError, `${error.constructor.name}: ${error.message}`);
    assert.match(error.message, pattern);
    return true;
  });
}

const authority = fixture.getAuthority();
const {trustedRoot} = authority;

/**
 * Replace a bundle's log entry with one the trusted log signs over `body`.
 */
function withEntry(bundle, body, options = {}) {
  const copy = clone(bundle);
  const {kindVersion} = copy.verificationMaterial.tlogEntries[0];
  copy.verificationMaterial.tlogEntries = [fixture.logEntry(body, {kind: `${kindVersion.kind}/${kindVersion.version}`, log: authority.log, ...options})];
  return copy;
}

test('pae encodes the DSSE pre-authentication message', () => {
  assert.strictEqual(sigstore.pae('type/x', Buffer.from('hello')).toString(), 'DSSEv1 6 type/x 5 hello');
  assert.strictEqual(sigstore.pae('ü', Buffer.alloc(0)).toString(), 'DSSEv1 2 ü 0 ');
});

test('real npm provenance and publish attestations verify', () => {
  const publicKeys = npmPublicKeys();
  const {attestations} = readJson('npm-sigstore-3.0.0.json');
  const digest = '3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78';
  const provenance = attestations.find(item => item.predicateType === 'https://slsa.dev/provenance/v1');
  const result = verifyBundle(provenance.bundle, {
    trustedRoot: realRoot,
    subject: {algorithm: 'sha512', digest},
    identity: {
      issuer: 'https://token.actions.githubusercontent.com',
      subjectAlternativeName: /^ht{2}ps:\/{2}github\.com(?:\/sigstore){2}-js\/\.github\/workflows\/release\.yml@refs\/heads\/main$/,
      sourceRepositoryURI: 'https://github.com/sigstore/sigstore-js',
    },
  });
  assert.strictEqual(result.signedAt.toISOString(), '2024-10-14T16:13:45.000Z');
  assert.strictEqual(result.keyHint, null);
  assert.strictEqual(result.statement.predicateType, 'https://slsa.dev/provenance/v1');
  assert.strictEqual(result.claims.runnerEnvironment, 'github-hosted');
  assert.match(result.claims.sourceRepositoryDigest, /^[\da-f]{40}$/);

  const publish = attestations.find(item => item.predicateType.includes('/npm/attestation/'));
  const published = verifyBundle(publish.bundle, {trustedRoot: realRoot, publicKeys, subject: {algorithm: 'sha512', digest}});
  assert.strictEqual(published.keyHint, 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA');
  assert.strictEqual(published.claims, null);
  assert.strictEqual(published.statement.subject[0].name, 'pkg:npm/sigstore@3.0.0');

  // Other bundle versions and log entry kinds from the registry.
  for (const attestation of readJson('npm-octokit-rest-22.0.1.json').attestations) {
    const verified = verifyBundle(attestation.bundle, {trustedRoot: realRoot, publicKeys});
    assert.ok(verified.signedAt.getTime() > Date.parse('2025-10-31T00:00:00Z'));
  }
});

test('real npm bundles fail when altered', () => {
  const {attestations} = readJson('npm-sigstore-3.0.0.json');
  const provenance = attestations.find(item => item.predicateType === 'https://slsa.dev/provenance/v1').bundle;
  rejects(() => verifyBundle(provenance, {trustedRoot: realRoot, subject: {algorithm: 'sha512', digest: '00'.repeat(64)}}), /does not name the artifact \(sha512:0{16}\.{3}\)/);
  rejects(() => verifyBundle(provenance, {trustedRoot: realRoot, identity: {sourceRepositoryURI: 'https://github.com/evil/fork'}}), /certificate sourceRepositoryURI is "https:\/\/github.com\/sigstore\/sigstore-js", expected https:\/\/github.com\/evil\/fork/);
  rejects(() => verifyBundle(provenance, {trustedRoot}), /transparency log is not in the trusted root/);

  const tampered = clone(provenance);
  const statement = fromB64json(tampered.dsseEnvelope.payload);
  statement.subject[0].digest.sha512 = 'ff'.repeat(64);
  tampered.dsseEnvelope.payload = b64json(statement);
  rejects(() => verifyBundle(tampered, {trustedRoot: realRoot}), /log entry is for a different payload/);

  const publish = attestations.find(item => item.predicateType.includes('/npm/attestation/')).bundle;
  rejects(() => verifyBundle(publish, {trustedRoot: realRoot}), /signed with a key that is not trusted/);
  rejects(() => verifyBundle(publish, {trustedRoot: realRoot, publicKeys: {other: npmPublicKeys()['SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA']}}), /not trusted/);
  // The right hint, but another key.
  rejects(() => verifyBundle(publish, {trustedRoot: realRoot, publicKeys: {'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA': npmPublicKeys()['SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U']}}), /records a different signature or signing key/);
});

test('a real cosign bundle: claims, inclusion proof and checkpoint', () => {
  const bundle = readJson('cpython-release.sigstore.json');
  const certificate = new crypto.X509Certificate(Buffer.from(bundle.verificationMaterial.certificate.rawBytes, 'base64'));
  const claims = sigstore.certificateClaims(certificate);
  assert.deepStrictEqual(claims, {subjectAlternativeName: 'thomas@python.org', issuer: 'https://accounts.google.com'});

  const entry = bundle.verificationMaterial.tlogEntries[0];
  const proof = entry.inclusionProof;
  const leaf = fixture.leafHash(Buffer.from(entry.canonicalizedBody, 'base64'));
  const root = sigstore.rootFromInclusionProof(BigInt(proof.logIndex), BigInt(proof.treeSize), leaf, proof.hashes.map(hash => Buffer.from(hash, 'base64')));
  assert.strictEqual(root.toString('base64'), proof.rootHash);

  const {logs} = sigstore.loadTrustedRoot(realRoot);
  const checkpoint = sigstore.verifyCheckpoint(proof.checkpoint.envelope, logs[0]);
  assert.strictEqual(checkpoint.origin, 'rekor.sigstore.dev - 1193050959916656506');
  assert.strictEqual(checkpoint.size, BigInt(proof.treeSize));
  assert.ok(checkpoint.root.equals(root));
  // The Rekor v2 log's Ed25519 key did not sign it.
  assert.throws(() => sigstore.verifyCheckpoint(proof.checkpoint.envelope, logs[1]), /checkpoint signature does not verify/);

  // The bundle signs a file directly, so the file is needed.
  rejects(() => verifyBundle(bundle, {trustedRoot: realRoot}), /pass its contents/);
  rejects(() => verifyBundle(bundle, {trustedRoot: realRoot, artifact: Buffer.from('not the release')}), /log entry is for a different payload/);
});

test('a real timestamp from Sigstore\'s timestamp authority', () => {
  const response = fs.readFileSync(path.join(DATA, 'tsa-response.tsr'));
  const signed = fs.readFileSync(path.join(DATA, 'tsa-signed.bin'));
  assert.strictEqual(new Date(sigstore.verifyTimestamp(response, signed, realRoot)).toISOString(), '2026-09-30T12:23:06.000Z');
  rejects(() => sigstore.verifyTimestamp(response, Buffer.from('other'), realRoot), /for a different signature/);
  rejects(() => sigstore.verifyTimestamp(response, signed, trustedRoot), /not signed by a trusted timestamp authority/);
});

test('loadTrustedRoot reads authorities, logs and validity windows', () => {
  const loaded = sigstore.loadTrustedRoot(realRoot);
  assert.strictEqual(loaded.authorities.length, 2);
  assert.strictEqual(loaded.authorities[0].end, Date.parse('2022-12-31T23:59:59.999Z'));
  assert.strictEqual(loaded.authorities[1].end, Infinity);
  assert.strictEqual(loaded.authorities[1].chain.length, 2);
  assert.strictEqual(loaded.logs[0].baseUrl, 'https://rekor.sigstore.dev');
  assert.strictEqual(loaded.logs[1].key.asymmetricKeyType, 'ed25519');
  assert.strictEqual(loaded.logs[0].start, Date.parse('2021-01-12T11:53:27Z'));

  const bare = clone(trustedRoot);
  delete bare.certificateAuthorities[0].validFor;
  bare.tlogs[0].publicKey.validFor = {end: '2030-01-01T00:00:00Z'};
  const windows = sigstore.loadTrustedRoot(bare);
  assert.deepStrictEqual([windows.authorities[0].start, windows.authorities[0].end], [-Infinity, Infinity]);
  assert.deepStrictEqual([windows.logs[0].start, windows.logs[0].end], [-Infinity, Date.parse('2030-01-01T00:00:00Z')]);
  assert.deepStrictEqual(sigstore.loadTrustedRoot({}), {authorities: [], logs: []});
});

test('rootFromInclusionProof matches every leaf of trees of many sizes', () => {
  for (let size = 1; size <= 33; size++) {
    for (let index = 0; index < size; index++) {
      const tree = fixture.merkleTree(Buffer.from('entry'), {size, index});
      assert.ok(sigstore.rootFromInclusionProof(BigInt(index), BigInt(size), tree.leaf, tree.hashes).equals(tree.root), `${index}/${size}`);
    }
  }
});

test('rootFromInclusionProof rejects malformed proofs', () => {
  const tree = fixture.merkleTree(Buffer.from('entry'), {size: 6, index: 2});
  assert.throws(() => sigstore.rootFromInclusionProof(6n, 6n, tree.leaf, tree.hashes), /outside the tree/);
  assert.throws(() => sigstore.rootFromInclusionProof(2n, 6n, tree.leaf, [...tree.hashes, tree.root]), /too long/);
  assert.throws(() => sigstore.rootFromInclusionProof(2n, 6n, tree.leaf, tree.hashes.slice(0, -1)), /too short/);
  // A proof for another position leads elsewhere.
  assert.ok(!sigstore.rootFromInclusionProof(3n, 6n, tree.leaf, tree.hashes).equals(tree.root));
});

test('verifyCheckpoint checks the note signature and its fields', () => {
  const [ecLog, edLog] = sigstore.loadTrustedRoot(trustedRoot).logs;
  const root = crypto.randomBytes(32);
  for (const [log, trusted] of [[authority.log, ecLog], [authority.log2, edLog]]) {
    const note = fixture.checkpoint(log, {size: 42, root});
    const parsed = sigstore.verifyCheckpoint(note, trusted);
    assert.strictEqual(parsed.origin, log.origin);
    assert.strictEqual(parsed.size, 42n);
    assert.ok(parsed.root.equals(root));
  }

  const note = fixture.checkpoint(authority.log, {size: 42, root});
  assert.throws(() => sigstore.verifyCheckpoint(note, edLog), /does not verify with the log's key/);
  assert.throws(() => sigstore.verifyCheckpoint(note.replace('\n\n', '\n'), ecLog), /malformed checkpoint/);
  assert.throws(() => sigstore.verifyCheckpoint(note.replace('42', '43'), ecLog), /does not verify/);
  // Lines that are not signatures, and signatures too short to hold one.
  const [body] = note.split('\n\n');
  assert.throws(() => sigstore.verifyCheckpoint(`${body}\n\nnot a signature\n— rekor.test AAAA\n`, ecLog), /does not verify/);
  // A signed note, but not a checkpoint.
  const sign = text => `${text}\n— x ${Buffer.concat([Buffer.alloc(4), crypto.sign('sha256', Buffer.from(text), authority.log.privateKey)]).toString('base64')}\n`;
  assert.throws(() => sigstore.verifyCheckpoint(sign('rekor.test\nmany\nAAAA\n'), ecLog), /malformed checkpoint size/);
  assert.throws(() => sigstore.verifyCheckpoint(sign('rekor.test\n'), ecLog), /malformed checkpoint size/);
  // A log key that cannot verify signatures at all.
  const x25519 = {key: crypto.generateKeyPairSync('x25519').publicKey};
  assert.throws(() => sigstore.verifyCheckpoint(note, x25519), /does not verify/);
});

test('certificateClaims reads Fulcio extensions', () => {
  const email = fixture.signingCertificate({
    san: 'email:dev@example.com', claims: {
      issuer: null, issuerV1: 'https://accounts.example.com', sourceRepositoryURI: null, sourceRepositoryDigest: null, sourceRepositoryRef: null,
    },
  });
  assert.deepStrictEqual(sigstore.certificateClaims(new crypto.X509Certificate(email.pem)), {subjectAlternativeName: 'dev@example.com', issuer: 'https://accounts.example.com'});

  // The current issuer extension wins over the deprecated one.
  const both = fixture.signingCertificate({issuer: 'https://new.example.com', claims: {issuerV1: 'https://old.example.com'}});
  assert.strictEqual(sigstore.certificateClaims(new crypto.X509Certificate(both.pem)).issuer, 'https://new.example.com');

  const bare = fixture.signingCertificate({
    san: null, claims: {
      issuer: null, sourceRepositoryURI: null, sourceRepositoryDigest: null, sourceRepositoryRef: null,
    },
  });
  assert.deepStrictEqual(sigstore.certificateClaims(new crypto.X509Certificate(bare.pem)), {subjectAlternativeName: null, issuer: null});

  const dns = fixture.signingCertificate({san: 'DNS:build.example.com'});
  const claims = sigstore.certificateClaims(new crypto.X509Certificate(dns.pem));
  assert.strictEqual(claims.subjectAlternativeName, null);
  assert.strictEqual(claims.sourceRepositoryRef, 'refs/heads/main');
  assert.strictEqual(claims.issuer, fixture.GITHUB_ISSUER);
  assert.ok(Object.values(sigstore.FULCIO_OIDS).includes('buildSignerURI'));
});

test('a GitHub attestation verifies with identity and subject', () => {
  const digest = crypto.createHash('sha256').update('artifact').digest('hex');
  const {bundle} = fixture.attest({
    subjects: [{name: 'other', digest: {sha512: 'x'}}, null, {name: 'app', digest: {sha256: digest}}], repository: 'octo/app', commit: 'b'.repeat(40), ref: 'refs/tags/v1.0.0',
  });
  const result = verifyBundle(bundle, {
    trustedRoot,
    subject: {algorithm: 'sha256', digest},
    identity: {
      issuer: fixture.GITHUB_ISSUER, subjectAlternativeName: /@refs\/tags\/v1\.0\.0$/, sourceRepositoryDigest: 'b'.repeat(40),
    },
  });
  assert.strictEqual(result.claims.sourceRepositoryURI, 'https://github.com/octo/app');
  assert.strictEqual(result.statement.subject[2].name, 'app');
  assert.ok(Math.abs(result.signedAt.getTime() - Date.now()) < 60_000);

  rejects(() => verifyBundle(bundle, {trustedRoot, identity: {subjectAlternativeName: /evil/}}), /certificate subjectAlternativeName is ".*", expected \/evil\//);
  rejects(() => verifyBundle(bundle, {trustedRoot, identity: {buildTrigger: /push/}}), /certificate buildTrigger is undefined/);
  rejects(() => verifyBundle(bundle, {trustedRoot, subject: {algorithm: 'sha256', digest: '0'.repeat(64)}}), /does not name the artifact/);
});

test('bundle media types, envelopes and key material', () => {
  const made = fixture.makeBundle({mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1', material: 'chain'});
  assert.strictEqual(verifyBundle(made.bundle, {trustedRoot}).claims.issuer, fixture.GITHUB_ISSUER);
  const v2 = clone(made.bundle);
  v2.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.2';
  assert.ok(verifyBundle(v2, {trustedRoot}).statement);

  for (const bad of [null, 'bundle', {}, {mediaType: 'application/vnd.dev.sigstore.bundle.v0.4+json'}]) {
    rejects(() => verifyBundle(bad, {trustedRoot}), /unsupported bundle media type/);
  }

  const {bundle} = made;
  const noEnvelope = clone(bundle);
  delete noEnvelope.dsseEnvelope;
  rejects(() => verifyBundle(noEnvelope, {trustedRoot}), /only bundles with one signature/);
  const twoSignatures = clone(bundle);
  twoSignatures.dsseEnvelope.signatures.push(twoSignatures.dsseEnvelope.signatures[0]);
  rejects(() => verifyBundle(twoSignatures, {trustedRoot}), /only bundles with one signature/);
  const noSignatures = clone(bundle);
  noSignatures.dsseEnvelope.signatures = 'sig';
  rejects(() => verifyBundle(noSignatures, {trustedRoot}), /only bundles with one signature/);

  const noMaterial = clone(bundle);
  delete noMaterial.verificationMaterial;
  rejects(() => verifyBundle(noMaterial, {trustedRoot}), /key that is not trusted/);
  const noEntries = clone(bundle);
  delete noEntries.verificationMaterial.tlogEntries;
  rejects(() => verifyBundle(noEntries, {trustedRoot}), /no transparency log entry/);
});

test('bundles signed with a known public key', () => {
  for (const curve of ['prime256v1', 'secp384r1', 'secp521r1']) {
    const {bundle, publicKeyPem} = fixture.makeBundle({material: 'publicKey', curve, hint: 'registry-key'});
    const result = verifyBundle(bundle, {trustedRoot, publicKeys: {'registry-key': publicKeyPem}});
    assert.strictEqual(result.keyHint, 'registry-key');
    assert.strictEqual(result.claims, null);
    rejects(() => verifyBundle(bundle, {trustedRoot, publicKeys: {'registry-key': publicKeyPem}, identity: {issuer: fixture.GITHUB_ISSUER}}), /certificate issuer is null/);
  }
});

test('log entry kinds: dsse, intoto, hashedrekord and Rekor v2 dsse', () => {
  const kinds = [
    {kind: 'intoto/0.0.2'},
    {kind: 'intoto/0.0.2', material: 'publicKey'},
    {kind: 'dsse/0.0.1', material: 'publicKey', proof: true},
    {rekor: 'v2'},
    {rekor: 'v2', material: 'publicKey'},
    {rekor: 'v2', material: 'chain', timestamps: 2},
  ];
  for (const options of kinds) {
    const {bundle, publicKeyPem} = fixture.makeBundle(options);
    const result = verifyBundle(bundle, {trustedRoot, publicKeys: {'test-key': publicKeyPem}});
    assert.strictEqual(result.statement.predicateType, 'https://slsa.dev/provenance/v1', JSON.stringify(options));
  }
});

test('signatures over an artifact (cosign sign-blob)', () => {
  const artifact = Buffer.from('SHA256SUMS contents\n');
  const {bundle} = fixture.makeBundle({artifact, certificate: {san: 'email:release@example.com', claims: {issuer: 'https://accounts.example.com'}}});
  const result = verifyBundle(bundle, {trustedRoot, artifact, identity: {subjectAlternativeName: 'release@example.com'}});
  assert.strictEqual(result.statement, null);
  assert.strictEqual(result.claims.issuer, 'https://accounts.example.com');
  assert.strictEqual(result.keyHint, null);
  rejects(() => verifyBundle(bundle, {trustedRoot, artifact, identity: {subjectAlternativeName: 'other@example.com'}}), /subjectAlternativeName/);
  rejects(() => verifyBundle(bundle, {trustedRoot, artifact: Buffer.from('other')}), /different payload/);

  // Key-signed, and logged by Rekor v2 with a timestamp.
  const keyed = fixture.makeBundle({
    artifact, material: 'publicKey', rekor: 'v2', kind: 'hashedrekord/0.0.1',
  });
  const keyedResult = verifyBundle(keyed.bundle, {trustedRoot, artifact, publicKeys: {'test-key': keyed.publicKeyPem}});
  assert.strictEqual(keyedResult.keyHint, 'test-key');
  assert.strictEqual(keyedResult.claims, null);

  // The message digest must be the artifact's SHA-256.
  const wrongAlgorithm = clone(bundle);
  wrongAlgorithm.messageSignature.messageDigest.algorithm = 'SHA2_384';
  rejects(() => verifyBundle(wrongAlgorithm, {trustedRoot, artifact}), /signs a different artifact/);
  const noDigest = clone(bundle);
  delete noDigest.messageSignature.messageDigest;
  rejects(() => verifyBundle(noDigest, {trustedRoot, artifact}), /signs a different artifact/);
  const wrongDigest = clone(bundle);
  wrongDigest.messageSignature.messageDigest.digest = crypto.createHash('sha256').update('other').digest('base64');
  rejects(() => verifyBundle(wrongDigest, {trustedRoot, artifact}), /signs a different artifact/);
});

test('an artifact signature that does not verify', () => {
  const artifact = Buffer.from('release notes');
  const made = fixture.makeBundle({artifact});
  // Sign something else, and log that signature for the artifact's hash.
  const signature = crypto.sign('sha256', Buffer.from('something else'), made.key).toString('base64');
  const body = fixture.entryBody('hashedrekord/0.0.1', {
    payloadHash: crypto.createHash('sha256').update(artifact).digest('hex'), signature, keyPem: made.certificate.pem,
  });
  const bundle = withEntry(made.bundle, body);
  bundle.messageSignature.signature = signature;
  rejects(() => verifyBundle(bundle, {trustedRoot, artifact}), /signature over the artifact does not verify/);
});

test('DSSE envelopes: signature, payload type and statement', () => {
  const made = fixture.makeBundle();
  const tampered = clone(made.bundle);
  tampered.dsseEnvelope.payloadType = 'application/json';
  rejects(() => verifyBundle(tampered, {trustedRoot}), /DSSE signature does not verify/);

  const custom = fixture.makeBundle({payloadType: 'application/vnd.example+json', payload: Buffer.from('{"custom":true}')});
  rejects(() => verifyBundle(custom.bundle, {trustedRoot}), /unexpected payload type application\/vnd.example\+json/);
  assert.deepStrictEqual(verifyBundle(custom.bundle, {trustedRoot, payloadType: 'application/vnd.example+json'}).statement, {custom: true});
  rejects(() => verifyBundle(custom.bundle, {trustedRoot, payloadType: 'application/vnd.example+json', subject: {algorithm: 'sha256', digest: 'ab'.repeat(32)}}), /does not name the artifact/);

  const untyped = fixture.makeBundle({payloadType: ''});
  delete untyped.bundle.dsseEnvelope.payloadType;
  rejects(() => verifyBundle(untyped.bundle, {trustedRoot}), /unexpected payload type $/);

  const notJson = fixture.makeBundle({payload: Buffer.from('not json')});
  rejects(() => verifyBundle(notJson.bundle, {trustedRoot}), /statement is not JSON/);
});

test('the log entry must be authentic', () => {
  const {bundle} = fixture.makeBundle({proof: true});
  const entryOf = value => value.verificationMaterial.tlogEntries[0];

  const unknownLog = clone(bundle);
  entryOf(unknownLog).logId.keyId = crypto.randomBytes(32).toString('base64');
  rejects(() => verifyBundle(unknownLog, {trustedRoot}), /not in the trusted root/);
  const noLogId = clone(bundle);
  delete entryOf(noLogId).logId;
  rejects(() => verifyBundle(noLogId, {trustedRoot}), /not in the trusted root/);

  const badPromise = clone(bundle);
  entryOf(badPromise).integratedTime = String(Number(entryOf(badPromise).integratedTime) + 1);
  rejects(() => verifyBundle(badPromise, {trustedRoot}), /signed entry timestamp does not verify/);
  const noTime = clone(bundle);
  delete entryOf(noTime).integratedTime;
  delete entryOf(noTime).canonicalizedBody;
  rejects(() => verifyBundle(noTime, {trustedRoot}), /signed entry timestamp does not verify/);

  // Without the signed entry timestamp the inclusion proof must hold.
  const proofOnly = clone(bundle);
  delete entryOf(proofOnly).inclusionPromise;
  rejects(() => verifyBundle(proofOnly, {trustedRoot}), /no verifiable signing time/);
  const wrongRoot = clone(proofOnly);
  entryOf(wrongRoot).inclusionProof.rootHash = crypto.randomBytes(32).toString('base64');
  rejects(() => verifyBundle(wrongRoot, {trustedRoot}), /does not lead to the signed checkpoint/);
  const wrongSize = clone(proofOnly);
  const envelope = fixture.checkpoint(authority.log, {size: 8, root: Buffer.from(entryOf(bundle).inclusionProof.rootHash, 'base64')});
  entryOf(wrongSize).inclusionProof.checkpoint.envelope = envelope;
  rejects(() => verifyBundle(wrongSize, {trustedRoot}), /does not lead to the signed checkpoint/);
  const otherCheckpoint = clone(proofOnly);
  entryOf(otherCheckpoint).inclusionProof.checkpoint.envelope = fixture.checkpoint(authority.log, {size: 7, root: crypto.randomBytes(32)});
  rejects(() => verifyBundle(otherCheckpoint, {trustedRoot}), /does not lead to the signed checkpoint/);
  const noHashes = clone(proofOnly);
  delete entryOf(noHashes).inclusionProof.hashes;
  rejects(() => verifyBundle(noHashes, {trustedRoot}), /inclusion proof is too short/);
  const noCheckpoint = clone(proofOnly);
  delete entryOf(noCheckpoint).inclusionProof.checkpoint;
  rejects(() => verifyBundle(noCheckpoint, {trustedRoot}), /malformed checkpoint/);

  const neither = clone(proofOnly);
  delete entryOf(neither).inclusionProof;
  rejects(() => verifyBundle(neither, {trustedRoot}), /neither a signed entry timestamp nor an inclusion proof/);
});

test('the log entry must record this signature, key and payload', () => {
  const made = fixture.makeBundle();
  const {body} = made;
  const payloadHash = body.spec.payloadHash.value;
  const signature = made.bundle.dsseEnvelope.signatures[0].sig;
  const {verifier} = body.spec.signatures[0];

  const mismatchedKind = withEntry(made.bundle, {...body, kind: 'intoto'});
  rejects(() => verifyBundle(mismatchedKind, {trustedRoot}), /kind does not match its body/);
  const noKind = clone(made.bundle);
  delete noKind.verificationMaterial.tlogEntries[0].kindVersion;
  rejects(() => verifyBundle(noKind, {trustedRoot}), /kind does not match its body/);

  const unsupported = withEntry(made.bundle, {apiVersion: '0.0.1', kind: 'rekord', spec: {}}, {kind: 'rekord/0.0.1'});
  rejects(() => verifyBundle(unsupported, {trustedRoot}), /unsupported log entry kind rekord\/0.0.1/);

  const cases = [
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: payloadHash}}}, /different signature or signing key/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {signatures: [{signature, verifier}]}}, /for a different payload/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha512', value: payloadHash}, signatures: [{signature, verifier}]}}, /for a different payload/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: '0'.repeat(64)}, signatures: [{signature, verifier}]}}, /for a different payload/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: payloadHash}, signatures: [{signature: 'other', verifier}]}}, /different signature or signing key/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: payloadHash}, signatures: [{signature, verifier: Buffer.from('garbage').toString('base64')}]}}, /different signature or signing key/],
    [{apiVersion: '0.0.1', kind: 'dsse', spec: {payloadHash: {algorithm: 'sha256', value: payloadHash}, signatures: [{signature, verifier: Buffer.from(fixture.makeBundle({material: 'publicKey'}).publicKeyPem).toString('base64')}]}}, /different signature or signing key/],
  ];
  for (const [entryBody, pattern] of cases) {
    rejects(() => verifyBundle(withEntry(made.bundle, entryBody), {trustedRoot}), pattern);
  }

  // Empty or partial bodies of each kind.
  const partial = [
    ['intoto/0.0.2', {apiVersion: '0.0.2', kind: 'intoto', spec: {}}],
    ['intoto/0.0.2', {apiVersion: '0.0.2', kind: 'intoto', spec: {content: {payloadHash: {algorithm: 'sha256', value: payloadHash}}}}],
    ['hashedrekord/0.0.1', {apiVersion: '0.0.1', kind: 'hashedrekord'}],
    ['hashedrekord/0.0.1', {apiVersion: '0.0.1', kind: 'hashedrekord', spec: {data: {}, signature: {}}}],
    ['hashedrekord/0.0.1', {apiVersion: '0.0.1', kind: 'hashedrekord', spec: {data: {hash: {algorithm: 'sha256', value: payloadHash}}, signature: {content: signature}}}],
    ['dsse/0.0.2', {apiVersion: '0.0.2', kind: 'dsse'}],
    ['dsse/0.0.2', {apiVersion: '0.0.2', kind: 'dsse', spec: {dsseV002: {payloadHash: {algorithm: 'SHA2_512', digest: Buffer.from(payloadHash, 'hex').toString('base64')}}}}],
    ['dsse/0.0.2', {apiVersion: '0.0.2', kind: 'dsse', spec: {dsseV002: {payloadHash: {algorithm: 'SHA2_256', digest: Buffer.from(payloadHash, 'hex').toString('base64')}, signatures: [{content: signature}]}}}],
    ['dsse/0.0.2', {apiVersion: '0.0.2', kind: 'dsse', spec: {dsseV002: {payloadHash: {algorithm: 'SHA2_256', digest: Buffer.from(payloadHash, 'hex').toString('base64')}, signatures: [{content: signature, verifier: {}}]}}}],
  ];
  for (const [kind, entryBody] of partial) {
    rejects(() => verifyBundle(withEntry(made.bundle, entryBody, {kind}), {trustedRoot}), /different payload|different signature or signing key/);
  }

  // A signature with the same bytes, logged for a different key.
  const other = fixture.makeBundle({kind: 'dsse/0.0.2', rekor: 'v1'});
  const otherBody = clone(other.body);
  otherBody.spec.dsseV002.payloadHash.digest = Buffer.from(payloadHash, 'hex').toString('base64');
  otherBody.spec.dsseV002.signatures[0].content = signature;
  rejects(() => verifyBundle(withEntry(made.bundle, otherBody, {kind: 'dsse/0.0.2'}), {trustedRoot}), /different signature or signing key/);
});

test('signing time, certificate validity and the log key\'s validity', () => {
  const now = Math.floor(Date.now() / 1000);
  // Logged after the one-day certificate expired.
  const late = fixture.makeBundle({integratedTime: now + (2 * 86_400)});
  rejects(() => verifyBundle(late.bundle, {trustedRoot}), /certificate was not valid when the entry was logged/);
  const early = fixture.makeBundle({integratedTime: now - 86_400});
  rejects(() => verifyBundle(early.bundle, {trustedRoot}), /certificate was not valid when the entry was logged/);

  const {bundle} = fixture.makeBundle();
  const retired = clone(trustedRoot);
  retired.tlogs[0].publicKey.validFor = {start: '2000-01-01T00:00:00Z', end: '2001-01-01T00:00:00Z'};
  rejects(() => verifyBundle(bundle, {trustedRoot: retired}), /logged outside the log key's validity/);
  const future = clone(trustedRoot);
  future.tlogs[0].publicKey.validFor = {start: '2100-01-01T00:00:00Z'};
  rejects(() => verifyBundle(bundle, {trustedRoot: future}), /logged outside the log key's validity/);

  // Rekor v2 entries carry no time; without a timestamp there is none.
  const v2 = fixture.makeBundle({rekor: 'v2', timestamps: 0});
  rejects(() => verifyBundle(v2.bundle, {trustedRoot}), /no verifiable signing time/);
});

test('entries without a signed entry timestamp: the log key must be valid at the timestamps', () => {
  for (const options of [{rekor: 'v2'}, {promise: false, proof: true, timestamps: 1}]) {
    const {bundle} = fixture.makeBundle(options);
    assert.ok(verifyBundle(bundle, {trustedRoot}));
    const index = options.rekor === 'v2' ? 1 : 0;
    // A retired log key (its checkpoints could be forged once it leaks).
    const retired = clone(trustedRoot);
    retired.tlogs[index].publicKey.validFor = {start: '2000-01-01T00:00:00Z', end: '2001-01-01T00:00:00Z'};
    rejects(() => verifyBundle(bundle, {trustedRoot: retired}), /logged outside the log key's validity/);
    const future = clone(trustedRoot);
    future.tlogs[index].publicKey.validFor = {start: '2100-01-01T00:00:00Z'};
    rejects(() => verifyBundle(bundle, {trustedRoot: future}), /logged outside the log key's validity/);
  }
});

test('the certificate must chain to a trusted authority when signed', () => {
  const {bundle} = fixture.makeBundle({timestamps: 1});
  assert.ok(verifyBundle(bundle, {trustedRoot}));

  const other = fixture.makeAuthority('other');
  const otherRoot = fixture.trustedRootFor({ca: other, logs: [authority.log], tsa: authority.tsa});
  rejects(() => verifyBundle(bundle, {trustedRoot: otherRoot}), /does not chain to a trusted certificate authority/);

  // The right intermediate, but under the wrong root.
  const mixed = clone(trustedRoot);
  mixed.certificateAuthorities[0].certChain.certificates[1] = {rawBytes: other.root.der.toString('base64')};
  rejects(() => verifyBundle(bundle, {trustedRoot: mixed}), /does not chain/);

  // An authority that was not valid then, next to one that was.
  const windows = clone(trustedRoot);
  windows.certificateAuthorities.unshift({...clone(trustedRoot.certificateAuthorities[0]), validFor: {start: '2000-01-01T00:00:00Z', end: '2001-01-01T00:00:00Z'}});
  assert.ok(verifyBundle(bundle, {trustedRoot: windows}));
  windows.certificateAuthorities.pop();
  rejects(() => verifyBundle(bundle, {trustedRoot: windows}), /does not chain/);
  const later = clone(trustedRoot);
  later.certificateAuthorities[0].validFor = {start: '2100-01-01T00:00:00Z'};
  rejects(() => verifyBundle(bundle, {trustedRoot: later}), /does not chain/);
});

test('verifyTimestamp: responses, tokens and digests', () => {
  const signature = crypto.randomBytes(64);
  const response = fixture.timestamp(signature);
  const time = sigstore.verifyTimestamp(response, signature, trustedRoot);
  assert.ok(Math.abs(time - Date.now()) < 60_000);
  const token = fixture.timestamp(signature, {token: true});
  assert.ok(Math.abs(sigstore.verifyTimestamp(token, signature, trustedRoot) - time) < 60_000);
  for (const [hash, signerDigest] of [['sha384', 'sha384'], ['sha512', 'sha512'], ['sha256', 'sha512']]) {
    assert.ok(sigstore.verifyTimestamp(fixture.timestamp(signature, {hash, signerDigest}), signature, trustedRoot));
  }

  rejects(() => sigstore.verifyTimestamp(fixture.timestamp(signature, {hash: 'sha1'}), signature, trustedRoot), /for a different signature/);
  rejects(() => sigstore.verifyTimestamp(fixture.timestamp(signature, {signerDigest: 'sha1'}), signature, trustedRoot), /no signed attributes/);
  rejects(() => sigstore.verifyTimestamp(response, crypto.randomBytes(64), trustedRoot), /for a different signature/);
});

test('verifyTimestamp rejects what is not a timestamp', () => {
  const signature = crypto.randomBytes(64);
  // A rejected request: a status and no token.
  const rejection = Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);
  rejects(() => sigstore.verifyTimestamp(rejection, signature, trustedRoot), /not CMS signed data/);
  rejects(() => sigstore.verifyTimestamp(authority.tsa.leaf.der, signature, trustedRoot), /not CMS signed data/);

  // CMS signed data holding something other than TSTInfo.
  const {directory, tsa} = authority;
  fs.writeFileSync(path.join(directory, 'cms.txt'), signature);
  const cms = execFileSync('openssl', ['cms', '-sign', '-binary', '-nodetach', '-in', 'cms.txt', '-signer', tsa.leaf.pemFile, '-inkey', tsa.leaf.keyFile, '-outform', 'DER'], {cwd: directory, stdio: ['ignore', 'pipe', 'pipe']});
  rejects(() => sigstore.verifyTimestamp(cms, signature, trustedRoot), /does not hold TSTInfo/);

  // A TSTInfo changed after signing.
  const tampered = Buffer.from(fixture.timestamp(signature, {token: true}));
  const signedData = asn1.parse(tampered).children[1].children[0];
  const encapsulated = signedData.children.find(child => child.tag === 16 && child.children[0].tag === 6);
  const tstInfoDer = asn1.content(encapsulated.children[1].children[0]);
  const serial = asn1.parse(tstInfoDer).children[3];
  tstInfoDer[serial.end - 1] ^= 1;
  rejects(() => sigstore.verifyTimestamp(tampered, signature, trustedRoot), /signed digest does not match its content/);
});

test('verifyTimestamp requires a trusted timestamp authority', () => {
  // Made before the timestamp, so it is valid at the time it certifies.
  const ed = fixture.makeCertificate(authority.directory, {subject: '/CN=ed25519 tsa', algorithm: 'ed25519', extensions: ['basicConstraints=critical,CA:TRUE']});
  const signature = crypto.randomBytes(64);
  const response = fixture.timestamp(signature);
  const without = clone(trustedRoot);
  delete without.timestampAuthorities;
  rejects(() => sigstore.verifyTimestamp(response, signature, without), /not signed by a trusted timestamp authority/);

  const window = clone(trustedRoot);
  window.timestampAuthorities[0].validFor = {start: '2100-01-01T00:00:00Z'};
  rejects(() => sigstore.verifyTimestamp(response, signature, window), /not signed by a trusted/);
  const ended = clone(trustedRoot);
  ended.timestampAuthorities[0].validFor = {start: '2000-01-01T00:00:00Z', end: '2001-01-01T00:00:00Z'};
  rejects(() => sigstore.verifyTimestamp(response, signature, ended), /not signed by a trusted/);
  const open = clone(trustedRoot);
  delete open.timestampAuthorities[0].validFor;
  assert.ok(sigstore.verifyTimestamp(response, signature, open));

  // The leaf under a root that did not issue it.
  const other = fixture.makeTsa('other');
  const mixed = clone(trustedRoot);
  mixed.timestampAuthorities[0].certChain.certificates[1] = {rawBytes: other.root.der.toString('base64')};
  rejects(() => sigstore.verifyTimestamp(response, signature, mixed), /not signed by a trusted/);
  // Another authority's leaf.
  const stranger = clone(trustedRoot);
  stranger.timestampAuthorities[0].certChain.certificates = [{rawBytes: other.leaf.der.toString('base64')}, {rawBytes: other.root.der.toString('base64')}];
  rejects(() => sigstore.verifyTimestamp(response, signature, stranger), /not signed by a trusted/);

  // An authority whose key cannot verify this signature is skipped.
  const edRoot = clone(trustedRoot);
  edRoot.timestampAuthorities.unshift({certChain: {certificates: [{rawBytes: ed.der.toString('base64')}]}});
  assert.ok(sigstore.verifyTimestamp(response, signature, edRoot));
  edRoot.timestampAuthorities.pop();
  rejects(() => sigstore.verifyTimestamp(response, signature, edRoot), /not signed by a trusted/);
});

test('timestamps in bundles bound the certificate\'s validity', () => {
  const {bundle} = fixture.makeBundle({timestamps: 1});
  const noTsa = clone(trustedRoot);
  noTsa.timestampAuthorities = [];
  rejects(() => verifyBundle(bundle, {trustedRoot: noTsa}), /not signed by a trusted timestamp authority/);
  // A timestamp over another signature.
  const swapped = clone(bundle);
  swapped.verificationMaterial.timestampVerificationData.rfc3161Timestamps = [{signedTimestamp: fixture.timestamp(Buffer.from('other')).toString('base64')}];
  rejects(() => verifyBundle(swapped, {trustedRoot}), /timestamp is for a different signature/);
});

test('an identity requirement must be a string or a RegExp', () => {
  // A certificate without a source repository claim (an email identity).
  const {bundle} = fixture.makeBundle({certificate: {san: 'email:dev@example.com', claims: {sourceRepositoryURI: null}}});
  assert.ok(verifyBundle(bundle, {trustedRoot, identity: {subjectAlternativeName: 'dev@example.com'}}));
  // An unset value (a missing setting) would match the missing claim.
  for (const expected of [undefined, null, 1]) {
    rejects(() => verifyBundle(bundle, {trustedRoot, identity: {sourceRepositoryURI: expected}}), /identity requirement sourceRepositoryURI must be a string or a RegExp/);
  }
});

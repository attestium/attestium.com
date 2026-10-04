'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  SigstoreTrust, githubIdentity, githubAttestations, verifyGithubAttestation, npmProvenance, snappyDecompress, GITHUB_ISSUER,
} = require('../lib/attestations');
const {tempDir, startServer, hasOpenssl} = require('./helpers');
const fixture = require('./fixtures/sigstore');
const {TufRepository} = require('./fixtures/tuf');

const DATA = path.join(__dirname, 'fixtures/sigstore-data');
const readJson = name => JSON.parse(fs.readFileSync(path.join(DATA, name), 'utf8'));
const realRoot = readJson('trusted_root.json');
// The private Sigstore's certificates are made with OpenSSL.
const trustedRoot = hasOpenssl ? fixture.getAuthority().trustedRoot : null;
const needsOpenssl = !trustedRoot && 'OpenSSL is not installed';

/**
 * Npm's registry keys in the form its TUF target has.
 */
function npmKeysTarget({end} = {}) {
  return {
    keys: readJson('npm-keys.json').keys.map(key => ({
      keyId: key.keyid,
      keyUsage: 'npm:signatures',
      publicKey: {
        rawBytes: key.key, keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: key.expires || end ? {start: '1999-01-01T00:00:00.000Z', end: end || key.expires} : {start: '1999-01-01T00:00:00.000Z'},
      },
    })),
  };
}

/**
 * Snappy raw block encoding using literals only (valid, if not small).
 */
function snappyLiterals(data) {
  const header = [];
  let {length} = data;
  do {
    header.push((length & 0x7F) | (length > 0x7F ? 0x80 : 0));
    length >>>= 7;
  } while (length > 0);

  const parts = [Buffer.from(header)];
  for (let offset = 0; offset < data.length; offset += 65_536) {
    const chunk = data.subarray(offset, offset + 65_536);
    const size = chunk.length - 1;
    parts.push(size < 60 ? Buffer.from([size << 2]) : (size < 256 ? Buffer.from([60 << 2, size]) : Buffer.from([61 << 2, size & 0xFF, size >> 8])), chunk);
  }

  return Buffer.concat(parts);
}

const sriOf = hex => `sha512-${Buffer.from(hex, 'hex').toString('base64')}`;
const SIGSTORE_DIGEST = '3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78';

test('snappyDecompress decodes literals and every copy form', () => {
  // "abcd" literal, then copy (1-byte offset) of 4 at offset 4, copy
  // (2-byte offset) of 3 at offset 2, copy (4-byte offset) of 2 at offset 11.
  const input = Buffer.from([
    22,
    3 << 2,
    0x61,
    0x62,
    0x63,
    0x64,
    ((4 - 4) << 2) | 1,
    4,
    ((3 - 1) << 2) | 2,
    2,
    0,
    ((2 - 1) << 2) | 3,
    11,
    0,
    0,
    0,
    ((9 - 1) << 2),
    ...Buffer.from('-snappy!!'),
  ]);
  assert.strictEqual(snappyDecompress(input).toString(), 'abcdabcdcdcab-snappy!!');
  // Overlapping copies repeat bytes (run-length).
  assert.strictEqual(snappyDecompress(Buffer.from([10, 0, 0x78, ((9 - 4) << 2) | 1, 1])).toString(), 'x'.repeat(10));
  // Long literals with one- and two-byte lengths.
  for (const size of [60, 200, 300, 70_000]) {
    const data = crypto.randomBytes(size);
    assert.deepStrictEqual(snappyDecompress(snappyLiterals(data)), data);
  }

  assert.deepStrictEqual(snappyDecompress(Buffer.from([0])), Buffer.alloc(0));
});

test('snappyDecompress rejects malformed input', () => {
  const cases = [
    [Buffer.alloc(0), /Malformed snappy length/],
    [Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), /Malformed snappy length/],
    [Buffer.from([0x80, 0x80, 0x80, 0x90, 0x01]), /too large/],
    [Buffer.from([4, 3 << 2, 0x61]), /Malformed snappy literal/],
    [Buffer.from([1, 1 << 2, 0x61, 0x62]), /Malformed snappy literal/],
    [Buffer.from([8, 0, 0x61, 1, 0]), /Malformed snappy copy/],
    [Buffer.from([8, 0, 0x61, 1, 2]), /Malformed snappy copy/],
    [Buffer.from([4, 0, 0x61, (4 << 2) | 1, 1]), /Malformed snappy copy/],
    [Buffer.from([10, 1 << 2, 0x61, 0x62]), /truncated/],
  ];
  for (const [input, pattern] of cases) {
    assert.throws(() => snappyDecompress(input), pattern, input.toString('hex'));
  }
});

test('githubIdentity builds the workflow certificate identity', () => {
  const exact = githubIdentity({repository: 'octo/app.js', workflow: '/.github/workflows/release (v2).yml', ref: 'refs/tags/v1.0.0'});
  assert.strictEqual(exact.issuer, GITHUB_ISSUER);
  assert.ok(exact.subjectAlternativeName.test('https://github.com/octo/app.js/.github/workflows/release (v2).yml@refs/tags/v1.0.0'));
  assert.ok(!exact.subjectAlternativeName.test('https://github.com/octo/appXjs/.github/workflows/release (v2).yml@refs/tags/v1.0.0'));
  assert.ok(!exact.subjectAlternativeName.test('https://github.com/octo/app.js/.github/workflows/release (v2).yml@refs/tags/v1.0.01'));

  assert.strictEqual(exact.sourceRepositoryURI, 'https://github.com/octo/app.js');

  const any = githubIdentity({repository: 'octo/app'});
  assert.ok(any.subjectAlternativeName.test('https://github.com/octo/app/.github/workflows/ci.yml@refs/heads/dev'));
  assert.ok(!any.subjectAlternativeName.test('https://github.com/octo/app/other/ci.yml@refs/heads/dev'));
  assert.ok(!any.subjectAlternativeName.test('https://github.com/octo/app-fork/.github/workflows/ci.yml@refs/heads/dev'));
});

test('SigstoreTrust uses given trust material, or the shipped TUF root', async () => {
  const given = new SigstoreTrust({trustedRoot: realRoot, npmKeys: npmKeysTarget()});
  assert.strictEqual(await given.trustedRoot(), realRoot);
  assert.strictEqual(given.trustedRoot(), given.trustedRoot());
  const keys = await given.npmKeys();
  assert.strictEqual(keys['SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA'].validUntil, Date.parse('2025-01-29T00:00:00.000Z'));
  assert.strictEqual(keys['SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U'].validUntil, Infinity);
  assert.match(keys['SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U'].pem, /^-{5}BEGIN PUBLIC KEY-{5}/);
  assert.deepStrictEqual(await new SigstoreTrust({npmKeys: {}}).npmKeys(), {});

  const shipped = new SigstoreTrust();
  assert.strictEqual(shipped.tuf.metadataUrl, 'https://tuf-repo-cdn.sigstore.dev');
  assert.strictEqual(shipped.tuf.initialRoot.signed.version, 15);
  assert.strictEqual(shipped.tuf.cacheDir, null);
});

test('SigstoreTrust fetches the trusted root and npm keys through TUF', async t => {
  const repository = new TufRepository();
  const {url, requests} = await startServer(t, repository.routes);
  const cacheDir = tempDir(t);
  const trust = new SigstoreTrust({
    tufUrl: url, initialRoot: repository.initialRoot, cacheDir, httpOptions: {maxRetries: 0},
  });
  // Nothing published yet: both fail, and are retried later.
  await assert.rejects(trust.trustedRoot(), /HTTP 404/);
  await assert.rejects(trust.npmKeys(), /HTTP 404/);

  repository.publish({
    targets: {'trusted_root.json': Buffer.from(JSON.stringify(realRoot))},
    delegated: {'registry.npmjs.org': {paths: ['registry.npmjs.org/*'], targets: {'registry.npmjs.org/keys.json': Buffer.from(JSON.stringify(npmKeysTarget()))}}},
  });
  assert.deepStrictEqual(await trust.trustedRoot(), realRoot);
  const keys = await trust.npmKeys();
  assert.deepStrictEqual(Object.keys(keys).sort(), ['SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U', 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA']);
  assert.strictEqual(await trust.npmKeys(), keys);
  assert.ok(fs.existsSync(path.join(cacheDir, 'sigstore-tuf/timestamp.json')));
  assert.ok(requests.some(request => request.url === '/1.registry.npmjs.org.json'));
});

test('githubAttestations lists the bundles GitHub stores', async t => {
  const digest = crypto.createHash('sha256').update('artifact').digest('hex');
  const inline = {mediaType: fixture.BUNDLE_V3, inline: true};
  const compressed = {mediaType: fixture.BUNDLE_V3, compressed: true};
  const routes = {
    [`/repos/octo/app/attestations/sha256:${digest}`]: {body: ''},
    '/bundle': {body: snappyLiterals(Buffer.from(JSON.stringify(compressed)))},
  };
  const server = await startServer(t, routes);
  routes[`/repos/octo/app/attestations/sha256:${digest}`].body = JSON.stringify({
    // eslint-disable-next-line camelcase -- GitHub API field
    attestations: [{bundle: inline}, {bundle_url: `${server.url}/bundle`}, {bundle_url: 42}, {}],
  });
  const bundles = await githubAttestations({
    repository: 'octo/app', digest, apiUrl: server.url, httpOptions: {headers: {authorization: 'Bearer token'}},
  });
  assert.deepStrictEqual(bundles, [inline, compressed]);
  const [api, download] = server.requests;
  assert.strictEqual(api.headers.accept, 'application/vnd.github+json');
  assert.strictEqual(api.headers.authorization, 'Bearer token');
  assert.strictEqual(download.headers.authorization, undefined);

  // No attestations at all, or none for this digest.
  const other = crypto.createHash('sha256').update('other').digest('hex');
  routes[`/repos/octo/app/attestations/sha256:${other}`] = {body: '{}'};
  assert.deepStrictEqual(await githubAttestations({repository: 'octo/app', digest: other, apiUrl: server.url}), []);
  assert.deepStrictEqual(await githubAttestations({repository: 'octo/app', digest: 'f'.repeat(64), apiUrl: server.url}), []);
  routes['/repos/octo/down/attestations/sha256:' + digest] = {status: 500, body: 'down'};
  await assert.rejects(githubAttestations({
    repository: 'octo/down', digest, apiUrl: server.url, httpOptions: {maxRetries: 0},
  }), /HTTP 500/);

  for (const input of [{repository: 'octo', digest}, {repository: 'octo/app/x', digest}, {repository: 'octo/app', digest: 'abc'}, {repository: 'octo/app', digest: digest.toUpperCase()}]) {
    await assert.rejects(githubAttestations(input), TypeError);
  }
});

test('verifyGithubAttestation accepts the first bundle that verifies', {skip: needsOpenssl}, async () => {
  const digest = crypto.createHash('sha256').update('release.tar.gz').digest('hex');
  const subjects = [{name: 'release.tar.gz', digest: {sha256: digest}}];
  const good = fixture.attest({
    subjects, repository: 'octo/app', ref: 'refs/tags/v2.0.0', commit: 'd'.repeat(40),
  }).bundle;
  const forked = fixture.attest({subjects, repository: 'evil/app', commit: 'e'.repeat(40)}).bundle;
  const trust = new SigstoreTrust({trustedRoot});
  const signer = {repository: 'octo/app', workflow: '.github/workflows/release.yml', ref: 'refs/tags/v2.0.0'};

  const result = await verifyGithubAttestation({
    bundles: [forked, good], digest, signer, trust, predicateType: 'https://slsa.dev/provenance/v1',
  });
  assert.strictEqual(result.claims.sourceRepositoryDigest, 'd'.repeat(40));
  assert.strictEqual(result.statement.subject[0].name, 'release.tar.gz');

  await assert.rejects(verifyGithubAttestation({
    bundles: [good], digest, signer, trust, predicateType: 'https://spdx.dev/Document/v2.3',
  }), /no attestation verified: statement type is https:\/\/slsa.dev\/provenance\/v1/);
  // Each distinct reason is reported once.
  await assert.rejects(verifyGithubAttestation({
    bundles: [forked, forked], digest, signer, trust,
  }), error => {
    assert.match(error.message, /^no attestation verified: certificate subjectAlternativeName is "https:\/\/github.com\/evil\/app\/[^;]+$/);
    return true;
  });
  await assert.rejects(verifyGithubAttestation({
    bundles: [good], digest: '0'.repeat(64), signer, trust,
  }), /does not name the artifact/);
  await assert.rejects(verifyGithubAttestation({
    bundles: [], digest, signer, trust,
  }), /no attestation found for this digest/);
});

test('verifyGithubAttestation: another repository calling the workflow as a reusable workflow', {skip: needsOpenssl}, async () => {
  // Any repository can call a public repository's reusable workflow; the
  // certificate then names that workflow, but the caller's repository (and
  // code) as its source.
  const digest = crypto.createHash('sha256').update('release.tar.gz').digest('hex');
  const subjects = [{name: 'release.tar.gz', digest: {sha256: digest}}];
  const san = 'https://github.com/octo/app/.github/workflows/release.yml@refs/tags/v2.0.0';
  const called = fixture.attest({
    subjects, repository: 'evil/app', ref: 'refs/heads/main', commit: 'e'.repeat(40), san,
  }).bundle;
  const trust = new SigstoreTrust({trustedRoot});
  await assert.rejects(verifyGithubAttestation({
    bundles: [called], digest, trust, signer: {repository: 'octo/app', workflow: '.github/workflows/release.yml', ref: 'refs/tags/v2.0.0'},
  }), /certificate sourceRepositoryURI is "https:\/\/github.com\/evil\/app", expected https:\/\/github.com\/octo\/app/);

  // A release built by a shared workflow of another repository.
  const result = await verifyGithubAttestation({
    bundles: [called], digest, trust, signer: {repository: 'evil/app', workflowRepository: 'octo/app', workflow: '.github/workflows/release.yml'},
  });
  assert.strictEqual(result.claims.sourceRepositoryDigest, 'e'.repeat(40));
});

test('npmProvenance verifies real registry attestations', async t => {
  const routes = {
    '/-/npm/v1/attestations/sigstore@3.0.0': {body: fs.readFileSync(path.join(DATA, 'npm-sigstore-3.0.0.json'))},
    '/-/npm/v1/attestations/@octokit%2frest@22.0.1': {body: fs.readFileSync(path.join(DATA, 'npm-octokit-rest-22.0.1.json'))},
  };
  const {url} = await startServer(t, routes);
  const trust = new SigstoreTrust({trustedRoot: realRoot, npmKeys: npmKeysTarget()});
  const result = await npmProvenance({
    name: 'sigstore', version: '3.0.0', integrity: sriOf(SIGSTORE_DIGEST), trust, registryUrl: `${url}/`,
  });
  assert.deepStrictEqual(result, {
    provenance: true,
    repository: 'https://github.com/sigstore/sigstore-js',
    commit: result.commit,
    workflow: 'https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main',
    signedAt: '2024-10-14T16:13:45.000Z',
    published: true,
  });
  assert.match(result.commit, /^[\da-f]{40}$/);

  const octokit = JSON.parse(routes['/-/npm/v1/attestations/@octokit%2frest@22.0.1'].body);
  const subject = JSON.parse(Buffer.from(octokit.attestations[0].bundle.dsseEnvelope.payload, 'base64')).subject[0];
  const scoped = await npmProvenance({
    name: '@octokit/rest', version: '22.0.1', integrity: `sha1-abc= ${sriOf(subject.digest.sha512)}`, trust, registryUrl: url,
  });
  assert.strictEqual(scoped.repository, 'https://github.com/octokit/rest.js');
  assert.strictEqual(scoped.published, true);

  // The lockfile pins another tarball.
  await assert.rejects(npmProvenance({
    name: 'sigstore', version: '3.0.0', integrity: sriOf('00'.repeat(64)), trust, registryUrl: url,
  }), /does not name the artifact/);
  // The registry key had expired when it signed.
  const expired = new SigstoreTrust({trustedRoot: realRoot, npmKeys: npmKeysTarget({end: '2020-01-01T00:00:00.000Z'})});
  await assert.rejects(npmProvenance({
    name: 'sigstore', version: '3.0.0', integrity: sriOf(SIGSTORE_DIGEST), trust: expired, registryUrl: url,
  }), /registry key SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA had expired when the publish attestation was signed/);
  // An unknown registry key.
  const unknown = new SigstoreTrust({trustedRoot: realRoot, npmKeys: {keys: []}});
  await assert.rejects(npmProvenance({
    name: 'sigstore', version: '3.0.0', integrity: sriOf(SIGSTORE_DIGEST), trust: unknown, registryUrl: url,
  }), /signed with a key that is not trusted/);
});

test('npmProvenance without provenance', {skip: needsOpenssl}, async t => {
  const digest = crypto.randomBytes(64).toString('hex');
  const {bundle} = fixture.makeBundle({
    statement: {_type: 'https://in-toto.io/Statement/v1', subject: [{name: 'pkg:npm/bare@1.0.0', digest: {sha512: digest}}], predicateType: 'https://slsa.dev/provenance/v1'},
    certificate: {san: 'email:dev@example.com', claims: {sourceRepositoryURI: null, sourceRepositoryDigest: null}},
  });
  const routes = {
    '/-/npm/v1/attestations/bare@1.0.0': {body: JSON.stringify({attestations: [{predicateType: 'https://slsa.dev/provenance/v1', bundle}, {predicateType: 'https://example.com/other'}, {}]})},
    '/-/npm/v1/attestations/empty@1.0.0': {body: '{}'},
    '/-/npm/v1/attestations/down@1.0.0': {status: 500, body: 'down'},
  };
  const {url} = await startServer(t, routes);
  const trust = new SigstoreTrust({trustedRoot});
  const input = {
    version: '1.0.0', integrity: sriOf(digest), trust, registryUrl: url, httpOptions: {maxRetries: 0},
  };
  const bare = await npmProvenance({...input, name: 'bare'});
  assert.deepStrictEqual(bare, {
    provenance: true, repository: null, commit: null, workflow: 'dev@example.com', signedAt: bare.signedAt,
  });
  assert.ok(Math.abs(Date.parse(bare.signedAt) - Date.now()) < 60_000);
  assert.deepStrictEqual(await npmProvenance({...input, name: 'empty'}), {provenance: false});
  assert.deepStrictEqual(await npmProvenance({...input, name: 'missing'}), {provenance: false});
  await assert.rejects(npmProvenance({...input, name: 'down'}), /HTTP 500/);
  assert.deepStrictEqual(await npmProvenance({...input, name: 'bare', integrity: 'sha256-abc='}), {provenance: false, reason: 'no sha512 integrity'});
  assert.deepStrictEqual(await npmProvenance({...input, name: 'bare', integrity: undefined}), {provenance: false, reason: 'no sha512 integrity'});
});

test('npmProvenance: only the registry key signs a publish attestation, and statement types must match', {skip: needsOpenssl}, async t => {
  const digest = crypto.randomBytes(64).toString('hex');
  const publish = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
  const statement = predicateType => ({
    _type: 'https://in-toto.io/Statement/v1', subject: [{name: 'pkg:npm/forged@1.0.0', digest: {sha512: digest}}], predicateType, predicate: {},
  });
  // Anyone's Fulcio certificate, with a key hint naming the registry's key.
  const forged = fixture.makeBundle({statement: statement(publish), certificate: {repository: 'evil/app'}});
  forged.bundle.verificationMaterial.publicKey = {hint: 'registry-key'};
  // A statement of another type, listed as provenance.
  const other = fixture.makeBundle({statement: statement('https://example.com/other'), certificate: {repository: 'evil/app'}});
  const registryKey = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).publicKey.export({type: 'spki', format: 'der'});
  const {url} = await startServer(t, {
    '/-/npm/v1/attestations/forged@1.0.0': {body: JSON.stringify({attestations: [{predicateType: publish, bundle: forged.bundle}]})},
    '/-/npm/v1/attestations/relabeled@1.0.0': {body: JSON.stringify({attestations: [{predicateType: 'https://slsa.dev/provenance/v1', bundle: other.bundle}]})},
  });
  const trust = new SigstoreTrust({trustedRoot, npmKeys: {keys: [{keyId: 'registry-key', publicKey: {rawBytes: registryKey.toString('base64')}}]}});
  const input = {
    version: '1.0.0', integrity: sriOf(digest), trust, registryUrl: url, httpOptions: {maxRetries: 0},
  };
  await assert.rejects(npmProvenance({...input, name: 'forged'}), /publish attestation is not signed by a registry key/);
  await assert.rejects(npmProvenance({...input, name: 'relabeled'}), /statement type is https:\/\/example\.com\/other/);
});

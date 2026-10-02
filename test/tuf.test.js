'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  TufClient, TufError, canonicalJson, verifyThreshold, checkHashes, matchPath,
} = require('../lib/tuf');
const {tempDir, startServer} = require('./helpers');
const {
  TufRepository, makeKey, signMetadata, keyMap, roleOf,
} = require('./fixtures/tuf');

const DATA = path.join(__dirname, 'fixtures/sigstore-data');
const readJson = name => JSON.parse(fs.readFileSync(path.join(DATA, name), 'utf8'));
const trustedRootJson = Buffer.from(JSON.stringify({mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1'}));
const npmKeysJson = Buffer.from(JSON.stringify({keys: []}));

async function serve(t, repository) {
  const server = await startServer(t, repository.routes);
  const client = options => new TufClient({
    metadataUrl: server.url, initialRoot: repository.initialRoot, httpOptions: {maxRetries: 0}, ...options,
  });
  const fetched = () => server.requests.map(request => request.url);
  return {server, client, fetched};
}

function standardRepository(options) {
  const repository = new TufRepository(options);
  repository.publish({
    targets: {'trusted_root.json': trustedRootJson},
    delegated: {'registry.npmjs.org': {paths: ['registry.npmjs.org/*'], targets: {'registry.npmjs.org/keys.json': npmKeysJson}}},
  });
  return repository;
}

test('canonicalJson is OLPC canonical JSON', () => {
  assert.strictEqual(canonicalJson({b: [1, true, null], a: 'x"y\\z\n', c: {}}), '{"a":"x\\"y\\\\z\n","b":[1,true,null],"c":{}}');
  assert.strictEqual(canonicalJson(false), 'false');
  assert.strictEqual(canonicalJson(-5), '-5');
  assert.strictEqual(canonicalJson([]), '[]');
  assert.throws(() => canonicalJson({a: 1.5}), TufError);
  assert.throws(() => canonicalJson(Number.NaN), /floating point/);
});

test('verifyThreshold accepts each key form', () => {
  for (const form of ['ed25519', 'ecdsa', 'ecdsa-hex']) {
    const key = makeKey(form);
    const metadata = signMetadata({_type: 'test', version: 1}, [key]);
    verifyThreshold(metadata, keyMap([key]), roleOf([key]), form);
    metadata.signed.version = 2;
    assert.throws(() => verifyThreshold(metadata, keyMap([key]), roleOf([key]), form), new RegExp(`${form} has 0 valid signature\\(s\\), needs 1`));
  }
});

test('verifyThreshold counts each trusted key once', () => {
  const [a, b, c, outsider] = ['ed25519', 'ecdsa', 'ecdsa-hex', 'ed25519'].map(form => makeKey(form));
  const role = roleOf([a, b, c], 2);
  const keys = keyMap([a, b, c]);
  const signed = {_type: 'root', version: 3};
  verifyThreshold(signMetadata(signed, [a, c]), keys, role, 'root');

  // The same key twice, a key outside the role, and a role key with no key entry.
  const duplicate = signMetadata(signed, [a, a, outsider]);
  assert.throws(() => verifyThreshold(duplicate, {...keys, [outsider.keyid]: outsider.key}, role, 'root'), /root has 1 valid signature\(s\), needs 2/);
  const {[b.keyid]: _missing, ...withoutB} = keys;
  assert.throws(() => verifyThreshold(signMetadata(signed, [a, b]), withoutB, role, 'root'), /has 1 valid/);
  assert.throws(() => verifyThreshold({signed}, keys, role, 'root'), /has 0 valid/);

  // Keys that cannot be used count for nothing.
  const unusable = {
    [a.keyid]: {keytype: 'rsa', scheme: 'rsassa-pss-sha256', keyval: {public: 'abcd'}},
    [b.keyid]: {keytype: 'ecdsa', scheme: 'ecdsa-sha2-nistp256'},
    [c.keyid]: {keytype: 'ed25519', scheme: 'ed25519', keyval: {public: 'abcd'}},
  };
  assert.throws(() => verifyThreshold(signMetadata(signed, [a, b, c]), unusable, role, 'root'), /has 0 valid/);
  // A signature that is not hex-encoded DER.
  const garbled = signMetadata(signed, [b]);
  garbled.signatures[0].sig = 'zz';
  assert.throws(() => verifyThreshold(garbled, keys, roleOf([b]), 'root'), /has 0 valid/);
});

test('verifyThreshold counts one key listed under two key ids once', () => {
  // A delegation (or a root) that lists the same key under two ids: one
  // signature, repeated under each id, must not meet a threshold of two.
  const [a, b] = ['ecdsa', 'ed25519'].map(form => makeKey(form));
  const alias = {...a, keyid: 'f'.repeat(64)};
  const role = roleOf([a, alias, b], 2);
  const keys = keyMap([a, alias, b]);
  const signed = {_type: 'targets', version: 1};
  const repeated = signMetadata(signed, [a, alias]);
  assert.throws(() => verifyThreshold(repeated, keys, role, 'npm'), /npm has 1 valid signature\(s\), needs 2/);
  verifyThreshold(signMetadata(signed, [a, alias, b]), keys, role, 'npm');
  // Prototype properties are not keys.
  assert.throws(() => verifyThreshold({signed, signatures: [{keyid: 'constructor', sig: '00'}]}, keys, {keyids: ['constructor'], threshold: 1}, 'npm'), /has 0 valid/);
});

test('verifyThreshold rejects thresholds below one', () => {
  const a = makeKey('ed25519');
  const signed = {_type: 'targets', version: 1};
  for (const threshold of [0, -1, 1.5, '1', undefined]) {
    assert.throws(() => verifyThreshold({signed, signatures: []}, keyMap([a]), {keyids: [a.keyid], threshold}, 'npm'), /npm has an invalid threshold/);
  }
});

test('real Sigstore roots rotate from version 1 to 15', async t => {
  const routes = {};
  for (let version = 1; version <= 15; version++) {
    routes[`/${version}.root.json`] = {body: fs.readFileSync(path.join(DATA, `tuf/${version}.root.json`))};
  }

  const server = await startServer(t, routes);
  const cacheDir = path.join(tempDir(t), 'cache');
  const client = new TufClient({
    metadataUrl: `${server.url}/`, initialRoot: readJson('tuf/1.root.json'), cacheDir, httpOptions: {maxRetries: 0}, now: () => new Date('2026-10-01T00:00:00Z'),
  });
  // Every root verifies; this repository has no timestamp to go on with.
  await assert.rejects(client.refresh(), /HTTP 404/);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(cacheDir, '15.root.json'), 'utf8')).signed.version, 15);
  assert.deepStrictEqual(server.requests.map(request => request.url).slice(-2), ['/16.root.json', '/timestamp.json']);
  assert.strictEqual(client.targetsUrl, `${server.url}/targets`);

  // The shipped root is version 15, and signs the real targets metadata.
  const shipped = require('../lib/data/sigstore-root.json');
  assert.deepStrictEqual(shipped, readJson('tuf/15.root.json'));
  const targets = readJson('targets.json');
  verifyThreshold(targets, shipped.signed.keys, shipped.signed.roles.targets, 'targets');
  checkHashes(fs.readFileSync(path.join(DATA, 'trusted_root.json')), targets.signed.targets['trusted_root.json'], 'trusted_root.json');
  assert.throws(() => checkHashes(Buffer.from('{}'), targets.signed.targets['trusted_root.json'], 'trusted_root.json'), /wrong length/);
});

test('updates and downloads targets, including delegated ones', async t => {
  const repository = standardRepository();
  const {client, fetched} = await serve(t, repository);
  const tuf = client();
  assert.deepStrictEqual(await tuf.target('trusted_root.json'), trustedRootJson);
  assert.deepStrictEqual(await tuf.target('registry.npmjs.org/keys.json'), npmKeysJson);
  assert.deepStrictEqual(await tuf.target('registry.npmjs.org/keys.json'), npmKeysJson);
  assert.strictEqual(tuf.refresh(), tuf.refresh());
  const urls = fetched();
  assert.deepStrictEqual(urls.slice(0, 4), ['/2.root.json', '/timestamp.json', '/1.snapshot.json', '/1.targets.json']);
  assert.strictEqual(urls.filter(url => url === '/1.registry.npmjs.org.json').length, 1);
  assert.ok(urls.includes(`/targets/registry.npmjs.org/${crypto.createHash('sha256').update(npmKeysJson).digest('hex')}.keys.json`));
  await assert.rejects(tuf.target('registry.npmjs.org/missing.json'), /no target named registry.npmjs.org\/missing.json/);
  await assert.rejects(tuf.target('elsewhere.json'), /no target named elsewhere.json/);
});

test('a separate targets URL', async t => {
  const repository = standardRepository();
  const {server, client} = await serve(t, repository);
  // Serve targets under /files instead of /targets.
  for (const [route, value] of Object.entries(repository.routes)) {
    if (route.startsWith('/targets/')) {
      server.routes[route.replace('/targets/', '/files/')] = value;
      delete server.routes[route];
    }
  }

  assert.deepStrictEqual(await client({targetsUrl: `${server.url}/files//`}).target('trusted_root.json'), trustedRootJson);
  await assert.rejects(client().target('trusted_root.json'), /HTTP 404/);
});

test('targets without delegations, and roles without paths', async t => {
  const repository = new TufRepository();
  repository.publish({targets: {'trusted_root.json': trustedRootJson}});
  const {client} = await serve(t, repository);
  await assert.rejects(client().target('registry.npmjs.org/keys.json'), /no target named/);

  const pathless = new TufRepository();
  pathless.publish({
    delegated: {other: {targets: {'a.json': npmKeysJson}}},
    mutate: {targets: signed => delete signed.delegations.roles[0].paths},
  });
  const second = await serve(t, pathless);
  await assert.rejects(second.client().target('a.json'), /no target named a.json/);
});

test('root rotation, and keys the new root must be signed by', async t => {
  const repository = standardRepository({rootKeyForms: ['ed25519', 'ecdsa'], threshold: 1});
  const newKeys = [makeKey('ecdsa-hex'), makeKey('ed25519'), makeKey('ecdsa')];
  repository.addRoot({keys: newKeys, threshold: 2});
  repository.addRoot();
  repository.publish({targets: {'trusted_root.json': trustedRootJson}});
  const {client, fetched} = await serve(t, repository);
  const state = await client().refresh();
  assert.strictEqual(state.root.signed.version, 3);
  assert.deepStrictEqual(fetched().slice(0, 4), ['/2.root.json', '/3.root.json', '/4.root.json', '/timestamp.json']);
});

test('root rotation failures', async t => {
  const byNewOnly = standardRepository();
  const fresh = [makeKey('ed25519'), makeKey('ecdsa')];
  byNewOnly.addRoot({keys: fresh, threshold: 2, signers: fresh});
  await assert.rejects((await serve(t, byNewOnly)).client().refresh(), /root v2 \(by the previous root\) has 0 valid signature\(s\), needs 2/);

  const byOldOnly = standardRepository();
  const old = byOldOnly.rootKeys;
  byOldOnly.addRoot({keys: [makeKey('ed25519'), makeKey('ecdsa')], threshold: 2, signers: old});
  await assert.rejects((await serve(t, byOldOnly)).client().refresh(), /root v2 \(by itself\) has 0 valid/);

  const skipped = standardRepository();
  skipped.addRoot({version: 3});
  await assert.rejects((await serve(t, skipped)).client().refresh(), /root version did not increase by one/);

  const wrongType = standardRepository();
  wrongType.routes['/2.root.json'] = wrongType.routes['/timestamp.json'];
  await assert.rejects((await serve(t, wrongType)).client().refresh(), /expected root metadata/);

  const expired = standardRepository();
  expired.addRoot({expires: '2001-01-01T00:00:00Z'});
  await assert.rejects((await serve(t, expired)).client().refresh(), /root metadata has expired/);

  // Any other failure to fetch the next root stops the update.
  const failing = standardRepository();
  const failingServer = await serve(t, failing);
  failingServer.server.routes['/2.root.json'] = {status: 500, body: 'down'};
  await assert.rejects(failingServer.client().refresh(), /HTTP 500/);
  // A forbidden next root, as some CDNs answer for missing files, ends rotation.
  failingServer.server.routes['/2.root.json'] = {status: 403, body: 'forbidden'};
  assert.strictEqual((await failingServer.client().refresh()).root.signed.version, 1);
});

test('a failed update is retried by the next call', async t => {
  const repository = new TufRepository();
  const {client} = await serve(t, repository);
  const tuf = client({httpOptions: undefined});
  await assert.rejects(tuf.target('trusted_root.json'), /HTTP 404/);
  repository.publish({targets: {'trusted_root.json': trustedRootJson}});
  assert.deepStrictEqual(await tuf.target('trusted_root.json'), trustedRootJson);
});

test('the cache keeps the newest root and prevents timestamp rollback', async t => {
  const cacheDir = path.join(tempDir(t), 'tuf');
  const repository = standardRepository();
  repository.addRoot();
  repository.publish({targets: {'trusted_root.json': trustedRootJson}, version: 2});
  const {server, client, fetched} = await serve(t, repository);
  await client({cacheDir}).refresh();
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(cacheDir, '2.root.json'), 'utf8')).signed.version, 2);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(cacheDir, 'timestamp.json'), 'utf8')).signed.version, 2);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(cacheDir, 'snapshot.json'), 'utf8')).signed.version, 2);
  assert.strictEqual(fs.statSync(path.join(cacheDir, '2.root.json')).mode & 0o777, 0o600);

  // The cached root is trusted without fetching version 2 again.
  const second = server.routes['/2.root.json'];
  delete server.routes['/2.root.json'];
  const before = fetched().length;
  await client({cacheDir}).refresh();
  assert.deepStrictEqual(fetched().slice(before, before + 1), ['/3.root.json']);

  // A cached root that does not follow the one before it is not used.
  const olderCache = path.join(tempDir(t), 'tuf');
  fs.mkdirSync(olderCache);
  fs.writeFileSync(path.join(olderCache, '2.root.json'), JSON.stringify(repository.initialRoot));
  fs.writeFileSync(path.join(olderCache, 'timestamp.json'), '{not json');
  server.routes['/2.root.json'] = second;
  const count = fetched().length;
  assert.strictEqual((await client({cacheDir: olderCache}).refresh()).root.signed.version, 2);
  assert.strictEqual(fetched()[count], '/2.root.json');

  // An older timestamp than the cached one is a rollback.
  repository.publish({targets: {'trusted_root.json': trustedRootJson}, version: 1});
  await assert.rejects(client({cacheDir}).refresh(), /timestamp version went backwards/);
});

test('a cached root is used only when it chains from the initial root', async t => {
  // Someone who can write the cache (but has no key of the trusted root)
  // plants their own root, and serves metadata signed by its keys.
  const trusted = standardRepository();
  const forged = standardRepository();
  forged.addRoot();
  forged.publish({targets: {'trusted_root.json': Buffer.from('{"forged":true}')}});
  const cacheDir = path.join(tempDir(t), 'tuf');
  fs.mkdirSync(cacheDir);
  for (const name of ['root.json', '2.root.json']) {
    fs.writeFileSync(path.join(cacheDir, name), JSON.stringify(forged.root));
  }

  const server = await startServer(t, forged.routes);
  const client = new TufClient({
    metadataUrl: server.url, initialRoot: trusted.initialRoot, cacheDir, httpOptions: {maxRetries: 0},
  });
  await assert.rejects(client.target('trusted_root.json'), /root v2 \(by the previous root\) has 0 valid signature/);
  // The cached copy failed, so the next root was asked of the repository.
  assert.deepStrictEqual(server.requests.map(request => request.url), ['/2.root.json']);
});

test('the cache prevents snapshot and targets rollback', async t => {
  const role = 'registry.npmjs.org';
  const delegated = {[role]: {paths: ['registry.npmjs.org/*'], targets: {'registry.npmjs.org/keys.json': npmKeysJson}}};
  const targets = {'trusted_root.json': trustedRootJson};
  const repository = new TufRepository();
  repository.publish({targets, delegated, version: 2});
  const {server, client} = await serve(t, repository);
  const cacheDir = path.join(tempDir(t), 'tuf');
  await client({cacheDir}).refresh();

  // A newer timestamp listing an older snapshot.
  repository.publish({
    targets, delegated, version: 1, mutate: {timestamp: signed => signed.version = 3},
  });
  await assert.rejects(client({cacheDir}).refresh(), /snapshot version went backwards/);

  // A newer timestamp and snapshot listing older or no targets metadata.
  const newerSnapshot = options => {
    repository.publish({
      targets,
      version: 1,
      ...options,
      mutate: {
        snapshot(signed) {
          signed.version = 3;
          if (signed.meta[`${role}.json`]) {
            signed.meta[`${role}.json`].version = 2;
          }
        },
        timestamp(signed) {
          signed.version = 3;
          signed.meta['snapshot.json'].version = 3;
        },
      },
    });
    server.routes['/3.snapshot.json'] = server.routes['/1.snapshot.json'];
  };

  newerSnapshot({delegated});
  await assert.rejects(client({cacheDir}).refresh(), /targets.json version went backwards/);
  newerSnapshot({});
  await assert.rejects(client({cacheDir}).refresh(), /snapshot no longer lists registry.npmjs.org.json/);

  // Without a cached timestamp, the cached snapshot still catches an older one.
  fs.rmSync(path.join(cacheDir, 'timestamp.json'));
  repository.publish({targets, delegated, version: 1});
  await assert.rejects(client({cacheDir}).refresh(), /snapshot version went backwards/);

  // Cached metadata that the current keys did not sign is ignored.
  const cached = JSON.parse(fs.readFileSync(path.join(cacheDir, 'snapshot.json'), 'utf8'));
  cached.signed.version = 99;
  fs.writeFileSync(path.join(cacheDir, 'snapshot.json'), JSON.stringify(cached));
  assert.strictEqual((await client({cacheDir}).refresh()).snapshot.signed.version, 1);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(cacheDir, 'snapshot.json'), 'utf8')).signed.version, 1);
});

test('timestamp, snapshot and targets must verify', async t => {
  const other = makeKey('ed25519');
  const cases = [
    [{mutate: {timestamp: signed => signed._type = 'snapshot'}}, /expected timestamp metadata/],
    [{signers: {timestamp: [other]}}, /timestamp has 0 valid signature/],
    [{expires: {timestamp: '2001-01-01T00:00:00Z'}}, /timestamp metadata has expired/],
    [{mutate: {snapshot: signed => signed._type = 'targets'}}, /expected snapshot metadata/],
    [{signers: {snapshot: [other]}}, /snapshot has 0 valid/],
    [{mutate: {snapshot: signed => signed.version = 2}}, /snapshot version does not match the timestamp/],
    [{expires: {snapshot: '2001-01-01T00:00:00Z'}}, /snapshot metadata has expired/],
    [{mutate: {targets: signed => signed._type = 'root'}}, /expected targets metadata/],
    [{signers: {targets: [other]}}, /targets has 0 valid/],
    [{mutate: {targets: signed => signed.version = 5}}, /targets version does not match the snapshot/],
    [{expires: {targets: '2001-01-01T00:00:00Z'}}, /targets metadata has expired/],
  ];
  for (const [options, pattern] of cases) {
    const repository = new TufRepository();
    repository.publish({targets: {'trusted_root.json': trustedRootJson}, ...options});
    await assert.rejects((await serve(t, repository)).client().refresh(), pattern, String(pattern));
  }
});

test('metadata must match the lengths and hashes that list it', async t => {
  // The snapshot, as the timestamp lists it.
  const snapshot = new TufRepository();
  snapshot.publish();
  const original = snapshot.routes['/1.snapshot.json'].body;
  snapshot.routes['/1.snapshot.json'] = {body: Buffer.from(original.toString().replace('"spec_version":"1.0.31"', '"spec_version":"1.0.3"'))};
  await assert.rejects((await serve(t, snapshot)).client().refresh(), /snapshot has the wrong length/);
  snapshot.routes['/1.snapshot.json'] = {body: Buffer.from(original.toString().replace('"_type":"snapshot"', '"_type":"snapshoT"'))};
  await assert.rejects((await serve(t, snapshot)).client().refresh(), /snapshot does not match its sha256 hash/);

  // Without a listed length the default limit applies.
  const unlisted = new TufRepository();
  unlisted.publish({mutate: {timestamp: signed => delete signed.meta['snapshot.json'].length}});
  assert.strictEqual((await (await serve(t, unlisted)).client().refresh()).snapshot.signed.version, 1);

  // Targets and delegated targets, when the snapshot lists their hashes.
  const hashed = standardRepository();
  hashed.publish({
    snapshotHashes: true,
    targets: {'trusted_root.json': trustedRootJson},
    delegated: {'registry.npmjs.org': {paths: ['registry.npmjs.org/*'], targets: {'registry.npmjs.org/keys.json': npmKeysJson}}},
  });
  const {server, client} = await serve(t, hashed);
  assert.deepStrictEqual(await client().target('registry.npmjs.org/keys.json'), npmKeysJson);
  const flip = route => {
    const content = Buffer.from(server.routes[route].body);
    content[content.length - 2] ^= 1;
    server.routes[route] = {body: content};
  };

  flip('/1.registry.npmjs.org.json');
  await assert.rejects(client().target('registry.npmjs.org/keys.json'), /registry.npmjs.org does not match its sha256 hash/);
  flip('/1.targets.json');
  await assert.rejects(client().refresh(), /targets does not match its sha256 hash/);
});

test('target files must match their hashes', async t => {
  const repository = standardRepository();
  const {server, client} = await serve(t, repository);
  const route = Object.keys(server.routes).find(name => name.endsWith('.trusted_root.json'));
  server.routes[route] = {body: Buffer.alloc(trustedRootJson.length, 0x20)};
  await assert.rejects(client().target('trusted_root.json'), /trusted_root.json does not match its sha256 hash/);
  server.routes[route] = {body: trustedRootJson.subarray(1)};
  await assert.rejects(client().target('trusted_root.json'), /trusted_root.json has the wrong length/);
});

test('delegated targets must verify', async t => {
  const other = makeKey('ecdsa');
  const role = 'registry.npmjs.org';
  const cases = [
    [{mutate: {snapshot: signed => delete signed.meta[`${role}.json`]}}, /snapshot does not list registry.npmjs.org/],
    [{mutate: {[role]: signed => signed._type = 'root'}}, /expected targets metadata/],
    [{signers: {[role]: [other]}}, /registry.npmjs.org has 0 valid signature/],
    [{mutate: {[role]: signed => signed.version = 9}}, /registry.npmjs.org version does not match the snapshot/],
    [{expires: {[role]: '2001-01-01T00:00:00Z'}}, /registry.npmjs.org metadata has expired/],
  ];
  for (const [options, pattern] of cases) {
    const repository = new TufRepository();
    repository.publish({delegated: {[role]: {paths: ['registry.npmjs.org/*'], targets: {'registry.npmjs.org/keys.json': npmKeysJson}}}, ...options});
    await assert.rejects((await serve(t, repository)).client().target('registry.npmjs.org/keys.json'), pattern, String(pattern));
  }
});

test('checkHashes checks listed lengths and known hashes', () => {
  const content = Buffer.from('content');
  const sha256 = crypto.createHash('sha256').update(content).digest('hex');
  const sha512 = crypto.createHash('sha512').update(content).digest('hex');
  checkHashes(content, {}, 'x');
  checkHashes(content, {hashes: {md5: 'ignored', sha256, sha512}}, 'x');
  assert.throws(() => checkHashes(content, {length: 8}, 'x'), /x has the wrong length/);
  assert.throws(() => checkHashes(content, {length: 7, hashes: {sha512: sha256}}, 'x'), /x does not match its sha512 hash/);
});

test('matchPath follows TUF path patterns', () => {
  assert.ok(matchPath('registry.npmjs.org/*', 'registry.npmjs.org/keys.json'));
  assert.ok(!matchPath('registry.npmjs.org/*', 'registry.npmjs.org/a/keys.json'));
  assert.ok(!matchPath('registry.npmjs.org/*', 'registryXnpmjs.org/keys.json'));
  assert.ok(matchPath('file-?.json', 'file-1.json'));
  assert.ok(!matchPath('file-?.json', 'file-10.json'));
  assert.ok(matchPath('a+(b)[c]{d}|^$.txt', 'a+(b)[c]{d}|^$.txt'));
  assert.ok(matchPath('*', 'anything'));
});

test('verifyThreshold uses the root\'s roles as a real client does', () => {
  const root = readJson('tuf/2.root.json');
  const previous = readJson('tuf/1.root.json');
  verifyThreshold(root, previous.signed.keys, previous.signed.roles.root, 'root v2');
  verifyThreshold(root, root.signed.keys, root.signed.roles.root, 'root v2');
  const altered = structuredClone(root);
  altered.signed.expires = '2099-01-01T00:00:00Z';
  assert.throws(() => verifyThreshold(altered, previous.signed.keys, previous.signed.roles.root, 'root v2'), /root v2 has 0 valid signature\(s\), needs 3/);
});

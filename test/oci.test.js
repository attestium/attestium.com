'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const https = require('node:https');
const http = require('node:http');
const {execFileSync} = require('node:child_process');
const oci = require('../lib/oci');
const {isPrivateAddress} = require('../lib/http');
const containers = require('../lib/containers');
const {
  tempDir, writeFiles, startServer, which, sleep,
} = require('./helpers');
const {
  sha256, hasDocker, startRegistry, startContainer,
} = require('./system-helpers');

const IMAGE = 'alpine:3.20';
const BUNDLE_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
const localArch = {x64: 'amd64', arm64: 'arm64'}[process.arch];
const hasImage = hasDocker() && (() => {
  try {
    execFileSync('docker', ['image', 'inspect', IMAGE], {stdio: 'ignore'});
    return true;
  } catch {
    return false;
  }
})();
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

/**
 * One ustar member.
 */
function tarEntry(name, {type = '0', data = '', mode = 0o644, linkName = ''} = {}) {
  const content = Buffer.from(data);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  header.write(`${mode.toString(8).padStart(7, '0')}\0`, 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${content.length.toString(8).padStart(11, '0')}\0`, 124);
  header.write('00000000000\0', 136);
  header.write('        ', 148);
  header.write(type, 156);
  header.write(linkName, 157, 100);
  header.write('ustar\0', 257);
  header.write('00', 263);
  let sum = 0;
  for (const byte of header) {
    sum += byte;
  }

  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return Buffer.concat([header, content, Buffer.alloc((512 - (content.length % 512)) % 512)]);
}

const tar = entries => Buffer.concat([...entries.map(([name, options]) => tarEntry(name, options)), Buffer.alloc(1024)]);

const reference = registry => oci.parseReference(`${registry.host}/${registry.repository}@${registry.digest}`);
const client = (registry, options = {}) => new oci.Registry({endpoints: {[registry.host]: registry.url}, ...options});

test('parseReference: registries, repositories, tags and digests', () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  assert.deepEqual(oci.parseReference('nginx'), {
    registry: 'docker.io', repository: 'library/nginx', tag: null, digest: null,
  });
  assert.deepEqual(oci.parseReference('nginx:1.27'), {
    registry: 'docker.io', repository: 'library/nginx', tag: '1.27', digest: null,
  });
  assert.equal(oci.parseReference('bitnami/redis:7').repository, 'bitnami/redis');
  assert.equal(oci.parseReference('library/nginx').registry, 'docker.io');
  assert.deepEqual(oci.parseReference(`ghcr.io/owner/repo@${digest}`), {
    registry: 'ghcr.io', repository: 'owner/repo', tag: null, digest,
  });
  assert.deepEqual(oci.parseReference(`localhost:5000/app:v1@${digest}`), {
    registry: 'localhost:5000', repository: 'app', tag: 'v1', digest,
  });
  assert.equal(oci.parseReference('localhost/app').registry, 'localhost');
  assert.equal(oci.parseReference('docker.io/nginx').repository, 'library/nginx');
  for (const invalid of ['', 'has space', ':tag', `app@sha256:${'z'.repeat(64)}`]) {
    assert.throws(() => oci.parseReference(invalid), /Invalid image reference/);
  }
});

test('Registry: manifests, platforms, layers and referrers from a local registry', {skip: !hasImage}, async t => {
  const registry = await startRegistry(t, IMAGE);
  const ref = reference(registry);
  const pull = client(registry);

  const top = await pull.manifest(ref);
  assert.ok(Array.isArray(top.manifests));
  const platform = await pull.platformManifest(ref, {os: 'linux', architecture: localArch});
  assert.equal(platform.index, registry.digest);
  assert.equal(platform.manifest.mediaType, 'application/vnd.oci.image.manifest.v1+json');
  // A platform manifest named directly is its own platform manifest.
  const direct = await pull.platformManifest({...ref, digest: platform.digest}, {os: 'linux', architecture: 'ignored'});
  assert.deepEqual(direct, {digest: platform.digest, manifest: platform.manifest, index: null});

  // Platforms the index lists but the registry does not hold, and ones it does not list.
  const absent = top.manifests.find(item => item.platform && item.platform.os === 'linux' && item.platform.architecture !== localArch);
  await assert.rejects(pull.platformManifest(ref, {os: 'linux', architecture: absent.platform.architecture, variant: absent.platform.variant}), /HTTP 404/);
  await assert.rejects(pull.platformManifest(ref, {os: 'linux', architecture: 's390z'}), /The image has no linux\/s390z manifest/);
  await assert.rejects(pull.platformManifest(ref, {os: 'linux', architecture: localArch, variant: 'v99'}), /no linux\/amd64 manifest|no linux\/arm64 manifest/);

  await assert.rejects(pull.manifest({...ref, digest: null}), /only by digest/);
  await assert.rejects(pull.manifest(ref, 'latest'), /only by digest/);
  await assert.rejects(pull.blob(ref, 'sha256:xyz'), /Invalid blob digest sha256:xyz/);
  await assert.rejects(pull.blob(ref), /Invalid blob digest undefined/);

  // The image's root filesystem: every file of the layer, with modes.
  const files = await oci.imageFiles(pull, ref, platform.manifest);
  assert.equal(files.get('bin/busybox')[1], '100755');
  assert.equal(files.get('bin/sh')[0], 'symlink:/bin/busybox');
  assert.equal(files.get('etc/alpine-release')[1], '100644');
  assert.equal((await oci.imageFiles(pull, ref, {})).size, 0);
  // A layer without a media type is recognized by its contents.
  const untyped = await oci.imageFiles(pull, ref, {layers: platform.manifest.layers.map(layer => ({digest: layer.digest}))});
  assert.deepEqual(untyped, files);
  // All layers together may expand only so far.
  await assert.rejects(oci.imageFiles(pull, ref, platform.manifest, {maxBytes: 1000}), /The layer expands to more than 1000 bytes/);
  const [first] = platform.manifest.layers;
  const size = oci.decompressLayer(await pull.blob(ref, first.digest), first.mediaType).length;
  assert.equal((await oci.imageFiles(pull, ref, {layers: [first]}, {maxBytes: size})).size, files.size);
  // Each layer fits; together they do not.
  const limit = Math.floor(1.5 * size);
  await assert.rejects(oci.imageFiles(pull, ref, {layers: [first, first]}, {maxBytes: limit}), new RegExp(`The layer expands to more than ${limit - size} bytes`));

  // Sigstore bundles attached as referrers; other artifacts are skipped.
  assert.deepEqual(await pull.referrerBundles(ref, platform.digest), []);
  const bundle = {mediaType: BUNDLE_TYPE, verificationMaterial: {}, dsseEnvelope: {payload: 'e30=', payloadType: 'application/vnd.in-toto+json', signatures: []}};
  registry.addReferrer(platform.digest, {artifactType: BUNDLE_TYPE, layers: [{mediaType: BUNDLE_TYPE, content: Buffer.from(JSON.stringify(bundle))}]});
  registry.addReferrer(platform.digest, {artifactType: 'application/spdx+json', layers: [{mediaType: 'application/spdx+json', content: Buffer.from('{}')}]});
  registry.addReferrer(platform.digest, {artifactType: BUNDLE_TYPE, descriptorType: null});
  const older = 'application/vnd.dev.sigstore.bundle+json;version=0.2';
  registry.addReferrer(platform.digest, {
    artifactType: older,
    layers: [
      {mediaType: 'application/octet-stream', content: Buffer.from('ignored')},
      {mediaType: undefined, content: Buffer.from('ignored too')},
      {mediaType: older, content: Buffer.from('{"version":2}')},
    ],
  });
  registry.addReferrer(platform.digest, {artifactType: BUNDLE_TYPE});
  assert.deepEqual(await pull.referrerBundles(ref, platform.digest), [bundle, {version: 2}]);
});

test('Registry: content that does not match its digest is refused', {skip: !hasImage}, async t => {
  const honest = await startRegistry(t, IMAGE);
  const platform = await client(honest).platformManifest(reference(honest), {os: 'linux', architecture: localArch});
  const layer = platform.manifest.layers[0].digest;
  const tampered = await startRegistry(t, IMAGE, {replace: {[platform.digest]: Buffer.from('{}'), [layer]: Buffer.from('tampered')}});
  const pull = client(tampered);
  await assert.rejects(pull.platformManifest(reference(tampered), {os: 'linux', architecture: localArch}), /Manifest sha256:[\da-f]{64} does not match its digest/);
  await assert.rejects(pull.blob(reference(tampered), layer), /Blob sha256:[\da-f]{64} does not match its digest/);
});

test('Registry: bearer tokens, basic credentials and static tokens', {skip: !hasImage}, async t => {
  const anonymous = await startRegistry(t, IMAGE, {bearer: true});
  const ref = reference(anonymous);
  const pull = client(anonymous);
  await pull.manifest(ref);
  await pull.manifest(ref);
  const tokenRequests = () => anonymous.requests.filter(request => request.url.startsWith('/token'));
  assert.equal(tokenRequests().length, 1);
  assert.equal(tokenRequests()[0].url, `/token?service=test-registry&scope=${encodeURIComponent('repository:test/app:pull')}`);
  assert.equal(tokenRequests()[0].authorization, null);
  // An expired token is replaced.
  anonymous.rotateToken();
  await pull.manifest(ref);
  assert.equal(tokenRequests().length, 2);
  assert.equal(anonymous.requests.at(-1).authorization, `Bearer ${anonymous.token}`);

  // A token the caller already holds is sent as is.
  const holder = client(anonymous, {credentials: {[anonymous.host]: {token: anonymous.token}}});
  await holder.manifest(ref);
  assert.equal(tokenRequests().length, 2);

  // Basic credentials for the token endpoint; the token is in access_token.
  const privateRegistry = await startRegistry(t, IMAGE, {bearer: true, basic: {username: 'user', password: 'secret'}, tokenField: 'access_token'});
  const credentialed = client(privateRegistry, {credentials: {[privateRegistry.host]: {username: 'user', password: 'secret'}}});
  await credentialed.manifest(reference(privateRegistry));
  assert.equal(privateRegistry.requests.find(request => request.url.startsWith('/token')).authorization, `Basic ${Buffer.from('user:secret').toString('base64')}`);
  const wrong = client(privateRegistry, {credentials: {[privateRegistry.host]: {username: 'user', password: 'wrong'}}});
  await assert.rejects(wrong.manifest(reference(privateRegistry)), /HTTP 401/);

  // A token endpoint that answers without a token.
  const tokenless = await startRegistry(t, IMAGE, {bearer: true, tokenField: 'none'});
  await assert.rejects(client(tokenless).manifest(reference(tokenless)), new RegExp(`${tokenless.host.replaceAll('.', String.raw`\.`)} issued no token`));
  // A challenge without a service.
  const serviceless = await startRegistry(t, IMAGE, {bearer: true, challenge: host => `Bearer realm="http://${host}/token"`});
  await client(serviceless).manifest(reference(serviceless));
  assert.match(serviceless.requests.find(request => request.url.startsWith('/token')).url, /^\/token\?service=&scope=/);

  // Registries that ask for authentication without a usable bearer challenge.
  for (const challenge of [() => null, () => 'Basic realm="registry"', () => 'Bearer service="registry"']) {
    const other = await startRegistry(t, IMAGE, {bearer: true, challenge});
    await assert.rejects(client(other).manifest(reference(other)), new RegExp(`${other.host.replaceAll('.', String.raw`\.`)} requires authentication`));
  }
});

test('Registry: challenge failures, server errors and HTTPS registries', async t => {
  const digest = `sha256:${'b'.repeat(64)}`;
  const ref = {registry: 'registry.test', repository: 'test/app', digest};
  const unauthorized = {status: 401, headers: {'www-authenticate': 'Bearer realm="http://127.0.0.1:1/token"'}};
  const server = await startServer(t, {
    [`/v2/test/app/manifests/${digest}`]: unauthorized,
    [`/v2/test/app/referrers/${digest}`]: {status: 500, body: 'error'},
    [`/v2/other/app/referrers/${digest}`]: {body: '{}'},
    '/v2/': request => request.socket.destroy(),
  });
  const pull = new oci.Registry({endpoints: {'registry.test': server.url}, httpOptions: {retryDelay: 1}});
  // The /v2/ endpoint closing the connection.
  await assert.rejects(pull.manifest(ref), /registry\.test requires authentication/);
  await assert.rejects(pull.referrerBundles(ref, digest), /HTTP 500/);
  assert.deepEqual(await pull.referrerBundles({...ref, repository: 'other/app'}, digest), []);
  // Registries without the referrers API.
  assert.deepEqual(await pull.referrerBundles({...ref, repository: 'missing/app'}, digest), []);

  // The /v2/ endpoint not answering.
  const slow = await startServer(t, {[`/v2/test/app/manifests/${digest}`]: unauthorized, '/v2/'() {}});
  const impatient = new oci.Registry({endpoints: {'registry.test': slow.url}, httpOptions: {timeout: 200}});
  await assert.rejects(impatient.manifest(ref), /registry\.test requires authentication/);
});

test('Registry: an HTTPS registry with its own CA and a bearer challenge', {skip: !which('openssl')}, async t => {
  const directory = tempDir(t);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], {cwd: directory, stdio: 'ignore'});
  const ca = fs.readFileSync(path.join(directory, 'cert.pem'));
  const blob = Buffer.from('layer');
  const digest = `sha256:${sha256(blob)}`;
  const requests = [];
  const server = https.createServer({key: fs.readFileSync(path.join(directory, 'key.pem')), cert: ca}, (request, response) => {
    requests.push(request.url);
    if (request.url.startsWith('/token')) {
      response.end('{"token":"tls-token"}');
    } else if (request.headers.authorization === 'Bearer tls-token') {
      response.end(blob);
    } else {
      response.writeHead(401, {'www-authenticate': `Bearer realm="https://${request.headers.host}/token",service="tls"`});
      response.end();
    }
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  const {port} = server.address();
  // No endpoint configured: https://<registry>.  A registry evidence names
  // is not reached at a private address unless that is allowed.
  const ref = oci.parseReference(`127.0.0.1:${port}/test/app@${digest}`);
  await assert.rejects(new oci.Registry({httpOptions: {ca}}).blob(ref, digest), error => error.code === 'EPRIVATEADDRESS');
  assert.deepEqual(requests, []);
  const pull = new oci.Registry({httpOptions: {ca, denyPrivateAddresses: false}});
  assert.deepEqual(await pull.blob(ref, digest), blob);
  assert.deepEqual(requests.map(url => url.split('?')[0]), [`/v2/test/app/blobs/${digest}`, '/v2/', '/token', `/v2/test/app/blobs/${digest}`]);
});

test('Registry: a registry evidence names is never reached at a private address, nor is its token service', async t => {
  const blob = Buffer.from('layer');
  const digest = `sha256:${sha256(blob)}`;
  const internal = await startServer(t, {
    '/token': {body: '{"token":"internal"}'},
    [`/v2/test/app/blobs/${digest}`]: {body: blob},
  });
  const {port} = new URL(internal.url);
  const names = {'registry.test': '127.0.0.1', 'internal.test': '127.0.0.1', localhost: '127.0.0.1'};
  const lookup = (hostname, options, callback) => (options.all ? callback(null, [{address: names[hostname], family: 4}]) : callback(null, names[hostname], 4));
  const httpOptions = {lookup, allowHttp: true, maxRetries: 0};
  // Named by evidence (no endpoint configured), by address or by a name
  // resolving to one: refused, and the challenge is not fetched either.
  for (const registry of [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]) {
    await assert.rejects(new oci.Registry({httpOptions}).blob({registry, repository: 'test/app'}, digest), error => error.code === 'EPRIVATEADDRESS', registry);
  }

  await assert.rejects(new oci.Registry({httpOptions})._challenge(`127.0.0.1:${port}`), error => error.code === 'EPRIVATEADDRESS');
  // Over plain HTTP here, as a registry named by a host name.
  const named = new oci.Registry({httpOptions});
  named._base = registry => `http://${registry}`;
  await assert.rejects(named.blob({registry: `registry.test:${port}`, repository: 'test/app'}, digest), /registry\.test: it resolves to a private address \(127\.0\.0\.1\)/);
  assert.equal(await named._challenge(`registry.test:${port}`), null);
  assert.deepEqual(internal.requests, []);

  // A public registry whose token service is at a private address.
  const publicAddress = Object.values(require('node:os').networkInterfaces()).flat().find(item => item.family === 'IPv4' && !isPrivateAddress(item.address))?.address;
  await t.test('a token service at a private address', {skip: !publicAddress && 'this machine has no public IPv4 address'}, async () => {
    const server = http.createServer((request, response) => {
      response.writeHead(401, {'www-authenticate': `Bearer realm="http://internal.test:${port}/token",service="x"`});
      response.end();
    });
    await new Promise(resolve => {
      server.listen(0, '0.0.0.0', resolve);
    });
    t.after(() => server.close());
    names['public.test'] = publicAddress;
    const pull = new oci.Registry({httpOptions});
    pull._base = registry => `http://${registry}`;
    await assert.rejects(pull.blob({registry: `public.test:${server.address().port}`, repository: 'test/app'}, digest), /internal\.test: it resolves to a private address/);
    assert.deepEqual(internal.requests, []);
  });

  // A configured endpoint is the verifier's own choice.
  const configured = new oci.Registry({httpOptions, endpoints: {'mirror.test': internal.url}});
  assert.deepEqual(await configured.blob({registry: 'mirror.test', repository: 'test/app'}, digest), blob);
});

test('decompressLayer: gzip, zstd and uncompressed layers', async t => {
  const layer = tar([['file', {data: 'content'}]]);
  const gzip = zlib.gzipSync(layer);
  assert.deepEqual(oci.decompressLayer(gzip, 'application/vnd.oci.image.layer.v1.tar+gzip'), layer);
  assert.deepEqual(oci.decompressLayer(gzip, 'application/vnd.docker.image.rootfs.diff.tar.gzip'), layer);
  // By content, when the media type does not say.
  assert.deepEqual(oci.decompressLayer(gzip, ''), layer);
  assert.equal(oci.decompressLayer(layer, 'application/vnd.oci.image.layer.v1.tar'), layer);
  assert.deepEqual(oci.decompressLayer(Buffer.alloc(0), 'application/vnd.oci.image.layer.v1.tar'), Buffer.alloc(0));
  assert.deepEqual(oci.decompressLayer(Buffer.from([0x28]), ''), Buffer.from([0x28]));

  // A small layer that expands beyond the limit (a decompression bomb).
  const bomb = zlib.gzipSync(Buffer.alloc(4 * 1024 * 1024));
  assert.ok(bomb.length < 8192);
  assert.throws(() => oci.decompressLayer(bomb, 'application/vnd.oci.image.layer.v1.tar+gzip', 1024 * 1024), /The layer expands to more than 1048576 bytes/);
  assert.equal(oci.decompressLayer(bomb, '', 4 * 1024 * 1024).length, 4 * 1024 * 1024);
  assert.throws(() => oci.decompressLayer(layer, 'application/vnd.oci.image.layer.v1.tar', layer.length - 1), /expands to more than/);
  assert.throws(() => oci.decompressLayer(gzip, '', 0), /expands to more than 0 bytes/);
  // Other decompression errors are reported as they are.
  assert.throws(() => oci.decompressLayer(Buffer.from([0x1F, 0x8B, 0, 0, 0, 0]), ''), error => error.code !== undefined && !/expands/.test(error.message));

  const magic = Buffer.from([0x28, 0xB5, 0x2F, 0xFD]);
  if (typeof zlib.zstdCompressSync === 'function') {
    const zstd = zlib.zstdCompressSync(layer);
    assert.deepEqual(oci.decompressLayer(zstd, 'application/vnd.oci.image.layer.v1.tar+zstd'), layer);
    assert.deepEqual(oci.decompressLayer(zstd, ''), layer);
    assert.throws(() => oci.decompressLayer(zlib.zstdCompressSync(Buffer.alloc(4 * 1024 * 1024)), '', 1024 * 1024), /The layer expands to more than 1048576 bytes/);
  } else {
    // Node.js before 22.15: zlib's zstd, where it exists, is used first.
    zlib.zstdDecompressSync = (blob, options) => {
      if (blob.length - 4 > options.maxOutputLength) {
        throw Object.assign(new RangeError('Cannot create a Buffer larger than the limit'), {code: 'ERR_BUFFER_TOO_LARGE'});
      }

      return blob.subarray(4);
    };

    try {
      assert.deepEqual(oci.decompressLayer(Buffer.concat([magic, layer]), ''), layer);
      assert.throws(() => oci.decompressLayer(Buffer.concat([magic, layer]), '', 10), /The layer expands to more than 10 bytes/);
    } finally {
      delete zlib.zstdDecompressSync;
    }
  }

  // Without zstd in zlib (Node.js before 22.15), the zstd program decompresses.
  const bin = tempDir(t);
  // A stand-in zstd whose "frames" are the magic number and the raw data.
  fs.writeFileSync(path.join(bin, 'zstd'), `#!${process.execPath}\nif (process.argv.slice(2).join(' ') !== '-d -c -q') process.exit(2);\nconst chunks = [];\nprocess.stdin.on('data', chunk => chunks.push(chunk)).on('end', () => process.stdout.write(Buffer.concat(chunks).subarray(4)));\n`, {mode: 0o755});
  const failing = tempDir(t);
  fs.writeFileSync(path.join(failing, 'zstd'), '#!/bin/sh\ncat >/dev/null\nexit 1\n', {mode: 0o755});
  const {zstdDecompressSync} = zlib;
  const {PATH} = process.env;
  zlib.zstdDecompressSync = undefined;
  try {
    process.env.PATH = `${bin}${path.delimiter}${PATH}`;
    assert.deepEqual(oci.decompressLayer(Buffer.concat([magic, layer]), 'application/vnd.oci.image.layer.v1.tar+zstd'), layer);
    assert.throws(() => oci.decompressLayer(Buffer.concat([magic, layer]), '', 10), /The layer expands to more than 10 bytes/);
    process.env.PATH = `${failing}${path.delimiter}${PATH}`;
    assert.throws(() => oci.decompressLayer(Buffer.concat([magic, layer]), ''), /zstd layers need Node\.js 22\.15 or later, or the zstd program/);
    process.env.PATH = tempDir(t);
    assert.throws(() => oci.decompressLayer(Buffer.concat([magic, layer]), ''), /zstd layers need/);
  } finally {
    zlib.zstdDecompressSync = zstdDecompressSync;
    process.env.PATH = PATH;
  }

  if (which('zstd')) {
    const file = path.join(tempDir(t), 'layer.tar');
    fs.writeFileSync(file, layer);
    execFileSync('zstd', ['-q', file]);
    assert.deepEqual(oci.decompressLayer(fs.readFileSync(`${file}.zst`), 'application/vnd.oci.image.layer.v1.tar+zstd'), layer);
  }
});

test('applyLayers: whiteouts, opaque directories, hard links and replacements', () => {
  const lower = tar([
    ['./', {type: '5'}],
    ['./bin/', {type: '5', mode: 0o755}],
    ['./bin/sh', {data: 'sh 1', mode: 0o755}],
    ['bin/ash', {type: '1', linkName: './bin/sh'}],
    ['bin/dangling', {type: '1', linkName: 'bin/none'}],
    ['etc/conf', {type: '7', data: 'conf'}],
    ['etc/link', {type: '2', linkName: '/etc/conf'}],
    ['usr/lib/a.so', {data: 'a'}],
    ['usr/lib/sub/b.so', {data: 'b'}],
    ['usr/libexec/keep', {data: 'keep'}],
    ['opt/app', {data: 'file'}],
    ['rootfile', {data: 'root'}],
    ['dev/null', {type: '3'}],
    ['../escape', {data: 'x'}],
    ['a/../../escape', {data: 'x'}],
  ]);
  const upper = tar([
    ['usr/lib/.wh..wh..opq', {}],
    ['usr/lib/c.so', {data: 'c'}],
    ['etc/.wh.link', {}],
    ['.wh.rootfile', {}],
    ['opt/app/', {type: '5'}],
    ['opt/new/', {type: '5'}],
    ['bin/sh', {data: 'sh 2', mode: 0o700}],
    ['etc/conf', {type: '2', linkName: 'conf.d/main'}],
  ]);
  const files = oci.applyLayers([lower, upper]);
  assert.deepEqual(Object.fromEntries(files), {
    'bin/sh': [sha256('sh 2'), '100755'],
    // A hard link keeps the contents it had in its layer.
    'bin/ash': [sha256('sh 1'), '100755'],
    'etc/conf': ['symlink:conf.d/main', '120000'],
    'usr/lib/c.so': [sha256('c'), '100644'],
    'usr/libexec/keep': [sha256('keep'), '100644'],
  });
  assert.equal(oci.applyLayers([]).size, 0);
});

test('compareRootfs: modified, missing, added and mode changes', () => {
  const expected = new Map([
    ['bin/sh', ['h1', '100755']],
    ['etc/conf', ['h2', '100644']],
    ['etc/gone', ['h3', '100644']],
    ['etc/mode', ['h4', '100644']],
    ['etc/hostname', ['h5', '100644']],
  ]);
  const actual = {
    'bin/sh': ['h1', '100755'],
    'etc/conf': ['other', '100644'],
    'etc/mode': ['h4', '100755'],
    'tmp/new': ['h6', '100644'],
    'etc/resolv.conf': ['h7', '100644'],
  };
  assert.deepEqual(oci.compareRootfs(actual, expected), {
    modified: ['etc/conf'], missing: ['etc/gone', 'etc/hostname'], added: ['etc/resolv.conf', 'tmp/new'], modeChanged: ['etc/mode'],
  });
  const ignore = file => ['etc/hostname', 'etc/resolv.conf'].includes(file);
  assert.deepEqual(oci.compareRootfs(actual, expected, {ignore}), {
    modified: ['etc/conf'], missing: ['etc/gone'], added: ['tmp/new'], modeChanged: ['etc/mode'],
  });
});

test('a running container compared with its image from the registry', {skip: !(hasImage && isRoot)}, async t => {
  const registry = await startRegistry(t, IMAGE);
  const pull = client(registry);
  const ref = reference(registry);
  const volume = tempDir(t, 'attestium-volume-');
  writeFiles(volume, {'app.js': 'console.log(1);\n'});
  const {pid} = await startContainer(t, ['-v', `${volume}:/srv`, IMAGE, 'sh', '-c', 'echo x >> /etc/profile && rm /etc/motd && chmod +x /etc/issue && touch /tmp/ready && exec sleep 600']);
  for (let attempt = 0; attempt < 100 && !fs.existsSync(`/proc/${pid}/root/tmp/ready`); attempt++) {
    await sleep(50);
  }

  const {manifest} = await pull.platformManifest(ref, {os: 'linux', architecture: localArch});
  const expected = await oci.imageFiles(pull, ref, manifest);
  const rootfs = await containers.walkRootfs(pid);
  // Files the runtime provides are not the image's.
  const runtimeFiles = new Set(['.dockerenv', 'etc/hostname', 'etc/hosts', 'etc/resolv.conf']);
  assert.deepEqual(oci.compareRootfs(rootfs.files, expected, {ignore: file => runtimeFiles.has(file)}), {
    modified: ['etc/profile'], missing: ['etc/motd'], added: ['tmp/ready'], modeChanged: ['etc/issue'],
  });
});

test('applyLayers: an opaque directory keeps its own layer\'s files, and a hard link takes its target as it is then', () => {
  const lower = tar([['etc/old', {data: 'old'}], ['etc/sub/deep', {data: 'deep'}], ['bin/sh', {data: 'sh'}]]);
  const upper = tar([
    // Written before the marker, in the same layer: kept (as containerd and overlayfs do).
    ['etc/new', {data: 'new'}],
    ['etc/.wh..wh..opq', {}],
    ['etc/later', {data: 'later'}],
    ['bin/link', {type: '1', linkName: 'bin/sh'}],
    ['bin/sh', {data: 'replaced'}],
    ['bin/sh2', {type: '1', linkName: 'bin/sh'}],
  ]);
  assert.deepEqual(Object.fromEntries(oci.applyLayers([lower, upper])), {
    'etc/new': [sha256('new'), '100644'],
    'etc/later': [sha256('later'), '100644'],
    'bin/link': [sha256('sh'), '100644'],
    'bin/sh': [sha256('replaced'), '100644'],
    'bin/sh2': [sha256('replaced'), '100644'],
  });
  // An opaque root, and a directory whited out with everything under it.
  const opaqueRoot = tar([['.wh..wh..opq', {}], ['top', {data: 't'}], ['new/.wh..wh..opq', {}]]);
  assert.deepEqual([...oci.applyLayers([lower, opaqueRoot]).keys()], ['top']);
  assert.deepEqual([...oci.applyLayers([lower, tar([['.wh.etc', {}]])]).keys()], ['bin/sh']);
});

test('applyLayers takes time in proportion to the image, not its square', () => {
  const count = 60_000;
  const entries = [];
  for (let index = 0; index < count; index++) {
    entries.push([`d${index % 100}/f${index}`, {}]);
  }

  const layer = tar(entries);
  const started = process.hrtime.bigint();
  const files = oci.applyLayers([layer, layer]);
  const seconds = Number(process.hrtime.bigint() - started) / 1e9;
  assert.equal(files.size, count);
  // Quadratic work over 60,000 files takes minutes.
  assert.ok(seconds < 10, `${seconds} s`);
});

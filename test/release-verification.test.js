'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const ReleaseVerification = require('../lib/release-verification');
const {sha256} = require('../lib/util');
const {tempDir, writeFiles, startServer, makeTarGz} = require('./helpers');

const VERSION = 'v1.2.3';
const NODE_BINARY = Buffer.from('#!/bin/sh\necho official node binary\n');
const NPM_FILES = {
  'package.json': JSON.stringify({name: 'npm', version: '9.9.9'}),
  'index.js': 'module.exports = "npm";\n',
  'node_modules/npm-dep/package.json': JSON.stringify({name: 'npm-dep', version: '1.0.0'}),
  'node_modules/npm-dep/index.js': 'module.exports = "dep";\n',
};

function integrityOf(buffer) {
  return `sha512-${crypto.createHash('sha512').update(buffer).digest('base64')}`;
}

/**
 * Package fixture: a registry tarball plus metadata.
 */
function makePackage(t, name, version, files) {
  const prefixed = Object.fromEntries(Object.entries(files).map(([file, content]) => [`package/${file}`, content]));
  const tarball = makeTarGz(t, prefixed);
  return {
    name, version, files, tarball, integrity: integrityOf(tarball),
  };
}

/**
 * Fake nodejs.org/dist and registry.npmjs.org on localhost.
 */
async function startUpstream(t, packages) {
  const nodeFiles = {[`node-${VERSION}-linux-x64/bin/node`]: NODE_BINARY};
  for (const [file, content] of Object.entries(NPM_FILES)) {
    nodeFiles[`node-${VERSION}-linux-x64/lib/node_modules/npm/${file}`] = content;
  }

  nodeFiles[`node-${VERSION}-linux-x64/lib/node_modules/npm/node_modules/broken/package.json`] = '{not json';
  const archive = makeTarGz(t, nodeFiles);
  const noBinaryArchive = makeTarGz(t, {'node-v1.2.4-linux-x64/README.md': 'no binary'});
  const shasums = [
    `${sha256(archive)}  node-${VERSION}-linux-x64.tar.gz`,
    `${sha256(archive)}  node-${VERSION}-darwin-arm64.tar.gz`,
    `${sha256(NODE_BINARY)}  win-x64/node.exe`,
    'not a shasums line',
  ].join('\n');

  const routes = {
    [`/dist/${VERSION}/SHASUMS256.txt`]: {body: shasums},
    [`/dist/${VERSION}/node-${VERSION}-linux-x64.tar.gz`]: {body: archive},
    [`/dist/${VERSION}/node-${VERSION}-darwin-arm64.tar.gz`]: {body: Buffer.from('corrupted download')},
    '/dist/v1.2.4/SHASUMS256.txt': {body: `${sha256(noBinaryArchive)}  node-v1.2.4-linux-x64.tar.gz\n`},
    '/dist/v1.2.4/node-v1.2.4-linux-x64.tar.gz': {body: noBinaryArchive},
  };

  for (const item of packages) {
    const base = item.name.split('/').pop();
    routes[`/registry/${item.name}/-/${base}-${item.version}.tgz`] = {body: item.tarball};
    routes[`/registry/${item.name.replace('/', '%2f')}/${item.version}`] = {
      body: JSON.stringify({name: item.name, version: item.version, dist: item.noIntegrity ? {} : (item.shasumOnly ? {shasum: crypto.createHash('sha1').update(item.tarball).digest('hex')} : {integrity: item.integrity})}),
    };
  }

  const server = await startServer(t, routes);
  return {
    server, archive, shasums, nodeDistUrl: `${server.url}/dist`, registryUrl: `${server.url}/registry`,
  };
}

/**
 * Install a package fixture into a directory (as a package manager would).
 */
function install(directory, files) {
  writeFiles(directory, files);
}

test('verifyNodeRelease compares with the binary inside the official archive', async t => {
  const upstream = await startUpstream(t, []);
  const cacheDir = path.join(tempDir(t), 'cache');
  const rv = new ReleaseVerification({nodeDistUrl: `${upstream.nodeDistUrl}/`, cacheDir, retryDelay: 1});
  const directory = tempDir(t);
  const good = path.join(directory, 'node');
  fs.writeFileSync(good, NODE_BINARY);
  const bad = path.join(directory, 'node-modified');
  fs.writeFileSync(bad, Buffer.concat([NODE_BINARY, Buffer.from('backdoor')]));

  const target = {version: VERSION, platform: 'linux', arch: 'x64'};
  const passed = await rv.verifyNodeRelease({...target, execPath: good});
  assert.equal(passed.passed, true);
  assert.equal(passed.details.officialSha256, sha256(NODE_BINARY));
  assert.match(passed.details.officialSource, /node-v1\.2\.3-linux-x64\.tar\.gz$/);

  // Second lookup is served from the cache (no new archive download).
  const before = upstream.server.requests.filter(request => request.url.endsWith('.tar.gz')).length;
  const failed = await rv.verifyNodeRelease({...target, execPath: bad});
  assert.equal(failed.passed, false);
  assert.match(failed.details.error, /differs from the official release/);
  assert.equal(upstream.server.requests.filter(request => request.url.endsWith('.tar.gz')).length, before);

  // A precomputed hash (remote evidence) needs no local file.
  assert.equal((await rv.verifyNodeRelease({...target, sha256: sha256(NODE_BINARY), execPath: '/nonexistent'})).passed, true);

  // Windows: SHASUMS256.txt lists the executable itself.
  assert.equal((await rv.verifyNodeRelease({
    version: VERSION, platform: 'win32', arch: 'x64', sha256: sha256(NODE_BINARY),
  })).passed, true);
  assert.match((await rv.verifyNodeRelease({
    version: VERSION, platform: 'win32', arch: 'arm64', sha256: 'x',
  })).details.error, /No win-arm64\/node\.exe entry/);

  // A download that does not match SHASUMS256.txt is rejected.
  assert.match((await rv.verifyNodeRelease({
    version: VERSION, platform: 'darwin', arch: 'arm64', sha256: 'x',
  })).details.error, /does not match SHASUMS256/);
  assert.match((await rv.verifyNodeRelease({
    version: VERSION, platform: 'linux', arch: 'arm', sha256: 'x',
  })).details.error, /No node-v1\.2\.3-linux-armv7l\.tar\.gz entry/);
  assert.match((await rv.verifyNodeRelease({
    version: 'v1.2.4', platform: 'linux', arch: 'x64', sha256: 'x',
  })).details.error, /bin\/node not found/);
  assert.match((await rv.verifyNodeRelease({
    version: 'v9.9.9', platform: 'linux', arch: 'x64', sha256: 'x',
  })).details.error, /HTTP 404/);
  assert.match((await rv.verifyNodeRelease({
    version: '../../etc', platform: 'linux', arch: 'x64', sha256: 'x',
  })).details.error, /Invalid Node\.js version/);
  await assert.rejects(rv.getOfficialNodeArchive({version: VERSION, platform: 'win32', arch: 'x64'}), /Windows releases/);

  // Defaults describe the running process.
  const own = await new ReleaseVerification({nodeDistUrl: upstream.nodeDistUrl, retryDelay: 1, maxRetries: 0}).verifyNodeRelease();
  assert.equal(own.details.version, process.version);
  assert.equal(own.details.execPath, process.execPath);
  assert.equal(own.passed, false);

  // A corrupt cache entry is ignored.
  for (const file of fs.readdirSync(cacheDir)) {
    fs.writeFileSync(path.join(cacheDir, file), '{broken');
  }

  assert.equal((await rv.verifyNodeRelease({...target, execPath: good})).passed, true);
});

test('SHASUMS256.txt must carry a valid signature when a keyring is configured', async t => {
  const upstream = await startUpstream(t, []);
  const home = tempDir(t);
  const environment = {...process.env, GNUPGHOME: home};
  execFileSync('gpg', ['--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-gen-key', 'release@example.test', 'ed25519', 'sign', 'never'], {env: environment, stdio: 'ignore'});
  const keyring = path.join(home, 'release-keys.gpg');
  fs.writeFileSync(keyring, execFileSync('gpg', ['--batch', '--export', 'release@example.test'], {env: environment}));
  const shasumsFile = path.join(home, 'SHASUMS256.txt');
  fs.writeFileSync(shasumsFile, upstream.shasums);
  execFileSync('gpg', ['--batch', '--detach-sign', '-o', `${shasumsFile}.sig`, shasumsFile], {env: environment, stdio: 'ignore'});
  upstream.server.routes[`/dist/${VERSION}/SHASUMS256.txt.sig`] = {body: fs.readFileSync(`${shasumsFile}.sig`)};

  const rv = new ReleaseVerification({nodeDistUrl: upstream.nodeDistUrl, nodeKeyring: keyring, retryDelay: 1});
  const shasums = await rv.getNodeShasums(VERSION);
  assert.equal(shasums.get('win-x64/node.exe'), sha256(NODE_BINARY));

  upstream.server.routes[`/dist/${VERSION}/SHASUMS256.txt`] = {body: `${upstream.shasums}\n${'0'.repeat(64)}  injected.tar.gz`};
  await assert.rejects(rv.getNodeShasums(VERSION), /signature verification failed/);

  // The key revoked (gpgv still exits with 0): the same signature is refused.
  upstream.server.routes[`/dist/${VERSION}/SHASUMS256.txt`] = {body: upstream.shasums};
  const fingerprint = execFileSync('gpg', ['--batch', '--list-keys', '--with-colons', 'release@example.test'], {env: environment}).toString().match(/^fpr:+([\dA-F]{40}):/m)[1];
  const certificate = path.join(home, 'revocation.asc');
  fs.writeFileSync(certificate, fs.readFileSync(path.join(home, 'openpgp-revocs.d', `${fingerprint}.rev`), 'utf8').replace(/^:-{5}BEGIN/m, '-----BEGIN'));
  execFileSync('gpg', ['--batch', '--import', certificate], {env: environment, stdio: 'ignore'});
  fs.writeFileSync(keyring, execFileSync('gpg', ['--batch', '--export', 'release@example.test'], {env: environment}));
  await assert.rejects(new ReleaseVerification({nodeDistUrl: upstream.nodeDistUrl, nodeKeyring: keyring, retryDelay: 1}).getNodeShasums(VERSION), /signature verification failed: the signing key is revoked/);
  try {
    execFileSync('gpgconf', ['--kill', 'gpg-agent'], {env: environment, stdio: 'ignore'});
  } catch {}
});

test('installed packages are compared with lockfile-pinned registry tarballs (pnpm layout)', async t => {
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'alpha\n'});
  const beta = makePackage(t, '@scope/beta', '2.0.0', {'package.json': JSON.stringify({name: '@scope/beta', version: '2.0.0'}), 'lib/beta.js': 'beta\n'});
  const bundler = makePackage(t, 'bundler', '1.0.0', {
    'package.json': JSON.stringify({name: 'bundler', version: '1.0.0', bundleDependencies: ['inner']}),
    'index.js': 'bundler\n',
    'node_modules/inner/package.json': JSON.stringify({name: 'inner', version: '0.1.0'}),
    'node_modules/inner/index.js': 'inner\n',
    'node_modules/inner/node_modules/deeper/package.json': JSON.stringify({name: 'deeper', version: '0.0.1'}),
    'node_modules/inner/node_modules/deeper/index.js': 'deeper\n',
    'node_modules/@s/scoped/package.json': JSON.stringify({name: '@s/scoped', version: '3.0.0'}),
    'node_modules/@s/scoped/index.js': 'scoped\n',
    'node_modules/nojson/index.js': 'no package.json\n',
    'node_modules/badjson/package.json': '{',
  });
  const patched = makePackage(t, 'patched', '1.0.0', {'package.json': JSON.stringify({name: 'patched', version: '1.0.0'}), 'index.js': 'original\n', 'other.js': 'other\n'});
  const native = makePackage(t, 'native', '1.0.0', {'package.json': JSON.stringify({name: 'native', version: '1.0.0'}), 'binding.gyp': '{}'});
  const tampered = makePackage(t, 'tampered', '1.0.0', {'package.json': JSON.stringify({name: 'tampered', version: '1.0.0'}), 'index.js': 'clean\n'});
  const wrongIntegrity = makePackage(t, 'swapped', '1.0.0', {'package.json': JSON.stringify({name: 'swapped', version: '1.0.0'}), 'index.js': 'swapped\n'});
  const patchedBad = makePackage(t, 'patchedbad', '1.0.0', {'package.json': JSON.stringify({name: 'patchedbad', version: '1.0.0'}), 'index.js': 'x\n', 'keep.js': 'keep\n'});
  const upstream = await startUpstream(t, [alpha, beta, bundler, patched, native, tampered, wrongIntegrity, patchedBad]);

  const root = tempDir(t);
  const store = (item, extra = {}) => {
    const directory = path.join(root, 'node_modules', '.pnpm', `${item.name.replace('/', '+')}@${item.version}`, 'node_modules', item.name);
    install(directory, {...item.files, ...extra});
    fs.mkdirSync(path.join(root, 'node_modules', path.dirname(item.name)), {recursive: true});
    fs.symlinkSync(directory, path.join(root, 'node_modules', item.name));
    return directory;
  };

  store(alpha);
  store(beta);
  store(bundler);
  store(patched, {'index.js': 'patched by pnpm\n'});
  store(native, {'build/Release/native.node': 'compiled'});
  store(tampered, {'index.js': 'BACKDOOR\n'});
  store(wrongIntegrity);
  store(patchedBad, {'index.js': 'patched\n', 'keep.js': 'modified outside the patch\n'});
  install(path.join(root, 'node_modules', '.pnpm', 'extra@9.9.9', 'node_modules', 'extra'), {'package.json': JSON.stringify({name: 'extra', version: '9.9.9'})});
  install(path.join(root, 'node_modules', '.pnpm', 'gitdep@1.0.0', 'node_modules', 'gitdep'), {'package.json': JSON.stringify({name: 'gitdep', version: '1.0.0'})});
  install(path.join(root, 'node_modules', '.pnpm', 'broken@1.0.0', 'node_modules', 'broken'), {'index.js': 'no manifest'});
  install(path.join(root, 'node_modules'), {
    '.modules.yaml': 'x', 'stray.js': 'unaccounted', '.pnpm/lock.yaml': 'x', '.pnpm/stray.txt': 'x', '.cache/x': 'tool cache', '.hidden/x': 'x', '.bin/tool': 'x',
  });
  fs.mkdirSync(path.join(root, 'node_modules', '.pnpm', 'no-modules-dir'));
  // Links: the ones pnpm makes, and ones that swap in other code.
  const outside = tempDir(t);
  install(outside, {'package.json': JSON.stringify({name: 'evil', version: '1.0.0'})});
  const modules = path.join(root, 'node_modules');
  fs.mkdirSync(path.join(modules, '.pnpm', 'node_modules'));
  fs.symlinkSync('../alpha@1.0.0/node_modules/alpha', path.join(modules, '.pnpm', 'node_modules', 'alpha'));
  fs.symlinkSync('../alpha@1.0.0/node_modules/alpha', path.join(modules, '.pnpm', 'node_modules', 'hoisted'));
  install(path.join(modules, '.pnpm', 'node_modules', 'evilreal'), {'package.json': JSON.stringify({name: 'evilreal', version: '1.0.0'})});
  fs.symlinkSync(outside, path.join(modules, 'evil'));
  // An alias (npm:other@1) links one name to another verified package.
  fs.symlinkSync('.pnpm/alpha@1.0.0/node_modules/alpha', path.join(modules, 'renamed'));
  fs.symlinkSync('.pnpm/no-modules-dir', path.join(modules, 'nonpackage'));
  fs.symlinkSync('nowhere', path.join(modules, 'dangling'));
  fs.symlinkSync('../alpha/index.js', path.join(modules, '.bin', 'alpha'));
  fs.symlinkSync('/bin/sh', path.join(modules, '.bin', 'shell'));
  fs.symlinkSync('../stray.js', path.join(modules, '.bin', 'stray'));

  writeFiles(root, {
    'package.json': JSON.stringify({
      name: 'app',
      pnpm: {
        patchedDependencies: {
          'patched@1.0.0': 'patches/patched@1.0.0.patch',
          'patchedbad@1.0.0': 'patches/patchedbad.patch',
          'escape@1.0.0': '../outside.patch',
          'absent@1.0.0': 'patches/missing.patch',
        },
        onlyBuiltDependencies: ['native'],
      },
    }),
    'patches/patched@1.0.0.patch': 'diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-original\n+patched by pnpm\n',
    'patches/patchedbad.patch': '--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+patched\n',
    'pnpm-lock.yaml': [
      'lockfileVersion: \'9.0\'',
      'packages:',
      ...[alpha, beta, bundler, patched, native, tampered, patchedBad].map(item => `  '${item.name}@${item.version}':\n    resolution: {integrity: ${item.integrity}}`),
      `  swapped@1.0.0:\n    resolution: {integrity: ${alpha.integrity}}`,
      '  gitdep@1.0.0:\n    resolution: {type: git, repo: https://github.com/x/y, commit: abc}',
      '  local@1.0.0:\n    resolution: {directory: ../local}',
      '  notinstalled@1.0.0:\n    resolution: {integrity: sha512-AAAA}',
      '',
    ].join('\n'),
  });

  const rv = new ReleaseVerification({
    projectRoot: root, registryUrl: upstream.registryUrl, retryDelay: 1, concurrency: 4,
  });
  const result = await rv.verifyModules();
  assert.equal(result.passed, false);
  const {details} = result;
  assert.equal(details.lockfile, 'pnpm 9.0');
  const byPackage = Object.fromEntries(details.findings.map(finding => [finding.package, finding]));

  assert.deepEqual(byPackage['tampered@1.0.0'].modified, ['index.js']);
  assert.match(byPackage['swapped@1.0.0'].reason, /does not match integrity/);
  assert.deepEqual(byPackage['patchedbad@1.0.0'].modified, ['keep.js']);
  assert.match(byPackage['extra@9.9.9'].reason, /not in the lockfile or any bundle/);
  assert.equal(byPackage['gitdep@1.0.0'].status, 'unverifiable');
  assert.match(byPackage['broken@null'].reason, /invalid package\.json/);
  assert.equal(byPackage['alpha@1.0.0'], undefined);
  assert.equal(byPackage['@scope/beta@2.0.0'], undefined);
  assert.equal(byPackage['patched@1.0.0'], undefined, 'pnpm patch accounted for');
  assert.equal(byPackage['native@1.0.0'], undefined, 'build output accounted for');
  assert.equal(byPackage['inner@0.1.0'], undefined, 'bundled dependency matched to its bundle');
  assert.equal(details.bundled, 3);
  assert.equal(details.patched, 1);
  assert.equal(details.built, 1);
  assert.ok(details.verified >= 3);
  assert.deepEqual(details.unaccounted, ['.hidden/', '.pnpm/no-modules-dir/', '.pnpm/stray.txt', 'stray.js']);
  assert.deepEqual(details.links.map(({path: linkPath, problem}) => `${linkPath}: ${problem}`), [
    '.bin/shell: points outside node_modules',
    '.bin/stray: does not point into an installed package',
    'dangling: broken link (ENOENT)',
    'evil: points outside node_modules',
    'nonpackage: does not point to an installed package',
  ]);
  assert.equal(details.links.find(link => link.path === 'nonpackage').target, '.pnpm/no-modules-dir');
  assert.equal(details.links.find(link => link.path === 'evil').target, fs.realpathSync(outside));
  assert.equal(details.links.find(link => link.path === 'dangling').target, null);
  assert.match(byPackage['evilreal@1.0.0'].reason, /not in the lockfile/);
  assert.ok(details.errors.some(error => /package\.json/.test(error.error)));
  assert.equal(fs.existsSync(path.join(root, 'node_modules', 'bundler')), true);

  const policy = rv.readPackagePolicy();
  assert.deepEqual(policy.patched['patched@1.0.0'].files, ['index.js']);
  assert.match(policy.patched['patched@1.0.0'].text, /\+patched by pnpm/);
  assert.equal(policy.patched['absent@1.0.0'], null);
  assert.equal('escape@1.0.0' in policy.patched, false, 'patch paths may not leave the project');
  assert.deepEqual(policy.built, ['native']);
});

test('npm package-lock.json layout, registry fallback, and global packages', async t => {
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'alpha\n'});
  const aliased = makePackage(t, '@real/name', '4.0.0', {'package.json': JSON.stringify({name: '@real/name', version: '4.0.0'})});
  const pm2 = makePackage(t, 'pm2', '5.0.0', {'package.json': JSON.stringify({name: 'pm2', version: '5.0.0'}), 'bin/pm2': 'pm2\n'});
  const pm2Dep = makePackage(t, 'pm2-dep', '1.0.0', {'package.json': JSON.stringify({name: 'pm2-dep', version: '1.0.0'})});
  const noIntegrity = {...makePackage(t, 'nointegrity', '1.0.0', {'package.json': JSON.stringify({name: 'nointegrity', version: '1.0.0'})}), noIntegrity: true};
  const legacy = {...makePackage(t, 'legacy', '1.0.0', {'package.json': JSON.stringify({name: 'legacy', version: '1.0.0'})}), shasumOnly: true};
  const upstream = await startUpstream(t, [alpha, aliased, pm2, pm2Dep, noIntegrity, legacy]);

  const root = tempDir(t);
  install(path.join(root, 'node_modules', 'alpha'), alpha.files);
  install(path.join(root, 'node_modules', 'alias'), aliased.files);
  install(path.join(root, 'node_modules', 'alpha', 'node_modules', 'nested'), {'package.json': JSON.stringify({name: 'nested', version: '1.0.0'})});
  writeFiles(root, {
    'package.json': '{broken',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {name: 'app'},
        'node_modules/alpha': {version: '1.0.0', resolved: `${upstream.registryUrl}/alpha/-/alpha-1.0.0.tgz`, integrity: alpha.integrity},
        'node_modules/alias': {
          name: '@real/name', version: '4.0.0', resolved: 'https://registry.npmjs.org/@real/name/-/name-4.0.0.tgz', integrity: aliased.integrity,
        },
        'node_modules/alpha/node_modules/nested': {version: '1.0.0', resolved: 'https://example.com/nested.tgz', integrity: 'sha512-x'},
        'node_modules/linked': {link: true},
        'node_modules/bundled': {inBundle: true, version: '1.0.0'},
      },
    }),
  });

  const rv = new ReleaseVerification({
    projectRoot: root, registryUrl: upstream.registryUrl, nodeDistUrl: upstream.nodeDistUrl, retryDelay: 1, maxRetries: 0,
  });
  assert.deepEqual(rv.readPackagePolicy(), {patched: {}, built: []});
  const lock = rv.readLockfile();
  assert.equal(lock.format, 'npm');
  assert.equal(lock.packages.find(item => item.name === '@real/name').source, 'registry');
  assert.equal(lock.packages.find(item => item.name === 'alpha').source, 'tarball', 'resolved outside the public registry');
  const modules = await rv.verifyModules();
  assert.deepEqual(modules.details.findings.map(finding => [finding.package, finding.status]).sort(), [
    ['alpha@1.0.0', 'unverifiable'],
    ['nested@1.0.0', 'unverifiable'],
  ]);
  assert.equal(modules.passed, false);

  // Global packages: npm from the Node.js archive, pm2 and its dependencies from registry metadata.
  const prefix = tempDir(t);
  const execPath = path.join(prefix, 'bin', 'node');
  install(path.join(prefix, 'bin'), {node: NODE_BINARY});
  const globalDir = ReleaseVerification.globalModulesDir(execPath, 'linux');
  assert.equal(globalDir, path.join(prefix, 'lib', 'node_modules'));
  assert.equal(ReleaseVerification.globalModulesDir(path.join('C:', 'node', 'node.exe'), 'win32'), path.join('C:', 'node', 'node_modules'));
  install(path.join(globalDir, 'npm'), NPM_FILES);
  install(path.join(globalDir, 'pm2'), pm2.files);
  install(path.join(globalDir, 'pm2', 'node_modules', 'pm2-dep'), pm2Dep.files);
  install(path.join(globalDir, 'pm2', 'node_modules', 'nointegrity'), noIntegrity.files);
  install(path.join(globalDir, 'pm2', 'node_modules', 'legacy'), legacy.files);
  install(path.join(prefix, 'elsewhere', 'linked'), alpha.files);
  fs.symlinkSync(path.join(prefix, 'elsewhere', 'linked'), path.join(globalDir, 'linked'));

  const node = {
    execPath, version: VERSION, platform: 'linux', arch: 'x64',
  };
  const report = await rv.verifyAll({node, globalPackages: ['npm', 'pm2', 'linked', 'absent'], modules: false});
  assert.equal(report.checks.nodeRelease.passed, true);
  assert.equal(report.checks.npmRelease.passed, true);
  assert.equal(report.checks.npmRelease.details.verified, 2);
  assert.equal(report.checks.pm2Release.passed, false);
  assert.match(report.checks.pm2Release.details.findings[0].reason, /no integrity/);
  assert.equal(report.checks.pm2Release.details.verified, 3);
  assert.equal(report.checks.linkedRelease.details.linkedTo, fs.realpathSync(path.join(prefix, 'elsewhere', 'linked')));
  assert.equal(report.checks.linkedRelease.passed, true);
  assert.equal(report.checks.absentRelease, undefined);
  assert.equal(report.passed, false);
  assert.match(report.summary, /^3\/4 release checks passed$/);

  // Windows and unreachable archives fall back to the registry for npm.
  const winNpm = await rv.verifyGlobalPackage(path.join(globalDir, 'npm'), {node: {...node, platform: 'win32'}});
  assert.equal(winNpm.details.nodeArchiveError, undefined);
  assert.equal(winNpm.passed, false);
  const noArchive = await rv.verifyGlobalPackage(path.join(globalDir, 'npm'), {node: {...node, version: 'v0.0.1'}});
  assert.match(noArchive.details.nodeArchiveError, /HTTP 404/);

  await assert.rejects(rv.verifyAll({globalPackages: ['../evil'], checkNode: false, modules: false}), /Invalid package name/);
  const everything = await rv.verifyAll({
    node, globalDir, globalPackages: [], checkNode: false,
  });
  assert.equal(everything.checks.moduleIntegrity.passed, false);
});

test('lockfile parsing, integrity strings and manifest helpers', async t => {
  assert.throws(() => ReleaseVerification.parseLockfile('lockfileVersion: 5.4\n', 'pnpm'), /Unsupported pnpm lockfileVersion: 5\.4/);
  assert.throws(() => ReleaseVerification.parseLockfile('', 'pnpm'), /missing/);
  assert.throws(() => ReleaseVerification.parseLockfile('{"lockfileVersion":1}', 'npm'), /Unsupported npm lockfileVersion: 1/);
  assert.throws(() => ReleaseVerification.parseLockfile('', 'yarn'), /Unsupported lockfile format/);
  const v6 = ReleaseVerification.parseLockfile([
    'lockfileVersion: \'6.0\'',
    'packages:',
    '  /@a/b@1.0.0(peer@2.0.0):',
    '    resolution: {integrity: sha512-x}',
    '  /aliased@1.0.0:',
    '    resolution: {integrity: sha512-y, tarball: https://registry.yarnpkg.com/x.tgz}',
    '    name: real',
    '    version: 2.0.0',
    '  /noint@1.0.0:',
    '    resolution: {tarball: https://example.com/x.tgz}',
    '  /empty@1.0.0: null',
    '  /noversion: {}',
    '',
  ].join('\n'), 'pnpm');
  assert.deepEqual(v6.packages, [
    {
      name: '@a/b', version: '1.0.0', integrity: 'sha512-x', tarball: null, source: 'registry',
    },
    {
      name: 'real', version: '2.0.0', integrity: 'sha512-y', tarball: 'https://registry.yarnpkg.com/x.tgz', source: 'registry',
    },
    {
      name: 'noint', version: '1.0.0', integrity: null, tarball: 'https://example.com/x.tgz', source: 'no-integrity',
    },
    {
      name: 'empty', version: '1.0.0', integrity: null, tarball: null, source: 'no-integrity',
    },
    {
      name: 'noversion', version: '', integrity: null, tarball: null, source: 'no-integrity',
    },
  ]);
  assert.equal(ReleaseVerification.parseLockfile('lockfileVersion: \'9.0\'\n', 'pnpm').packages.length, 0);

  const data = Buffer.from('payload');
  const sha1 = `sha1-${crypto.createHash('sha1').update(data).digest('base64')}`;
  assert.equal(ReleaseVerification.verifyIntegrity(data, `${integrityOf(data)}?opt ${sha1}`), true);
  assert.equal(ReleaseVerification.verifyIntegrity(data, `sha512-AAAA ${sha1}`), false, 'strongest algorithm wins');
  assert.equal(ReleaseVerification.verifyIntegrity(data, sha1), true);
  assert.equal(ReleaseVerification.verifyIntegrity(data, 'md5-xyz'), false);
  assert.equal(ReleaseVerification.verifyIntegrity(data, 'garbage'), false);
  assert.equal(ReleaseVerification.verifyIntegrity(data, null), false);

  assert.deepEqual(ReleaseVerification.parseShasums(`${'a'.repeat(64)} *node.exe\n\n`), new Map([['node.exe', 'a'.repeat(64)]]));
  assert.deepEqual(ReleaseVerification.nodeReleaseTarget('aix', 'ppc64'), {platform: 'aix', arch: 'ppc64'});
  assert.deepEqual(ReleaseVerification.nodeReleaseTarget('sunos', 'x64'), {platform: 'sunos', arch: 'x64'});
  assert.deepEqual(ReleaseVerification.filesTouchedByPatch('--- a/x.js\n+++ b/x.js\n--- /dev/null\n+++ b/new.js \n'), ['new.js', 'x.js']);
  for (const bad of ['', '../x', '@a/../b', 'a b', 'x'.repeat(215), 5]) {
    assert.equal(ReleaseVerification.isValidPackageName(bad), false, String(bad));
  }

  const rv = new ReleaseVerification({registryUrl: 'http://127.0.0.1:1', retryDelay: 1, maxRetries: 0});
  await assert.rejects(rv.getPackageManifest({name: '../x', version: '1.0.0', integrity: 'x'}), /Invalid package reference/);
  await assert.rejects(rv.getPackageManifest({name: 'x', version: '1/../2', integrity: 'x'}), /Invalid package reference/);
  await assert.rejects(rv.getRegistryReference('x', 'a b'), /Invalid package reference/);
  await assert.rejects(rv.getPackageManifest({name: 'x', version: '1.0.0', integrity: 'sha512-x'}), /ECONNREFUSED/);

  const root = tempDir(t);
  const empty = new ReleaseVerification({projectRoot: root});
  assert.throws(() => empty.readLockfile(), /No pnpm-lock\.yaml or package-lock\.json/);
  assert.deepEqual(empty.readPackagePolicy(), {patched: {}, built: []});
  const missing = await empty.verifyModules();
  assert.match(missing.details.error, /No pnpm-lock\.yaml/);
  assert.equal((await empty.scanInstalledPackages()).errors[0].error, 'ENOENT');
  assert.equal((await empty.verifyGlobalPackage(path.join(root, 'nothing'))).details.installed, false);
  assert.equal(empty.projectRoot, root);
  assert.equal(new ReleaseVerification().projectRoot, process.cwd());
});

test('manifest cache, malformed metadata and comparison edge cases', async t => {
  const pkg = makePackage(t, 'cached', '1.0.0', {'package.json': JSON.stringify({name: 'cached', version: '1.0.0'}), 'index.js': 'x\n', 'build.gyp': '{}'});
  const upstream = await startUpstream(t, [pkg]);
  const cacheDir = tempDir(t);
  const first = new ReleaseVerification({registryUrl: upstream.registryUrl, cacheDir, retryDelay: 1});
  const manifest = await first.getPackageManifest(pkg);
  const downloads = () => upstream.server.requests.filter(request => request.url.endsWith('.tgz')).length;
  const count = downloads();

  // A second verifier with the same cache directory does not download again.
  const second = new ReleaseVerification({registryUrl: upstream.registryUrl, cacheDir, retryDelay: 1});
  assert.deepEqual(await second.getPackageManifest(pkg), manifest);
  assert.equal(downloads(), count);

  // A cache file whose recorded key differs (collision or tampering) is ignored.
  for (const file of fs.readdirSync(cacheDir)) {
    const content = JSON.parse(fs.readFileSync(path.join(cacheDir, file), 'utf8'));
    fs.writeFileSync(path.join(cacheDir, file), JSON.stringify({key: 'other', value: {...content.value, digest: 'forged'}}));
  }

  const third = new ReleaseVerification({registryUrl: upstream.registryUrl, cacheDir, retryDelay: 1});
  assert.equal((await third.getPackageManifest(pkg)).digest, manifest.digest);
  assert.equal(downloads(), count + 1);

  // Bundled package.json without name/version falls back to the directory name.
  const bundled = ReleaseVerification.packageManifestFromFiles(new Map([
    ['index.js', Buffer.from('x')],
    ['node_modules/anon/package.json', Buffer.from('{}')],
  ]));
  assert.deepEqual(bundled.bundled.map(item => [item.name, item.version]), [['anon', null]]);

  // Comparing without per-file data, without a policy's built list, and a built package missing a file.
  const installed = {
    name: 'cached', version: '1.0.0', path: 'cached', digest: 'different',
  };
  const noFiles = await third.comparePackages({installed: [installed], references: [{...pkg, source: 'registry'}], policy: {patched: {}}});
  assert.deepEqual(noFiles.findings[0].reason, 'files differ from reference tarball');
  const {'build.gyp': removed, ...remaining} = manifest.files;
  const builtMissing = await third.comparePackages({
    installed: [{...installed, files: {...remaining, 'build/Release/x.node': 'y'}}],
    references: [{...pkg, source: 'registry'}],
    policy: {patched: {}, built: ['cached']},
  });
  assert.deepEqual(builtMissing.findings[0].missing, ['build.gyp']);
  assert.equal(removed, manifest.files['build.gyp']);
  assert.equal(builtMissing.findings[0].added, undefined, 'build output may add files');
});

test('package scanning: malformed manifests, unstable files, explicit file lists', async t => {
  const root = tempDir(t);
  writeFiles(root, {
    'node_modules/numeric/package.json': JSON.stringify({name: 5, version: 1}),
    'node_modules/ok/package.json': JSON.stringify({name: 'ok', version: '1.0.0'}),
    'node_modules/ok/big.bin': Buffer.alloc(2 * 1024 * 1024),
  });
  const rv = new ReleaseVerification({projectRoot: root});
  const originalRead = fs.read;
  let appended = false;
  t.mock.method(fs, 'read', (...args) => {
    const [, buffer] = args;
    if (!appended && buffer.length >= 1024 * 1024) {
      appended = true;
      fs.appendFileSync(path.join(root, 'node_modules/ok/big.bin'), 'x');
    }

    return Reflect.apply(originalRead, fs, args);
  });
  const scan = await rv.scanInstalledPackages(undefined, {includeFiles: true});
  const numeric = scan.packages.find(item => item.path === 'numeric');
  assert.equal(numeric.name, 'numeric');
  assert.equal(numeric.invalid, true);
  assert.ok(scan.packages.every(item => item.files));
  assert.match(scan.errors.find(error => error.path === 'ok/big.bin').error, /changed while hashing/);
});

test('project policy and verification details', async t => {
  const tampered = makePackage(t, 'tampered', '1.0.0', {'package.json': JSON.stringify({name: 'tampered', version: '1.0.0'}), 'index.js': 'clean\n'});
  const upstream = await startUpstream(t, [tampered]);
  const root = tempDir(t);
  writeFiles(root, {
    'package.json': JSON.stringify({name: 'app'}),
    'pnpm-lock.yaml': `lockfileVersion: '9.0'\npackages:\n  tampered@1.0.0:\n    resolution: {integrity: ${tampered.integrity}}\n`,
  });
  install(path.join(root, 'node_modules', 'tampered'), {...tampered.files, 'index.js': 'evil\n'});
  install(path.join(root, 'node_modules', 'tampered', 'node_modules', 'tampered-nested'), {'package.json': JSON.stringify({name: 'tampered', version: '1.0.0'}), ...tampered.files});
  const rv = new ReleaseVerification({projectRoot: root, registryUrl: upstream.registryUrl, retryDelay: 1});
  assert.deepEqual(rv.readPackagePolicy(), {patched: {}, built: []});
  const result = await rv.verifyModules();
  assert.deepEqual(result.details.findings.map(finding => [finding.path, finding.modified]), [['tampered', ['index.js']]]);
  assert.equal(result.details.verified, 1);

  writeFiles(root, {'package.json': JSON.stringify({pnpm: {onlyBuiltDependencies: 'native'}})});
  assert.deepEqual(rv.readPackagePolicy(), {patched: {}, built: []});

  // Scan errors alone fail verification.
  install(path.join(root, 'node_modules', 'tampered'), tampered.files);
  fs.writeFileSync(path.join(root, 'node_modules', 'tampered', 'node_modules', 'tampered-nested', 'package.json'), 'not json');
  const withError = await rv.verifyModules();
  assert.equal(withError.passed, false);
  assert.equal(withError.details.failed, 1);

  // With every package matching, a non-bytecode file in a cache still fails.
  fs.rmSync(path.join(root, 'node_modules', 'tampered', 'node_modules'), {recursive: true});
  assert.equal((await rv.verifyModules()).passed, true);
  install(path.join(root, 'node_modules', 'tampered'), {'__pycache__/payload.js': 'x'});
  const cached = await rv.verifyModules();
  assert.equal(cached.passed, false);
  assert.deepEqual(cached.details.caches, [{path: 'tampered/__pycache__', files: ['payload.js']}]);
});

test('global package defaults', async t => {
  const upstream = await startUpstream(t, []);
  const globalDir = tempDir(t);
  install(path.join(globalDir, '.hidden'), {'package.json': JSON.stringify({name: 'hidden', version: '1.0.0'})});
  const rv = new ReleaseVerification({
    nodeDistUrl: upstream.nodeDistUrl, registryUrl: upstream.registryUrl, retryDelay: 1, maxRetries: 0,
  });
  assert.equal((await rv.verifyGlobalPackage(path.join(globalDir, '.hidden'))).details.error, 'Not a package directory');
  install(path.join(globalDir, 'solo'), {'package.json': JSON.stringify({name: 'solo', version: '1.0.0'})});
  const solo = await rv.verifyGlobalPackage(path.join(globalDir, 'solo'));
  assert.match(solo.details.nodeArchiveError, /HTTP 404/, 'defaults to the running Node.js release');
  const report = await rv.verifyAll({globalDir, checkNode: false, modules: false});
  assert.deepEqual(report.checks, {});
  assert.equal(report.passed, false, 'nothing verified is not a pass');
});

test('pnpm patches are applied to the reference exactly; structural scan errors fail even when packages match', async t => {
  const pkg = makePackage(t, 'addsfile', '1.0.0', {'package.json': JSON.stringify({name: 'addsfile', version: '1.0.0'}), 'index.js': 'x\n', 'old.js': 'old\n'});
  const upstream = await startUpstream(t, [pkg]);
  const rv = new ReleaseVerification({registryUrl: upstream.registryUrl, retryDelay: 1});
  const manifest = await rv.getPackageManifest(pkg);

  // A real patch, as git writes it: change index.js, add new.js, delete old.js.
  const work = tempDir(t);
  writeFiles(work, pkg.files);
  execFileSync('git', ['init', '-q'], {cwd: work});
  execFileSync('git', ['add', '-A'], {cwd: work});
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'tarball'], {cwd: work});
  writeFiles(work, {'index.js': 'x\npatched\n', 'new.js': 'added by patch\n'});
  fs.rmSync(path.join(work, 'old.js'));
  execFileSync('git', ['add', '-A'], {cwd: work});
  const text = execFileSync('git', ['-c', 'core.pager=cat', 'diff', '--cached', '--no-color'], {cwd: work, encoding: 'utf8'});
  const policy = {patched: {'addsfile@1.0.0': {files: ReleaseVerification.filesTouchedByPatch(text), text}}, built: []};
  const patchedFiles = {...manifest.files, 'index.js': sha256('x\npatched\n'), 'new.js': sha256('added by patch\n')};
  delete patchedFiles['old.js'];
  const compare = files => rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files,
    }],
    references: [{...pkg, source: 'registry'}],
    policy,
  });

  const byName = await rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files: patchedFiles,
    }],
    references: [{...pkg, source: 'registry'}],
    policy: {patched: {addsfile: policy.patched['addsfile@1.0.0']}, built: []},
  });
  assert.equal(byName.summary.patched, 1, 'a patch keyed by name applies to every version');
  const exact = await compare(patchedFiles);
  assert.equal(exact.passed, true, JSON.stringify(exact.findings));
  assert.equal(exact.summary.patched, 1);

  // The patch names index.js, but any content other than the patched one fails.
  const altered = await compare({...patchedFiles, 'index.js': sha256('x\nsomething else\n')});
  assert.deepEqual(altered.findings[0].modified, ['index.js']);
  const stale = await compare({...patchedFiles, 'old.js': manifest.files['old.js']});
  assert.deepEqual(stale.findings[0].added, ['old.js']);
  const extra = await compare({...patchedFiles, 'more.js': sha256('more')});
  assert.deepEqual(extra.findings[0].added, ['more.js']);
  assert.equal(extra.findings[0].reason, 'files differ from reference tarball', 'a file added to a patched package is not build output');

  // A patch that does not apply to the pinned tarball fails.
  const wrong = await rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files: patchedFiles,
    }],
    references: [{...pkg, source: 'registry'}],
    policy: {patched: {'addsfile@1.0.0': {files: ['index.js'], text: '--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-y\n+z\n'}}, built: []},
  });
  assert.match(wrong.findings[0].reason, /^patch could not be applied to the reference: Patch does not apply to index\.js at line 1$/);
  await assert.rejects(rv.getPackageFiles({name: '../x', version: '1.0.0', integrity: pkg.integrity}, []), /Invalid package reference/);
  await assert.rejects(rv.getPackageFiles({...pkg, integrity: `sha512-${'A'.repeat(86)}==`}, ['index.js']), /does not match integrity/);
  assert.deepEqual([...(await rv.getPackageFiles(pkg, ['index.js'])).keys()], ['index.js']);

  // Odd layouts: .bin that is not a directory, a link where a store entry belongs.
  const odd = tempDir(t);
  writeFiles(odd, {'node_modules/.bin': 'not a directory', 'node_modules/.pnpm/real@1.0.0/node_modules/real/package.json': JSON.stringify({name: 'real', version: '1.0.0'})});
  fs.symlinkSync('real@1.0.0', path.join(odd, 'node_modules', '.pnpm', 'alias@1.0.0'));
  const oddScan = await rv.scanInstalledPackages(path.join(odd, 'node_modules'));
  assert.deepEqual(oddScan.errors, [{path: '.bin', error: 'ENOTDIR'}]);
  assert.deepEqual(oddScan.links.map(link => `${link.path}: ${link.problem}`), ['.pnpm/alias@1.0.0: does not point to an installed package']);

  const root = tempDir(t);
  writeFiles(root, {
    'package.json': '{}',
    'pnpm-lock.yaml': `lockfileVersion: '9.0'\npackages:\n  addsfile@1.0.0:\n    resolution: {integrity: ${pkg.integrity}}\n`,
    'node_modules/.pnpm/addsfile@1.0.0/node_modules/addsfile/package.json': pkg.files['package.json'],
    'node_modules/.pnpm/addsfile@1.0.0/node_modules/addsfile/index.js': pkg.files['index.js'],
    'node_modules/.pnpm/addsfile@1.0.0/node_modules/addsfile/old.js': pkg.files['old.js'],
    'node_modules/.pnpm/weird@1.0.0/node_modules': 'a file where a directory belongs',
  });
  const result = await new ReleaseVerification({projectRoot: root, registryUrl: upstream.registryUrl, retryDelay: 1}).verifyModules();
  assert.equal(result.details.verified, 1);
  assert.equal(result.details.failed, 0);
  assert.deepEqual(result.details.errors, [{path: '.pnpm/weird@1.0.0/node_modules', error: 'ENOTDIR'}]);
  assert.equal(result.passed, false);

  // A package link that leaves node_modules fails verification by itself.
  fs.rmSync(path.join(root, 'node_modules/.pnpm/weird@1.0.0'), {recursive: true});
  fs.symlinkSync(tempDir(t), path.join(root, 'node_modules', 'escape'));
  const linked = await new ReleaseVerification({projectRoot: root, registryUrl: upstream.registryUrl, retryDelay: 1}).verifyModules();
  assert.deepEqual(linked.details.errors, []);
  assert.equal(linked.details.failed, 0);
  assert.deepEqual(linked.details.links.map(link => link.path), ['escape']);
  assert.equal(linked.passed, false);

  // Without a policy, or with a manifest provider, no patch is applied.
  const provided = await rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files: patchedFiles,
    }],
    manifestProvider: async () => manifest,
    policy,
  });
  assert.deepEqual(provided.findings[0].added, ['new.js']);
  // Files only added (a native addon an install script wrote): the reason says how to allow them.
  const addon = await rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files: {...manifest.files, 'build/Release/addon.node': sha256('addon')},
    }],
    references: [{...pkg, source: 'registry'}],
    policy: {patched: {}, built: []},
  });
  assert.deepEqual(addon.findings[0].added, ['build/Release/addon.node']);
  assert.equal(addon.findings[0].reason, 'files differ from reference tarball (install script output is allowed only for packages in pnpm.onlyBuiltDependencies)');
  const unpatched = await rv.comparePackages({
    installed: [{
      name: 'addsfile', version: '1.0.0', path: 'addsfile', digest: 'x', files: manifest.files,
    }],
    references: [{...pkg, source: 'registry'}],
    policy: {built: []},
  });
  assert.equal(unpatched.passed, false, 'the digest "x" does not match, so files are compared');
});

test('applyPatch: hunks, new, deleted and renamed files, missing newlines, and refusals', () => {
  const {applyPatch} = ReleaseVerification;
  const originals = new Map([
    ['a.js', Buffer.from('1\n2\n3\n4\n5\n6\n7\n8\n9\n')],
    ['tail.js', Buffer.from('last')],
    ['gone.js', Buffer.from('bye\n')],
    ['from.js', Buffer.from('same\n')],
  ]);
  const text = [
    'diff --git a/a.js b/a.js',
    'index 1..2 100644',
    '--- a/a.js\t2020-01-01 00:00:00',
    '+++ b/a.js',
    '@@ -1,3 +1,3 @@',
    ' 1',
    '-2',
    '+two',
    ' 3',
    '@@ -7,3 +7,4 @@',
    ' 7',
    ' 8',
    ' 9',
    '+10',
    '--- a/tail.js',
    '+++ b/tail.js',
    '@@ -1 +1 @@',
    '-last',
    String.raw`\ No newline at end of file`,
    '+last!',
    String.raw`\ No newline at end of file`,
    '--- /dev/null',
    '+++ b/new.js',
    '@@ -0,0 +1,2 @@',
    '+a',
    '+b',
    '--- a/gone.js',
    '+++ /dev/null',
    '@@ -1 +0,0 @@',
    '-bye',
    '--- a/from.js',
    '+++ b/to.js',
    '',
  ].join('\n');
  const result = applyPatch(text, originals);
  assert.equal(result.get('a.js').toString(), '1\ntwo\n3\n4\n5\n6\n7\n8\n9\n10\n');
  assert.equal(result.get('tail.js').toString(), 'last!');
  assert.equal(result.get('new.js').toString(), 'a\nb\n');
  assert.equal(result.get('gone.js'), null);
  assert.equal(result.get('from.js'), null);
  assert.equal(result.get('to.js').toString(), 'same\n');

  // A context line followed by the marker keeps the original missing newline.
  assert.equal(applyPatch('--- a/tail.js\n+++ b/tail.js\n@@ -1 +1,2 @@\n+first\n last\n\\ No newline at end of file\n', originals).get('tail.js').toString(), 'first\nlast');
  // Inserting into an empty file.
  assert.equal(applyPatch('--- a/e.js\n+++ b/e.js\n@@ -0,0 +1 @@\n+x\n', new Map([['e.js', Buffer.alloc(0)]])).get('e.js').toString(), 'x\n');

  const refuses = (patch, pattern) => assert.throws(() => applyPatch(patch, originals), pattern);
  refuses('--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-nope\n+x\n', /Patch does not apply to a\.js at line 1/);
  refuses('--- a/a.js\n+++ b/a.js\n@@ -20 +20 @@\n-x\n+y\n', /out of order or out of range/);
  refuses('--- a/a.js\n+++ b/a.js\n@@ -5 +5 @@\n-5\n+x\n@@ -1 +1 @@\n-1\n+y\n', /out of order or out of range/);
  refuses('--- a/a.js\n+++ b/a.js\n@@ -1,2 +1,2 @@\n 1\n', /Truncated hunk in a\.js/);
  refuses('--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n?1\n', /Malformed hunk line in a\.js/);
  refuses('--- a/a.js\n+++ b/a.js\n@@ bad @@\n', /Malformed hunk header/);
  refuses('--- a/a.js\nnot a header\n', /Malformed patch header at line 1/);
  refuses('--- a/missing.js\n+++ b/missing.js\n', /Patched file is not in the package: missing\.js/);
  refuses('--- x/a.js\n+++ b/a.js\n', /Unsupported patch path: x\/a\.js/);
  refuses('diff --git a/img.png b/img.png\nGIT binary patch\nliteral 1\n', /Binary patches are not supported/);
  refuses('Binary files a/x and b/x differ\n', /Binary patches are not supported/);
  assert.deepEqual([...applyPatch('', originals)], []);
  // No final newline in the patch text; two sections for one file.
  assert.equal(applyPatch('--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-1\n+one\n--- a/a.js\n+++ b/a.js\n@@ -2 +2 @@\n-2\n+two', originals).get('a.js').toString(), 'one\ntwo\n3\n4\n5\n6\n7\n8\n9\n');
  // Errors in new files name the new path.
  refuses('--- /dev/null\n+++ b/n.js\n@@ -3 +3 @@\n-x\n+y\n', /out of order or out of range in n\.js/);
  refuses('--- /dev/null\n+++ b/n.js\n@@ -0,0 +1 @@\n?x\n', /Malformed hunk line in n\.js/);
  refuses('--- /dev/null\n+++ b/n.js\n@@ -0,0 +1,2 @@\n+x\n', /Truncated hunk in n\.js/);
});

test('packages pinned to a GitHub commit are compared with the commit\'s archive', async t => {
  const sha = 'a'.repeat(40);
  const other = 'b'.repeat(40);
  const repoFiles = {
    'package.json': JSON.stringify({name: 'ghdep', version: '0.0.0', files: ['index.js', 'patched.js']}),
    'index.js': 'module.exports = "from github";\n',
    'patched.js': 'original\n',
    'test/test.js': 'not packed\n',
  };
  const archive = makeTarGz(t, Object.fromEntries(Object.entries(repoFiles).map(([file, content]) => [`ghdep-${sha}/${file}`, content])));
  const server = await startServer(t, {
    [`/gh/owner/ghdep/tar.gz/${sha}`]: {body: archive},
    [`/gh/owner/patchdep/tar.gz/${sha}`]: {body: archive},
  });

  const lock = ReleaseVerification.parseLockfile([
    'lockfileVersion: \'9.0\'',
    'packages:',
    `  ghdep@https://codeload.github.com/owner/ghdep/tar.gz/${sha}:`,
    `    resolution: {tarball: https://codeload.github.com/owner/ghdep/tar.gz/${sha}}`,
    '    version: 0.0.0',
    '  viagit@1.0.0:',
    `    resolution: {type: git, repo: https://github.com/owner/viagit, commit: ${sha}}`,
    `  pinned@https://codeload.github.com/owner/pinned/tar.gz/${sha}:`,
    `    resolution: {integrity: sha512-AAAA, tarball: https://codeload.github.com/owner/pinned/tar.gz/${sha}}`,
    '    version: 1.0.0',
    '',
  ].join('\n'), 'pnpm');
  const byName = Object.fromEntries(lock.packages.map(item => [item.name, item]));
  assert.deepEqual(byName.ghdep.github, {owner: 'owner', repo: 'ghdep', commit: sha});
  assert.equal(byName.ghdep.source, 'github');
  assert.equal(byName.viagit.source, 'github');
  assert.equal(byName.pinned.source, 'tarball', 'an integrity pins the tarball itself');
  assert.deepEqual([...ReleaseVerification.filesNeeded(lock, {patched: {'x@1.0.0': null}, built: ['y']})].sort(), ['ghdep@0.0.0', 'viagit@1.0.0', 'x@1.0.0', 'y']);

  assert.deepEqual(ReleaseVerification.githubCommitOf(`git+ssh://git@github.com/owner/repo.git#${sha}`), {owner: 'owner', repo: 'repo', commit: sha});
  assert.deepEqual(ReleaseVerification.githubCommitOf(`github.com:owner/repo#${sha}`), null);
  assert.deepEqual(ReleaseVerification.githubCommitOf(`git+https://github.com/owner/repo#${sha}`), {owner: 'owner', repo: 'repo', commit: sha});
  assert.equal(ReleaseVerification.githubCommitOf(`https://codeload.github.com/../x/tar.gz/${sha}`), null);
  assert.equal(ReleaseVerification.githubCommitOf('https://codeload.github.com/owner/repo/tar.gz/main'), null);
  assert.equal(ReleaseVerification.githubCommitOf(undefined), null);

  const rv = new ReleaseVerification({githubArchiveUrl: `${server.url}/gh/`, retryDelay: 1, maxRetries: 0});
  const packed = {'package.json': repoFiles['package.json'], 'index.js': repoFiles['index.js'], 'patched.js': repoFiles['patched.js']};
  const hashes = files => Object.fromEntries(Object.entries(files).map(([file, content]) => [file, sha256(Buffer.from(content))]));
  const item = (name, files, version = '0.0.0') => ({
    name, version, path: name, digest: 'x', fileCount: Object.keys(files).length, files: hashes(files),
  });
  const references = [
    byName.ghdep,
    {...byName.ghdep, name: 'patchdep', github: {...byName.ghdep.github, repo: 'patchdep'}},
    {...byName.ghdep, name: 'missing', github: {...byName.ghdep.github, commit: other}},
  ];
  const comparison = await rv.comparePackages({
    installed: [
      item('ghdep', packed),
      {...item('ghdep', {...packed, 'index.js': 'backdoor\n'}), path: 'a/node_modules/ghdep'},
      {...item('ghdep', {...packed, 'extra.js': 'added\n'}), path: 'b/node_modules/ghdep'},
      {...item('ghdep', {'index.js': repoFiles['index.js']}), path: 'c/node_modules/ghdep'},
      item('patchdep', {...packed, 'patched.js': 'patched\n'}),
      item('missing', packed),
    ],
    references,
    policy: {
      patched: {patchdep: {files: ['patched.js'], text: '--- a/patched.js\n+++ b/patched.js\n@@ -1 +1 @@\n-original\n+patched\n'}},
      built: [],
    },
  });
  const byPath = Object.fromEntries(comparison.findings.map(finding => [finding.path, finding]));
  assert.equal(byPath.ghdep, undefined, 'files left out by packing are not missing');
  assert.deepEqual(byPath['a/node_modules/ghdep'].modified, ['index.js']);
  assert.deepEqual(byPath['b/node_modules/ghdep'].added, ['extra.js']);
  assert.deepEqual(byPath['c/node_modules/ghdep'].missing, ['package.json']);
  assert.equal(byPath.patchdep, undefined, 'a pnpm patch applies to the archive');
  assert.match(byPath.missing.reason, /HTTP 404/);
  assert.equal(comparison.summary.verified, 1);
  assert.equal(comparison.summary.patched, 1);
  assert.equal(comparison.summary.failed, 3);
  assert.equal(comparison.summary.error, 1, 'an archive that cannot be downloaded is not a mismatch');
  assert.equal(byPath.missing.status, 'error');
  assert.equal(comparison.passed, false);
});

test('package manager rewrites: CRLF shebangs of bin files, and Python bytecode caches', async t => {
  const crlf = '#!/usr/bin/env node\r\nconsole.log("cli");\r\n';
  const fixed = '#!/usr/bin/env node\nconsole.log("cli");\r\n';
  const cli = makePackage(t, 'cli', '1.0.0', {
    'package.json': JSON.stringify({name: 'cli', version: '1.0.0', bin: {cli: './bin/cli.js', up: '../escape.js'}}),
    'bin/cli.js': crlf,
    'lib/other.js': crlf,
  });
  const dirbin = makePackage(t, 'dirbin', '1.0.0', {
    'package.json': JSON.stringify({name: 'dirbin', version: '1.0.0', directories: {bin: './bin/'}}),
    'bin/run': crlf,
    'bin/unix': '#!/bin/sh\necho unix\n',
  });
  const single = makePackage(t, 'single', '1.0.0', {
    'package.json': JSON.stringify({name: 'single', version: '1.0.0', bin: 'run.js'}),
    'run.js': crlf,
  });
  const nobin = makePackage(t, 'nobin', '1.0.0', {'package.json': JSON.stringify({name: 'nobin', version: '1.0.0'}), 'x.js': crlf});
  const gyp = makePackage(t, 'gyp', '1.0.0', {
    'package.json': JSON.stringify({name: 'gyp', version: '1.0.0'}),
    'pylib/gyp.py': 'print(1)\n',
    // A cache shipped in the tarball is left out of the reference as well.
    'pylib/__pycache__/shipped.cpython-39.pyc': 'published bytecode',
  });
  const upstream = await startUpstream(t, [cli, dirbin, single, nobin, gyp]);

  const root = tempDir(t);
  const modules = path.join(root, 'node_modules');
  install(path.join(modules, 'cli'), {...cli.files, 'bin/cli.js': fixed});
  install(path.join(modules, 'dirbin'), {...dirbin.files, 'bin/run': fixed});
  install(path.join(modules, 'single'), single.files);
  install(path.join(modules, 'nobin'), {...nobin.files, 'x.js': fixed});
  install(path.join(modules, 'gyp'), {...gyp.files, 'pylib/__pycache__/gyp.cpython-312.pyc': 'bytecode', 'pylib/__pycache__/sub/odd.js': 'x'});
  install(path.join(modules, 'other', 'node_modules', 'cli'), {...cli.files, 'bin/cli.js': fixed, 'lib/other.js': fixed});

  const rv = new ReleaseVerification({registryUrl: upstream.registryUrl, retryDelay: 1, maxRetries: 0});
  install(path.join(modules, 'gyp'), {'pylib/__pycache__/locked/x.pyc': 'x'});
  const {readdir} = fs.promises;
  fs.promises.readdir = async (directory, ...rest) => {
    // Directories are listed through their open descriptors.
    const target = String(directory).startsWith('/proc/self/fd/') ? fs.readlinkSync(directory) : String(directory);
    if (target.endsWith(`__pycache__${path.sep}locked`)) {
      throw Object.assign(new Error('denied'), {code: 'EACCES'});
    }

    return readdir(directory, ...rest);
  };

  t.after(() => {
    fs.promises.readdir = readdir;
  });
  const scan = await rv.scanInstalledPackages(modules, {includeFiles: item => item.path === 'dirbin'});
  fs.promises.readdir = readdir;
  assert.deepEqual(scan.caches, [{path: 'gyp/pylib/__pycache__', files: ['gyp.cpython-312.pyc', 'shipped.cpython-39.pyc', 'sub/odd.js']}]);
  assert.deepEqual(scan.errors, [{path: 'other', error: 'package.json: ENOENT'}, {path: 'gyp/pylib/__pycache__/locked', error: 'EACCES'}]);
  assert.deepEqual(ReleaseVerification.foreignCacheFiles(scan.caches), ['gyp/pylib/__pycache__/sub/odd.js']);
  assert.deepEqual(ReleaseVerification.foreignCacheFiles(), []);
  const comparison = await rv.comparePackages({installed: scan.packages});
  const byPath = Object.fromEntries(comparison.findings.map(finding => [finding.path, finding]));
  assert.equal(byPath.cli, undefined, 'bin file with its shebang line ending fixed');
  assert.equal(byPath.dirbin, undefined, 'directories.bin, compared file by file');
  assert.equal(byPath.single, undefined, 'bin as a string, left as published');
  assert.equal(byPath.gyp, undefined, 'bytecode caches are listed, not hashed with the package');
  assert.match(byPath.nobin.reason, /files differ/, 'no bin declared, so no rewrite is expected');
  assert.match(byPath['other/node_modules/cli'].reason, /files differ/, 'only bin files may be rewritten');
  assert.equal(comparison.summary.verified, 4);

  const manifest = await rv.getPackageManifest({...cli, source: 'registry'});
  assert.deepEqual(Object.keys(manifest.binFixes), ['bin/cli.js']);
  assert.equal(manifest.binFixes['bin/cli.js'], sha256(Buffer.from(fixed)));
  assert.equal(ReleaseVerification.packageManifestFromFiles(new Map([['package.json', Buffer.from('{broken')], ['x', Buffer.from(crlf)]])).binFixes, undefined);
  assert.equal(ReleaseVerification.packageManifestFromFiles(new Map([['x', Buffer.from(crlf)]])).binFixes, undefined);
  assert.equal(ReleaseVerification.packageManifestFromFiles(new Map([['package.json', Buffer.from('null')], ['x', Buffer.from(crlf)]])).binFixes, undefined);
  assert.equal(ReleaseVerification.packageManifestFromFiles(new Map([['package.json', Buffer.from('{"bin":{"a":1,"b":"x"}}')], ['x', Buffer.from(crlf)]])).fixedDigest.length, 64);

  // A modified bin file is still caught when files are compared one by one.
  const tampered = scan.packages.find(item => item.path === 'dirbin');
  tampered.files['bin/run'] = sha256(Buffer.from('#!/bin/sh\nevil\n'));
  tampered.digest = 'x';
  const again = await rv.comparePackages({installed: [tampered], policy: {patched: {}, built: ['dirbin']}});
  assert.deepEqual(again.findings[0].modified, ['bin/run']);
});

test('a package must be the one the lockfile pins where it is installed', async t => {
  const sanitizer = makePackage(t, 'sanitizer', '2.0.0', {'package.json': JSON.stringify({name: 'sanitizer', version: '2.0.0'}), 'index.js': 'module.exports = html => escape(html);\n'});
  const oldSanitizer = makePackage(t, 'sanitizer', '1.0.0', {'package.json': JSON.stringify({name: 'sanitizer', version: '1.0.0'}), 'index.js': 'module.exports = html => html;\n'});
  const noop = makePackage(t, 'noop', '1.0.0', {'package.json': JSON.stringify({name: 'noop', version: '1.0.0'}), 'index.js': 'module.exports = value => value;\n'});
  const bundler = makePackage(t, 'bundler', '1.0.0', {
    'package.json': JSON.stringify({name: 'bundler', version: '1.0.0', bundleDependencies: ['inner']}),
    'node_modules/inner/package.json': JSON.stringify({name: 'inner', version: '1.0.0'}),
    'node_modules/inner/index.js': 'module.exports = value => value;\n',
  });
  const upstream = await startUpstream(t, [sanitizer, oldSanitizer, noop, bundler]);
  const entry = item => ({version: item.version, resolved: `https://registry.npmjs.org/${item.name}/-/${item.name}-${item.version}.tgz`, integrity: item.integrity});
  const lockfile = {
    lockfileVersion: 3,
    packages: {
      '': {name: 'app'},
      'node_modules/sanitizer': entry(sanitizer),
      'node_modules/noop': entry(noop),
      'node_modules/bundler': entry(bundler),
      'node_modules/bundler/node_modules/inner': {version: '1.0.0', inBundle: true},
      'node_modules/noop/node_modules/sanitizer': entry(oldSanitizer),
    },
  };
  const verify = async layout => {
    const root = tempDir(t);
    for (const [directory, item] of Object.entries(layout)) {
      install(path.join(root, 'node_modules', ...directory.split('/')), item.files);
    }

    writeFiles(root, {'package-lock.json': JSON.stringify(lockfile)});
    const rv = new ReleaseVerification({projectRoot: root, registryUrl: upstream.registryUrl, maxRetries: 0});
    return (await rv.verifyModules()).details;
  };

  const inner = {files: {'package.json': JSON.stringify({name: 'inner', version: '1.0.0'}), 'index.js': 'module.exports = value => value;\n'}};
  const honest = await verify({
    sanitizer, noop, bundler, 'bundler/node_modules/inner': inner, 'noop/node_modules/sanitizer': oldSanitizer,
  });
  assert.deepEqual(honest.findings, []);
  assert.equal(honest.bundled, 1);

  // Require('sanitizer') loads another locked package, an older locked
  // version, or a bundled copy moved out of its bundle.
  for (const [swapped, reason] of [
    [noop, 'the lockfile pins sanitizer@2.0.0 at this path'],
    [oldSanitizer, 'the lockfile pins sanitizer@2.0.0 at this path'],
    [inner, 'the lockfile pins sanitizer@2.0.0 at this path'],
  ]) {
    const details = await verify({
      sanitizer: swapped, noop, bundler, 'bundler/node_modules/inner': inner, 'noop/node_modules/sanitizer': oldSanitizer,
    });
    assert.deepEqual(details.findings.map(finding => [finding.path, finding.status, finding.reason]), [['sanitizer', 'failed', reason]]);
  }

  // A copy where the lockfile has none shadows the one it pins for the
  // package it is nested in.
  const extra = await verify({
    sanitizer, noop, bundler, 'bundler/node_modules/inner': inner, 'noop/node_modules/sanitizer': oldSanitizer, 'bundler/node_modules/sanitizer': oldSanitizer,
  });
  assert.deepEqual(extra.findings.map(finding => [finding.path, finding.reason]), [['bundler/node_modules/sanitizer', 'the lockfile pins no package at this path']]);
});

test('a package in pnpm\'s store must be the one its directory is named for', async t => {
  const rv = new ReleaseVerification({registryUrl: 'http://127.0.0.1:9/registry', maxRetries: 0});
  const item = (itemPath, name, version) => ({
    name, version, path: itemPath, digest: 'x', fileCount: 0,
  });
  const reasons = async items => (await rv.comparePackages({installed: items, references: []})).findings.map(finding => [finding.path, finding.reason]);
  const wrong = 'installed where pnpm keeps another package';
  const notLocked = 'installed package is not in the lockfile or any bundle';
  assert.deepEqual(await reasons([
    item('.pnpm/sanitizer@2.0.0/node_modules/sanitizer', 'noop', '1.0.0'),
    item('.pnpm/sanitizer@2.0.0/node_modules/sanitizer', 'sanitizer', '1.0.0'),
    item('.pnpm/sanitizer@2.0.0_peer@1.0.0/node_modules/sanitizer', 'sanitizer', '2.0.1'),
    item('.pnpm/@scope+a@1.0.0/node_modules/@scope/a', '@scope/b', '1.0.0'),
    item(`.pnpm/long@1.0.0_${'p'.repeat(80)}_abcdefghijklmnopqrstuvwxyz/node_modules/long`, 'long', '2.0.0'),
    // Consistent directories reach the lockfile.
    item('.pnpm/sanitizer@2.0.0/node_modules/sanitizer', 'sanitizer', '2.0.0'),
    item('.pnpm/sanitizer@2.0.0_peer@1.0.0/node_modules/sanitizer', 'sanitizer', '2.0.0'),
    item('.pnpm/Upper@1.0.0_abcdefghijklmnopqrstuvwxyz/node_modules/Upper', 'Upper', '1.0.0'),
    item('.pnpm/@scope+a@1.0.0/node_modules/@scope/a', '@scope/a', '1.0.0'),
    item('.pnpm/gh@https+++codeload.github.com+o+r+tar.gz+abc/node_modules/gh', 'gh', '3.0.0'),
    item(`.pnpm/${'v'.repeat(80)}@1.0.0-beta.12_abcdefghijklmnopqrstuvwxyz/node_modules/${'v'.repeat(80)}`, 'v'.repeat(80), '1.0.0-beta.1234567890'),
    item('plain/node_modules/other', 'x', '1.0.0'),
  ]), [
    ['.pnpm/@scope+a@1.0.0/node_modules/@scope/a', wrong],
    ['.pnpm/@scope+a@1.0.0/node_modules/@scope/a', notLocked],
    ['.pnpm/Upper@1.0.0_abcdefghijklmnopqrstuvwxyz/node_modules/Upper', notLocked],
    ['.pnpm/gh@https+++codeload.github.com+o+r+tar.gz+abc/node_modules/gh', notLocked],
    [`.pnpm/long@1.0.0_${'p'.repeat(80)}_abcdefghijklmnopqrstuvwxyz/node_modules/long`, wrong],
    ['.pnpm/sanitizer@2.0.0/node_modules/sanitizer', wrong],
    ['.pnpm/sanitizer@2.0.0/node_modules/sanitizer', wrong],
    ['.pnpm/sanitizer@2.0.0/node_modules/sanitizer', notLocked],
    ['.pnpm/sanitizer@2.0.0_peer@1.0.0/node_modules/sanitizer', wrong],
    ['.pnpm/sanitizer@2.0.0_peer@1.0.0/node_modules/sanitizer', notLocked],
    [`.pnpm/${'v'.repeat(80)}@1.0.0-beta.12_abcdefghijklmnopqrstuvwxyz/node_modules/${'v'.repeat(80)}`, notLocked],
    ['plain/node_modules/other', notLocked],
  ]);
});

test('a built package may replace a file it shipped with the same file of a verified optional dependency (esbuild)', async t => {
  const native = Buffer.from('\u007FELF native launcher');
  const launcher = makePackage(t, 'launcher', '1.0.0', {
    'package.json': JSON.stringify({name: 'launcher', version: '1.0.0', optionalDependencies: {'@launcher/linux-x64': '1.0.0'}}),
    'bin/launcher': '#!/usr/bin/env node\nrequire("../install.js")\n',
    'install.js': 'copy the platform binary over bin/launcher\n',
  });
  const platform = makePackage(t, '@launcher/linux-x64', '1.0.0', {'package.json': JSON.stringify({name: '@launcher/linux-x64', version: '1.0.0'}), 'bin/launcher': native});
  const unrelated = makePackage(t, 'unrelated', '1.0.0', {'package.json': JSON.stringify({name: 'unrelated', version: '1.0.0'}), 'bin/launcher': native});
  const nameless = makePackage(t, 'nameless', '1.0.0', {'bin/launcher': '#!/bin/sh\n'});
  const upstream = await startUpstream(t, [launcher, platform, unrelated, nameless]);
  const rv = new ReleaseVerification({registryUrl: upstream.registryUrl, cacheDir: tempDir(t), retryDelay: 1});
  const installedAs = (pkg, directory, changes = {}) => {
    const files = new Map(Object.entries({...pkg.files, ...changes}).map(([file, content]) => [file, Buffer.from(content)]));
    const {files: hashes, digest} = ReleaseVerification.packageManifestFromFiles(files);
    return {
      name: pkg.name, version: pkg.version, path: directory, digest, files: hashes,
    };
  };

  const references = [launcher, platform, unrelated, nameless].map(pkg => ({...pkg, source: 'registry'}));
  const compare = (installed, built = ['launcher']) => rv.comparePackages({installed, references, policy: {patched: {}, built}});
  const replaced = installedAs(launcher, 'launcher', {'bin/launcher': native});
  const withPlatform = installedAs(platform, '@launcher/linux-x64');

  const result = await compare([replaced, withPlatform]);
  assert.deepEqual(result.findings, []);
  assert.equal(result.summary.built, 1);
  assert.equal(result.passed, true);

  // Only for a package allowed to run its install script.
  assert.deepEqual((await compare([replaced, withPlatform], [])).findings.map(finding => finding.modified), [['bin/launcher']]);
  // Not when the optional dependency is not installed, or does not match its reference.
  assert.equal((await compare([replaced])).passed, false);
  assert.equal((await compare([replaced, installedAs(platform, '@launcher/linux-x64', {'bin/launcher': 'other'})])).findings.length, 2);
  // Not with the same file of a package that is not an optional dependency.
  assert.deepEqual((await compare([replaced, installedAs(unrelated, 'unrelated')])).findings.map(finding => finding.package), ['launcher@1.0.0']);
  // Not with content no optional dependency ships.
  assert.equal((await compare([installedAs(launcher, 'launcher', {'bin/launcher': 'evil'}), withPlatform])).passed, false);
  // A package without a package.json names no optional dependency.
  assert.equal((await compare([installedAs(nameless, 'nameless', {'bin/launcher': native}), withPlatform], ['nameless'])).passed, false);
});

test('npm installs a tarball\'s .gitignore files as .npmignore: the same content under that name matches', async t => {
  const icons = makePackage(t, 'icons', '1.0.0', {
    'package.json': JSON.stringify({name: 'icons', version: '1.0.0'}),
    'svg/.gitignore': '*.tmp\n',
    '.gitignore': 'node_modules\n',
    'index.js': 'icons\n',
  });
  const upstream = await startUpstream(t, [icons]);
  const rv = new ReleaseVerification({registryUrl: upstream.registryUrl, cacheDir: tempDir(t), retryDelay: 1});
  const installedAs = (files, directory = 'icons') => {
    const {files: hashes, digest} = ReleaseVerification.packageManifestFromFiles(new Map(Object.entries(files).map(([file, content]) => [file, Buffer.from(content)])));
    return {
      name: 'icons', version: '1.0.0', path: directory, digest, files: hashes,
    };
  };

  const compare = installed => rv.comparePackages({installed: [installed], references: [{...icons, source: 'registry'}], policy: {patched: {}, built: []}});
  const {'svg/.gitignore': svgIgnore, '.gitignore': rootIgnore, ...rest} = icons.files;
  const renamed = {...rest, 'svg/.npmignore': svgIgnore, '.npmignore': rootIgnore};
  const result = await compare(installedAs(renamed));
  assert.deepEqual(result.findings, []);
  assert.equal(result.summary.verified, 1);
  // Evidence may carry only the digest of a package.
  const {files: _, ...digestOnly} = installedAs(renamed);
  assert.equal((await compare(digestOnly)).summary.verified, 1);
  const {files: __, ...changedDigest} = installedAs({...renamed, 'svg/.npmignore': 'other\n'});
  assert.equal((await compare(changedDigest)).passed, false);

  // Other content under the new name, or another file, still fails.
  const changed = await compare(installedAs({...renamed, 'svg/.npmignore': 'require("x")\n'}));
  assert.deepEqual(changed.findings.map(finding => [finding.missing, finding.added]), [[['svg/.gitignore'], ['svg/.npmignore']]]);
  assert.equal((await compare(installedAs({...renamed, 'index.js': 'evil\n'}))).passed, false);
  // Both names installed: the .npmignore is an added file.
  assert.equal((await compare(installedAs({...icons.files, 'svg/.npmignore': svgIgnore}))).passed, false);
});

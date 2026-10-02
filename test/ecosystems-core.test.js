'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const ecosystems = require('../lib/ecosystems');
const {
  ReferenceStore, NoLockfileError, STATUSES, hashFiles, compareFiles, collect, parseCsv, isInside,
} = require('../lib/ecosystems/common');
const npm = require('../lib/ecosystems/npm');
const go = require('../lib/ecosystems/go');
const cargo = require('../lib/ecosystems/cargo');
const ReleaseVerification = require('../lib/release-verification');
const {goBuildInfo, cargoAuditable} = require('../lib/elf');
const {sha256} = require('../lib/util');
const {
  tempDir, writeFiles, startServer, makeTarGz, which,
} = require('./helpers');
const {
  hasGo, hasCargoAuditable, goProject, cargoProject,
} = require('./fixtures/formats/binaries');

// ─── common ─────────────────────────────────────────────────────────────

test('ReferenceStore defaults and options', () => {
  const store = new ReferenceStore();
  assert.equal(store.cacheDir, null);
  assert.deepEqual(store.httpOptions, {});
  assert.equal(store.concurrency, 8);
  assert.equal(store.urls.pypi, 'https://pypi.org');
  assert.equal(store.urls.crates, 'https://static.crates.io/crates');
  assert.equal(store.urls.goproxy, 'https://proxy.golang.org');
  assert.equal(store.readCache('key'), null, 'no cache directory');
  store.writeCache('key', 1);

  const custom = new ReferenceStore({
    cacheDir: '/tmp/x', httpOptions: {retryDelay: 1}, urls: {pypi: 'http://127.0.0.1:1'}, concurrency: 2,
  });
  assert.equal(custom.urls.pypi, 'http://127.0.0.1:1');
  assert.equal(custom.urls.rubygems, 'https://rubygems.org');
  assert.equal(custom.concurrency, 2);
});

test('ReferenceStore.memo computes once, persists to the cache and does not cache failures', async t => {
  const cacheDir = path.join(tempDir(t), 'cache');
  const store = new ReferenceStore({cacheDir});
  let calls = 0;
  const compute = async () => {
    calls++;
    return {value: calls};
  };

  const [first, second] = await Promise.all([store.memo('a', compute), store.memo('a', compute)]);
  assert.deepEqual(first, {value: 1});
  assert.equal(second, first);
  assert.equal(calls, 1);
  const file = path.join(cacheDir, `${sha256('a')}.json`);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), {key: 'a', value: {value: 1}});
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(cacheDir), [`${sha256('a')}.json`], 'no temporary files left');

  // Another run reads the cache.
  const next = new ReferenceStore({cacheDir});
  assert.deepEqual(await next.memo('a', compute), {value: 1});
  assert.equal(calls, 1);

  // Not persisted: computed per run, never written.
  assert.deepEqual(await next.memo('b', compute, {persist: false}), {value: 2});
  assert.equal(fs.existsSync(path.join(cacheDir, `${sha256('b')}.json`)), false);
  assert.deepEqual(await new ReferenceStore({cacheDir}).memo('b', compute, {persist: false}), {value: 3});

  // A cache file for another key (a hash collision) or a corrupt one is ignored.
  fs.writeFileSync(path.join(cacheDir, `${sha256('c')}.json`), JSON.stringify({key: 'other', value: 'wrong'}));
  assert.equal(next.readCache('c'), null);
  fs.writeFileSync(path.join(cacheDir, `${sha256('d')}.json`), '{corrupt');
  assert.equal(next.readCache('d'), null);
  assert.deepEqual(await next.memo('d', compute), {value: 4});
  assert.deepEqual(next.readCache('d'), {value: 4}, 'rewritten');

  // Failures are not remembered.
  let attempts = 0;
  const flaky = async () => {
    attempts++;
    if (attempts === 1) {
      throw new Error('temporary');
    }

    return 'ok';
  };

  await assert.rejects(next.memo('e', flaky), /temporary/);
  assert.equal(await next.memo('e', flaky), 'ok');
  assert.equal(attempts, 2);
});

test('ReferenceStore.get and getJson merge headers and options', async t => {
  const server = await startServer(t, {
    '/data.json': {body: '{"ok":true}', headers: {'content-type': 'application/json'}},
    '/flaky': {status: 503, body: 'unavailable'},
  });
  const store = new ReferenceStore({httpOptions: {headers: {'x-store': 'store'}, retryDelay: 1, maxRetries: 0}});
  assert.equal((await store.get(`${server.url}/data.json`, {headers: {'x-call': 'call'}})).toString(), '{"ok":true}');
  assert.equal(server.requests[0].headers['x-store'], 'store');
  assert.equal(server.requests[0].headers['x-call'], 'call');

  assert.deepEqual(await store.getJson(`${server.url}/data.json`), {ok: true});
  assert.equal(server.requests[1].headers.accept, 'application/json');
  assert.equal(server.requests[1].headers['x-store'], 'store');
  await store.getJson(`${server.url}/data.json`, {headers: {accept: 'application/vnd.custom+json'}});
  assert.equal(server.requests[2].headers.accept, 'application/vnd.custom+json');

  await assert.rejects(store.get(`${server.url}/flaky`), /503/);
  await assert.rejects(store.get(`${server.url}/missing`), /404/);
  await assert.rejects(store.get(`${server.url}/flaky`, {maxRetries: 1}), /503/);
  assert.equal(server.requests.filter(request => request.url === '/flaky').length, 3, 'call options override the store options');
});

test('hashFiles and compareFiles', () => {
  const hashes = hashFiles(new Map([['a.txt', Buffer.from('a')], ['b.txt', 'b']]));
  assert.deepEqual(hashes, {'a.txt': sha256('a'), 'b.txt': sha256('b')});

  const expected = {
    'same.txt': 'h1', 'changed.txt': 'h2', 'gone.txt': 'h3', 'optional.txt': 'h4', 'equivalent.txt': 'h5',
  };
  const installed = {
    'same.txt': 'h1', 'changed.txt': 'x', 'equivalent.txt': 'y', 'z-new.txt': 'n', 'a-new.txt': 'n', 'generated.pyc': 'g',
  };
  assert.deepEqual(compareFiles(installed, expected), {
    modified: ['changed.txt', 'equivalent.txt'], missing: ['gone.txt', 'optional.txt'], added: ['a-new.txt', 'generated.pyc', 'z-new.txt'],
  });
  assert.deepEqual(compareFiles(installed, expected, {
    allowMissing: file => file === 'optional.txt',
    allowExtra: (file, hash) => file.endsWith('.pyc') && hash === 'g',
    equivalent: (file, installedHash, expectedHash) => file === 'equivalent.txt' && installedHash === 'y' && expectedHash === 'h5',
  }), {modified: ['changed.txt'], missing: ['gone.txt'], added: ['a-new.txt', 'z-new.txt']});
  assert.deepEqual(compareFiles({}, {}), {modified: [], missing: [], added: []});
});

test('collect summarizes per-package results', () => {
  const item = (name, version = '1.0.0') => ({name, version, path: `lib/${name}`});
  const many = Array.from({length: 60}, (_, index) => `file${index}`);
  const result = collect([
    {status: 'verified', item: item('ok')},
    {status: 'bundled', item: item('inner')},
    {
      status: 'failed', item: item('zeta'), reason: 'differs', modified: many, missing: [], added: ['x'],
    },
    {status: 'unverifiable', item: item('alpha'), reason: 'no reference'},
    {status: 'error', item: item('mid'), reason: 'HTTP 500'},
  ]);
  assert.equal(result.passed, false);
  assert.deepEqual(result.summary, {
    total: 5, verified: 1, bundled: 1, patched: 0, built: 0, failed: 1, unverifiable: 1, error: 1,
  });
  assert.deepEqual(Object.keys(result.summary), ['total', ...STATUSES]);
  assert.deepEqual(result.findings.map(finding => finding.package), ['alpha@1.0.0', 'mid@1.0.0', 'zeta@1.0.0']);
  const zeta = result.findings[2];
  assert.equal(zeta.modified.length, 50);
  assert.equal('missing' in zeta, false);
  assert.deepEqual(zeta.added, ['x']);
  assert.deepEqual(result.issues, []);

  assert.equal(collect([{status: 'verified', item: item('a')}]).passed, true);
  assert.equal(collect([], [{severity: 'warn', message: 'w'}]).passed, true);
  assert.equal(collect([], [{severity: 'fail', message: 'f'}]).passed, false);
  assert.equal(collect([{status: 'unverifiable', item: item('a')}]).passed, false);
  assert.equal(collect([{status: 'error', item: item('a')}]).passed, false);
  const same = collect([{status: 'failed', item: item('a')}, {status: 'failed', item: item('a', '2.0.0')}]);
  assert.deepEqual(same.findings.map(finding => finding.package), ['a@1.0.0', 'a@2.0.0'], 'stable for equal paths');
});

test('parseCsv reads a wheel RECORD', () => {
  assert.deepEqual(parseCsv([
    'pkg/__init__.py,sha256=abc,123',
    '"pkg/with,comma.py",sha256=def,4',
    '"pkg/""quoted"".py",,',
    'pkg-1.0.dist-info/RECORD,,',
    '',
    'last,row',
  ].join('\r\n')), [
    ['pkg/__init__.py', 'sha256=abc', '123'],
    ['pkg/with,comma.py', 'sha256=def', '4'],
    ['pkg/"quoted".py', '', ''],
    ['pkg-1.0.dist-info/RECORD', '', ''],
    ['last', 'row'],
  ]);
  assert.deepEqual(parseCsv('a,b\n'), [['a', 'b']]);
  assert.deepEqual(parseCsv('a\rb\n\n'), [['a'], ['b']]);
  assert.deepEqual(parseCsv('""\n'), [['']], 'an empty quoted field is a row');
  assert.deepEqual(parseCsv('x"y,"multi\nline"'), [['x"y', 'multi\nline']]);
  assert.deepEqual(parseCsv(','), [['', '']]);
  assert.deepEqual(parseCsv(''), []);
});

test('isInside', () => {
  assert.equal(isInside('/srv/app', '/srv/app'), true);
  assert.equal(isInside('/srv/app', '/srv/app/lib/x.js'), true);
  assert.equal(isInside('/srv/app', '/srv/application'), false);
  assert.equal(isInside('/srv/app', '/srv/app/../etc'), false);
  assert.equal(isInside('/srv/app', '/etc/passwd'), false);
  assert.equal(isInside('/srv/app', '/srv/app/..data'), true, 'a name starting with dots stays inside');
  assert.equal(isInside('/srv/app', '/srv'), false);
});

test('NoLockfileError', () => {
  const error = new NoLockfileError('none');
  assert.equal(error.name, 'NoLockfileError');
  assert.equal(error.message, 'none');
  assert.ok(error instanceof Error);
});

// ─── index ──────────────────────────────────────────────────────────────

test('the plugin index and detectInstalls', t => {
  assert.deepEqual(Object.keys(ecosystems.INSTALLED), ['npm', 'pypi', 'rubygems', 'hex', 'composer', 'maven', 'nuget']);
  assert.deepEqual(Object.keys(ecosystems.COMPILED), ['go', 'cargo']);
  for (const name of [...Object.keys(ecosystems.INSTALLED), ...Object.keys(ecosystems.COMPILED)]) {
    assert.equal(ecosystems[name].name, name);
    assert.ok(Array.isArray(ecosystems[name].lockfiles));
  }

  assert.equal(ecosystems.ReferenceStore, ReferenceStore);
  assert.equal(ecosystems.NoLockfileError, NoLockfileError);
  assert.equal(ecosystems.compareFiles, compareFiles);
  assert.equal(ecosystems.collect, collect);
  assert.equal(ecosystems.parseCsv, parseCsv);

  const empty = tempDir(t);
  assert.deepEqual(ecosystems.detectInstalls(empty), []);
  const root = tempDir(t);
  writeFiles(root, {'node_modules/a/package.json': '{}'});
  assert.deepEqual(ecosystems.detectInstalls(root), [{ecosystem: 'npm', dir: path.join(root, 'node_modules'), installRoot: path.join(root, 'node_modules')}]);
  assert.deepEqual(ecosystems.detectInstalls(root, ['pypi']), []);
  assert.throws(() => ecosystems.detectInstalls(root, ['npm', 'cpan']), /Unknown package ecosystem: cpan/);
});

// ─── npm ────────────────────────────────────────────────────────────────

function integrityOf(buffer) {
  return `sha512-${crypto.createHash('sha512').update(buffer).digest('base64')}`;
}

/**
 * A registry package: tarball, metadata route and files to install.
 */
function makePackage(t, name, version, files) {
  const tarball = makeTarGz(t, Object.fromEntries(Object.entries(files).map(([file, content]) => [`package/${file}`, content])));
  return {
    name, version, files, tarball, integrity: integrityOf(tarball),
  };
}

async function startRegistry(t, packages) {
  const routes = {};
  for (const item of packages) {
    routes[`/registry/${item.name}/-/${item.name}-${item.version}.tgz`] = {body: item.tarball};
    routes[`/registry/${item.name}/${item.version}`] = {body: JSON.stringify({name: item.name, version: item.version, dist: {integrity: item.integrity}})};
  }

  const server = await startServer(t, routes);
  return {server, registryUrl: `${server.url}/registry`};
}

test('npm plugin: detect, scan, readLock and compare', async t => {
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'alpha\n'});
  const patched = makePackage(t, 'patched', '1.0.0', {'package.json': JSON.stringify({name: 'patched', version: '1.0.0'}), 'index.js': 'original\n'});
  const {registryUrl} = await startRegistry(t, [alpha, patched]);

  const root = tempDir(t);
  assert.deepEqual(npm.detect(root), []);
  writeFiles(path.join(root, 'node_modules', 'alpha'), alpha.files);
  writeFiles(path.join(root, 'node_modules', 'patched'), {...patched.files, 'index.js': 'patched\n'});
  writeFiles(root, {
    'package.json': JSON.stringify({name: 'app', pnpm: {patchedDependencies: {'patched@1.0.0': 'patches/patched.patch'}}}),
    'patches/patched.patch': 'diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-original\n+patched\n',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {name: 'app'},
        'node_modules/alpha': {version: '1.0.0', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz', integrity: alpha.integrity},
        'node_modules/patched': {version: '1.0.0', resolved: 'https://registry.npmjs.org/patched/-/patched-1.0.0.tgz', integrity: patched.integrity},
      },
    }),
  });

  const modules = path.join(root, 'node_modules');
  assert.deepEqual(npm.detect(root), [modules]);
  assert.equal(npm.installRoot(modules), modules);
  assert.equal(npm.name, 'npm');
  assert.deepEqual(npm.lockfiles, ['pnpm-lock.yaml', 'npm-shrinkwrap.json', 'package-lock.json']);

  const scan = await npm.scan(modules);
  const byName = Object.fromEntries(scan.packages.map(item => [item.name, item]));
  assert.ok(byName.patched.files, 'patched packages carry per-file hashes');
  assert.equal(byName.alpha.files, undefined, 'other packages carry only a digest');
  assert.deepEqual(scan.links, []);

  const lock = npm.readLock(root);
  assert.equal(lock.format, 'npm');
  assert.deepEqual(lock.policy.patched['patched@1.0.0'].files, ['index.js']);

  const release = new ReleaseVerification({registryUrl, retryDelay: 1, maxRetries: 0});
  const clean = await npm.compare({scan, lock, release});
  assert.equal(clean.passed, true);
  assert.equal(clean.summary.verified, 1);
  assert.equal(clean.summary.patched, 1);
  assert.deepEqual(clean.issues, []);

  // Without a lockfile at the public commit nothing is pinned.
  const unlocked = await npm.compare({scan, lock: null, release});
  assert.equal(unlocked.passed, false);
  assert.deepEqual(unlocked.findings.map(finding => finding.reason), ['installed package is not in the lockfile or any bundle', 'installed package is not in the lockfile or any bundle']);

  // A patched file that differs from the patch.
  writeFiles(path.join(modules, 'patched'), {'index.js': 'tampered\n'});
  const tampered = await npm.compare({scan: await npm.scan(modules), lock, release});
  assert.deepEqual(tampered.findings.map(finding => [finding.package, finding.status]), [['patched@1.0.0', 'failed']]);

  assert.throws(() => npm.readLock(tempDir(t)), NoLockfileError);
});

/**
 * A pnpm install as pnpm 10 lays it out for {"is-number": "7.0.0", "odd":
 * "npm:is-odd@3.0.1"} (is-odd depends on is-number 6), with small stand-in
 * packages served by a local registry.
 */
async function pnpmInstall(t) {
  const manifest = (name, version) => ({'package.json': JSON.stringify({name, version}), 'index.js': `${name} ${version}\n`});
  const packages = [['is-number', '6.0.0'], ['is-number', '7.0.0'], ['is-odd', '3.0.1']].map(([name, version]) => makePackage(t, name, version, manifest(name, version)));
  const [number6, number7, odd] = packages;
  const {registryUrl} = await startRegistry(t, packages);
  const root = tempDir(t);
  writeFiles(root, {
    'package.json': JSON.stringify({name: 'app', dependencies: {'is-number': '7.0.0', odd: 'npm:is-odd@3.0.1'}}),
    'pnpm-lock.yaml': [
      'lockfileVersion: \'9.0\'',
      '',
      'importers:',
      '',
      '  .:',
      '    dependencies:',
      '      is-number:',
      '        specifier: 7.0.0',
      '        version: 7.0.0',
      '      odd:',
      '        specifier: npm:is-odd@3.0.1',
      '        version: is-odd@3.0.1',
      '',
      'packages:',
      '',
      ...packages.flatMap(item => [`  ${item.name}@${item.version}:`, `    resolution: {integrity: ${item.integrity}}`, '']),
      'snapshots:',
      '',
      '  is-number@6.0.0: {}',
      '',
      '  is-number@7.0.0: {}',
      '',
      '  is-odd@3.0.1:',
      '    dependencies:',
      '      is-number: 6.0.0',
      '',
    ].join('\n'),
  });
  const modules = path.join(root, 'node_modules');
  for (const item of [number6, number7, odd]) {
    writeFiles(path.join(modules, '.pnpm', `${item.name}@${item.version}`, 'node_modules', item.name), item.files);
  }

  fs.symlinkSync('.pnpm/is-number@7.0.0/node_modules/is-number', path.join(modules, 'is-number'));
  fs.symlinkSync('.pnpm/is-odd@3.0.1/node_modules/is-odd', path.join(modules, 'odd'));
  fs.symlinkSync('../../is-number@6.0.0/node_modules/is-number', path.join(modules, '.pnpm/is-odd@3.0.1/node_modules/is-number'));
  const release = new ReleaseVerification({registryUrl, retryDelay: 1, maxRetries: 0});
  const check = async () => npm.compare({scan: await npm.scan(modules), lock: npm.readLock(root), release});
  // Point a link somewhere else, as a relative link like pnpm's.
  const relink = (link, target) => {
    const file = path.join(modules, link);
    fs.rmSync(file, {force: true});
    fs.mkdirSync(path.dirname(file), {recursive: true});
    fs.symlinkSync(path.relative(path.dirname(file), path.join(modules, target)), file);
  };

  return {
    root, modules, check, relink,
  };
}

test('npm plugin: each pnpm link must point to the package the lockfile resolves its name to', async t => {
  const {modules, check, relink} = await pnpmInstall(t);
  const scan = await npm.scan(modules);
  assert.deepEqual(scan.links, []);
  assert.deepEqual(scan.packageLinks, [
    {path: '.pnpm/is-odd@3.0.1/node_modules/is-number', target: '.pnpm/is-number@6.0.0/node_modules/is-number'},
    {path: 'is-number', target: '.pnpm/is-number@7.0.0/node_modules/is-number'},
    {path: 'odd', target: '.pnpm/is-odd@3.0.1/node_modules/is-odd'},
  ]);
  const clean = await check();
  assert.equal(clean.passed, true, JSON.stringify(clean.issues));
  assert.equal(clean.summary.verified, 3);

  // Every package is still the verified one; only which name loads which changes.
  const retargeted = async (link, target) => {
    relink(link, target);
    const result = await check();
    assert.equal(result.passed, false, link);
    return result.issues.find(issue => /other than the one the lockfile names/.test(issue.message)).items;
  };

  // The project's own dependency, to another version of the same package.
  assert.deepEqual(await retargeted('is-number', '.pnpm/is-number@6.0.0/node_modules/is-number'), ['is-number: points to is-number@6.0.0 (.pnpm/is-number@6.0.0/node_modules/is-number), where the lockfile has is-number@7.0.0']);
  relink('is-number', '.pnpm/is-number@7.0.0/node_modules/is-number');
  // An npm: alias, to a package other than the one it names.
  assert.deepEqual(await retargeted('odd', '.pnpm/is-number@7.0.0/node_modules/is-number'), ['odd: points to is-number@7.0.0 (.pnpm/is-number@7.0.0/node_modules/is-number), where the lockfile has is-odd@3.0.1']);
  relink('odd', '.pnpm/is-odd@3.0.1/node_modules/is-odd');
  // A dependency of a package in the store: is-odd requires is-number 6.
  assert.deepEqual(await retargeted('.pnpm/is-odd@3.0.1/node_modules/is-number', '.pnpm/is-number@7.0.0/node_modules/is-number'), ['.pnpm/is-odd@3.0.1/node_modules/is-number: points to is-number@7.0.0 (.pnpm/is-number@7.0.0/node_modules/is-number), where the lockfile has is-number@6.0.0']);
  relink('.pnpm/is-odd@3.0.1/node_modules/is-number', '.pnpm/is-number@6.0.0/node_modules/is-number');
  assert.equal((await check()).passed, true);

  // A hoisted link may point to any version the lockfile has for the name.
  relink('.pnpm/node_modules/is-number', '.pnpm/is-number@6.0.0/node_modules/is-number');
  assert.equal((await check()).passed, true);
  assert.deepEqual(await retargeted('.pnpm/node_modules/is-number', '.pnpm/is-odd@3.0.1/node_modules/is-odd'), ['.pnpm/node_modules/is-number: points to is-odd@3.0.1 (.pnpm/is-odd@3.0.1/node_modules/is-odd), where the lockfile has is-number@7.0.0 or is-number@6.0.0']);
  fs.rmSync(path.join(modules, '.pnpm/node_modules/is-number'));
  // A name the lockfile never declares only to a package of that name.
  assert.deepEqual(await retargeted('@scope/lodash', '.pnpm/is-number@7.0.0/node_modules/is-number'), ['@scope/lodash: points to is-number@7.0.0 (.pnpm/is-number@7.0.0/node_modules/is-number), where the lockfile has @scope/lodash']);
});

test('npm plugin: link checks without a pnpm lockfile, and scans that do not report link targets', async t => {
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'alpha\n'});
  const {registryUrl} = await startRegistry(t, [alpha]);
  const release = new ReleaseVerification({registryUrl, retryDelay: 1, maxRetries: 0});
  const root = tempDir(t);
  const modules = path.join(root, 'node_modules');
  writeFiles(path.join(modules, 'alpha'), alpha.files);
  const lockFile = aliases => JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {name: 'app'},
      'node_modules/alpha': {version: '1.0.0', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz', integrity: alpha.integrity},
      ...aliases,
    },
  });
  fs.writeFileSync(path.join(root, 'package-lock.json'), lockFile({}));
  fs.symlinkSync('alpha', path.join(modules, 'beta'));
  const scan = await npm.scan(modules);
  assert.deepEqual(scan.packageLinks, [{path: 'beta', target: 'alpha'}]);
  const unaliased = await npm.compare({scan, lock: npm.readLock(root), release});
  assert.equal(unaliased.passed, false);
  assert.deepEqual(unaliased.issues.map(issue => issue.items), [['beta: points to alpha@1.0.0 (alpha), where the lockfile has beta']]);
  // Nor without any lockfile.
  assert.deepEqual((await npm.compare({scan, lock: null, release})).issues.map(issue => issue.items), [['beta: points to alpha@1.0.0 (alpha), where the lockfile has beta']]);

  // A package-lock.json alias (beta installed as npm:alpha@1.0.0).
  fs.writeFileSync(path.join(root, 'package-lock.json'), lockFile({'node_modules/beta': {name: 'alpha', version: '1.0.0', integrity: alpha.integrity}}));
  const aliased = await npm.compare({scan, lock: npm.readLock(root), release});
  assert.deepEqual(aliased.issues, []);

  // A link to something that is not a scanned package (forged evidence).
  const forged = await npm.compare({scan: {...scan, packageLinks: [{path: 'beta', target: 'gamma'}]}, lock: npm.readLock(root), release});
  assert.deepEqual(forged.issues.map(issue => issue.items), [['beta: points to gamma, which is not a scanned package']]);
  // A scan without link targets cannot show where its links point.
  const {packageLinks, ...older} = scan;
  const result = await npm.compare({scan: older, lock: npm.readLock(root), release});
  assert.equal(result.passed, false);
  assert.match(result.issues[0].message, /does not say where links in node_modules point/);
});

test('parseLockfile: what each pnpm link may point to, in lockfile v6 and v9', () => {
  const v6 = [
    'lockfileVersion: \'6.0\'',
    'dependencies:',
    '  odd:',
    '    specifier: npm:is-odd@3.0.1',
    '    version: /is-odd@3.0.1',
    '  react-dom:',
    '    specifier: 18.2.0',
    '    version: 18.2.0(react@18.2.0)',
    'devDependencies:',
    '  local:',
    '    specifier: link:../local',
    '    version: link:../local',
    'packages:',
    '  /is-odd@3.0.1:',
    '    resolution: {integrity: sha512-AA==}',
    '    dependencies:',
    '      is-number: 6.0.0',
    '  /react-dom@18.2.0(react@18.2.0):',
    '    resolution: {integrity: sha512-AA==}',
    '    dependencies:',
    '      react: 18.2.0',
    '      scheduler: 0.23.0',
    '    optionalDependencies:',
    '      from-git: github.com/o/r/abc',
    '      from-url: https://codeload.github.com/o/r/tar.gz/abc',
    '      aliased-url: tarred@https://example.com/t.tgz',
    '  /react-dom@18.2.0(react@18.3.0):',
    '    resolution: {integrity: sha512-AA==}',
    '    dependencies:',
    '      react: 18.3.0',
    '      scheduler: 0.23.0',
  ].join('\n');
  const {links} = ReleaseVerification.parseLockfile(v6, 'pnpm');
  assert.deepEqual(links.importer, {
    odd: [{name: 'is-odd', version: '3.0.1'}],
    'react-dom': [{name: 'react-dom', version: '18.2.0'}],
  });
  // Peer variants of one package are merged.
  assert.deepEqual(links.owners['react-dom@18.2.0'], {
    react: [{name: 'react', version: '18.2.0'}, {name: 'react', version: '18.3.0'}],
    scheduler: [{name: 'scheduler', version: '0.23.0'}],
    'from-git': [{name: 'from-git', version: null}],
    'from-url': [{name: 'from-url', version: null}],
    'aliased-url': [{name: 'tarred', version: null}],
  });
  assert.deepEqual(links.owners['is-odd@3.0.1'], {'is-number': [{name: 'is-number', version: '6.0.0'}]});
  assert.equal(Object.hasOwn(links.declared, 'local'), false, 'a workspace link points outside node_modules');

  // Workspace projects other than the root declare names too.
  const v9 = 'lockfileVersion: \'9.0\'\nimporters:\n  .: {}\n  web:\n    dependencies:\n      __proto__:\n        specifier: 1.0.0\n        version: 1.0.0\n';
  const workspace = ReleaseVerification.parseLockfile(v9, 'pnpm').links;
  assert.deepEqual(workspace.importer, {});
  assert.deepEqual(Object.getOwnPropertyDescriptor(workspace.declared, '__proto__').value, [{name: '__proto__', version: '1.0.0'}]);
  assert.deepEqual(Object.getPrototypeOf(workspace.declared), Object.prototype);

  // Package-lock.json: aliases by path, top-level ones for the project.
  const npmLinks = ReleaseVerification.parseLockfile(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {name: 'app'},
      'node_modules/odd': {name: 'is-odd', version: '3.0.1'},
      'node_modules/odd/node_modules/is-number': {version: '6.0.0'},
      'node_modules/unversioned': {resolved: 'file:../unversioned'},
    },
  }), 'npm').links;
  assert.deepEqual(npmLinks.importer, {odd: [{name: 'is-odd', version: '3.0.1'}], unversioned: [{name: 'unversioned', version: null}]});
  assert.deepEqual(npmLinks.declared['is-number'], [{name: 'is-number', version: '6.0.0'}]);
});

test('npm plugin: npm-shrinkwrap.json, and a lockfile named by the configuration', t => {
  const lockOf = (name, version) => JSON.stringify({
    lockfileVersion: 3,
    packages: {'': {name: 'app'}, [`node_modules/${name}`]: {version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: 'sha512-AAAA'}},
  });
  const root = tempDir(t);
  writeFiles(root, {
    'npm-shrinkwrap.json': lockOf('shrinkwrapped', '1.0.0'),
    'package-lock.json': lockOf('locked', '2.0.0'),
    'web/package.json': JSON.stringify({name: 'web', pnpm: {patchedDependencies: {'x@1.0.0': 'patches/x.patch'}}}),
    'web/patches/x.patch': 'diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-a\n+b\n',
    'web/package-lock.json': lockOf('frontend', '3.0.0'),
  });
  const names = lock => lock.packages.map(item => `${item.name}@${item.version}`);
  // Like npm, npm-shrinkwrap.json is read before package-lock.json.
  const shrinkwrap = npm.readLock(root);
  assert.deepEqual([shrinkwrap.file, shrinkwrap.format, names(shrinkwrap)], ['npm-shrinkwrap.json', 'npm', ['shrinkwrapped@1.0.0']]);
  // A named lockfile (lockfiles.npm); its package.json holds the policy.
  const web = npm.readLock(root, {lockfile: 'web/package-lock.json'});
  assert.deepEqual([web.file, names(web)], ['web/package-lock.json', ['frontend@3.0.0']]);
  assert.deepEqual(Object.keys(web.policy.patched), ['x@1.0.0']);
  assert.deepEqual(names(npm.readLock(root, {lockfile: 'package-lock.json'})), ['locked@2.0.0']);
  assert.throws(() => npm.readLock(root, {lockfile: 'api/package-lock.json'}), error => error.name === 'NoLockfileError' && error.message === 'No lockfile at api/package-lock.json');
  assert.throws(() => npm.readLock(tempDir(t)), /No pnpm-lock\.yaml, npm-shrinkwrap\.json, package-lock\.json found/);
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'lockfileVersion: \'9.0\'\npackages: {}\n');
  assert.equal(npm.readLock(root).format, 'pnpm');
});

test('npm plugin reports links, bytecode caches and stray files', async t => {
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'alpha\n'});
  const {registryUrl} = await startRegistry(t, [alpha]);
  const root = tempDir(t);
  const outside = tempDir(t);
  writeFiles(path.join(root, 'node_modules', 'alpha'), {
    ...alpha.files,
    '__pycache__/gyp.cpython-311.pyc': 'bytecode',
    '__pycache__/hidden.js': 'not bytecode',
  });
  writeFiles(path.join(root, 'node_modules'), {'stray.js': 'stray'});
  fs.symlinkSync(outside, path.join(root, 'node_modules', 'evil'));

  // No lockfile in this project: the scan still works (root given explicitly).
  const scan = await npm.scan(path.join(root, 'node_modules'), {root});
  const release = new ReleaseVerification({registryUrl, retryDelay: 1, maxRetries: 0});
  const lock = {
    packages: [{
      name: 'alpha', version: '1.0.0', integrity: alpha.integrity, source: 'registry',
    }], policy: {patched: {}, built: []},
  };
  const result = await npm.compare({scan, lock, release});
  assert.equal(result.summary.verified, 1);
  assert.equal(result.passed, false, 'fail issues fail the comparison');
  assert.deepEqual(result.issues.map(issue => [issue.severity, issue.message.split(' ').slice(0, 3).join(' '), issue.items]), [
    ['fail', 'Links in node_modules', ['evil: points outside node_modules']],
    ['fail', 'Files in Python', ['alpha/__pycache__/hidden.js']],
    ['warn', 'Python bytecode caches', ['alpha/__pycache__ (2)']],
    ['warn', 'Files in node_modules', ['stray.js']],
  ]);
});

// ─── go ─────────────────────────────────────────────────────────────────

const H1 = 'h1:bAce8d8lOBjdgQl2rpWCHocW68jduckBTpJSiLND5Dk=';

test('go readLock reads go.mod and go.sum', t => {
  const repo = tempDir(t);
  assert.throws(() => go.readLock(repo), {name: 'NoLockfileError', message: /No go\.mod found in the repository root/});
  assert.throws(() => go.readLock(repo, {dir: 'cmd/tool'}), /No go\.mod found in cmd\/tool/);

  writeFiles(repo, {
    'go.mod': 'module "example.com/quoted"\n\ngo 1.22\n',
    'go.sum': [
      `example.com/lib v1.0.0 ${H1}`,
      'example.com/lib v1.0.0/go.mod h1:ksJkiDVshjYqf/AixlfFHJPhJ4S5qtSJnXwv1r6wJT4=',
      '',
      '  example.com/other v2.0.0 h1:other=  ',
      'example.com/legacy v0.1.0 h2:unknown=',
      'example.com/short v0.1.0',
    ].join('\r\n'),
    'cmd/tool/go.mod': '// no module line\ngo 1.22\n',
  });
  const lock = go.readLock(repo);
  assert.equal(lock.format, 'go.sum');
  assert.equal(lock.module, 'example.com/quoted');
  assert.deepEqual([...lock.sums], [['example.com/lib v1.0.0', H1], ['example.com/other v2.0.0', 'h1:other=']]);

  const tool = go.readLock(repo, {dir: 'cmd/tool'});
  assert.equal(tool.module, null);
  assert.equal(tool.sums.size, 0, 'no go.sum');
});

test('go compareBuildInfo checks crafted build information', () => {
  const lock = {module: 'example.com/app', sums: new Map([['example.com/lib v1.0.0', H1], ['example.com/fork v1.1.0', 'h1:fork=']])};
  const info = {
    main: {path: 'example.com/app'},
    deps: [
      {path: 'example.com/lib', version: 'v1.0.0', sum: H1},
      {
        path: 'example.com/orig', version: 'v1.0.0', sum: 'h1:orig=', replace: {path: 'example.com/fork', version: 'v1.1.0', sum: 'h1:fork='},
      },
      {
        path: 'example.com/local', version: 'v0.0.0', sum: null, replace: {path: '/abs/local', version: null, sum: null},
      },
      {path: 'example.com/tampered', version: 'v1.0.0', sum: 'h1:x='},
    ],
    settings: {'vcs.revision': 'a'.repeat(40), '-trimpath': 'true'},
  };
  lock.sums.set('example.com/tampered v1.0.0', 'h1:pinned=');
  const result = go.compareBuildInfo({info, lock, commit: 'a'.repeat(40)});
  assert.equal(result.passed, false);
  assert.deepEqual(result.summary, {
    total: 4, verified: 2, bundled: 0, patched: 0, built: 0, failed: 1, unverifiable: 1, error: 0,
  });
  assert.deepEqual(result.findings.map(finding => [finding.path, finding.status, finding.reason]), [
    ['example.com/local', 'unverifiable', 'replaced by the local directory /abs/local'],
    ['example.com/tampered', 'failed', 'hash h1:x= differs from go.sum (h1:pinned=)'],
  ]);
  assert.deepEqual(result.issues, []);

  const other = go.compareBuildInfo({
    info: {main: {path: 'example.com/evil'}, deps: [], settings: {'vcs.revision': 'b'.repeat(40), 'vcs.modified': 'true'}}, lock, commit: 'c'.repeat(40), label: 'bin/app',
  });
  assert.deepEqual(other.issues.map(issue => [issue.severity, issue.message]), [
    ['fail', 'bin/app was built from module example.com/evil, not example.com/app'],
    ['fail', 'bin/app was built from commit bbbbbbbbbbbb, not the deployed cccccccccccc'],
    ['fail', 'bin/app was built from a modified working tree'],
    ['info', 'bin/app was built without -trimpath; it will not reproduce byte for byte on another machine'],
  ]);
  assert.equal(other.passed, false);

  // Nothing to compare the module or commit with.
  const bare = go.compareBuildInfo({info: {main: null, deps: []}, lock: {module: null, sums: new Map()}});
  assert.deepEqual(bare.issues.map(issue => issue.message), [
    'the binary records no commit (built with -buildvcs=false or outside a repository)',
    'the binary was built without -trimpath; it will not reproduce byte for byte on another machine',
  ]);
  assert.equal(bare.passed, true);
  assert.equal(go.compareBuildInfo({info: {main: {path: 'x'}, deps: [], settings: {'vcs.revision': 'a'}}, lock: {module: null, sums: new Map()}}).issues.length, 1);

  const old = go.compareBuildInfo({info: {unsupported: 'Go 1.17 or earlier (no inline build information)', deps: []}, lock});
  assert.deepEqual(old.issues, [{severity: 'warn', message: 'the binary was built with Go 1.17 or earlier (no inline build information)', items: []}]);
  assert.equal(old.summary.total, 0);
  assert.equal(old.passed, true);
});

test('go: a real binary against the go.sum it was built with', {skip: !hasGo && 'needs go, git and zip'}, t => {
  const project = goProject(t);
  const info = goBuildInfo(project.build('app', ['-trimpath']));
  const lock = go.readLock(path.join(project.root, 'repo'), {dir: 'app'});
  assert.equal(lock.module, 'example.com/app');

  const result = go.compareBuildInfo({info, lock, commit: project.commit});
  assert.deepEqual(result.summary, {
    total: 2, verified: 1, bundled: 0, patched: 0, built: 0, failed: 0, unverifiable: 1, error: 0,
  });
  assert.deepEqual(result.findings.map(finding => [finding.path, finding.reason]), [['example.com/dep', 'replaced by the local directory ../dep']]);
  assert.deepEqual(result.issues, []);

  // Another commit, and a go.sum that pins a different hash.
  const moved = go.compareBuildInfo({info, lock, commit: '0'.repeat(40)});
  assert.match(moved.issues[0].message, /not the deployed 0{12}/);
  const pinned = info.deps.find(dependency => dependency.path === 'example.com/lib').sum;
  fs.writeFileSync(path.join(project.app, 'go.sum'), fs.readFileSync(path.join(project.app, 'go.sum'), 'utf8').replace(pinned, 'h1:AAAA'));
  const tampered = go.compareBuildInfo({info, lock: go.readLock(project.app), commit: project.commit});
  assert.match(tampered.findings.find(finding => finding.path === 'example.com/lib').reason, /differs from go\.sum \(h1:AAAA\)/);

  fs.writeFileSync(path.join(project.app, 'go.sum'), '');
  const missing = go.compareBuildInfo({info, lock: go.readLock(project.app), commit: project.commit});
  assert.equal(missing.findings.find(finding => finding.path === 'example.com/lib').reason, 'example.com/lib v1.0.0 is not in go.sum');

  fs.writeFileSync(path.join(project.app, 'extra.go'), 'package main\n');
  const dirty = go.compareBuildInfo({info: goBuildInfo(project.build('dirty')), lock, commit: project.commit});
  assert.deepEqual(dirty.issues.map(issue => issue.severity), ['fail', 'info']);
});

// ─── cargo ──────────────────────────────────────────────────────────────

const CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index';
const CHECKSUM = 'c8e3592472072e6e22e0a54d5904d9febf8508f65fb8552499a1abc7d1078c3a';

const CARGO_LOCK = `# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "gitdep", "floating", "private", "nosum"]

[[package]]
name = "serde"
version = "1.0.210"
source = "${CRATES_IO}"
checksum = "${CHECKSUM}"

[[package]]
name = "sparse"
version = "0.1.0"
source = "sparse+https://index.crates.io/"
checksum = "${CHECKSUM}"

[[package]]
name = "gitdep"
version = "0.2.0"
source = "git+https://github.com/owner/gitdep?rev=main#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "floating"
version = "0.3.0"
source = "git+https://github.com/owner/floating?branch=main"

[[package]]
name = "private"
version = "1.0.0"
source = "sparse+https://registry.example.com/index/"
checksum = "${CHECKSUM}"

[[package]]
name = "nosum"
version = "1.0.0"
source = "${CRATES_IO}"
`;

test('cargo readLock and sourceKind', t => {
  const repo = tempDir(t);
  assert.throws(() => cargo.readLock(repo), {name: 'NoLockfileError', message: 'No Cargo.lock found'});
  writeFiles(repo, {'Cargo.lock': CARGO_LOCK, 'sub/Other.lock': 'version = 4\n'});
  const lock = cargo.readLock(repo);
  assert.equal(lock.format, 'cargo');
  assert.equal(lock.file, 'Cargo.lock');
  assert.deepEqual(lock.packages.get('app 0.1.0'), {
    name: 'app', version: '0.1.0', source: null, checksum: null,
  });
  assert.deepEqual(lock.packages.get('serde 1.0.210'), {
    name: 'serde', version: '1.0.210', source: CRATES_IO, checksum: CHECKSUM,
  });
  const other = cargo.readLock(repo, {lockfile: 'sub/Other.lock'});
  assert.equal(other.file, 'sub/Other.lock');
  assert.equal(other.packages.size, 0);

  assert.equal(cargo.sourceKind(null), 'local');
  assert.equal(cargo.sourceKind(CRATES_IO), 'crates.io');
  assert.equal(cargo.sourceKind('sparse+https://index.crates.io/'), 'crates.io');
  assert.equal(cargo.sourceKind('git+https://github.com/x/y#abc'), 'git');
  assert.equal(cargo.sourceKind('registry+https://example.com/index'), 'registry');
});

test('cargo compareAuditable checks each crate against Cargo.lock', t => {
  const repo = tempDir(t);
  writeFiles(repo, {'Cargo.lock': CARGO_LOCK});
  const lock = cargo.readLock(repo);
  const crate = (name, version, source, extra = {}) => ({
    name, version, source, kind: 'runtime', root: false, ...extra,
  });
  const result = cargo.compareAuditable({
    lock,
    packages: [
      crate('app', '0.1.0', 'local', {root: true}),
      crate('serde', '1.0.210', 'crates.io'),
      crate('sparse', '0.1.0', 'crates.io', {kind: 'build'}),
      crate('gitdep', '0.2.0', 'git'),
      crate('floating', '0.3.0', 'git'),
      crate('private', '1.0.0', 'registry'),
      crate('nosum', '1.0.0', 'crates.io'),
      crate('serde', '1.0.999', 'crates.io'),
      crate('private', '1.0.0', 'crates.io'),
    ],
  });
  assert.equal(result.passed, false);
  assert.deepEqual(result.summary, {
    total: 8, verified: 4, bundled: 0, patched: 0, built: 0, failed: 2, unverifiable: 2, error: 0,
  });
  assert.deepEqual(result.findings.map(finding => [finding.path, finding.status, finding.reason]), [
    ['floating@0.3.0', 'unverifiable', 'Cargo.lock pins no commit for this git source'],
    ['nosum@1.0.0', 'unverifiable', 'Cargo.lock pins no checksum'],
    ['private@1.0.0', 'failed', 'built from crates.io, Cargo.lock says registry'],
    ['serde@1.0.999', 'failed', 'not in Cargo.lock'],
  ]);
});

test('cargo: a real cargo-auditable binary against its Cargo.lock', {skip: !hasCargoAuditable && 'needs cargo-auditable'}, t => {
  const {dir, file, binary} = cargoProject(t);
  const lock = cargo.readLock(dir);
  const result = cargo.compareAuditable({packages: cargoAuditable(binary), lock});
  assert.equal(result.passed, true);
  assert.deepEqual(result.summary, {
    total: 2, verified: 2, bundled: 0, patched: 0, built: 0, failed: 0, unverifiable: 0, error: 0,
  });

  // The same binary claiming a crates.io crate the lockfile does not have.
  if (!which('objcopy')) {
    t.diagnostic('objcopy not found; skipping the rewritten section');
    return;
  }

  const section = path.join(tempDir(t), 'dep.bin');
  fs.writeFileSync(section, zlib.deflateSync(JSON.stringify({
    packages: [{
      name: 'app', version: '0.1.0', source: 'local', root: true,
    }, {name: 'helper', version: '0.2.0', source: 'crates.io'}],
  })));
  const rewritten = path.join(tempDir(t), 'app');
  execFileSync('objcopy', ['--update-section', `.dep-v0=${section}`, file, rewritten]);
  const swapped = cargo.compareAuditable({packages: cargoAuditable(fs.readFileSync(rewritten)), lock});
  assert.deepEqual(swapped.findings.map(finding => finding.reason), ['built from crates.io, Cargo.lock says local']);
});

test('every ecosystem fails a scan with files it could not read, and any issue severity but warn and info', async t => {
  const store = new ReferenceStore({cacheDir: tempDir(t)});
  const errors = [{path: 'lib/shadow.rb', error: 'ENOTFILE'}];
  const scan = {
    packages: [], unaccounted: [], links: [], packageLinks: [], caches: [], errors, meta: {
      generated: {}, other: {}, bin: {}, plugins: {},
    },
  };
  const locks = {
    npm: {packages: [], policy: {patched: {}, built: []}},
    pypi: {packages: new Map()},
    rubygems: {gems: new Map(), checksums: new Map()},
    hex: {packages: new Map()},
    composer: {packages: new Map()},
    maven: {pinned: new Map()},
    nuget: {packages: new Map()},
  };
  for (const [name, plugin] of Object.entries(ecosystems.INSTALLED)) {
    const clean = await plugin.compare({
      scan: {...scan, errors: []}, lock: locks[name], store, release: new ReleaseVerification(),
    });
    assert.equal(clean.passed, true, name);
    const result = await plugin.compare({
      scan, lock: locks[name], store, release: new ReleaseVerification(),
    });
    assert.equal(result.passed, false, name);
    assert.deepEqual(result.issues.at(-1), {severity: 'fail', message: 'Files or directories the scan could not read (not compared with anything)', items: ['lib/shadow.rb: ENOTFILE']}, name);
  }

  const nuget = await ecosystems.nuget.compare({scan, lock: null, store});
  assert.equal(nuget.passed, false);
  assert.equal(collect([], [{severity: 'error', message: 'x', items: []}]).passed, false);
  assert.equal(collect([], [{severity: 'warn', message: 'x', items: []}, {severity: 'info', message: 'y', items: []}]).passed, true);
});

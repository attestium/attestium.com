'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {promisify} = require('node:util');
const crypto = require('node:crypto');
const {execFile, execFileSync} = require('node:child_process');
const hex = require('../lib/ecosystems/hex');
const {NoLockfileError, ReferenceStore} = require('../lib/ecosystems/common');
const {
  tempDir, writeFiles, startServer, makeTarGz, which,
} = require('./helpers');

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');

function metadataConfig(name, version) {
  return `{<<"name">>,<<"${name}">>}.\n{<<"version">>,<<"${version}">>}.\n{<<"build_tools">>,[<<"mix">>]}.\n`;
}

/**
 * A Hex package tarball (format version 3): an uncompressed tar holding
 * VERSION, CHECKSUM, metadata.config and contents.tar.gz.
 */
function hexTarball(t, {name, version, files, members = {}}) {
  const staging = tempDir(t, 'attestium-hex-');
  const metadata = metadataConfig(name, version);
  const contents = makeTarGz(t, files);
  const inner = sha256(Buffer.concat([Buffer.from('3'), Buffer.from(metadata), contents]));
  const outer = {
    VERSION: '3', CHECKSUM: inner.toUpperCase(), 'metadata.config': metadata, 'contents.tar.gz': contents, ...members,
  };
  for (const [member, content] of Object.entries(outer)) {
    if (content === null) {
      delete outer[member];
    }
  }

  writeFiles(staging, outer);
  const output = path.join(tempDir(t, 'attestium-hex-out-'), `${name}-${version}.tar`);
  execFileSync('tar', ['-cf', output, '-C', staging, ...Object.keys(outer)]);
  const tarball = fs.readFileSync(output);
  return {
    tarball, inner, outer: sha256(tarball), metadata,
  };
}

function lockLine(name, version, {inner, outer}, repo = 'hexpm') {
  return `  "${name}": {:hex, :${name}, "${version}", "${inner}", [:mix], [{:dep, "~> 1.0", [hex: :dep, repo: "hexpm", optional: false]}], "${repo}"${outer ? `, "${outer}"` : ''}},`;
}

/**
 * A temporary directory that may hold paths longer than PATH_MAX (removed
 * with find, which does not build full paths).
 */
function deepTempDir(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-deep-')));
  t.after(() => {
    execFileSync('find', [directory, '-delete']);
  });
  return directory;
}

/**
 * A file whose full path is longer than PATH_MAX, so it is listed but
 * cannot be opened.  Returns the directory holding it.
 */
function unreadableEntry(parent) {
  let directory = parent;
  while (directory.length < 3900) {
    directory = path.join(directory, 'd'.repeat(Math.min(200, 3950 - directory.length)));
  }

  fs.mkdirSync(directory, {recursive: true});
  execFileSync('touch', ['f'.repeat(250)], {cwd: directory});
  return directory;
}

test('detect finds deps/ next to mix.lock', t => {
  const root = tempDir(t);
  assert.deepEqual(hex.detect(root), []);
  writeFiles(root, {'mix.lock': '%{}\n', 'deps/jason/mix.exs': ''});
  assert.deepEqual(hex.detect(root), [path.join(root, 'deps')]);
  fs.rmSync(path.join(root, 'mix.lock'));
  assert.deepEqual(hex.detect(root), []);
  assert.equal(hex.installRoot('/srv/app/deps'), '/srv/app/deps');
  assert.equal(hex.name, 'hex');
  assert.deepEqual(hex.lockfiles, ['mix.lock']);
});

test('scan hashes each dependency, skipping build output, and reads its version', async t => {
  const deps = path.join(tempDir(t), 'deps');
  writeFiles(deps, {
    'jason/hex_metadata.config': metadataConfig('jason', '1.4.4'),
    'jason/lib/jason.ex': 'defmodule Jason do end\n',
    'jason/.hex': 'hex',
    'jason/_build/dev/x.beam': 'beam',
    'jason/ebin/jason.app': 'app',
    'local/lib/local.ex': 'defmodule Local do end\n',
    'odd/hex_metadata.config': '{<<"name">>,<<"odd">>}.\n',
    'README.md': 'not a package',
  });
  fs.symlinkSync('jason.ex', path.join(deps, 'jason', 'lib', 'link.ex'));

  const result = await hex.scan(deps);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.packages.map(item => [item.name, item.version]), [['jason', '1.4.4'], ['local', null], ['odd', null]]);
  const [jason] = result.packages;
  assert.equal(jason.path, 'jason');
  assert.deepEqual(Object.keys(jason.files).sort(), ['.hex', 'hex_metadata.config', 'lib/jason.ex', 'lib/link.ex']);
  assert.equal(jason.files['lib/jason.ex'], sha256('defmodule Jason do end\n'));
  assert.equal(jason.files['lib/link.ex'], 'symlink:jason.ex');
  assert.deepEqual(result.unaccounted, []);
});

test('scan reports a missing deps/ and unreadable files', async t => {
  const missing = await hex.scan(path.join(tempDir(t), 'deps'));
  assert.deepEqual(missing.packages, []);
  assert.deepEqual(missing.errors, [{path: '.', error: 'ENOENT'}]);

  const deps = path.join(deepTempDir(t), 'deps');
  writeFiles(deps, {'deep/mix.exs': ''});
  const holder = unreadableEntry(path.join(deps, 'deep'));
  const result = await hex.scan(deps);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].error, 'ENAMETOOLONG');
  assert.ok(result.errors[0].path.startsWith(`deep/${path.relative(path.join(deps, 'deep'), holder).split(path.sep).join('/')}/`));
});

test('parseMixLock reads Hex, git and path entries', () => {
  const inner = 'a'.repeat(64);
  const outer = 'b'.repeat(64);
  const text = [
    '%{',
    lockLine('jason', '1.4.4', {inner, outer}),
    '  "old": {:hex, :old, "0.1.0", "' + inner + '", [:mix], [], "hexpm"},',
    '  "renamed": {:hex, :"real_name", "2.0.0-rc.1", "' + inner + '", [:rebar3], [], "private", "' + outer + '"},',
    '  "phoenix": {:git, "https://github.com/phoenixframework/phoenix.git", "0123456789abcdef0123456789abcdef01234567", []},',
    '  "mine": {:path, "../mine", []},',
    '}',
  ].join('\n');
  const packages = hex.parseMixLock(text);
  assert.deepEqual(packages.get('jason'), {
    name: 'jason', package: 'jason', version: '1.4.4', innerChecksum: inner, repo: 'hexpm', outerChecksum: outer,
  });
  assert.equal(packages.get('old').outerChecksum, null);
  assert.equal(packages.get('renamed').package, 'real_name');
  assert.equal(packages.get('renamed').repo, 'private');
  assert.deepEqual(packages.get('phoenix'), {name: 'phoenix', source: 'git'});
  assert.deepEqual(packages.get('mine'), {name: 'mine', source: 'path'});
});

test('readLock reads mix.lock, or a named lockfile, and fails without one', t => {
  const repo = tempDir(t);
  assert.throws(() => hex.readLock(repo), NoLockfileError);
  writeFiles(repo, {'mix.lock': `%{\n${lockLine('jason', '1.4.4', {inner: 'a'.repeat(64), outer: 'b'.repeat(64)})}\n}\n`, 'apps/web/other.lock': '%{}\n'});
  const lock = hex.readLock(repo);
  assert.equal(lock.format, 'mix');
  assert.equal(lock.file, 'mix.lock');
  assert.equal(lock.packages.get('jason').version, '1.4.4');
  assert.equal(hex.readLock(repo, {lockfile: 'apps/web/other.lock'}).packages.size, 0);
  assert.throws(() => hex.readLock(repo, {lockfile: 'nope.lock'}), /No mix\.lock found/);
});

test('readHexTarball lists the contents plus hex_metadata.config', t => {
  const {tarball, metadata} = hexTarball(t, {name: 'greet', version: '0.1.0', files: {'lib/greet.ex': 'x', 'mix.exs': 'y'}});
  assert.deepEqual(hex.readHexTarball(tarball), {'lib/greet.ex': sha256('x'), 'mix.exs': sha256('y'), 'hex_metadata.config': sha256(metadata)});
  assert.throws(() => hex.readHexTarball(hexTarball(t, {
    name: 'bad', version: '1.0.0', files: {'a.ex': ''}, members: {'contents.tar.gz': null},
  }).tarball), /Not a Hex package tarball/);
  assert.throws(() => hex.readHexTarball(hexTarball(t, {
    name: 'bad', version: '1.0.0', files: {'a.ex': ''}, members: {'metadata.config': null},
  }).tarball), /Not a Hex package tarball/);
});

test('compare checks each dependency against the tarball mix.lock pins', async t => {
  const files = {'lib/greet.ex': 'defmodule Greet do end\n', 'mix.exs': 'defmodule Greet.MixProject do end\n'};
  const good = hexTarball(t, {name: 'greet', version: '0.1.0', files});
  const other = hexTarball(t, {name: 'other', version: '1.0.0', files: {'lib/other.ex': 'x'}});
  const broken = hexTarball(t, {
    name: 'broken', version: '1.0.0', files: {'a.ex': ''}, members: {'metadata.config': null},
  });
  const server = await startServer(t, {
    '/tarballs/greet-0.1.0.tar': {body: good.tarball},
    '/tarballs/other-1.0.0.tar': {body: other.tarball},
    '/tarballs/broken-1.0.0.tar': {body: broken.tarball},
  });

  const deps = path.join(tempDir(t), 'deps');
  const installed = {
    ...files, 'hex_metadata.config': good.metadata, '.hex': 'x', '.fetch': '',
  };
  writeFiles(deps, Object.fromEntries(Object.entries(installed).flatMap(([file, content]) => [
    [`greet/${file}`, content],
    [`changed/${file}`, file === 'lib/greet.ex' ? 'defmodule Evil do end\n' : content],
  ])));
  writeFiles(deps, {
    'changed/extra.ex': '', 'unlocked/mix.exs': '', 'gitdep/mix.exs': '', 'private/mix.exs': '', 'old/mix.exs': '', 'tampered/mix.exs': '', 'gone/mix.exs': '', 'broken/mix.exs': '',
  });
  fs.rmSync(path.join(deps, 'changed', 'mix.exs'));

  const inner = 'c'.repeat(64);
  const lock = {
    format: 'mix',
    packages: hex.parseMixLock([
      '%{',
      lockLine('greet', '0.1.0', {inner: good.inner, outer: good.outer}),
      lockLine('changed', '0.1.0', {inner: good.inner, outer: good.outer}).replace(':changed', ':greet'),
      '  "gitdep": {:git, "https://example.com/gitdep.git", "' + 'd'.repeat(40) + '", []},',
      lockLine('private', '1.0.0', {inner, outer: 'e'.repeat(64)}, 'acme'),
      lockLine('old', '1.0.0', {inner, outer: null}),
      lockLine('tampered', '1.0.0', {inner, outer: 'f'.repeat(64)}).replace(':tampered', ':other'),
      lockLine('gone', '1.0.0', {inner, outer: 'f'.repeat(64)}),
      lockLine('broken', '1.0.0', {inner: broken.inner, outer: broken.outer}),
      '}',
    ].join('\n')),
  };
  const store = new ReferenceStore({urls: {hex: server.url}, httpOptions: {maxRetries: 0}});
  const scan = await hex.scan(deps);
  const result = await hex.compare({scan, lock, store});

  const byPackage = Object.fromEntries(result.findings.map(finding => [finding.path, finding]));
  assert.equal(result.passed, false);
  assert.deepEqual(result.summary, {
    total: 9, verified: 1, bundled: 0, patched: 0, built: 0, failed: 3, unverifiable: 3, error: 2,
  });
  assert.equal(byPackage.greet, undefined);
  assert.deepEqual(byPackage.changed, {
    status: 'failed', package: 'changed@0.1.0', path: 'changed', reason: 'files differ from the Hex tarball', modified: ['lib/greet.ex'], missing: ['mix.exs'], added: ['extra.ex'],
  });
  assert.equal(byPackage.unlocked.reason, 'dependency is not in mix.lock');
  assert.match(byPackage.gitdep.reason, /fetched from git, not Hex/);
  assert.match(byPackage.private.reason, /"acme", not hexpm/);
  assert.match(byPackage.old.reason, /only the inner checksum/);
  assert.equal(byPackage.tampered.status, 'failed');
  assert.match(byPackage.tampered.reason, /other-1\.0\.0\.tar does not match mix\.lock/);
  assert.equal(byPackage.gone.status, 'error');
  assert.match(byPackage.gone.reason, /404/);
  assert.equal(byPackage.broken.status, 'error');
  assert.equal(byPackage.broken.reason, 'Not a Hex package tarball');
  assert.equal(result.issues[0].severity, 'info');
  // Both packages pinned to the same tarball share one download.
  assert.equal(server.requests.filter(request => request.url === '/tarballs/greet-0.1.0.tar').length, 1);
});

test('compare without mix.lock fails every dependency', async () => {
  const scan = {
    packages: [{
      name: 'jason', version: '1.4.4', path: 'jason', files: {},
    }],
  };
  const result = await hex.compare({scan, lock: null, store: new ReferenceStore()});
  assert.equal(result.findings[0].reason, 'no mix.lock pins this dependency');
  assert.equal(result.passed, false);
});

test('a Mix project fetched from a local Hex repository verifies', {skip: !(which('mix') && which('openssl')) && 'mix or openssl is not installed', timeout: 120_000}, async t => {
  const work = tempDir(t);
  const environment = {
    ...process.env, HEX_HOME: path.join(work, 'hex-home'), MIX_ENV: 'dev',
  };
  // Asynchronous, so the registry server in this process can answer.
  const run = (cwd, ...args) => promisify(execFile)('mix', args, {cwd, env: environment});
  writeFiles(work, {
    'greet/mix.exs': 'defmodule Greet.MixProject do\n  use Mix.Project\n  def project, do: [app: :greet, version: "0.1.0", description: "Greets", package: [licenses: ["MIT"], links: %{}]]\nend\n',
    'greet/lib/greet.ex': 'defmodule Greet do\n  def hello, do: :world\nend\n',
    'app/mix.exs': 'defmodule App.MixProject do\n  use Mix.Project\n  def project, do: [app: :app, version: "0.1.0", deps: [{:greet, "0.1.0"}]]\nend\n',
  });
  try {
    await run(path.join(work, 'greet'), 'hex.build');
  } catch (error) {
    t.skip(`Hex is not available: ${String(error.stderr).trim().split('\n').pop()}`);
    return;
  }

  execFileSync('openssl', ['genrsa', '-out', path.join(work, 'key.pem'), '2048'], {stdio: 'ignore'});
  const registry = path.join(work, 'public');
  writeFiles(registry, {'tarballs/greet-0.1.0.tar': fs.readFileSync(path.join(work, 'greet', 'greet-0.1.0.tar'))});
  await run(work, 'hex.registry', 'build', registry, '--name=hexpm', `--private-key=${path.join(work, 'key.pem')}`);

  const routes = {};
  const serve = directory => {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        serve(full);
      } else {
        routes[`/${path.relative(registry, full).split(path.sep).join('/')}`] = {body: fs.readFileSync(full)};
      }
    }
  };

  serve(registry);
  const server = await startServer(t, routes);
  const app = path.join(work, 'app');
  await run(app, 'hex.repo', 'set', 'hexpm', '--url', server.url, '--public-key', path.join(registry, 'public_key'));
  await run(app, 'deps.get');

  assert.deepEqual(hex.detect(app), [path.join(app, 'deps')]);
  const lock = hex.readLock(app);
  assert.equal(lock.packages.get('greet').outerChecksum, sha256(routes['/tarballs/greet-0.1.0.tar'].body));
  const scan = await hex.scan(path.join(app, 'deps'));
  assert.equal(scan.packages[0].version, '0.1.0');
  const store = new ReferenceStore({urls: {hex: server.url}});
  const result = await hex.compare({scan, lock, store});
  assert.equal(result.passed, true, JSON.stringify(result.findings));
  assert.equal(result.summary.verified, 1);

  fs.appendFileSync(path.join(app, 'deps', 'greet', 'lib', 'greet.ex'), '# changed\n');
  const changed = await hex.compare({scan: await hex.scan(path.join(app, 'deps')), lock, store});
  assert.deepEqual(changed.findings[0].modified, ['lib/greet.ex']);
});

test('a dependency replaced by a link is not left out of the check', async t => {
  const files = {'lib/greet.ex': 'defmodule Greet do end\n', 'mix.exs': 'defmodule Greet.MixProject do end\n'};
  const good = hexTarball(t, {name: 'greet', version: '0.1.0', files});
  const server = await startServer(t, {'/tarballs/greet-0.1.0.tar': {body: good.tarball}});
  const work = tempDir(t);
  const deps = path.join(work, 'deps');
  writeFiles(deps, Object.fromEntries(Object.entries({...files, 'hex_metadata.config': good.metadata}).map(([file, content]) => [`greet/${file}`, content])));
  const lock = {format: 'mix', packages: hex.parseMixLock(`%{\n${lockLine('greet', '0.1.0', {inner: good.inner, outer: good.outer})}\n}`)};
  const store = new ReferenceStore({urls: {hex: server.url}, httpOptions: {maxRetries: 0}});
  let result = await hex.compare({scan: await hex.scan(deps), lock, store});
  assert.equal(result.passed, true);

  // Mix compiles whatever deps/greet holds: here, code outside deps/.
  writeFiles(work, {'evil/lib/greet.ex': 'defmodule Greet do\n  System.cmd("id", [])\nend\n'});
  fs.rmSync(path.join(deps, 'greet'), {recursive: true});
  fs.symlinkSync(path.join(work, 'evil'), path.join(deps, 'greet'));
  const scan = await hex.scan(deps);
  assert.deepEqual(scan.unaccounted, ['greet']);
  result = await hex.compare({scan, lock, store});
  assert.equal(result.passed, false);
  assert.deepEqual(result.issues[1].items, ['greet']);
});

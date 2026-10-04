'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {promisify} = require('node:util');
const {execFile, execFileSync} = require('node:child_process');
const composer = require('../lib/ecosystems/composer');
const {GitTrees} = require('../lib/git-trees');
const {NoLockfileError, ReferenceStore} = require('../lib/ecosystems/common');
const {gitBlobId} = require('../lib/file-tree');
const {
  tempDir, writeFiles, needsPosix, PATH_MAX, deepTempDir, unreadableEntry, which,
} = require('./helpers');

const hasGit = which('git');

function git(cwd, ...args) {
  const settings = ['user.name=Test', 'user.email=test@example.com', 'commit.gpgsign=false', 'init.defaultBranch=main'].flatMap(setting => ['-c', setting]);
  return execFileSync('git', [...settings, ...args], {cwd, stdio: 'pipe'}).toString('utf8').trim();
}

/**
 * A git repository with one commit holding `files` (and `symlinks`).
 * @returns {{directory: string, commit: string}}
 */
function makeRepository(t, files, symlinks = {}) {
  const directory = tempDir(t, 'attestium-composer-repo-');
  git(directory, 'init', '--quiet');
  writeFiles(directory, files);
  for (const [link, target] of Object.entries(symlinks)) {
    fs.symlinkSync(target, path.join(directory, link));
  }

  git(directory, 'add', '-A');
  git(directory, 'commit', '--quiet', '-m', 'Release');
  return {directory, commit: git(directory, 'rev-parse', 'HEAD')};
}

/** Extract `git archive` of a commit (export-ignore applied) into a directory. */
function archiveInto(repository, commit, target) {
  fs.mkdirSync(target, {recursive: true});
  const archive = execFileSync('git', ['archive', '--format=tar', commit], {cwd: repository, maxBuffer: 64 * 1024 * 1024});
  execFileSync('tar', ['-xf', '-', '-C', target], {input: archive});
}

const LIBRARY = {
  'composer.json': '{"name": "acme/lib", "version": "1.2.0"}\n',
  'src/A.php': '<?php\nnamespace Acme;\nclass A {}\n',
  'bin/tool': '#!/usr/bin/env php\n<?php echo 1;\n',
  'tests/ATest.php': '<?php\n',
  '.gitattributes': '# Left out of dist archives\n/tests export-ignore\n',
  // Names that plain objects already have as properties.
  constructor: 'a file named like an inherited property\n',
};

test('detect finds vendor/ next to composer.lock', t => {
  const root = tempDir(t);
  assert.deepEqual(composer.detect(root), []);
  writeFiles(root, {'composer.lock': '{}', 'vendor/autoload.php': '<?php\n'});
  assert.deepEqual(composer.detect(root), []);
  writeFiles(root, {'vendor/composer/installed.json': '[]'});
  assert.deepEqual(composer.detect(root), [path.join(root, 'vendor')]);
  assert.equal(composer.installRoot('/srv/vendor'), '/srv/vendor');
  assert.equal(composer.label, 'Composer');
});

test('scan groups files by package and separates generated files', {skip: needsPosix}, async t => {
  const vendor = path.join(tempDir(t), 'vendor');
  writeFiles(vendor, {
    'autoload.php': '<?php\n',
    'composer/autoload_real.php': '<?php\n',
    'composer/installed.json': JSON.stringify({packages: [{name: 'composer/installers'}, {name: 'bad name'}, {name: 7}, null]}),
    'composer/installers/composer.json': '{"name": "composer/installers"}',
    'composer/installers/src/Installer.php': '<?php\n',
    'acme/lib/composer.json': LIBRARY['composer.json'],
    'acme/lib/src/A.php': LIBRARY['src/A.php'],
    'acme/lib/__proto__': '<?php\n',
    'acme/lib/.git/HEAD': 'ref: refs/heads/main\n',
    'acme/lib/src/.git/kept': 'not the package repository',
    'acme/nojson/src/B.php': '<?php\n',
    'acme/badjson/composer.json': '{',
    'bin/tool': '<?php\n',
    'README.md': 'stray',
    'acme/stray.php': '<?php\n',
  });
  fs.symlinkSync('../acme/lib/bin/tool', path.join(vendor, 'bin', 'linked'));
  fs.symlinkSync('A.php', path.join(vendor, 'acme', 'lib', 'src', 'Alias.php'));

  const result = await composer.scan(vendor);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.packages.map(item => [item.name, item.version]), [
    ['acme/badjson', null], ['acme/lib', '1.2.0'], ['acme/nojson', null], ['composer/installers', null],
  ]);
  const lib = result.packages.find(item => item.name === 'acme/lib');
  assert.deepEqual(Object.keys(lib.files).sort(), ['__proto__', 'composer.json', 'src/.git/kept', 'src/A.php', 'src/Alias.php']);
  assert.ok(Object.hasOwn(lib.meta.blobs, '__proto__'));
  assert.equal(lib.files['src/Alias.php'], 'symlink:A.php');
  assert.equal(lib.meta.blobs['src/A.php'], gitBlobId(LIBRARY['src/A.php']));
  assert.equal(lib.meta.blobs['src/Alias.php'], gitBlobId('A.php'));
  assert.deepEqual(Object.keys(result.meta.generated).sort(), ['autoload.php', 'bin/linked', 'bin/tool', 'composer/autoload_real.php', 'composer/installed.json']);
  assert.equal(result.meta.generated['bin/linked'], 'symlink:../acme/lib/bin/tool');
  assert.deepEqual(result.unaccounted, ['README.md', 'acme/stray.php']);
});

test('scan reads installed.json in its older array form, and survives a broken one', async t => {
  const vendor = path.join(tempDir(t), 'vendor');
  writeFiles(vendor, {
    'composer/installed.json': JSON.stringify([{name: 'composer/ca-bundle'}]),
    'composer/ca-bundle/res/cacert.pem': 'pem',
    'composer/autoload_real.php': '<?php\n',
  });
  const result = await composer.scan(vendor);
  assert.deepEqual(result.packages.map(item => item.name), ['composer/ca-bundle']);
  assert.deepEqual(Object.keys(result.meta.generated).sort(), ['composer/autoload_real.php', 'composer/installed.json']);

  writeFiles(vendor, {'composer/installed.json': '{}'});
  assert.deepEqual((await composer.scan(vendor)).packages, []);
  writeFiles(vendor, {'composer/installed.json': 'not json'});
  assert.deepEqual((await composer.scan(vendor)).packages, []);
});

test('scan reports files it cannot read', {skip: !PATH_MAX && 'paths have no length limit here'}, async t => {
  const vendor = path.join(deepTempDir(t), 'vendor');
  writeFiles(vendor, {'acme/deep/composer.json': '{}'});
  unreadableEntry(path.join(vendor, 'acme', 'deep'));
  const result = await composer.scan(vendor);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].error, 'ENAMETOOLONG');
  assert.ok(result.errors[0].path.startsWith('acme/deep/'));
});

test('readLock reads packages and dev packages', t => {
  const repo = tempDir(t);
  assert.throws(() => composer.readLock(repo), NoLockfileError);
  writeFiles(repo, {
    'composer.lock': JSON.stringify({
      packages: [{name: 'acme/lib', version: '1.2.0', source: {type: 'git', url: 'https://github.com/acme/lib.git', reference: 'a'.repeat(40)}}],
      'packages-dev': [{name: 'acme/dev', version: '0.1.0', dist: {type: 'zip', url: 'https://example.com/dev.zip'}}],
    }),
    'other/composer.lock': '{}',
  });
  const lock = composer.readLock(repo);
  assert.equal(lock.format, 'composer');
  assert.deepEqual(lock.packages.get('acme/lib').source.reference, 'a'.repeat(40));
  assert.equal(lock.packages.get('acme/lib').dist, null);
  assert.deepEqual(lock.packages.get('acme/dev'), {
    name: 'acme/dev', version: '0.1.0', source: null, dist: {type: 'zip', url: 'https://example.com/dev.zip'},
  });
  const empty = composer.readLock(repo, {lockfile: 'other/composer.lock'});
  assert.equal(empty.file, 'other/composer.lock');
  assert.equal(empty.packages.size, 0);
});

test('sourceOf finds the pinned commit in the source or a GitHub dist URL', () => {
  const commit = 'b'.repeat(40);
  assert.deepEqual(composer.sourceOf({source: {type: 'git', url: 'https://github.com/acme/lib.git', reference: commit}}), {url: 'https://github.com/acme/lib', commit});
  assert.deepEqual(composer.sourceOf({source: {type: 'git', url: 'https://gitlab.com/acme/lib', reference: 'v1.0.0'}, dist: {url: `https://api.github.com/repos/acme/lib/zipball/${commit}`}}), {url: 'https://github.com/acme/lib', commit});
  assert.equal(composer.sourceOf({source: {type: 'git', url: 'https://example.com/lib'}}), null);
  assert.equal(composer.sourceOf({source: {type: 'svn', url: 'https://example.com/lib', reference: commit}}), null);
  assert.equal(composer.sourceOf({dist: {type: 'zip', url: 'https://example.com/lib.zip'}}), null);
  assert.equal(composer.sourceOf({dist: {type: 'path'}}), null);
  assert.equal(composer.sourceOf({}), null);
});

test('compare checks installed files against the locked commit tree', {skip: !hasGit && 'git is not installed'}, async t => {
  const {directory: repository, commit} = makeRepository(t, LIBRARY, {'src/Alias.php': 'A.php'});
  const vendor = path.join(tempDir(t), 'vendor');
  // A dist install (git archive leaves out tests/) and a source install.
  archiveInto(repository, commit, path.join(vendor, 'acme', 'dist'));
  archiveInto(repository, commit, path.join(vendor, 'acme', 'source'));
  writeFiles(vendor, {'acme/source/tests/ATest.php': LIBRARY['tests/ATest.php'], 'acme/source/.git/HEAD': 'x'});
  // Tampered copies.
  archiveInto(repository, commit, path.join(vendor, 'acme', 'modified'));
  fs.appendFileSync(path.join(vendor, 'acme', 'modified', 'src', 'A.php'), '// injected\n');
  fs.rmSync(path.join(vendor, 'acme', 'modified', 'composer.json'));
  fs.rmSync(path.join(vendor, 'acme', 'modified', 'constructor'));
  writeFiles(vendor, {'acme/modified/src/Backdoor.php': '<?php\n', 'acme/modified/__proto__': '<?php\n'});
  archiveInto(repository, commit, path.join(vendor, 'acme', 'unlinked'));
  fs.rmSync(path.join(vendor, 'acme', 'unlinked', 'src', 'Alias.php'));
  writeFiles(vendor, {
    'acme/unlinked/src/Alias.php': 'A.php',
    'acme/unlocked/index.php': '<?php\n',
    'acme/nosource/index.php': '<?php\n',
    'acme/missing/index.php': '<?php\n',
    'autoload.php': '<?php\n',
    'composer/autoload_real.php': '<?php\n',
    'stray.php': '<?php\n',
  });

  const source = {type: 'git', url: `${repository}.git`, reference: commit};
  const lock = {
    packages: new Map([
      ...['acme/dist', 'acme/source', 'acme/modified', 'acme/unlinked'].map(name => [name, {name, source}]),
      ['acme/nosource', {name: 'acme/nosource', source: {type: 'path', url: '../nosource'}}],
      ['acme/missing', {name: 'acme/missing', source: {type: 'git', url: path.join(repository, 'nope'), reference: 'c'.repeat(40)}}],
    ]),
  };
  const store = new ReferenceStore({cacheDir: tempDir(t)});
  const gitTrees = new GitTrees({cacheDir: path.join(store.cacheDir, 'git'), allowFileUrls: true});
  const scan = await composer.scan(vendor);
  const result = await composer.compare({
    scan, lock, store, gitTrees, covered: file => file === 'autoload.php',
  });

  const byPackage = Object.fromEntries(result.findings.map(finding => [finding.path, finding]));
  assert.deepEqual(result.summary, {
    total: 7, verified: 2, bundled: 0, patched: 0, built: 0, failed: 3, unverifiable: 1, error: 1,
  });
  assert.equal(byPackage['acme/dist'], undefined);
  assert.equal(byPackage['acme/source'], undefined);
  assert.deepEqual(byPackage['acme/modified'], {
    status: 'failed',
    package: 'acme/modified@null',
    path: 'acme/modified',
    reason: `files differ from ${repository} at ${commit.slice(0, 12)}`,
    modified: ['src/A.php'],
    missing: ['composer.json', 'constructor'],
    added: ['__proto__', 'src/Backdoor.php'],
  });
  assert.deepEqual(byPackage['acme/unlinked'].modified, ['src/Alias.php']);
  assert.equal(byPackage['acme/unlocked'].reason, 'installed package is not in composer.lock');
  assert.equal(byPackage['acme/nosource'].status, 'unverifiable');
  assert.equal(byPackage['acme/missing'].status, 'error');
  assert.match(byPackage['acme/missing'].reason, /^could not read .*nope at c{12}: git /);
  assert.deepEqual(result.issues, [
    {severity: 'warn', message: result.issues[0].message, items: ['composer/autoload_real.php']},
    {severity: 'fail', message: 'Files in vendor/ that belong to no package', items: ['stray.php']},
  ]);
  assert.equal(result.passed, false);
});

test('compare without a lock, or with every generated file covered', async t => {
  const scan = {
    packages: [{
      name: 'acme/lib', version: null, path: 'acme/lib', files: {}, meta: {blobs: {}},
    }], unaccounted: [], meta: {},
  };
  const store = new ReferenceStore({cacheDir: tempDir(t)});
  const result = await composer.compare({scan, lock: null, store});
  assert.equal(result.findings[0].reason, 'no composer.lock pins this package');
  assert.deepEqual(result.issues, []);

  const covered = await composer.compare({
    scan: {...scan, packages: [], meta: {generated: {'autoload.php': 'x'}}}, lock: null, store, covered: () => true,
  });
  assert.equal(covered.passed, true);
  assert.deepEqual(covered.issues, []);
});

test('compare clones with its own GitTrees, which accepts only https URLs', async t => {
  const scan = {
    packages: [{
      name: 'acme/lib', version: null, path: 'acme/lib', files: {}, meta: {blobs: {}},
    }], unaccounted: [], meta: {generated: {'autoload.php': 'x'}},
  };
  const lock = {packages: new Map([['acme/lib', {name: 'acme/lib', source: {type: 'git', url: 'file:///srv/lib', reference: 'd'.repeat(40)}}]])};
  for (const store of [new ReferenceStore({cacheDir: tempDir(t)}), new ReferenceStore()]) {
    const result = await composer.compare({scan, lock, store});
    assert.equal(result.findings[0].status, 'error');
    assert.match(result.findings[0].reason, /Unsupported repository URL: file:\/\/\/srv\/lib/);
    assert.deepEqual(result.issues.map(issue => issue.items), [['autoload.php']]);
  }
});

test('a Composer install from a git repository verifies', {skip: !(hasGit && which('composer') && which('php')) && 'composer is not installed', timeout: 120_000}, async t => {
  const {directory: repository, commit} = makeRepository(t, {
    ...LIBRARY,
    'composer.json': JSON.stringify({name: 'acme/lib', autoload: {'psr-4': {'Acme\\': 'src/'}}, bin: ['bin/tool']}),
  });
  git(repository, 'tag', '1.2.0');
  const app = tempDir(t);
  writeFiles(app, {
    'composer.json': JSON.stringify({repositories: [{type: 'vcs', url: repository}, {'packagist.org': false}], require: {'acme/lib': '1.2.0'}}),
  });
  await promisify(execFile)('composer', ['install', '--no-interaction', '--no-plugins', '--no-scripts'], {
    cwd: app,
    env: {
      ...process.env, COMPOSER_HOME: path.join(app, '.composer-home'), COMPOSER_ALLOW_SUPERUSER: '1',
    },
  });

  assert.deepEqual(composer.detect(app), [path.join(app, 'vendor')]);
  const lock = composer.readLock(app);
  assert.deepEqual(composer.sourceOf(lock.packages.get('acme/lib')), {url: repository, commit});
  const scan = await composer.scan(path.join(app, 'vendor'));
  assert.deepEqual(scan.packages.map(item => item.name), ['acme/lib']);
  assert.ok('autoload.php' in scan.meta.generated);
  assert.ok('composer/installed.json' in scan.meta.generated);

  const store = new ReferenceStore({cacheDir: tempDir(t)});
  const gitTrees = new GitTrees({cacheDir: path.join(store.cacheDir, 'git'), allowFileUrls: true});
  const covered = file => file === 'autoload.php' || file.startsWith('composer/') || file.startsWith('bin/');
  const result = await composer.compare({
    scan, lock, store, gitTrees, covered,
  });
  assert.equal(result.passed, true, JSON.stringify(result));
  assert.equal(result.summary.verified, 1);

  fs.appendFileSync(path.join(app, 'vendor', 'acme', 'lib', 'src', 'A.php'), '// changed\n');
  const changed = await composer.compare({
    scan: await composer.scan(path.join(app, 'vendor')), lock, store, gitTrees, covered,
  });
  assert.deepEqual(changed.findings[0].modified, ['src/A.php']);
});

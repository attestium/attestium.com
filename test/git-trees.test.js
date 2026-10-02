'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {GitTrees, exportIgnore} = require('../lib/git-trees');
const {tempDir, writeFiles, which} = require('./helpers');
const {GIT_ENV} = require('./fixtures/formats/binaries');

const hasGit = which('git');

function git(cwd, ...args) {
  return execFileSync('git', args, {cwd, env: {...process.env, ...GIT_ENV}, stdio: ['ignore', 'pipe', 'pipe']}).toString().trim();
}

/**
 * A source repository allowing partial clones, with a commit per file map.
 * @returns {{dir: string, url: string, commit: (files: Object) => string}}
 */
function sourceRepository(t, directory = path.join(tempDir(t, 'attestium-git-src-'), 'repo')) {
  fs.mkdirSync(directory, {recursive: true});
  git(directory, 'init', '--quiet');
  git(directory, 'config', 'uploadpack.allowFilter', 'true');
  git(directory, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  return {
    dir: directory,
    url: `file://${directory}`,
    commit(files, message = 'commit') {
      writeFiles(directory, files);
      git(directory, 'add', '-A');
      git(directory, 'commit', '--quiet', '--no-gpg-sign', '-m', message);
      return git(directory, 'rev-parse', 'HEAD');
    },
  };
}

test('tree lists the files of a commit and file fetches their contents', {skip: !hasGit && 'needs git'}, async t => {
  const source = sourceRepository(t);
  const first = source.commit({
    'README.md': 'readme\n',
    'src/index.php': '<?php echo 1;\n',
    'src/odd\tname.txt': 'tab in the name\n',
    'tests/test.php': 'test\n',
    '.gitattributes': '/tests export-ignore\n',
  });
  // A submodule (gitlink) entry is not a file.
  git(source.dir, 'update-index', '--add', '--cacheinfo', `160000,${first},vendor/sub`);
  git(source.dir, 'commit', '--quiet', '--no-gpg-sign', '-m', 'submodule');
  fs.chmodSync(path.join(source.dir, 'README.md'), 0o755);
  const second = source.commit({'src/index.php': '<?php echo 2;\n'});

  const cacheDir = path.join(tempDir(t, 'attestium-git-cache-'), 'cache');
  const trees = new GitTrees({cacheDir, allowFileUrls: true});
  const files = await trees.tree(source.url, first);
  assert.deepEqual([...files.keys()].sort(), ['.gitattributes', 'README.md', 'src/index.php', 'src/odd\tname.txt', 'tests/test.php']);
  assert.equal(files.get('README.md').mode, '100644');
  assert.equal(files.get('README.md').blob, git(source.dir, 'rev-parse', `${first}:README.md`));
  assert.equal(await trees.tree(source.url, first), files, 'cached per run');

  const later = await trees.tree(source.url, second);
  assert.equal(later.get('README.md').mode, '100755');
  assert.equal(later.has('vendor/sub'), false, 'gitlinks are skipped');

  assert.equal((await trees.file(source.url, first, 'src/index.php')).toString(), '<?php echo 1;\n');
  assert.equal((await trees.file(source.url, second, 'src/index.php')).toString(), '<?php echo 2;\n');
  assert.equal(await trees.file(source.url, first, 'missing.txt'), null);
  const attributes = exportIgnore((await trees.file(source.url, first, '.gitattributes')).toString());
  assert.deepEqual([...files.keys()].filter(file => !attributes(file)).sort(), ['.gitattributes', 'README.md', 'src/index.php', 'src/odd\tname.txt']);

  // A new instance reuses the clone on disk without fetching again: it
  // works with the source gone.
  fs.renameSync(source.dir, `${source.dir}-moved`);
  const again = new GitTrees({cacheDir, allowFileUrls: true});
  assert.deepEqual(await again.tree(source.url, second), later);
  assert.ok(fs.existsSync(path.join(cacheDir, fs.readdirSync(cacheDir).find(name => name.endsWith('.git')), 'HEAD')));
});

test('replacement refs planted in a cached clone are not honored', {skip: !hasGit && 'needs git'}, async t => {
  const source = sourceRepository(t);
  const real = source.commit({'lib/app.php': '<?php echo "real";\n'});
  const evil = source.commit({'lib/app.php': '<?php system($_GET["c"]);\n', 'lib/extra.php': 'extra\n'});
  const cacheDir = path.join(tempDir(t, 'attestium-git-cache-'), 'cache');
  const first = new GitTrees({cacheDir, allowFileUrls: true});
  const expected = await first.tree(source.url, real);
  await first.tree(source.url, evil);

  // Someone with write access to the cache makes the real commit, and its
  // tree, read as the other ones.
  const gitDir = path.join(cacheDir, fs.readdirSync(cacheDir).find(name => name.endsWith('.git')));
  const [realTree, evilTree] = [real, evil].map(commit => git(gitDir, '--git-dir', gitDir, 'rev-parse', `${commit}^{tree}`));
  git(gitDir, '--git-dir', gitDir, 'update-ref', `refs/replace/${real}`, evil);
  git(gitDir, '--git-dir', gitDir, 'update-ref', `refs/replace/${realTree}`, evilTree);
  assert.equal(git(gitDir, '--git-dir', gitDir, 'ls-tree', '-r', '--name-only', real), 'lib/app.php\nlib/extra.php', 'git itself honors them');

  const again = new GitTrees({cacheDir, allowFileUrls: true});
  assert.deepEqual(await again.tree(source.url, real), expected);
  assert.equal((await again.file(source.url, real, 'lib/app.php')).toString(), '<?php echo "real";\n');
});

test('failures are reported and not cached', {skip: !hasGit && 'needs git'}, async t => {
  const directory = path.join(tempDir(t, 'attestium-git-late-'), 'repo');
  const url = `file://${directory}`;
  const trees = new GitTrees({cacheDir: tempDir(t, 'attestium-git-cache-'), allowFileUrls: true});
  const commit = 'a'.repeat(40);
  await assert.rejects(trees.tree(url, commit), /git fetch failed: /);

  // The same URL works once the repository exists.
  const source = sourceRepository(t, directory);
  const real = source.commit({'a.txt': 'a\n'});
  assert.deepEqual([...(await trees.tree(url, real)).keys()], ['a.txt']);
  await assert.rejects(trees.tree(url, commit), /git fetch failed: /);

  // An https repository that cannot be reached (nothing listens on port 1).
  const remote = new GitTrees({cacheDir: tempDir(t), timeout: 30_000});
  await assert.rejects(remote.tree('https://127.0.0.1:1/owner/repo.git', real), /git fetch failed: .*127\.0\.0\.1/);

  const missingGit = new GitTrees({cacheDir: tempDir(t), git: '/nonexistent/git', allowFileUrls: true});
  await assert.rejects(missingGit.tree(url, real), /git init failed: spawn \/nonexistent\/git ENOENT/);
});

test('only https URLs (and file URLs when allowed) and full commit ids', async t => {
  const trees = new GitTrees({cacheDir: tempDir(t)});
  const commit = '0123456789abcdef0123456789abcdef01234567';
  assert.equal(trees.git, 'git');
  assert.equal(trees.timeout, 600_000);
  assert.doesNotThrow(() => trees._checkUrl('https://github.com/owner/repo.git'));
  assert.doesNotThrow(() => trees._checkUrl('https://git.example.com:8443/~user/repo%20x'));
  for (const url of [
    'http://github.com/owner/repo',
    'ssh://git@github.com/owner/repo',
    'git@github.com:owner/repo.git',
    'https://github.com/owner/../repo',
    'https://github.com/owner/repo --upload-pack=evil',
    'ext::sh -c evil',
    'file:///tmp/repo',
    '/tmp/repo',
    `https://example.com/${'x'.repeat(200)} y`,
  ]) {
    await assert.rejects(trees.tree(url, commit), /Unsupported repository URL/, url);
  }

  await assert.rejects(trees.file('ext::x', commit, 'a'), /Unsupported repository URL/);
  await assert.rejects(trees.tree('https://github.com/owner/repo', 'main'), {name: 'TypeError', message: /Invalid commit id: main/});
  await assert.rejects(trees.tree('https://github.com/owner/repo', commit.toUpperCase()), TypeError);

  const local = new GitTrees({cacheDir: tempDir(t), allowFileUrls: true});
  assert.doesNotThrow(() => local._checkUrl('file:///tmp/repo'));
  assert.doesNotThrow(() => local._checkUrl('/tmp/repo'));
  assert.throws(() => local._checkUrl('file:///tmp/repo with space'), /Unsupported repository URL/);
});

test('exportIgnore matches .gitattributes patterns as git archive does', () => {
  const ignored = exportIgnore([
    '# comment',
    '',
    '* text=auto',
    '/tests export-ignore',
    'docs/ export-ignore',
    '*.md export-ignore',
    '/README.md -export-ignore',
    'CHANGELOG.md !export-ignore',
    '.github export-ignore',
    'src/**/fixtures export-ignore',
    'phpunit.xml?dist export-ignore',
    '**/Thumbs.db export-ignore',
    'logs/** export-ignore',
    'a+b(c).txt   export-ignore\r',
  ].join('\n'));
  const cases = {
    'tests/unit/a.php': true,
    tests: true,
    'lib/tests/a.php': false,
    'docs/guide.md': true,
    'lib/docs/x.txt': true,
    'notes.md': true,
    'lib/notes.md': true,
    'README.md': false,
    'lib/README.md': true,
    'CHANGELOG.md': false,
    '.github/workflows/ci.yml': true,
    'src/a/b/fixtures/x.json': true,
    'src/fixtures/x.json': true,
    'lib/src/fixtures/x.json': false,
    'Thumbs.db': true,
    'a/b/Thumbs.db': true,
    logs: false,
    'logs/a/b.log': true,
    'phpunit.xml.dist': true,
    'phpunit.xml/dist': false,
    'a+b(c).txt': true,
    'aab(c).txt': false,
    'src/index.php': false,
  };
  for (const [file, expected] of Object.entries(cases)) {
    assert.equal(ignored(file), expected, file);
  }

  assert.equal(exportIgnore(null)('anything'), false);
  assert.equal(exportIgnore('')('anything'), false);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const {execFileSync} = require('node:child_process');
const util = require('../lib/util');
const signing = require('../lib/signing');
const fileTree = require('../lib/file-tree');
const tar = require('../lib/tar');
const {
  httpGet, httpGetJson, assertAllowedUrl, isPrivateAddress, privateAddressLookup, connectOptions,
} = require('../lib/http');
const {
  tempDir, writeFiles, needsPosix, startServer, listenOnLoopback, makeTarGz, sleep, which, hasOpenssl,
} = require('./helpers');

// ─── util ───────────────────────────────────────────────────────────

test('canonicalize sorts keys, omits undefined properties and rejects ambiguous values', () => {
  assert.equal(util.canonicalize({b: 1, a: [true, null, 'x'], c: undefined}), '{"a":[true,null,"x"],"b":1}');
  assert.equal(util.canonicalize(Object.assign(Object.create(null), {z: false})), '{"z":false}');
  // UTF-16 code unit order (SPEC.md): U+1F600 is D83D DE00, before U+E000.
  assert.equal(util.canonicalize({'\uE000': 1, '\u{1F600}': 2}), '{"\u{1F600}":2,"\uE000":1}');
  assert.throws(() => util.canonicalize(Number.NaN), /non-finite/);
  assert.throws(() => util.canonicalize([undefined]), /undefined inside an array/);
  assert.throws(() => util.canonicalize(new Date()), /non-plain object/);
  assert.throws(() => util.canonicalize(() => {}), /type function/);
  assert.throws(() => util.canonicalize(1n), /type bigint/);
  assert.equal(util.isPlainObject(null), false);
  assert.equal(util.isPlainObject('x'), false);
});

test('digests and constant-time comparison', () => {
  assert.equal(util.sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(util.digestOf({b: 2, a: 1}), util.sha256('{"a":1,"b":2}'));
  assert.equal(util.safeEqual('abc', 'abc'), true);
  assert.equal(util.safeEqual('abc', 'abd'), false);
  assert.equal(util.safeEqual('abc', 'ab'), false);
  assert.equal(util.safeEqual(1, 1), false);
});

test('pid and nonce validation keep untrusted input out of paths and commands', () => {
  assert.equal(util.normalizePid(42), '42');
  assert.equal(util.normalizePid('self'), 'self');
  for (const bad of ['0', '-1', '1;id', '../1', '1 ', 'abc', 99_999_999_999, '01']) {
    assert.throws(() => util.normalizePid(bad), /Invalid process id/);
  }

  assert.equal(util.normalizeNonce('AB'.repeat(16)), 'ab'.repeat(16));
  assert.throws(() => util.normalizeNonce('ab'), /16 to 64 bytes/);
  assert.throws(() => util.normalizeNonce('zz'.repeat(16)), /16 to 64 bytes/);
  assert.throws(() => util.normalizeNonce(null), /16 to 64 bytes/);
  assert.equal(util.generateNonce().length, 64);
  assert.equal(util.generateNonce(16).length, 32);
});

test('parallelMap preserves order and bounds concurrency', async () => {
  let active = 0;
  let peak = 0;
  const tasks = Array.from({length: 10}, (_, i) => async () => {
    active++;
    peak = Math.max(peak, active);
    await sleep(5);
    active--;
    return i * 2;
  });
  assert.deepEqual(await util.parallelMap(tasks, 3), [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]);
  assert.equal(peak, 3);
  assert.deepEqual(await util.parallelMap([], 4), []);
});

// ─── signing ────────────────────────────────────────────────────────

test('Ed25519 envelopes verify only with the trusted key and untampered payloads', () => {
  const keys = signing.generateKeyPair();
  const other = signing.generateKeyPair();
  const envelope = signing.sign({hello: 'world', n: 1}, keys.privateKey);
  assert.equal(envelope.alg, 'ed25519');
  assert.equal(envelope.keyId, signing.fingerprint(keys.publicKey));
  assert.equal(signing.fingerprint(keys.privateKey), envelope.keyId);

  assert.deepEqual(signing.verify(envelope, keys.publicKey), {valid: true, trusted: true, keyId: envelope.keyId});
  assert.deepEqual(signing.verify(envelope), {valid: true, trusted: false, keyId: envelope.keyId});

  const wrongKey = signing.verify(envelope, other.publicKey);
  assert.equal(wrongKey.valid, false);
  assert.match(wrongKey.error, /Key id does not match/);

  const tampered = {...envelope, payload: {hello: 'world', n: 2}};
  assert.match(signing.verify(tampered, keys.publicKey).error, /does not verify/);

  // Attacker swaps in their own embedded key and re-signs: trusted key still rejects.
  const forged = signing.sign({hello: 'evil'}, other.privateKey);
  assert.equal(signing.verify(forged, keys.publicKey).valid, false);

  assert.match(signing.verify(null).error, /Malformed/);
  assert.match(signing.verify({alg: 'rsa', signature: 'x'}).error, /Malformed/);
  assert.match(signing.verify({...envelope, publicKey: 'not a key'}).error, /./);

  const rsa = crypto.generateKeyPairSync('rsa', {modulusLength: 1024});
  assert.throws(() => signing.toPublicKey(rsa.publicKey), /Expected an ed25519 key/);
  assert.throws(() => signing.toPublicKey(rsa.privateKey), /Expected an ed25519 key/);
  assert.throws(() => signing.toPrivateKey(rsa.privateKey), /Expected an ed25519 key/);
  assert.equal(signing.toPrivateKey(crypto.createPrivateKey(keys.privateKey)).type, 'private');
});

// ─── file tree ──────────────────────────────────────────────────────

test('globToRegExp matches literally and supports *, ** and ?', () => {
  const {globToRegExp, createMatcher} = fileTree;
  assert.ok(globToRegExp('**/*.js').test('a.js'));
  assert.ok(globToRegExp('**/*.js').test('a/b/c.js'));
  assert.ok(!globToRegExp('*.js').test('a/b.js'));
  assert.ok(globToRegExp('src/**').test('src/a/b'));
  assert.ok(globToRegExp('file?.txt').test('file1.txt'));
  assert.ok(!globToRegExp('file?.txt').test('file/.txt'));
  // Regex metacharacters are literal (the old implementation treated them as regex).
  assert.ok(globToRegExp('a+b(c)[d]{e}|$^.txt').test('a+b(c)[d]{e}|$^.txt'));
  assert.ok(!globToRegExp('a+b.txt').test('aab.txt'));
  const matcher = createMatcher(['**/*.md', 'LICENSE']);
  assert.ok(matcher('docs/x.md'));
  assert.ok(matcher('LICENSE'));
  assert.ok(!matcher('src/x.js'));
  assert.equal(createMatcher()('x'), false);
});

test('gitBlobId matches git hash-object', {skip: !which('git') && 'git is not installed'}, t => {
  const directory = tempDir(t);
  writeFiles(directory, {'a.txt': 'hello\n'});
  const expected = execFileSync('git', ['hash-object', path.join(directory, 'a.txt')], {encoding: 'utf8'}).trim();
  assert.equal(fileTree.gitBlobId('hello\n'), expected);
  assert.equal(fileTree.gitBlobId(Buffer.from('hello\n')), expected);
});

test('walkTree hashes files, records symlinks without following them, and reports errors', {skip: needsPosix}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {
    'a.txt': 'alpha',
    'sub/b.bin': Buffer.alloc(3 * 1024 * 1024, 7),
    'skip/c.txt': 'skipped',
    'empty.txt': '',
  });
  fs.chmodSync(path.join(directory, 'a.txt'), 0o755);
  fs.symlinkSync('/etc/passwd', path.join(directory, 'link'));
  fs.symlinkSync('.', path.join(directory, 'loop'));
  fs.mkdirSync(path.join(directory, 'locked'));
  fs.writeFileSync(path.join(directory, 'locked', 'x'), 'x');
  fs.writeFileSync(path.join(directory, 'unreadable.txt'), 'secret');
  fs.chmodSync(path.join(directory, 'unreadable.txt'), 0);
  fs.chmodSync(path.join(directory, 'locked'), 0);

  const {entries, errors} = await fileTree.walkTree(directory, {exclude: relativePath => relativePath === 'skip'});
  const byPath = Object.fromEntries(entries.map(entry => [entry.path, entry]));
  assert.deepEqual(Object.keys(byPath).sort(), process.getuid && process.getuid() === 0
    ? ['a.txt', 'empty.txt', 'link', 'locked/x', 'loop', 'sub/b.bin', 'unreadable.txt']
    : ['a.txt', 'empty.txt', 'link', 'loop', 'sub/b.bin']);
  assert.equal(byPath['a.txt'].sha256, util.sha256('alpha'));
  assert.equal(byPath['a.txt'].mode, '100755');
  assert.equal(byPath['sub/b.bin'].mode, '100644');
  assert.equal(byPath['sub/b.bin'].size, 3 * 1024 * 1024);
  assert.equal(byPath['empty.txt'].sha256, util.sha256(''));
  assert.equal(byPath.link.type, 'symlink');
  assert.equal(byPath.link.target, '/etc/passwd');
  assert.equal(byPath.link.mode, '120000');
  assert.equal(byPath.link.sha256, util.sha256('/etc/passwd'));
  assert.equal(byPath.loop.type, 'symlink');
  if (!(process.getuid && process.getuid() === 0)) {
    assert.deepEqual(errors.map(error => error.path).sort(), ['locked', 'unreadable.txt']);
  }

  const missing = await fileTree.walkTree(path.join(directory, 'nope'));
  assert.deepEqual(missing.entries, []);
  assert.deepEqual(missing.directories, []);
  assert.equal(missing.errors[0].error, 'ENOENT');
});

test('walkTree reports each directory it lists with its times, which show a file added and removed again', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'index.js': 'main', 'lib/foo/index.js': 'foo', 'skip/x.js': 'x'});
  const times = relative => {
    const stats = fs.statSync(path.join(directory, relative));
    return {path: relative, ctimeMs: stats.ctimeMs, mtimeMs: stats.mtimeMs};
  };

  const exclude = relative => relative === 'skip';
  const before = await fileTree.walkTree(directory, {exclude});
  assert.deepEqual(before.directories, [times('.'), times('lib'), times('lib/foo')]);
  // A file that shadows lib/foo/index.js for require('./lib/foo'), removed
  // again: every file is as it was, but its directory changed.
  await sleep(20);
  fs.writeFileSync(path.join(directory, 'lib', 'foo.js'), 'shadow');
  fs.rmSync(path.join(directory, 'lib', 'foo.js'));
  const after = await fileTree.walkTree(directory, {exclude});
  assert.deepEqual(after.entries, before.entries);
  const lib = after.directories.find(item => item.path === 'lib');
  assert.deepEqual(lib, times('lib'));
  assert.ok(lib.mtimeMs > before.directories[1].mtimeMs && lib.ctimeMs > before.directories[1].ctimeMs);
  assert.deepEqual(after.directories.filter(item => item.path !== 'lib'), before.directories.filter(item => item.path !== 'lib'));
});

test('walkTree with hash: false only reads the status of each entry', {skip: needsPosix}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'a.js': 'a', 'sub/b.js': 'b'});
  fs.symlinkSync('a.js', path.join(directory, 'link'));
  fs.chmodSync(path.join(directory, 'sub', 'b.js'), 0);
  t.mock.method(fs.promises, 'readlink', async () => {
    throw new Error('read a link');
  });
  const walk = await fileTree.walkTree(directory, {hash: false});
  const lstat = (relative, type) => {
    const stats = fs.lstatSync(path.join(directory, relative));
    return {
      path: relative, type, ctimeMs: stats.ctimeMs, mtimeMs: stats.mtimeMs,
    };
  };

  // An unreadable file is listed too: it is never opened.
  assert.deepEqual(walk.entries, [lstat('a.js', 'file'), lstat('link', 'symlink'), lstat('sub/b.js', 'file')]);
  assert.deepEqual(walk.directories.map(item => item.path), ['.', 'sub']);
  assert.deepEqual(walk.errors, []);
});

const linux = process.platform === 'linux';

test('hashFile refuses FIFOs and devices instead of waiting or reading forever', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const fifo = path.join(directory, 'fifo');
  execFileSync('mkfifo', [fifo]);
  // A FIFO with no writer: open() would wait for one forever.
  const outcome = await Promise.race([fileTree.hashFile(fifo).then(() => 'hashed').catch(error => error.message), sleep(3000).then(() => 'still waiting')]);
  assert.match(outcome, /Not a regular file/);
  // A device that never ends (reached through a directory, so O_NOFOLLOW does not apply).
  fs.symlinkSync('/dev', path.join(directory, 'dev'));
  const device = await Promise.race([fileTree.hashFile(path.join(directory, 'dev', 'zero')).then(() => 'hashed').catch(error => error.message), sleep(3000).then(() => 'still reading')]);
  assert.match(device, /Not a regular file/);
  // A file that is not the inode a process mapped.
  writeFiles(directory, {'lib.so': 'code'});
  await assert.rejects(fileTree.hashFile(path.join(directory, 'lib.so'), {inode: fs.statSync(path.join(directory, 'lib.so')).ino + 1}), /Replaced since it was mapped/);
  assert.equal((await fileTree.hashFile(path.join(directory, 'lib.so'), {inode: fs.statSync(path.join(directory, 'lib.so')).ino})).size, 4);
});

test('walkTree reports FIFOs and devices as errors instead of skipping them, and leaves out sockets, which have no content', {skip: !linux}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'lib/real.rb': 'real', 'tmp/.keep': ''});
  execFileSync('mkfifo', [path.join(directory, 'lib/shadow.rb'), path.join(directory, 'top.fifo'), path.join(directory, 'tmp/excluded.fifo')]);
  const server = require('node:net').createServer();
  await new Promise(resolve => {
    server.listen(path.join(directory, 'lib/control.sock'), resolve);
  });
  t.after(() => server.close());
  // A server's socket (Puma's tmp/sockets/puma.sock) cannot be opened, so nothing is read or loaded from it.
  const expected = [{path: 'lib/shadow.rb', error: 'ENOTFILE'}, {path: 'top.fifo', error: 'ENOTFILE'}];
  if (process.getuid() === 0) {
    execFileSync('mknod', [path.join(directory, 'lib/null'), 'c', '1', '3']);
    execFileSync('mknod', [path.join(directory, 'lib/loop'), 'b', '7', '0']);
    expected.push({path: 'lib/loop', error: 'ENOTFILE'}, {path: 'lib/null', error: 'ENOTFILE'});
    expected.sort((a, b) => (a.path > b.path) - (a.path < b.path));
  }

  // Never opened, so a FIFO without a writer cannot make the walk wait.
  const walk = await Promise.race([fileTree.walkTree(directory, {exclude: relative => relative === 'tmp/excluded.fifo'}), sleep(5000).then(() => null)]);
  assert.ok(walk, 'the walk waited on a FIFO');
  assert.deepEqual(walk.entries.map(entry => entry.path), ['lib/real.rb', 'tmp/.keep']);
  assert.deepEqual(walk.errors, expected);
});

test('walkTree does not follow a directory replaced by a symbolic link during the walk', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const secret = tempDir(t);
  writeFiles(directory, {'sub/a.txt': 'a', 'z.txt': 'z'});
  writeFiles(secret, {'private.key': 'private key'});
  const {readdir} = fs.promises;
  let swapped = false;
  t.mock.method(fs.promises, 'readdir', async (...args) => {
    const result = await readdir(...args);
    if (!swapped) {
      // Between listing the root and entering "sub", sub becomes a link.
      swapped = true;
      fs.renameSync(path.join(directory, 'sub'), path.join(directory, 'old'));
      fs.symlinkSync(secret, path.join(directory, 'sub'));
    }

    return result;
  });
  const {entries, errors} = await fileTree.walkTree(directory);
  assert.deepEqual(entries.map(entry => entry.path), ['z.txt']);
  assert.deepEqual(errors.map(error => error.path), ['sub']);
});

test('walkTree walks a directory resolved inside a root, and reports one it cannot open', {skip: !linux}, async t => {
  const root = tempDir(t);
  const outside = tempDir(t);
  writeFiles(root, {'gems/real/a.rb': 'a'});
  writeFiles(outside, {'gems/real/secret': 's'});
  fs.symlinkSync(path.join(outside, 'gems'), path.join(root, 'link'));
  // Inside the root, the absolute link names root + that path, which does not exist.
  const walk = await fileTree.walkTree('/link/real', {root});
  assert.deepEqual(walk, {entries: [], directories: [], errors: [{path: '.', error: 'ENOENT'}]});
  const inside = await fileTree.walkTree('/gems/../gems/real', {root});
  assert.deepEqual(inside.entries.map(entry => entry.path), ['a.rb']);
});

test('walkTree and hashFile inside a root: links another user made, and directories that cannot be listed', {skip: !linux}, async t => {
  const root = tempDir(t);
  writeFiles(root, {'lib/real/a.rb': 'a'});
  fs.symlinkSync('real', path.join(root, 'lib', 'link'));
  // A link another user made (any link is one when the tests do not run as root).
  if (process.getuid() === 0) {
    fs.lchownSync(path.join(root, 'lib', 'link'), 1000, 1000);
  }

  assert.deepEqual((await fileTree.walkTree('/lib/link', {root, rootOwnedLinks: true})).errors, [{path: '.', error: 'A symbolic link not owned by root: /lib/link'}]);
  assert.equal((await fileTree.walkTree('/lib/link', {root})).entries.length, 1);
  assert.equal((await fileTree.hashFile('/lib/link/a.rb', {root})).sha256, util.sha256('a'));
  await assert.rejects(fileTree.hashFile('/lib/link/a.rb', {root, rootOwnedLinks: true}), /not owned by root/);

  // A directory that opens but cannot be listed.
  const {readdir} = fs.promises;
  t.mock.method(fs.promises, 'readdir', async (...args) => {
    throw Object.assign(new Error('denied'), {code: 'EACCES'});
  });
  assert.deepEqual(await fileTree.walkTree(root), {entries: [], directories: [], errors: [{path: '.', error: 'EACCES'}]});
  const containers = require('../lib/containers');
  assert.deepEqual(await containers.walkUpper(root), {files: {}, deleted: [], errors: [{path: '.', error: 'EACCES'}]});
  fs.promises.readdir = readdir;
});

test('openInRoot keeps symbolic links and ".." inside the root', {skip: !linux}, async t => {
  const root = tempDir(t);
  const outside = tempDir(t);
  writeFiles(outside, {'secret.txt': 'secret'});
  writeFiles(root, {'etc/hosts': 'inside', [`${outside.slice(1)}/secret.txt`]: 'decoy'});
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'etc', 'absolute'));
  fs.symlinkSync('../../../../../../../../etc/hosts', path.join(root, 'etc', 'relative'));
  fs.symlinkSync('loop', path.join(root, 'loop'));
  const readAt = (file, options) => {
    const fd = fileTree.openInRoot(root, file, options);
    try {
      return fs.readFileSync(fd, 'utf8');
    } finally {
      fs.closeSync(fd);
    }
  };

  assert.equal(readAt('/etc/absolute'), 'decoy', 'an absolute link resolves inside the root');
  assert.equal(readAt('/etc/relative'), 'inside', '".." stops at the root');
  assert.equal(readAt('/../../etc/./hosts'), 'inside');
  assert.throws(() => fileTree.openInRoot(root, '/loop'), {code: 'ELOOP'});
  assert.throws(() => fileTree.openInRoot(root, '/missing/x'), {code: 'ENOENT'});
  const directory = fileTree.openInRoot(root, '/etc/..', {flags: fs.constants.O_RDONLY | fs.constants.O_DIRECTORY});
  assert.ok(fs.fstatSync(directory).isDirectory());
  fs.closeSync(directory);
  // Links another user made are refused where only root's are trusted
  // (any link is one when the tests do not run as root).
  if (process.getuid() === 0) {
    fs.lchownSync(path.join(root, 'etc', 'relative'), 1000, 1000);
    assert.equal(readAt('/etc/absolute', {rootOwnedLinks: true}), 'decoy');
  }

  assert.throws(() => fileTree.openInRoot(root, '/etc/relative', {rootOwnedLinks: true}), /not owned by root/);
  // The default root is /.
  const fd = fileTree.openInRoot('', path.join(outside, 'secret.txt'));
  assert.equal(fs.readFileSync(fd, 'utf8'), 'secret');
  fs.closeSync(fd);
});

test('walkTree records files that vanish mid-walk as errors', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'a.txt': 'a', 'b.txt': 'b'});
  const result = await fileTree.walkTree(directory, {
    exclude(relativePath) {
      if (relativePath === 'b.txt') {
        fs.rmSync(path.join(directory, 'a.txt'));
      }

      return false;
    },
  });
  assert.deepEqual(result.entries.map(entry => entry.path), ['b.txt']);
  assert.deepEqual(result.errors, [{path: 'a.txt', error: 'ENOENT'}]);
});

test('hashFile refuses symlinks and detects files that change while being read', {skip: needsPosix}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'a.txt': 'abc'});
  fs.symlinkSync(path.join(directory, 'a.txt'), path.join(directory, 'link'));
  await assert.rejects(fileTree.hashFile(path.join(directory, 'link')), {code: 'ELOOP'});

  const big = path.join(directory, 'grow.bin');
  fs.writeFileSync(big, Buffer.alloc(4 * 1024 * 1024));
  let calls = 0;
  const originalRead = fs.read;
  t.mock.method(fs, 'read', (...args) => {
    if (++calls === 1) {
      fs.appendFileSync(big, 'more');
    }

    return Reflect.apply(originalRead, fs, args);
  });
  await assert.rejects(fileTree.hashFile(big), /changed while hashing/);
});

test('manifestDigest is order independent and content sensitive', () => {
  const a = [{path: 'x', sha256: '1'}, {path: 'y', sha256: '2'}];
  const b = [{path: 'y', sha256: '2'}, {path: 'x', sha256: '1'}];
  assert.equal(fileTree.manifestDigest(a), fileTree.manifestDigest(b));
  assert.notEqual(fileTree.manifestDigest(a), fileTree.manifestDigest([{path: 'x', sha256: '1'}, {path: 'y', sha256: '3'}]));
  assert.equal(fileTree.toPosixRelative('/a', path.join('/a', 'b', 'c')), 'b/c');
});

// ─── tar ────────────────────────────────────────────────────────────

test('readGzipTarFiles reads GNU, pax and ustar archives with long names', t => {
  const longName = `pkg/${'d'.repeat(60)}/${'f'.repeat(90)}.js`;
  for (const format of ['gnu', 'pax', 'ustar']) {
    const archive = makeTarGz(t, {
      'pkg/index.js': 'module.exports = 1;\n',
      [longName]: 'long',
      'pkg/empty.txt': '',
    }, {format, symlinks: {'pkg/link.js': 'index.js'}});
    const files = tar.readGzipTarFiles(archive);
    assert.equal(files.get('pkg/index.js').toString(), 'module.exports = 1;\n', format);
    assert.equal(files.get(longName).toString(), 'long', format);
    assert.equal(files.get('pkg/empty.txt').length, 0);
    assert.equal(files.has('pkg/link.js'), false, 'symlinks are not returned as files');
    const stripped = tar.readGzipTarFiles(archive, {stripFirstComponent: true});
    assert.ok(stripped.has('index.js'));
  }
});

/**
 * Build a raw tar header by hand for malformed-input tests.
 */
function header(name, {size = 0, type = '0', mode = '0000644', checksum} = {}) {
  const block = Buffer.alloc(512);
  block.write(name, 0);
  block.write(`${mode}\0`, 100);
  block.write('0000000\0', 108);
  block.write('0000000\0', 116);
  block.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
  block.write('00000000000\0', 136);
  block.write('        ', 148);
  block.write(type, 156);
  block.write('ustar\u000000', 257);
  let sum = 0;
  for (const byte of block) {
    sum += byte;
  }

  block.write(`${(checksum ?? sum).toString(8).padStart(6, '0')}\0 `, 148);
  return block;
}

function pad(data) {
  return Buffer.concat([data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}

test('tar reader handles base-256 sizes, global pax headers, unsafe paths and malformed input', () => {
  const content = Buffer.from('hi');
  const base256 = header('pkg/big.txt', {size: 2});
  base256.fill(0, 124, 136);
  base256[124] = 0x80;
  base256[135] = 2;
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += (i >= 148 && i < 156) ? 32 : base256[i];
  }

  base256.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  const globalPax = Buffer.from('17 comment=hello\n');
  const archive = Buffer.concat([
    header('pax_global_header', {type: 'g', size: globalPax.length}),
    pad(globalPax),
    base256,
    pad(content),
    header('../evil.txt', {size: 2}),
    pad(content),
    header('pkg/dir/', {type: '5'}),
    header('pkg/contig.txt', {size: 2, type: '7'}),
    pad(content),
    header('top.txt', {size: 2}),
    pad(content),
    Buffer.alloc(1024),
  ]);
  const files = tar.readGzipTarFiles(zlib.gzipSync(archive));
  assert.deepEqual([...files.keys()].sort(), ['pkg/big.txt', 'pkg/contig.txt', 'top.txt']);
  const stripped = tar.readGzipTarFiles(zlib.gzipSync(archive), {stripFirstComponent: true});
  assert.deepEqual([...stripped.keys()].sort(), ['big.txt', 'contig.txt']);

  assert.throws(() => tar.readTar(header('x', {checksum: 1})), /checksum mismatch/);
  assert.throws(() => tar.readTar(Buffer.concat([header('x', {size: 100})])), /Truncated tar/);
  const badOctal = header('x');
  badOctal.write('zz', 124);
  assert.throws(() => tar.readTar(badOctal), /./);
  const emptySize = header('x');
  emptySize.fill(0x20, 124, 136);
  let emptySum = 0;
  for (let i = 0; i < 512; i++) {
    emptySum += (i >= 148 && i < 156) ? 32 : emptySize[i];
  }

  emptySize.write(`${emptySum.toString(8).padStart(6, '0')}\0 `, 148);
  assert.equal(tar.readTar(emptySize)[0].size, 0);
  // A header without a type flag byte is a regular file.
  const noType = header('plain.txt', {size: 0, type: '\0'});
  assert.equal(tar.readTar(noType)[0].type, '0');

  assert.equal(tar.safeMemberPath('./a//b/'), 'a/b');
  assert.equal(tar.safeMemberPath('a/../b'), null);
  assert.equal(tar.safeMemberPath('./'), null);
  assert.equal(tar.safeMemberPath(String.raw`a\b`), 'a/b');

  assert.deepEqual(tar.parsePax(Buffer.from('12 path=a.b\n11 novalue\n')), {path: 'a.b'});
  assert.deepEqual(tar.parsePax(Buffer.from('noseparator')), {});
  assert.throws(() => tar.parsePax(Buffer.from('99 path=x\n')), /Malformed pax/);
  assert.throws(() => zlib.gunzipSync(Buffer.alloc(10)), /./);
  assert.throws(() => tar.readGzipTarFiles(zlib.gzipSync(Buffer.alloc(4096)), {maxUncompressedBytes: 1024}), /./);
});

// ─── http ───────────────────────────────────────────────────────────

test('httpGet fetches, follows redirects, and strips credentials across hosts', async t => {
  const other = await startServer(t, {'/final': {body: 'done'}});
  const server = await startServer(t, {
    '/ok': {body: 'hello'},
    '/json': {body: '{"a":1}', headers: {'content-type': 'application/json'}},
    '/same-host': {status: 302, headers: {location: '/ok'}},
    '/cross-host': {status: 301, headers: {location: `${other.url.replace('127.0.0.1', 'localhost')}/final`}},
    '/loop': {status: 302, headers: {location: '/loop'}},
  });
  assert.equal((await httpGet(`${server.url}/ok`)).toString(), 'hello');
  assert.deepEqual(await httpGetJson(`${server.url}/json`), {a: 1});
  assert.equal((await httpGet(`${server.url}/same-host`, {headers: {Authorization: 'token secret'}})).toString(), 'hello');
  assert.equal(server.requests.at(-1).headers.authorization, 'token secret');
  assert.equal((await httpGet(`${server.url}/cross-host`, {
    headers: {
      Authorization: 'token secret', Cookie: 'session=1', 'Proxy-Authorization': 'basic x', 'X-Other': '1',
    },
  })).toString(), 'done');
  assert.equal(other.requests.at(-1).headers.authorization, undefined);
  assert.equal(other.requests.at(-1).headers.cookie, undefined);
  assert.equal(other.requests.at(-1).headers['proxy-authorization'], undefined);
  assert.equal(other.requests.at(-1).headers['x-other'], '1');
  await assert.rejects(httpGet(`${server.url}/loop`, {maxRedirects: 2}), /Too many redirects/);
});

test('httpGet refuses plain HTTP to non-loopback hosts', async () => {
  assert.throws(() => assertAllowedUrl(new URL('http://example.com/')), /non-HTTPS/);
  assert.throws(() => assertAllowedUrl(new URL('ftp://127.0.0.1/')), /non-HTTPS/);
  assertAllowedUrl(new URL('https://example.com/'));
  assertAllowedUrl(new URL('http://[::1]:1/'));
  await assert.rejects(httpGet('http://example.com/'), /non-HTTPS/);
});

test('isPrivateAddress: every non-public range, also inside IPv6 forms', () => {
  const private_ = [
    '127.0.0.1',
    '127.255.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '100.64.0.1',
    '100.127.255.255',
    '169.254.169.254',
    '0.0.0.0',
    '0.1.2.3',
    '192.0.0.8',
    '198.18.0.1',
    '198.19.255.255',
    '224.0.0.1',
    '240.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '[::1]',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::FFFF:169.254.169.254',
    '0:0:0:0:0:ffff:10.0.0.1',
    '::127.0.0.1',
    '::10.0.0.1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'fe80::1%eth0',
    'febf::1',
    'fec0::1',
    'ff02::1',
    '64:ff9b::7f00:1',
    '64:ff9b::10.0.0.1',
    '64:ff9b:1::1',
    '2002:7f00:1::',
    '2002:a00:1::1',
    'example.com',
    'localhost',
    '',
    '1.2.3',
  ];
  const public_ = ['8.8.8.8', '1.1.1.1', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '169.253.0.1', '192.0.2.1', '198.17.0.1', '223.255.255.255', '::ffff:8.8.8.8', '2001:4860:4860::8888', '[2606:4700::1111]', '64:ff9b::808:808', '2002:808:808::', '1::', '2001:db8:0:0:0:0:0:1'];
  for (const address of private_) {
    assert.equal(isPrivateAddress(address), true, address);
  }

  for (const address of public_) {
    assert.equal(isPrivateAddress(address), false, address);
  }
});

test('privateAddressLookup refuses names that resolve to private addresses, one address or all of them', async () => {
  const resolve = (lookup, ...args) => new Promise(resolve => {
    lookup(...args, (error, address, family) => resolve({error, address, family}));
  });
  const fake = answers => (hostname, options, callback) => callback(null, ...(options.all ? [answers.map(address => ({address, family: 4}))] : [answers[0], 4]));
  assert.deepEqual(await resolve(privateAddressLookup(fake(['8.8.8.8'])), 'public.test', {}), {error: null, address: '8.8.8.8', family: 4});
  assert.deepEqual((await resolve(privateAddressLookup(fake(['8.8.8.8', '1.1.1.1'])), 'public.test', {all: true})).address, [{address: '8.8.8.8', family: 4}, {address: '1.1.1.1', family: 4}]);
  // Without options, as dns.lookup(hostname, callback).
  assert.equal((await resolve(privateAddressLookup(fake(['8.8.8.8'])), 'public.test')).address, '8.8.8.8');
  const refused = await resolve(privateAddressLookup(fake(['127.0.0.1'])), 'internal.test', {});
  assert.equal(refused.error.code, 'EPRIVATEADDRESS');
  assert.match(refused.error.message, /internal\.test: it resolves to a private address \(127\.0\.0\.1\)/);
  // One private address among public ones is enough to refuse.
  assert.equal((await resolve(privateAddressLookup(fake(['8.8.8.8', '10.0.0.1'])), 'mixed.test', {all: true})).error.code, 'EPRIVATEADDRESS');
  const failing = (hostname, options, callback) => callback(Object.assign(new Error('not found'), {code: 'ENOTFOUND'}));
  assert.equal((await resolve(privateAddressLookup(failing), 'missing.test', {})).error.code, 'ENOTFOUND');
  // A resolver answering with no address at all.
  assert.equal((await resolve(privateAddressLookup(fake([])), 'empty.test', {})).error.code, 'ENOTFOUND');
  // The system resolver by default.
  assert.equal((await resolve(privateAddressLookup(), 'localhost', {})).error.code, 'EPRIVATEADDRESS');
  assert.deepEqual(connectOptions({}), {});
  const lookup = () => {};
  assert.deepEqual(connectOptions({lookup}), {lookup});
  assert.equal(connectOptions({denyPrivateAddresses: true}).agent, false);
});

test('httpGet with denyPrivateAddresses: checked when connecting, so neither a literal, a rebound name nor a redirect reaches a private address', async t => {
  const internal = await startServer(t, {'/secret': {body: 'metadata credentials'}});
  const {port} = new URL(internal.url);
  const options = {denyPrivateAddresses: true, allowHttp: true, maxRetries: 0};
  // Literal addresses are connected to without a lookup.
  for (const host of ['127.0.0.1', '[::1]', '[::ffff:127.0.0.1]', '127.1', '0x7f.1', '2130706433', 'localhost']) {
    await assert.rejects(httpGet(`http://${host}:${port}/secret`, options), error => error.code === 'EPRIVATEADDRESS', host);
  }

  assert.throws(() => assertAllowedUrl(new URL('https://10.0.0.1/'), {denyPrivateAddresses: true}), /Refusing to connect to a private address: 10\.0\.0\.1/);
  assertAllowedUrl(new URL('https://8.8.8.8/'), {denyPrivateAddresses: true});
  // A name the resolver maps to a private address.
  const names = {'internal.test': '127.0.0.1'};
  const lookup = (hostname, lookupOptions, callback) => {
    const address = names[hostname];
    if (lookupOptions.all) {
      callback(null, [{address, family: 4}]);
    } else {
      callback(null, address, 4);
    }
  };

  await assert.rejects(httpGet(`http://internal.test:${port}/secret`, {...options, lookup}), /Refusing to connect to internal\.test: it resolves to a private address \(127\.0\.0\.1\)/);
  // Without the option the same resolver is used, and nothing is refused.
  assert.equal((await httpGet(`http://internal.test:${port}/secret`, {allowHttp: true, lookup})).toString(), 'metadata credentials');
  assert.equal(internal.requests.length, 1);

  // A public address of this machine (not loopback or private), if it has
  // one, stands for a public server.
  const publicAddress = Object.values(require('node:os').networkInterfaces()).flat().find(item => item.family === 'IPv4' && !isPrivateAddress(item.address))?.address;
  await t.test('rebinding and redirects', {skip: !publicAddress && 'this machine has no public IPv4 address'}, async () => {
    const server = require('node:http').createServer((request, response) => {
      if (request.url === '/redirect-name') {
        response.writeHead(302, {location: `http://internal.test:${port}/secret`});
      } else if (request.url === '/redirect-literal') {
        response.writeHead(302, {location: `http://127.0.0.1:${port}/secret`});
      }

      response.end('public');
    });
    await new Promise(resolve => {
      server.listen(0, '0.0.0.0', resolve);
    });
    t.after(() => server.close());
    const publicPort = server.address().port;
    let answers = 0;
    names['public.test'] = publicAddress;
    const rebinding = (hostname, lookupOptions, callback) => {
      // The name resolves to the public address first, then to loopback.
      lookup(hostname === 'rebind.test' ? (answers++ === 0 ? 'public.test' : 'internal.test') : hostname, lookupOptions, callback);
    };

    assert.equal((await httpGet(`http://public.test:${publicPort}/`, {...options, lookup})).toString(), 'public');
    assert.equal((await httpGet(`http://rebind.test:${publicPort}/`, {...options, lookup: rebinding})).toString(), 'public');
    await assert.rejects(httpGet(`http://rebind.test:${publicPort}/`, {...options, lookup: rebinding}), error => error.code === 'EPRIVATEADDRESS');
    await assert.rejects(httpGet(`http://public.test:${publicPort}/redirect-name`, {...options, lookup}), /internal\.test: it resolves to a private address/);
    await assert.rejects(httpGet(`http://public.test:${publicPort}/redirect-literal`, {...options, lookup}), /Refusing to connect to a private address: 127\.0\.0\.1/);
    assert.equal(internal.requests.length, 1);
  });
});

test('httpGet retries 429 and 5xx with back-off, honoring Retry-After', async t => {
  let calls = 0;
  const server = await startServer(t, {
    '/flaky'(request, response) {
      calls++;
      if (calls === 1) {
        response.writeHead(429, {'retry-after': '0.05'});
        response.end();
      } else if (calls === 2) {
        response.writeHead(503);
        response.end();
      } else {
        response.end('recovered');
      }
    },
    '/down': {status: 500},
    '/missing': {status: 404},
  });
  assert.equal((await httpGet(`${server.url}/flaky`, {retryDelay: 1})).toString(), 'recovered');
  assert.equal(calls, 3);
  await assert.rejects(httpGet(`${server.url}/down`, {retryDelay: 1, maxRetries: 1}), {statusCode: 500});
  await assert.rejects(httpGet(`${server.url}/missing`, {retryDelay: 1}), {statusCode: 404, retryable: false});
});

test('httpGet retries a download cut off mid-body (a proxy or mirror resetting the connection)', async t => {
  let calls = 0;
  const server = await startServer(t, {
    '/package.deb'(request, response) {
      calls++;
      response.writeHead(200, {'content-length': '1000'});
      if (calls === 1) {
        response.write('x'.repeat(10));
        setTimeout(() => response.socket.destroy(), 20);
        return;
      }

      response.end('y'.repeat(1000));
    },
  });
  assert.equal((await httpGet(`${server.url}/package.deb`, {retryDelay: 1})).toString(), 'y'.repeat(1000));
  assert.equal(calls, 2);
});

test('httpGet enforces size limits and timeouts', async t => {
  const server = await startServer(t, {
    '/declared': {body: 'x'.repeat(100), headers: {'content-length': '100'}},
    '/streamed'(request, response) {
      response.writeHead(200);
      response.write('x'.repeat(60));
      response.end('y'.repeat(60));
    },
    '/slow'(request, response) {
      setTimeout(() => {
        response.end('late');
      }, 500);
    },
  });
  await assert.rejects(httpGet(`${server.url}/declared`, {maxBytes: 10}), /too large/);
  await assert.rejects(httpGet(`${server.url}/streamed`, {maxBytes: 100}), /exceeded 100 bytes/);
  await assert.rejects(httpGet(`${server.url}/slow`, {timeout: 50, maxRetries: 0}), /Timeout/);
});

test('httpGet retries refused connections, then gives up', async () => {
  const net = require('node:net');
  const probe = net.createServer();
  await new Promise(resolve => {
    probe.listen(0, '127.0.0.1', resolve);
  });
  const {port} = probe.address();
  await new Promise(resolve => {
    probe.close(resolve);
  });
  await assert.rejects(httpGet(`http://127.0.0.1:${port}/`, {maxRetries: 1, retryDelay: 1}), {code: 'ECONNREFUSED'});
  await assert.rejects(httpGet('http://localhost:0/', {maxRetries: 0}), /./);
});

test('httpGet verifies TLS certificates (a self-signed server is rejected)', {skip: !hasOpenssl && 'OpenSSL is not installed'}, async t => {
  const https = require('node:https');
  const directory = tempDir(t);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', path.join(directory, 'key.pem'), '-out', path.join(directory, 'cert.pem')], {stdio: 'ignore'});
  const options = {key: fs.readFileSync(path.join(directory, 'key.pem')), cert: fs.readFileSync(path.join(directory, 'cert.pem'))};
  const servers = await listenOnLoopback(() => https.createServer(options, (request, response) => {
    response.end('should never be read');
  }));
  t.after(() => Promise.all(servers.map(server => new Promise(resolve => {
    server.close(resolve);
  }))));
  await assert.rejects(httpGet(`https://localhost:${servers[0].address().port}/`, {maxRetries: 0}), {code: 'DEPTH_ZERO_SELF_SIGNED_CERT'});
});

test('walkTree reports a file that changes while it is being hashed', async t => {
  const directory = tempDir(t);
  const file = path.join(directory, 'growing.bin');
  fs.writeFileSync(file, Buffer.alloc(2 * 1024 * 1024));
  const originalRead = fs.read;
  let appended = false;
  t.mock.method(fs, 'read', (...args) => {
    if (!appended) {
      appended = true;
      fs.appendFileSync(file, 'more');
    }

    return Reflect.apply(originalRead, fs, args);
  });
  const {entries, errors} = await fileTree.walkTree(directory);
  assert.deepEqual(entries, []);
  assert.match(errors[0].error, /File changed while hashing/);
});

test('tar reader rejects non-octal numeric fields', () => {
  const block = header('x.txt');
  block.write('9z', 124);
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += (i >= 148 && i < 156) ? 32 : block[i];
  }

  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  assert.throws(() => tar.readTar(block), /Invalid octal field/);
});

test('httpGet over HTTPS: trusted CA, and no downgrade to HTTP on redirect', {skip: !hasOpenssl && 'OpenSSL is not installed'}, async t => {
  const https = require('node:https');
  const directory = tempDir(t);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', path.join(directory, 'key.pem'), '-out', path.join(directory, 'cert.pem')], {stdio: 'ignore'});
  const cert = fs.readFileSync(path.join(directory, 'cert.pem'));
  const plain = await startServer(t, {'/plain': {body: 'downgraded'}});
  const server = https.createServer({key: fs.readFileSync(path.join(directory, 'key.pem')), cert}, (request, response) => {
    if (request.url === '/down') {
      response.writeHead(302, {location: `${plain.url}/plain`, 'set-cookie': 'x=1'});
      response.end();
      return;
    }

    response.end('secure');
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.close(resolve);
  }));
  const url = `https://127.0.0.1:${server.address().port}`;
  assert.equal((await httpGet(`${url}/ok`, {ca: cert})).toString(), 'secure');
  await assert.rejects(httpGet(`${url}/ok`, {maxRetries: 0}), /self-signed|unable to verify|certificate/i);
  await assert.rejects(httpGet(`${url}/down`, {ca: cert, headers: {Cookie: 'session=1'}}), /Refusing to follow a redirect from HTTPS to http:\/\/127\.0\.0\.1/);
  assert.equal(plain.requests.length, 0);
});

test('tar hard links resolve to the linked member; symlinks differ from files in manifests', t => {
  const archive = makeTarGz(t, {'package/a.js': 'shared\n'}, {format: 'pax', hardlinks: {'package/b.js': 'package/a.js'}});
  const files = tar.readGzipTarFiles(archive, {stripFirstComponent: true});
  assert.equal(files.get('a.js').toString(), 'shared\n');
  assert.equal(files.get('b.js').toString(), 'shared\n');
  assert.ok(tar.readTar(zlib.gunzipSync(archive)).some(entry => entry.type === '1'), 'stored as a hard link');
  // Long link targets are carried in a pax header.
  const long = `package/${'d'.repeat(120)}`;
  const longArchive = makeTarGz(t, {'package/a.js': 'shared\n', [`${long}/original.js`]: 'long\n'}, {format: 'pax', hardlinks: {[`${long}/copy.js`]: `${long}/original.js`}});
  const longFiles = tar.readGzipTarFiles(longArchive, {stripFirstComponent: true});
  assert.equal(longFiles.get(`${'d'.repeat(120)}/copy.js`).toString(), 'long\n');

  const file = [{path: 'x', sha256: util.sha256('target')}];
  const link = [{path: 'x', sha256: util.sha256('target'), type: 'symlink'}];
  assert.notEqual(fileTree.manifestDigest(file), fileTree.manifestDigest(link));
  assert.equal(fileTree.manifestDigest(file), fileTree.manifestDigest([{...file[0], type: 'file'}]));
});

test('tar reader reads archives the way installers do: pax sizes, GNU long links and GNU headers, and refuses a lone zero block', () => {
  const reseal = block => {
    block.write('        ', 148);
    let sum = 0;
    for (const byte of block) {
      sum += byte;
    }

    block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
    return block;
  };

  const evil = Buffer.from('require("child_process").exec("id")\n');
  const benign = Buffer.from('module.exports = 1;\n');
  const end = Buffer.alloc(1024);

  // Readers that stop at the first zero block see the benign file; npm's
  // tar reads on and installs the other one last.
  const smuggled = Buffer.concat([header('package/index.js', {size: benign.length}), pad(benign), Buffer.alloc(512), header('package/index.js', {size: evil.length}), pad(evil), end]);
  assert.throws(() => tar.readTar(smuggled), /entries after a zero block/);
  assert.throws(() => tar.readGzipTarFiles(zlib.gzipSync(smuggled)), /entries after a zero block/);
  // Padding after the end is fine.
  assert.equal(tar.readTar(Buffer.concat([header('a', {size: 0}), end, Buffer.alloc(8192)])).length, 1);

  // A pax size replaces the header's: data the header would hide is an entry.
  const pax = Buffer.from('10 size=0\n');
  const hidden = Buffer.concat([header('package/hidden.js', {size: evil.length}), pad(evil)]);
  const paxArchive = Buffer.concat([
    header('PaxHeader', {type: 'x', size: pax.length}),
    pad(pax),
    header('package/empty.js', {size: hidden.length}),
    hidden,
    end,
  ]);
  assert.deepEqual([...tar.readGzipTarFiles(zlib.gzipSync(paxArchive)).keys()].sort(), ['package/empty.js', 'package/hidden.js']);
  const badPax = Buffer.from('12 size=-1x\n');
  assert.throws(() => tar.readTar(Buffer.concat([header('PaxHeader', {type: 'x', size: badPax.length}), pad(badPax), header('a'), end])), /Invalid pax size/);

  // GNU long link names ('K') for link targets over 100 bytes.
  const target = `${'t'.repeat(150)}/file`;
  const longLink = Buffer.from(`${target}\0`);
  const links = tar.readTar(Buffer.concat([header('././@LongLink', {type: 'K', size: longLink.length}), pad(longLink), header('package/link', {type: '2'}), header('package/plain', {type: '2'}), end]));
  assert.equal(links[0].linkName, target);
  assert.equal(links[1].linkName, '');

  // A GNU header ("ustar  ") keeps access and change times where ustar
  // keeps a name prefix.
  const gnu = header('package/a.js', {size: 0});
  gnu.write('ustar  \0', 257);
  gnu.write('14000000000\0', 345);
  assert.equal(tar.readTar(reseal(gnu))[0].name, 'package/a.js');
  const ustar = header('a.js', {size: 0});
  ustar.write('package', 345);
  assert.equal(tar.readTar(reseal(ustar))[0].name, 'package/a.js');

  // An old-style directory: a file entry whose name ends in "/".
  assert.deepEqual([...tar.readGzipTarFiles(zlib.gzipSync(Buffer.concat([header('package/dir/', {size: 0}), header('package/dir/x', {size: 0}), end]))).keys()], ['package/dir/x']);
});

test('httpGet bounds a response that never ends, however steadily it trickles', async t => {
  const server = await startServer(t, {
    '/drip'(request, response) {
      response.writeHead(200);
      const timer = setInterval(() => response.write('x'), 20);
      response.on('close', () => clearInterval(timer));
    },
  });
  const started = Date.now();
  await assert.rejects(httpGet(`${server.url}/drip`, {timeout: 1000, deadline: 300, maxRetries: 0}), /Deadline of 300 ms exceeded fetching/);
  assert.ok(Date.now() - started < 5000);
});

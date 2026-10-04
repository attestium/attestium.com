'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  DpkgDatabase, ArchiveReference, parseStanzas, aliases, osRelease, defaultArchives,
} = require('../lib/distro');
const {ReferenceStore} = require('../lib/ecosystems/common');
const {tempDir, writeFiles, windows} = require('./helpers');
const {
  sha256, hasDebianTools, makeGpgKey, buildDeb, writeAptSuite, serveDirectory, makeDpkgRoot,
} = require('./system-helpers');

// ─── attester: the dpkg database ────────────────────────────────────────

test('aliases: merged-/usr paths are looked up with and without /usr', () => {
  assert.deepEqual(aliases('/usr/lib/x86_64-linux-gnu/libc.so.6'), ['/usr/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libc.so.6']);
  assert.deepEqual(aliases('/bin/sh'), ['/bin/sh', '/usr/bin/sh']);
  assert.deepEqual(aliases('/etc/passwd'), ['/etc/passwd']);
  assert.deepEqual(aliases('/usr/share/doc/x'), ['/usr/share/doc/x']);
});

test('parseStanzas: fields, continuation lines and stanza boundaries', () => {
  const text = [
    '',
    'Package: a',
    'Description: first line',
    ' second line',
    'not a field',
    ':no name',
    '',
    '',
    'Package: b',
    'Version: 1:2.0-1',
  ].join('\n');
  assert.deepEqual(parseStanzas(text), [
    {Package: 'a', Description: 'first line\nsecond line'},
    {Package: 'b', Version: '1:2.0-1'},
  ]);
  // A continuation line before any field is ignored.
  assert.deepEqual(parseStanzas(' orphan\nPackage: c\n'), [{Package: 'c'}]);
  assert.deepEqual(parseStanzas(''), []);
});

test('DpkgDatabase: installed packages and file owners', {skip: windows && 'dpkg names files with colons, which Windows file names cannot hold'}, t => {
  const root = makeDpkgRoot(t, [
    {
      name: 'coreutils', version: '9.4-3', arch: 'amd64', files: ['/usr/bin/ls', '/bin/cat'],
    },
    {
      name: 'libfoo1', version: '1.0-1', arch: 'amd64', multiArch: 'same', source: 'foo (1.0-0)', files: ['/usr/lib/x86_64-linux-gnu/libfoo.so.1'],
    },
    {
      name: 'removed', version: '1', arch: 'all', status: 'deinstall ok config-files', files: ['/etc/removed.conf'],
    },
  ]);
  // Status lines without a package, or without a status, are not installed packages.
  fs.appendFileSync(path.join(root, 'var/lib/dpkg/status'), '\nStatus: install ok installed\n\nPackage: nostatus\nVersion: 1\n');
  // A list file named with an architecture for a package that is not Multi-Arch: same.
  writeFiles(root, {'var/lib/dpkg/info/coreutils:amd64.list': '/usr/bin/dir\n/usr/bin/ls\n'});
  // A list file for a package that is not installed.
  writeFiles(root, {'var/lib/dpkg/info/ghost.list': '/usr/bin/ghost\n'});
  const listed = new Date('2024-01-02T03:04:05.000Z');
  fs.utimesSync(path.join(root, 'var/lib/dpkg/info/coreutils.list'), listed, listed);

  const database = new DpkgDatabase({root});
  assert.equal(database.available(), true);
  assert.deepEqual([...database.packages().keys()].sort(), ['coreutils', 'libfoo1:amd64']);
  assert.equal(database.packages(), database.packages());
  assert.deepEqual(database.packages().get('libfoo1:amd64'), {
    name: 'libfoo1', version: '1.0-1', arch: 'amd64', source: 'foo',
  });

  assert.deepEqual(database.ownerOf('/usr/bin/cat'), {
    name: 'coreutils', version: '9.4-3', arch: 'amd64', source: null, listedAs: '/bin/cat', installedAt: listed.toISOString(),
  });
  assert.equal(database.ownerOf('/lib/x86_64-linux-gnu/libfoo.so.1').name, 'libfoo1');
  // The first list naming a file owns it.
  assert.equal(database.owners().get('/usr/bin/ls'), 'coreutils');
  assert.equal(database.ownerOf('/usr/bin/dir').name, 'coreutils');
  assert.equal(database.ownerOf('/usr/bin/ghost'), null);
  assert.equal(database.ownerOf('/etc/removed.conf'), null);
  assert.equal(database.ownerOf('/opt/unowned'), null);

  // The list file's time is when the package was installed; without it, no time.
  fs.rmSync(path.join(root, 'var/lib/dpkg/info/coreutils.list'));
  assert.equal(database.ownerOf('/usr/bin/ls').installedAt, null);
});

test('DpkgDatabase: a root without dpkg', t => {
  const root = tempDir(t);
  const database = new DpkgDatabase({root});
  assert.equal(database.available(), false);
  assert.equal(database.owners().size, 0);
  assert.equal(database.ownerOf('/bin/sh'), null);
  assert.equal(new DpkgDatabase().root, '/');
});

test('osRelease: /etc/os-release, then /usr/lib/os-release', t => {
  const root = tempDir(t);
  writeFiles(root, {'usr/lib/os-release': 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n# comment\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'});
  assert.deepEqual(osRelease(root), {id: 'debian', versionId: '12', codename: 'bookworm'});
  writeFiles(root, {'etc/os-release': 'NAME="Alpine Linux"\nID=alpine\n'});
  assert.deepEqual(osRelease(root), {id: 'alpine', versionId: null, codename: null});
  writeFiles(root, {'etc/os-release': 'NAME=""\n'});
  assert.deepEqual(osRelease(root), {id: null, versionId: null, codename: null});
  assert.equal(osRelease(tempDir(t)), null);
  const system = osRelease();
  assert.ok(system === null || 'id' in system);
});

test('defaultArchives: Ubuntu, Ubuntu ports, Debian and others', () => {
  const [ubuntu] = defaultArchives({id: 'ubuntu', codename: 'noble'}, 'amd64');
  assert.equal(ubuntu.url, 'http://archive.ubuntu.com/ubuntu');
  assert.deepEqual(ubuntu.suites, ['noble', 'noble-updates', 'noble-security']);
  assert.equal(ubuntu.snapshot, 'https://snapshot.ubuntu.com/ubuntu');
  assert.equal(defaultArchives({id: 'ubuntu', codename: 'noble'}, 'i386')[0].url, 'http://archive.ubuntu.com/ubuntu');
  const [ports] = defaultArchives({id: 'ubuntu', codename: 'noble'}, 'arm64');
  assert.equal(ports.url, 'http://ports.ubuntu.com/ubuntu-ports');
  assert.equal(ports.snapshot, 'https://snapshot.ubuntu.com/ubuntu-ports');
  const debian = defaultArchives({id: 'debian', codename: 'bookworm'}, 'amd64');
  assert.deepEqual(debian.map(archive => archive.suites), [['bookworm', 'bookworm-updates'], ['bookworm-security']]);
  assert.equal(debian[1].snapshot, 'https://snapshot.debian.org/archive/debian-security');
  assert.deepEqual(defaultArchives({id: 'alpine', codename: null}, 'amd64'), []);
});

// ─── verifier: signed archives ──────────────────────────────────────────

const LS = Buffer.from('#!/bin/sh\necho ls\n');
const LS_OLD = Buffer.from('#!/bin/sh\necho old ls\n');

test('ArchiveReference: installed files against a signed archive', {skip: !hasDebianTools}, async t => {
  const key = makeGpgKey(t);
  const root = tempDir(t, 'attestium-apt-');
  // The current archive: coreutils 9.4-3 and an architecture-independent package.
  writeAptSuite(t, {
    root: path.join(root, 'current'),
    key,
    packages: [
      {
        name: 'coreutils', version: '9.4-3', arch: 'amd64', files: {'/usr/bin/ls': LS}, symlinks: {'/usr/bin/dir': 'ls'},
      },
      {
        name: 'data', version: '1', arch: 'all', indexArch: 'arm64', files: {'/usr/share/data/file': 'data'},
      },
      {
        name: 'tampered', version: '1', arch: 'amd64', files: {'/usr/bin/t': 't'}, indexSha256: 'ab'.repeat(32),
      },
    ],
  });
  // A suite whose release file does not match its package index.
  writeAptSuite(t, {
    root: path.join(root, 'current'),
    key,
    suite: 'broken',
    packages: [{
      name: 'x', version: '1', arch: 'amd64', files: {'/x': 'x'},
    }],
    release: `Suite: broken\nSHA256:\n ${'00'.repeat(32)} 10 main/binary-amd64/Packages.gz\n`,
  });
  // A suite whose release file lists no hashes.
  writeAptSuite(t, {
    root: path.join(root, 'current'), key, suite: 'empty', packages: [{
      name: 'y', version: '1', arch: 'amd64', files: {'/y': 'y'},
    }], release: '',
  });
  // Snapshots: 9.4-2 in the one from the hour after it was installed, 9.4-1 a day later.
  writeAptSuite(t, {
    root: path.join(root, 'snapshot/20240102T040000Z'), key, packages: [{
      name: 'coreutils', version: '9.4-2', arch: 'amd64', files: {'/usr/bin/ls': LS_OLD},
    }],
  });
  writeAptSuite(t, {
    root: path.join(root, 'snapshot/20240106T000000Z'), key, packages: [{
      name: 'coreutils', version: '9.4-1', arch: 'amd64', files: {'/usr/bin/ls': LS_OLD},
    }],
  });
  const server = await serveDirectory(t, root);

  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const archive = {
    url: `${server.url}/current`, suites: ['test', 'missing'], components: ['main'], keyring: key.keyring, snapshot: `${server.url}/snapshot`,
  };
  const reference = new ArchiveReference({archives: [archive], store});

  // An installed file compared with the one in its package.
  const dpkg = makeDpkgRoot(t, [{
    name: 'coreutils', version: '9.4-3', arch: 'amd64', files: ['/usr/bin/ls', '/usr/bin/dir'],
  }]);
  writeFiles(dpkg, {'usr/bin/ls': LS});
  const owner = new DpkgDatabase({root: dpkg}).ownerOf('/usr/bin/ls');
  const files = await reference.files(owner.name, owner.version, owner.arch, owner.installedAt);
  assert.deepEqual(files, {'/usr/bin/ls': sha256(LS), '/usr/bin/dir': 'symlink:ls'});
  assert.equal(files['/usr/bin/ls'], sha256(fs.readFileSync(path.join(dpkg, 'usr/bin/ls'))));
  // Computed once per store.
  assert.equal(await reference.files('coreutils', '9.4-3', 'amd64'), files);

  assert.deepEqual(await reference.locate('coreutils', '9.4-3', 'amd64'), {
    url: `${archive.url}/pool/main/coreutils_9.4-3_amd64.deb`, filename: 'pool/main/coreutils_9.4-3_amd64.deb', sha256: sha256(fs.readFileSync(path.join(root, 'current/pool/main/coreutils_9.4-3_amd64.deb'))),
  });
  // The versions published for an architecture, and the contents of a package's regular files.
  assert.deepEqual(await reference.versions('coreutils', 'amd64'), ['9.4-3']);
  assert.deepEqual(await reference.versions('data', 'arm64'), ['1']);
  assert.deepEqual(await reference.versions('data', 'all'), ['1']);
  assert.deepEqual(await reference.versions('coreutils', 'arm64'), []);
  assert.deepEqual([...await reference.contents('coreutils', '9.4-3', 'amd64', () => true)], [['/usr/bin/ls', LS]]);
  assert.deepEqual([...await reference.contents('coreutils', '9.4-3', 'amd64', file => file !== '/usr/bin/ls')], []);
  await assert.rejects(reference.contents('coreutils', '9.0-1', 'amd64', () => true), error => error.code === 'ENOTINARCHIVE');
  assert.equal(reference.cacheKey(), `${archive.url} ${key.keyring}`);
  // Architecture-independent packages are listed in each architecture's index.
  assert.deepEqual(await reference.files('data', '1', 'all'), {'/usr/share/data/file': sha256('data')});
  assert.equal(await reference.locate('data', '2', 'all'), null);
  // And found by an installed package's own architecture.
  assert.equal((await reference.locate('data', '1', 'arm64')).filename, 'pool/main/data_1_all.deb');

  // A superseded version, from the snapshot of when it was installed.
  assert.equal(await reference.locate('coreutils', '9.4-2', 'amd64'), null);
  const old = await reference.locate('coreutils', '9.4-2', 'amd64', '2024-01-02T03:04:05.000Z');
  assert.equal(old.url, `${server.url}/snapshot/20240102T040000Z/pool/main/coreutils_9.4-2_amd64.deb`);
  // Or the one a day later.
  const older = await reference.locate('coreutils', '9.4-1', 'amd64', '2024-01-05T00:00:00.000Z');
  assert.equal(older.url, `${server.url}/snapshot/20240106T000000Z/pool/main/coreutils_9.4-1_amd64.deb`);
  assert.deepEqual(await reference.files('coreutils', '9.4-2', 'amd64', '2024-01-02T03:04:05.000Z'), {'/usr/bin/ls': sha256(LS_OLD)});
  assert.equal(await reference.locate('coreutils', '9.4-0', 'amd64', '2024-01-02T03:04:05.000Z'), null);

  // Not in any archive.
  await assert.rejects(reference.files('coreutils', '9.0-1', 'amd64'), error => error.code === 'ENOTINARCHIVE' && /not in the configured archives/.test(error.message));
  // Archives without a snapshot are not looked up in snapshots.
  const noSnapshot = new ArchiveReference({archives: [{...archive, snapshot: undefined}], store: new ReferenceStore()});
  assert.equal(await noSnapshot.locate('coreutils', '9.4-2', 'amd64', '2024-01-02T03:04:05.000Z'), null);

  // A package whose contents do not match the signed index.
  await assert.rejects(reference.files('tampered', '1', 'amd64'), /tampered_1_amd64\.deb does not match the archive's index/);

  // A package index that does not match the signed release file.
  const broken = new ArchiveReference({archives: [{...archive, suites: ['broken']}], store});
  await assert.rejects(broken.locate('x', '1', 'amd64'), /broken\/main\/binary-amd64\/Packages\.gz does not match the signed release file/);
  await assert.rejects(broken.versions('x', 'amd64'), /does not match the signed release file/);
  // A release file listing no index.
  const empty = new ArchiveReference({archives: [{...archive, suites: ['empty']}], store});
  assert.equal(await empty.locate('y', '1', 'amd64'), null);

  // Dpkg-deb failing.
  const noDpkgDeb = new ArchiveReference({archives: [archive], store: new ReferenceStore(), dpkgDeb: path.join(root, 'no-dpkg-deb')});
  await assert.rejects(noDpkgDeb.files('coreutils', '9.4-3', 'amd64'), /no-dpkg-deb failed: .*ENOENT/);
});

test('maintainer scripts dpkg keeps and runs are their package\'s, compared with its control archive', {skip: !hasDebianTools}, async t => {
  const root = tempDir(t);
  const key = makeGpgKey(t);
  const postinst = '#!/bin/sh\nset -e\nldconfig\n';
  writeAptSuite(t, {
    root: path.join(root, 'current'),
    key,
    packages: [{
      name: 'libbar1', version: '2.0-1', arch: 'amd64', files: {'/usr/lib/libbar.so.1': 'bar'}, scripts: {postinst, prerm: '#!/bin/sh\n'},
    }],
  });
  const server = await serveDirectory(t, root);
  const archive = {
    url: `${server.url}/current`, suites: ['test'], components: ['main'], keyring: key.keyring,
  };
  const reference = new ArchiveReference({archives: [archive], store: new ReferenceStore({httpOptions: {maxRetries: 0}})});
  const dpkg = makeDpkgRoot(t, [{
    name: 'libbar1', version: '2.0-1', arch: 'amd64', multiArch: 'same', files: ['/usr/lib/libbar.so.1'],
  }]);
  const database = new DpkgDatabase({root: dpkg});
  // Named with the architecture for a Multi-Arch: same package, as dpkg does.
  const owner = database.ownerOf('/var/lib/dpkg/info/libbar1:amd64.postinst');
  assert.deepEqual({...owner, installedAt: null}, {
    name: 'libbar1', version: '2.0-1', arch: 'amd64', source: null, listedAs: '/DEBIAN/postinst', installedAt: null,
  });
  assert.equal(database.ownerOf('/var/lib/dpkg/info/libbar1:amd64.list'), null, 'dpkg\'s own records are not scripts');
  assert.equal(database.ownerOf('/var/lib/dpkg/info/ghost.postinst'), null, 'a script of a package that is not installed');
  const files = await reference.files(owner.name, owner.version, owner.arch);
  assert.deepEqual(files, {'/usr/lib/libbar.so.1': sha256('bar'), '/DEBIAN/postinst': sha256(postinst), '/DEBIAN/prerm': sha256('#!/bin/sh\n')});
  assert.equal(files[owner.listedAs], sha256(postinst));
});

test('ArchiveReference: the release file must be signed by the keyring', {skip: !hasDebianTools}, async t => {
  const key = makeGpgKey(t);
  const other = makeGpgKey(t);
  const root = tempDir(t, 'attestium-apt-');
  writeAptSuite(t, {
    root, key, packages: [{
      name: 'p', version: '1', arch: 'amd64', files: {'/p': 'p'},
    }],
  });
  const server = await serveDirectory(t, root);
  const archive = {
    url: server.url, suites: ['test'], components: ['main'], keyring: other.keyring,
  };
  const reference = new ArchiveReference({archives: [archive], store: new ReferenceStore({httpOptions: {maxRetries: 0}})});
  await assert.rejects(reference.locate('p', '1', 'amd64'), /gpgv failed: .*(?:signature|public key)/i);

  // A failure is not remembered: with the right keyring the same archive verifies.
  archive.keyring = key.keyring;
  assert.equal((await reference.locate('p', '1', 'amd64')).filename, 'pool/main/p_1_amd64.deb');

  // A modified release file fails the signature.
  const inRelease = path.join(root, 'dists/test/InRelease');
  fs.writeFileSync(inRelease, fs.readFileSync(inRelease, 'utf8').replace('Suite: test', 'Suite: tset'));
  const fresh = new ArchiveReference({archives: [archive], store: new ReferenceStore({httpOptions: {maxRetries: 0}})});
  await assert.rejects(fresh.locate('p', '1', 'amd64'), /gpgv failed/);

  // Server errors other than 404 are reported.
  const failing = new ArchiveReference({archives: [{...archive, url: 'http://127.0.0.1:1'}], store: new ReferenceStore({httpOptions: {maxRetries: 0}})});
  await assert.rejects(failing.locate('p', '1', 'amd64'), /ECONNREFUSED/);
});

test('ArchiveReference: a release file signed by a revoked or expired key is refused', {skip: !hasDebianTools}, async t => {
  const packages = [{
    name: 'p', version: '1', arch: 'amd64', files: {'/p': 'p'},
  }];
  const revoked = makeGpgKey(t);
  const expired = makeGpgKey(t, {expired: true});
  const root = tempDir(t, 'attestium-apt-');
  writeAptSuite(t, {root: path.join(root, 'revoked'), key: revoked, packages});
  writeAptSuite(t, {root: path.join(root, 'expired'), key: expired, packages});
  const server = await serveDirectory(t, root);
  const locate = (name, keyring) => new ArchiveReference({
    archives: [{
      url: `${server.url}/${name}`, suites: ['test'], components: ['main'], keyring,
    }],
    store: new ReferenceStore({httpOptions: {maxRetries: 0}}),
  }).locate('p', '1', 'amd64');

  // Accepted while the key is valid.
  assert.equal((await locate('revoked', revoked.keyring)).filename, 'pool/main/p_1_amd64.deb');
  // The publisher revokes the key (a compromise): gpgv still exits with 0.
  revoked.revoke();
  await assert.rejects(locate('revoked', revoked.keyring), /InRelease does not verify \(gpgv\): the signing key is revoked/);
  // A key that expired (in 2020) signed while it was valid.
  await assert.rejects(locate('expired', expired.keyring), /InRelease does not verify \(gpgv\): the signing key has expired/);
});

test('ArchiveReference: only gpgv\'s status descriptor counts, not status-like lines on stdout or stderr', {skip: !hasDebianTools, timeout: 20_000}, async t => {
  const key = makeGpgKey(t);
  const root = tempDir(t, 'attestium-apt-');
  writeAptSuite(t, {
    root, key, packages: [{
      name: 'p', version: '1', arch: 'amd64', files: {'/p': 'p'},
    }],
  });
  const server = await serveDirectory(t, root);
  const bin = tempDir(t);
  // Stand-ins for gpgv: each prints the release file (the last argument).
  const fake = (name, body) => {
    const file = path.join(bin, name);
    fs.writeFileSync(file, `#!/bin/sh\nfor last; do :; done\n${body}\n`, {mode: 0o755});
    return file;
  };

  const locate = gpgv => new ArchiveReference({
    archives: [{
      url: server.url, suites: ['test'], components: ['main'], keyring: key.keyring,
    }],
    store: new ReferenceStore({httpOptions: {maxRetries: 0}}),
    gpgv,
  }).locate('p', '1', 'amd64');

  // Good-signature lines anywhere but the status descriptor (a message that
  // quotes signed data, say) do not make a signature.
  const status = '[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0 k\n[GNUPG:] VALIDSIG 0\n';
  await assert.rejects(locate(fake('stderr', `printf '${status}' >&2\nsed -n '/^Suite/,/^-----BEGIN PGP SIGNATURE/{/^-----/!p}' "$last"`)), /InRelease does not verify \(gpgv\): no good signature/);
  await assert.rejects(locate(fake('stdout', `printf '${status}'`)), /InRelease does not verify \(gpgv\): no good signature/);
  // On descriptor 3 they count (this is what gpgv writes there).
  const trusted = fake('fd3', `printf '${status}' >&3\nsed -n '/^Suite/,/^-----BEGIN PGP SIGNATURE/{/^-----/!p}' "$last"`);
  assert.equal((await locate(trusted)).filename, 'pool/main/p_1_amd64.deb');
  // Dpkg-deb failing is reported with its last message.
  const unpack = new ArchiveReference({
    archives: [{
      url: server.url, suites: ['test'], components: ['main'], keyring: key.keyring,
    }],
    store: new ReferenceStore({httpOptions: {maxRetries: 0}}),
    gpgv: trusted,
    dpkgDeb: fake('dpkg-deb', 'echo "dpkg-deb: error: not a Debian archive" >&2\nexit 2'),
  });
  await assert.rejects(unpack.files('p', '1', 'amd64'), /dpkg-deb failed: dpkg-deb: error: not a Debian archive/);
  // Failures: an exit status, a signal, a missing program.
  await assert.rejects(locate(fake('exit', 'echo "gpgv: bad" >&2\nexit 2')), /exit failed: gpgv: bad/);
  await assert.rejects(locate(fake('quiet', 'exit 2')), /quiet failed: exit code 2/);
  await assert.rejects(locate(fake('killed', 'kill -KILL $$')), /killed failed: killed by SIGKILL/);
  await assert.rejects(locate(path.join(bin, 'missing')), /missing failed: .*ENOENT/);
});

test('ArchiveReference: a package built with dpkg-deb matches its extracted files', {skip: !hasDebianTools}, async t => {
  // The tar members of a real .deb, including directories, are read from dpkg-deb.
  const deb = buildDeb(t, {
    name: 'nested', version: '2', arch: 'amd64', files: {'/usr/lib/nested/a.so': 'a', '/usr/share/doc/nested/copyright': 'c'},
  });
  const key = makeGpgKey(t);
  const root = tempDir(t, 'attestium-apt-');
  writeAptSuite(t, {
    root, key, packages: [{
      name: 'nested', version: '2', arch: 'amd64', deb,
    }],
  });
  const server = await serveDirectory(t, root);
  const reference = new ArchiveReference({
    archives: [{
      url: server.url, suites: ['test'], components: ['main'], keyring: key.keyring,
    }],
    store: new ReferenceStore(),
  });
  assert.deepEqual(await reference.files('nested', '2', 'amd64'), {
    '/usr/lib/nested/a.so': sha256('a'),
    '/usr/share/doc/nested/copyright': sha256('c'),
  });
});

test('ArchiveReference: hard links in a package, and packages of the same name and version in other archives', {skip: !hasDebianTools}, async t => {
  const {execFileSync} = require('node:child_process');
  const staging = tempDir(t, 'attestium-deb-');
  writeFiles(staging, {
    'DEBIAN/control': 'Package: tools\nVersion: 1\nArchitecture: amd64\nMaintainer: Test <test@example.com>\nDescription: test\n',
    'usr/lib/tools/tool': 'tool',
  });
  fs.linkSync(path.join(staging, 'usr/lib/tools/tool'), path.join(staging, 'usr/lib/tools/tool-alias'));
  const debFile = path.join(tempDir(t, 'attestium-deb-out-'), 'package.deb');
  execFileSync('dpkg-deb', ['--build', '--root-owner-group', staging, debFile], {stdio: 'ignore'});
  const key = makeGpgKey(t);
  const root = tempDir(t, 'attestium-apt-');
  writeAptSuite(t, {
    root: path.join(root, 'debian'), key, packages: [{
      name: 'tools', version: '1', arch: 'amd64', deb: fs.readFileSync(debFile),
    }],
  });
  writeAptSuite(t, {
    root: path.join(root, 'ubuntu'), key, packages: [{
      name: 'tools', version: '1', arch: 'amd64', files: {'/usr/lib/tools/tool': 'rebuilt'},
    }],
  });
  const server = await serveDirectory(t, root);
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const archive = name => ({
    url: `${server.url}/${name}`, suites: ['test'], components: ['main'], keyring: key.keyring,
  });
  const debian = await new ArchiveReference({archives: [archive('debian')], store}).files('tools', '1', 'amd64');
  assert.deepEqual(debian, {'/usr/lib/tools/tool': sha256('tool'), '/usr/lib/tools/tool-alias': sha256('tool')});
  // The same store, another distribution's archive: its own build.
  const ubuntu = await new ArchiveReference({archives: [archive('ubuntu')], store}).files('tools', '1', 'amd64');
  assert.deepEqual(ubuntu, {'/usr/lib/tools/tool': sha256('rebuilt')});
});

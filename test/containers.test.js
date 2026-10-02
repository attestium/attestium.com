'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const containers = require('../lib/containers');
const {tempDir, writeFiles, sleep} = require('./helpers');
const {sha256, hasDocker, startContainer} = require('./system-helpers');

const linux = process.platform === 'linux';
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const ID = 'a1b2c3d4e5f6'.repeat(6).slice(0, 64);

/**
 * A process table with one process whose files are given.
 */
function fakeProc(t, pid, files) {
  const procRoot = tempDir(t, 'attestium-proc-');
  writeFiles(path.join(procRoot, String(pid)), files);
  return procRoot;
}

/**
 * An HTTP server on a Unix socket, like the Docker Engine API.
 */
async function unixServer(t, handler) {
  const socketPath = path.join(tempDir(t, 'attestium-sock-'), 'docker.sock');
  const server = http.createServer(handler);
  await new Promise(resolve => {
    server.listen(socketPath, resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  return socketPath;
}

test('containerOf: the container of a process, by runtime', t => {
  const cases = [
    [`12:pids:/docker/${ID}\n0::/docker/${ID}`, 'docker'],
    [`0::/system.slice/docker-${ID}.scope`, 'docker'],
    [`0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-${ID}.scope`, 'containerd'],
    [`0::/kubepods.slice/crio-${ID}.scope`, 'cri-o'],
    [`0::/machine.slice/libpod-${ID}.scope/container`, 'podman'],
    [`1:name=systemd:/libpod_parent/libpod-${ID}`, 'podman'],
    [`0::/kubepods/besteffort/pod1234/${ID}`, 'containerd'],
    [`0::/containerd/default/${ID}`, 'containerd'],
  ];
  for (const [cgroup, runtime] of cases) {
    const procRoot = fakeProc(t, 42, {cgroup: `${cgroup}\n`});
    assert.deepEqual(containers.containerOf(42, procRoot), {id: ID, runtime}, cgroup);
  }

  assert.equal(containers.containerOf('42', fakeProc(t, 42, {cgroup: '0::/user.slice/user-1000.slice/session-1.scope\n'})), null);
  assert.equal(containers.containerOf(42, tempDir(t)), null);
  assert.equal(containers.containerOf('self'), linux ? containers.containerOf(process.pid) : null);
  assert.equal(containers.containerOf('../1'), null);
});

const MOUNTINFO = [
  String.raw`94 61 0:42 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/snap/2/fs:/var/lib/snap/1/fs,upperdir=/var/lib/snap/3/fs,workdir=/var/lib/snap/3/work`,
  String.raw`96 94 0:50 / /proc rw,nosuid - proc proc rw`,
  String.raw`97 94 0:51 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k`,
  String.raw`120 94 8:1 /srv/my\040data /data ro,relatime - ext4 /dev/sda1 rw`,
  String.raw`121 94 8:1 /var/lib/docker/containers/abc/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw`,
  String.raw`122 94 0:60 / /mnt/odd rw - fuse.sshfs`,
  'not a mount line',
  '',
].join('\n');

test('parseMountinfo, rootOverlay and externalMounts', () => {
  const mounts = containers.parseMountinfo(MOUNTINFO);
  assert.equal(mounts.length, 6);
  assert.deepEqual(mounts[3], {
    id: 120, parent: 94, device: '8:1', root: '/srv/my data', mountPoint: '/data', options: 'ro,relatime', fsType: 'ext4', source: '/dev/sda1', superOptions: 'rw',
  });
  assert.equal(mounts[5].source, '');
  assert.equal(mounts[5].superOptions, '');

  assert.deepEqual(containers.rootOverlay(mounts), {lower: ['/var/lib/snap/2/fs', '/var/lib/snap/1/fs'], upper: '/var/lib/snap/3/fs', work: '/var/lib/snap/3/work'});
  assert.deepEqual(containers.externalMounts(mounts), [
    {
      destination: '/data', source: '/dev/sda1', root: '/srv/my data', fsType: 'ext4', readOnly: true,
    },
    {
      destination: '/etc/hostname', source: '/dev/sda1', root: '/var/lib/docker/containers/abc/hostname', fsType: 'ext4', readOnly: false,
    },
    {
      destination: '/mnt/odd', source: '', root: '/', fsType: 'fuse.sshfs', readOnly: false,
    },
  ]);

  // Escaped commas and colons in overlay options; the last root mount wins.
  const escaped = containers.parseMountinfo([
    '1 0 8:1 / / rw - ext4 /dev/sda1 rw',
    String.raw`2 1 0:42 / / rw - overlay overlay rw,lowerdir=/a\:b:/c\,d,upperdir=/up\,per,index=off`,
  ].join('\n'));
  assert.deepEqual(containers.rootOverlay(escaped), {lower: ['/a:b', '/c,d'], upper: '/up,per', work: null});
  assert.deepEqual(containers.rootOverlay(containers.parseMountinfo('2 1 0:42 / / rw - overlay overlay rw,=x,volatile')), {lower: [], upper: null, work: null});
  assert.equal(containers.rootOverlay(containers.parseMountinfo('1 0 8:1 / / rw - ext4 /dev/sda1 rw')), null);
  assert.equal(containers.rootOverlay(containers.parseMountinfo('1 0 8:1 / /data rw - ext4 /dev/sda1 rw')), null);
});

test('walkRootfs: the root filesystem through /proc/<pid>/root, without other mounts', async t => {
  const procRoot = fakeProc(t, 4242, {
    mountinfo: MOUNTINFO,
    'root/bin/sh': '#!/bin/sh\n',
    'root/etc/os-release': 'ID=alpine\n',
    'root/proc/1/status': 'excluded',
    'root/data/secret': 'excluded',
    'root/etc/hostname': 'excluded',
  });
  fs.chmodSync(path.join(procRoot, '4242/root/bin/sh'), 0o755);
  fs.symlinkSync('/bin/sh', path.join(procRoot, '4242/root/bin/ash'));
  // A FIFO is reported, never opened (the walk does not wait for a writer).
  execFileSync('mkfifo', [path.join(procRoot, '4242/root/bin/pipe')]);

  const result = await containers.walkRootfs(4242, {procRoot});
  assert.deepEqual(result.files, {
    'bin/ash': ['symlink:/bin/sh', '120000'],
    'bin/sh': [sha256('#!/bin/sh\n'), '100755'],
    'etc/os-release': [sha256('ID=alpine\n'), '100644'],
  });
  assert.equal(result.fileCount, 3);
  assert.deepEqual(result.errors, [{path: 'bin/pipe', error: 'ENOTFILE'}]);
  assert.equal(result.mounts.length, 6);
  assert.equal(result.truncated, undefined);

  const limited = await containers.walkRootfs('4242', {procRoot, maxFiles: 2});
  assert.equal(limited.truncated, true);
  assert.equal(Object.keys(limited.files).length, 2);
  assert.equal(limited.fileCount, 3);
  await assert.rejects(containers.walkRootfs(4243, {procRoot}), /ENOENT/);
});

test('walkUpper: files written in a container and whiteouts for deleted ones', {skip: !(linux && isRoot)}, async t => {
  const upper = tempDir(t, 'attestium-upper-');
  writeFiles(upper, {'etc/added': 'added\n', 'usr/local/bin/tool': '#!/bin/sh\n'});
  fs.chmodSync(path.join(upper, 'usr/local/bin/tool'), 0o755);
  fs.symlinkSync('/usr/local/bin/tool', path.join(upper, 'usr/local/bin/link'));
  // Overlayfs whiteouts are character devices 0/0; other devices are reported.
  execFileSync('mknod', [path.join(upper, 'etc/motd'), 'c', '0', '0']);
  fs.mkdirSync(path.join(upper, 'lib'));
  execFileSync('mknod', [path.join(upper, 'lib/removed.so'), 'c', '0', '0']);
  execFileSync('mknod', [path.join(upper, 'etc/null'), 'c', '1', '3']);
  // Other special files are reported: a program may read a FIFO or a block device.
  execFileSync('mkfifo', [path.join(upper, 'fifo')]);
  execFileSync('mknod', [path.join(upper, 'lib/loop0'), 'b', '7', '0']);
  // A server's socket (PostgreSQL's in /run/postgresql) has no content: left out.
  fs.mkdirSync(path.join(upper, 'run'));
  const server = require('node:net').createServer();
  await new Promise(resolve => {
    server.listen(path.join(upper, 'run/.s.PGSQL.5432'), resolve);
  });
  t.after(() => server.close());

  const result = await containers.walkUpper(upper);
  assert.deepEqual(result.files, {
    'etc/added': [sha256('added\n'), '100644'],
    'etc/null': ['device', 'device'],
    'usr/local/bin/link': ['symlink:/usr/local/bin/tool', '120000'],
    'usr/local/bin/tool': [sha256('#!/bin/sh\n'), '100755'],
  });
  assert.deepEqual(result.deleted, ['etc/motd', 'lib/removed.so']);
  assert.deepEqual(result.errors.sort((a, b) => (a.path > b.path) - (a.path < b.path)), [{path: 'fifo', error: 'ENOTFILE'}, {path: 'lib/loop0', error: 'ENOTFILE'}]);

  assert.deepEqual(await containers.walkUpper(path.join(upper, 'missing')), {files: {}, deleted: [], errors: [{path: '.', error: 'ENOENT'}]});
});

test('walkUpper: a directory the container replaces with a link during the walk is not followed', {skip: !linux}, async t => {
  const upper = tempDir(t, 'attestium-upper-');
  const host = tempDir(t);
  writeFiles(upper, {'etc/added': 'added\n', z: 'z'});
  writeFiles(host, {shadow: 'secret\n'});
  const {readdir} = fs.promises;
  let swapped = false;
  t.mock.method(fs.promises, 'readdir', async (...args) => {
    const result = await readdir(...args);
    if (!swapped) {
      swapped = true;
      fs.renameSync(path.join(upper, 'etc'), path.join(upper, 'old'));
      fs.symlinkSync(host, path.join(upper, 'etc'));
    }

    return result;
  });
  const result = await containers.walkUpper(upper);
  assert.deepEqual(Object.keys(result.files), ['z']);
  assert.deepEqual(result.errors.map(error => error.path), ['etc']);
});

test('walkUpper: a file that cannot be hashed is reported', {skip: !(linux && isRoot)}, async t => {
  // A file whose contents differ from its size (a procfs file bind-mounted
  // over it) cannot be hashed consistently.
  const upper = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'attestium-upper-'));
  const file = path.join(upper, 'version');
  fs.writeFileSync(file, '');
  try {
    execFileSync('mount', ['--bind', '/proc/version', file], {stdio: 'ignore'});
  } catch {
    fs.rmSync(upper, {recursive: true, force: true});
    t.skip('bind mounts are not permitted');
    return;
  }

  t.after(() => {
    execFileSync('umount', [file]);
    fs.rmSync(upper, {recursive: true, force: true});
  });
  const result = await containers.walkUpper(upper);
  assert.deepEqual(result.files, {});
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].path, 'version');
  assert.match(result.errors[0].error, /File changed while hashing/);
});

test('unixGetJson and inspectDocker: the Docker Engine API', async t => {
  const descriptor = {digest: `sha256:${'1'.repeat(64)}`, platform: {architecture: 'arm64', os: 'linux'}};
  const answers = {
    '/containers/full/json': {
      Name: '/web', Image: 'sha256:img', Platform: 'linux', Config: {Image: 'nginx:1.27', Labels: {app: 'web'}}, ImageManifestDescriptor: descriptor,
    },
    '/images/sha256%3Aimg/json': {RepoDigests: ['nginx@sha256:abc'], Os: 'linux', Architecture: 'amd64'},
    '/containers/bare/json': {Image: 'sha256:gone'},
    '/containers/descriptor/json': {
      Image: 'sha256:partial', Platform: 'linux', Config: {}, ImageManifestDescriptor: descriptor,
    },
    '/images/sha256%3Apartial/json': {RepoDigests: 'not a list'},
    '/containers/nodigest/json': {Image: 'sha256:partial', ImageManifestDescriptor: {}},
    '/containers/noimage/json': {Name: '/orphan'},
  };
  const socketPath = await unixServer(t, (request, response) => {
    assert.equal(request.headers.host, 'docker');
    if (request.url === '/invalid') {
      response.end('{not json');
      return;
    }

    if (request.url === '/slow') {
      return;
    }

    if (request.url === '/huge') {
      response.on('error', () => {});
      const chunk = Buffer.alloc(1024 * 1024, 0x20);
      let sent = 0;
      const write = () => {
        while (sent < 70 && response.write(chunk)) {
          sent++;
        }

        if (sent < 70 && !response.destroyed) {
          response.once('drain', write);
        } else {
          response.end();
        }
      };

      write();
      return;
    }

    const answer = answers[request.url];
    response.writeHead(answer ? 200 : 404, {'content-type': 'application/json'});
    response.end(JSON.stringify(answer || {message: 'No such container'}));
  });

  assert.deepEqual(await containers.inspectDocker('full', socketPath), {
    name: 'web',
    image: {
      reference: 'nginx:1.27', id: 'sha256:img', manifestDigest: descriptor.digest, repoDigests: ['nginx@sha256:abc'],
    },
    platform: {os: 'linux', architecture: 'amd64'},
    labels: {app: 'web'},
  });
  // Without an image record, a configuration or a descriptor.
  assert.deepEqual(await containers.inspectDocker('bare', socketPath), {
    name: '',
    image: {
      reference: null, id: 'sha256:gone', manifestDigest: null, repoDigests: [],
    },
    platform: {os: null, architecture: null},
    labels: {},
  });
  const partial = await containers.inspectDocker('descriptor', socketPath);
  assert.deepEqual(partial.platform, {os: 'linux', architecture: 'arm64'});
  assert.equal(partial.image.reference, null);
  assert.deepEqual(partial.image.repoDigests, []);
  const noDigest = await containers.inspectDocker('nodigest', socketPath);
  assert.equal(noDigest.image.manifestDigest, null);
  assert.equal(noDigest.platform.architecture, null);
  assert.equal((await containers.inspectDocker('noimage', socketPath)).image.id, null);

  await assert.rejects(containers.inspectDocker('missing', socketPath), /Docker API \/containers\/missing\/json answered 404/);
  await assert.rejects(containers.unixGetJson(socketPath, '/invalid'), SyntaxError);
  await assert.rejects(containers.unixGetJson(socketPath, '/slow', 100), /Docker API \/slow timed out/);
  await assert.rejects(containers.unixGetJson(socketPath, '/huge'), /response too large/);
  await assert.rejects(containers.unixGetJson(path.join(path.dirname(socketPath), 'none.sock'), '/x'), /ENOENT/);
});

test('inspectCri: what crictl says about a container', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const crictl = path.join(directory, 'crictl');
  fs.writeFileSync(crictl, `#!/bin/sh\n[ "$1 $2 $3" = "inspect -o json" ] || exit 64\nexec cat "${directory}/$4.json"\n`, {mode: 0o755});
  writeFiles(directory, {
    'pod.json': JSON.stringify({
      status: {
        metadata: {name: 'app'},
        image: {image: 'registry.example/app:1'},
        imageRef: 'registry.example/app@sha256:abc',
        labels: {'io.kubernetes.pod.name': 'app-7d9', 'io.kubernetes.pod.namespace': 'prod'},
      },
    }),
    'nonamespace.json': JSON.stringify({status: {labels: {'io.kubernetes.pod.name': 'app-7d9'}}}),
    'empty.json': '{}',
    'invalid.json': '{',
  });

  assert.deepEqual(await containers.inspectCri('pod', {crictl}), {
    name: 'app',
    image: {
      reference: 'registry.example/app:1', id: null, manifestDigest: null, repoDigests: ['registry.example/app@sha256:abc'],
    },
    platform: {os: 'linux', architecture: null},
    labels: {'io.kubernetes.pod.name': 'app-7d9', 'io.kubernetes.pod.namespace': 'prod'},
    pod: {name: 'app-7d9', namespace: 'prod'},
  });
  assert.deepEqual((await containers.inspectCri('nonamespace', {crictl})).pod, {name: 'app-7d9', namespace: null});
  const empty = await containers.inspectCri('empty', {crictl});
  assert.equal(empty.name, null);
  assert.equal(empty.image.reference, null);
  assert.deepEqual(empty.image.repoDigests, []);
  assert.deepEqual(empty.labels, {});
  assert.equal(empty.pod, null);
  await assert.rejects(containers.inspectCri('invalid', {crictl}), SyntaxError);
  await assert.rejects(containers.inspectCri('missing', {crictl}), /crictl inspect failed: Command failed/);

  // Crictl from the PATH by default.
  const {PATH} = process.env;
  process.env.PATH = `${directory}${path.delimiter}${PATH}`;
  try {
    assert.equal((await containers.inspectCri('pod')).name, 'app');
  } finally {
    process.env.PATH = PATH;
  }
});

test('a running Docker container: identity, image, mounts, writable layer and files', {skip: !(hasDocker() && isRoot && fs.existsSync('/var/run/docker.sock'))}, async t => {
  const volume = tempDir(t, 'attestium-volume-');
  writeFiles(volume, {'config.js': 'module.exports = 1;\n'});
  const {id, name, pid} = await startContainer(t, [
    '-v',
    `${volume}:/data:ro`,
    '--label',
    'attestium.test=1',
    'alpine:3.20',
    'sh',
    '-c',
    'echo added > /etc/added && rm /etc/motd && ln -s /bin/busybox /usr/local/bin/tool && touch /tmp/ready && exec sleep 600',
  ]);
  for (let attempt = 0; attempt < 100 && !fs.existsSync(`/proc/${pid}/root/tmp/ready`); attempt++) {
    await sleep(50);
  }

  assert.deepEqual(containers.containerOf(pid), {id, runtime: 'docker'});
  const inspected = await containers.inspectDocker(id);
  assert.equal(inspected.name, name);
  assert.equal(inspected.image.reference, 'alpine:3.20');
  assert.match(inspected.image.id, /^sha256:[\da-f]{64}$/);
  assert.equal(inspected.platform.os, 'linux');
  assert.equal(inspected.labels['attestium.test'], '1');

  const mounts = containers.parseMountinfo(fs.readFileSync(`/proc/${pid}/mountinfo`, 'utf8'));
  const overlay = containers.rootOverlay(mounts);
  assert.ok(overlay.lower.length > 0);
  assert.ok(overlay.upper);
  const external = containers.externalMounts(mounts);
  const data = external.find(mount => mount.destination === '/data');
  assert.equal(data.readOnly, true);
  assert.ok(external.some(mount => mount.destination === '/etc/hostname'));

  const upper = await containers.walkUpper(overlay.upper);
  assert.deepEqual(upper.files['etc/added'], [sha256('added\n'), '100644']);
  assert.deepEqual(upper.files['usr/local/bin/tool'], ['symlink:/bin/busybox', '120000']);
  assert.ok(upper.deleted.includes('etc/motd'));

  const rootfs = await containers.walkRootfs(pid);
  assert.deepEqual(rootfs.files['etc/added'], [sha256('added\n'), '100644']);
  assert.equal(rootfs.files['etc/motd'], undefined);
  assert.equal(rootfs.files['bin/busybox'][1], '100755');
  assert.equal(rootfs.files['bin/busybox'][0], crypto.createHash('sha256').update(fs.readFileSync(`/proc/${pid}/root/bin/busybox`)).digest('hex'));
  // Volumes and the runtime's bind mounts are not part of the root filesystem.
  assert.equal(rootfs.files['data/config.js'], undefined);
  assert.equal(rootfs.files['etc/hostname'], undefined);
  assert.ok(!Object.keys(rootfs.files).some(file => file.startsWith('proc/')));
});

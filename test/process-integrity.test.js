'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const ProcessIntegrity = require('../lib/process-integrity');
const {tempDir, writeFiles, sleep} = require('./helpers');

const linux = process.platform === 'linux';
const KEEP_ALIVE = 'setInterval(() => {}, 1000)';
const SYSCALLS = {x64: {memfd: 319, ptrace: 101}, arm64: {memfd: 279, ptrace: 117}}[process.arch];

/**
 * Spawn a child and wait until it is running.
 */
const cleanEnvironment = () => {
  const environment = {...process.env};
  delete environment.NODE_PATH;
  delete environment.NODE_OPTIONS;
  return environment;
};

// Node.js children run a script file: code given with -e is itself reported.
function keepAlive(t) {
  const script = path.join(tempDir(t), 'keep-alive.js');
  fs.writeFileSync(script, KEEP_ALIVE);
  return script;
}

async function child(t, command, args, options = {}) {
  const proc = spawn(command, args, {stdio: ['ignore', 'pipe', 'ignore'], env: cleanEnvironment(), ...options});
  t.after(() => {
    proc.kill('SIGKILL');
  });
  if (options.waitForOutput) {
    const line = await new Promise((resolve, reject) => {
      proc.stdout.once('data', data => resolve(String(data).trim()));
      proc.once('exit', () => reject(new Error(`${command} exited early`)));
    });
    return {proc, line};
  }

  // Wait for the dynamic loader to finish mapping libraries.
  for (let i = 0; i < 50; i++) {
    await sleep(20);
    try {
      if (fs.readFileSync(`/proc/${proc.pid}/maps`, 'utf8').includes('libc')) {
        break;
      }
    } catch {}
  }

  return {proc};
}

test('a clean process passes every check', {skip: !linux}, async t => {
  const pi = new ProcessIntegrity();
  const self = pi.checkAll(process.pid);
  assert.equal(self.passed, true, JSON.stringify(self.findings));
  assert.equal(self.executablePages.matched, true);
  assert.ok(self.executablePages.regions.length >= 2, 'binary and shared libraries are compared');
  assert.ok(self.executablePages.regions.some(region => region.path === fs.realpathSync(process.execPath)));
  assert.equal(self.linkerIntegrity.environReadable, true);
  assert.equal(self.tracer.traced, false);
  assert.ok(self.memoryMaps.libraries.length > 0);
  assert.ok(self.fileDescriptors.totalFds > 0);

  const {proc} = await child(t, process.execPath, [keepAlive(t)]);
  const report = pi.checkAll(proc.pid);
  assert.equal(report.passed, true, JSON.stringify(report.findings));
  assert.equal(report.pid, String(proc.pid));
});

test('code modified in memory is detected even though the file on disk is unchanged', {skip: !linux}, async t => {
  const {proc} = await child(t, process.execPath, [keepAlive(t)]);
  const maps = fs.readFileSync(`/proc/${proc.pid}/maps`, 'utf8').split('\n').map(line => ProcessIntegrity.parseMapsLine(line));
  const region = maps.find(item => item && item.perms === 'r-xp' && /libc[.-]/.test(item.pathname || ''));
  assert.ok(region, 'libc text mapping found');

  // Flip one byte of libc's code in the child through /proc/<pid>/mem (what
  // a ptrace/proc-mem injection does).
  const address = Number(region.end) - 64;
  const fd = fs.openSync(`/proc/${proc.pid}/mem`, 'r+');
  const byte = Buffer.alloc(1);
  fs.readSync(fd, byte, 0, 1, address);
  byte[0] ^= 0xFF;
  fs.writeSync(fd, byte, 0, 1, address);
  fs.closeSync(fd);

  const report = new ProcessIntegrity().checkAll(proc.pid);
  assert.equal(report.passed, false);
  assert.equal(report.executablePages.matched, false);
  const [mismatch] = report.executablePages.mismatched;
  assert.equal(mismatch.path, region.pathname);
  assert.equal(mismatch.firstDifferenceOffset, Number(region.end - region.start) - 64);
  assert.deepEqual(report.findings.map(finding => finding.type), ['code-modified-in-memory']);
});

test('library and Node.js preload injection vectors are reported', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const preloadFile = path.join(directory, 'ld.so.preload');
  fs.writeFileSync(preloadFile, '# comment only\n/lib/evil.so # trailing comment\n');
  const spaced = path.join(directory, 'with space.js');
  fs.writeFileSync(spaced, '');
  const libm = fs.readFileSync(`/proc/${process.pid}/maps`, 'utf8').match(/\s(\/\S*libc\.so[.\d]*)$/m)[1];
  // --env-file exists from Node.js 20.6; older versions refuse to start with it.
  const [major, minor] = process.versions.node.split('.').map(Number);
  const envFile = major > 20 || (major === 20 && minor >= 6) ? ['--env-file=/dev/null'] : ['--experimental-loader=data:text/javascript,'];
  const {proc} = await child(t, process.execPath, ['--require', '/dev/null', '--require=/dev/null', '--inspect=127.0.0.1:0', '-C', 'development', ...envFile, keepAlive(t), '--require', 'app-argument'], {
    env: {
      ...cleanEnvironment(),
      LD_PRELOAD: libm,
      LD_AUDIT: libm,
      LD_LIBRARY_PATH: '/opt/lib',
      NODE_OPTIONS: `--require "${spaced}" --import=data:text/javascript, --inspect-port=0 --inspect=127.0.0.1:0`,
    },
  });

  const pi = new ProcessIntegrity({ldPreloadPath: preloadFile});
  const report = pi.checkLinkerIntegrity(proc.pid);
  assert.equal(report.clean, false);
  assert.equal(report.ldLibraryPath, '/opt/lib');
  assert.deepEqual(report.findings.map(finding => `${finding.type} ${finding.value}`).sort(), [
    `LD_AUDIT ${libm}`,
    `LD_PRELOAD ${libm}`,
    'NODE_OPTIONS-inspector --inspect=127.0.0.1:0',
    'NODE_OPTIONS-preload --import=data:text/javascript,',
    `NODE_OPTIONS-preload --require ${spaced}`,
    'argv-inspector --inspect=127.0.0.1:0',
    `argv-preload ${envFile[0]}`,
    'argv-preload --require /dev/null',
    'argv-preload --require=/dev/null',
    'inspector-random-port a debugger or management port would listen on an unpredictable port',
    'ld.so.preload /lib/evil.so',
  ]);

  // Code given on the command line, and a preload after an option value.
  const inline = await child(t, process.execPath, ['--conditions', 'development', '-e', KEEP_ALIVE], {env: {...cleanEnvironment(), NODE_PATH: '/opt/modules'}});
  const plain = new ProcessIntegrity({ldPreloadPath: path.join(directory, 'none')});
  const inlineReport = plain.checkLinkerIntegrity(inline.proc.pid);
  assert.deepEqual(inlineReport.findings, [{type: 'NODE_PATH', value: '/opt/modules', severity: 'warning'}, {type: 'argv-preload', value: `-e ${KEEP_ALIVE}`, severity: 'critical'}]);
  assert.equal(inlineReport.runtime, 'node');
  const full = plain.checkAll(inline.proc.pid);
  assert.equal(full.findings.find(finding => finding.type === 'NODE_PATH').severity, 'warning');
  assert.equal(full.passed, false);

  // Each runtime is checked for its own options: Perl's -e is Perl code,
  // and Node.js options mean nothing to it.
  const perl = await child(t, 'perl', ['-e', 'sleep 30'], {env: {...cleanEnvironment(), NODE_OPTIONS: '--require /x.js'}});
  assert.deepEqual(plain.checkLinkerIntegrity(perl.proc.pid).findings, [{type: 'argv-code', value: 'sleep 30', severity: 'critical'}]);
  assert.equal(plain.checkLinkerIntegrity(perl.proc.pid, {isNode: true}).findings[0].value, '--require /x.js');
  assert.equal(plain.checkLinkerIntegrity(perl.proc.pid, {runtime: 'native'}).findings.length, 0);

  const empty = path.join(directory, 'empty.preload');
  fs.writeFileSync(empty, '# nothing\n\n');
  assert.equal(new ProcessIntegrity({ldPreloadPath: empty}).checkLinkerIntegrity(process.pid).findings.some(finding => finding.type === 'ld.so.preload'), false);
});

test('an inspector opened at runtime with SIGUSR1 is reported', {skip: !linux}, async t => {
  const {proc} = await child(t, process.execPath, [keepAlive(t)]);
  const pi = new ProcessIntegrity();
  assert.deepEqual(pi.checkListeningSockets(proc.pid).listening, []);
  process.kill(proc.pid, 'SIGUSR1');
  let sockets = [];
  for (let i = 0; i < 50 && sockets.length === 0; i++) {
    await sleep(50);
    sockets = pi.checkListeningSockets(proc.pid).listening;
  }

  assert.deepEqual(sockets, [{address: '127.0.0.1', port: 9229}]);
  const report = pi.checkAll(proc.pid);
  assert.equal(report.passed, false);
  assert.deepEqual(report.findings.map(finding => finding.type), ['inspector-listening']);
  assert.equal(report.runtime.name, 'node');
  // Node.js's default port is always watched; configured ports are added.
  assert.equal(new ProcessIntegrity({inspectorPorts: [1]}).checkAll(proc.pid).passed, false);
  assert.equal(new ProcessIntegrity().checkAll(proc.pid, {runtime: 'native'}).passed, true, 'a native program may listen on 9229');

  // On a port the process's options choose, it is found the same way.
  const port = 40_000 + (process.pid % 20_000);
  const custom = await child(t, process.execPath, [keepAlive(t)], {env: {...cleanEnvironment(), NODE_OPTIONS: `--inspect-port=127.0.0.1:${port}`}});
  const configured = new ProcessIntegrity({inspectorPorts: [1]});
  assert.equal(configured.checkAll(custom.proc.pid).passed, true, 'configuring the port alone opens nothing');
  process.kill(custom.proc.pid, 'SIGUSR1');
  let opened = [];
  for (let i = 0; i < 50 && opened.length === 0; i++) {
    await sleep(50);
    opened = configured.checkListeningSockets(custom.proc.pid).listening;
  }

  const customReport = configured.checkAll(custom.proc.pid);
  assert.deepEqual(customReport.inspectorPorts, [1, 9229, port]);
  assert.deepEqual(customReport.findings.map(finding => `${finding.type} ${finding.detail}`), [`inspector-listening 127.0.0.1:${port}`]);
});

test('an attached debugger is reported', {skip: !linux || !SYSCALLS}, async t => {
  // The perl process forks a child that asks to be traced by its parent.
  const {line} = await child(t, 'perl', ['-e', `$|=1; my $p=fork(); if(!$p){syscall(${SYSCALLS.ptrace},0,0,0,0); exec("sleep","30")} print "$p\\n"; sleep 30;`], {waitForOutput: true});
  let tracer;
  for (let i = 0; i < 50; i++) {
    tracer = new ProcessIntegrity().checkTracerPid(line);
    if (tracer.traced) {
      break;
    }

    await sleep(20);
  }

  assert.equal(tracer.traced, true);
  assert.ok(tracer.tracerPid > 0);
  assert.equal(new ProcessIntegrity().checkAll(line).findings.some(finding => finding.type === 'debugger-attached'), true);
});

test('fileless payloads held in memfd objects are reported', {skip: !linux || !SYSCALLS}, async t => {
  const {proc} = await child(t, 'perl', ['-e', `$|=1; my $n="payload"; my $fd=syscall(${SYSCALLS.memfd},$n,0); open(my $h, "<", "/etc/hostname"); print "ready\\n"; sleep 30;`], {waitForOutput: true});
  const report = new ProcessIntegrity().checkAll(proc.pid);
  assert.equal(report.passed, false);
  assert.deepEqual(report.fileDescriptors.suspicious.map(item => item.type), ['memfd']);
  assert.match(report.findings.find(finding => finding.type === 'memfd-open').detail, /^\/memfd:payload/);
});

test('a binary deleted after start is reported as unverifiable, not tampered', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const copy = path.join(directory, 'node-copy');
  fs.copyFileSync(process.execPath, copy);
  fs.chmodSync(copy, 0o755);
  const {proc} = await child(t, copy, [keepAlive(t)]);
  fs.rmSync(copy);
  const pi = new ProcessIntegrity();
  const report = pi.checkAll(proc.pid);
  assert.equal(report.passed, true, 'warnings do not fail the check');
  assert.deepEqual(report.findings.map(finding => [finding.type, finding.severity]), [['deleted-backing', 'warning']]);
  assert.ok(report.executablePages.skipped.length > 0);
  assert.ok(report.executablePages.skipped.every(item => item.reason === 'deleted' && item.path.startsWith(copy)));
  const info = pi.getProcessInfo(proc.pid);
  assert.equal(info.exe, copy);
  assert.equal(info.exeDeleted, true);
});

test('process discovery reports start time, owner, cwd and argv, and filters', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const {proc} = await child(t, process.execPath, [keepAlive(t), 'marker-argument'], {cwd: directory});
  const pi = new ProcessIntegrity();
  const info = pi.getProcessInfo(proc.pid);
  assert.equal(info.cwd, directory);
  assert.equal(info.exe, fs.realpathSync(process.execPath));
  assert.equal(info.ppid, process.pid);
  assert.equal(info.uid, process.getuid());
  assert.equal(info.cmdline.at(-1), 'marker-argument');
  assert.ok(Math.abs(info.startTimeMs - Date.now()) < 60_000, `start time ${info.startTimeMs}`);

  const byCwd = pi.listProcesses({cwdPrefix: `${directory}/`});
  assert.deepEqual(byCwd.map(item => item.pid), [String(proc.pid)]);
  assert.deepEqual(pi.listProcesses({cwdPrefix: `${directory}-other`}), []);
  assert.ok(pi.listProcesses({uid: process.getuid(), exe: info.exe}).some(item => item.pid === String(proc.pid)));
  assert.deepEqual(pi.listProcesses({uid: 2_147_483_000}), []);
  assert.ok(pi.listProcesses({exe: '/nonexistent'}).length === 0);
});

test('a huge command line or environment is read only up to a limit, and reported as not fully checked', {skip: !linux}, async t => {
  // Each argument or variable may be up to 128 KiB; together they may be
  // far larger than any one read should be.
  const argument = 'a'.repeat(100_000);
  const huge = {
    ...cleanEnvironment(), HUGE_1: 'x'.repeat(100_000), HUGE_2: 'x'.repeat(100_000), HUGE_3: 'x'.repeat(100_000),
  };
  const script = keepAlive(t);
  const {proc} = await child(t, process.execPath, [script, argument, argument, argument]);
  const {proc: withEnvironment} = await child(t, process.execPath, [script], {env: huge});
  const {proc: small} = await child(t, process.execPath, [script]);
  const pi = new ProcessIntegrity();

  const info = pi.getProcessInfo(proc.pid);
  assert.equal(info.cmdlineTruncated, true);
  assert.ok(info.cmdline.join('\0').length <= 256 * 1024, String(info.cmdline.join('\0').length));
  assert.deepEqual(info.cmdline.slice(1, 3), [script, argument]);
  assert.equal(pi.getProcessInfo(small.pid).cmdlineTruncated, undefined);

  const linker = pi.checkLinkerIntegrity(proc.pid, {runtime: 'native'});
  assert.equal(linker.clean, null);
  assert.equal(linker.error, 'Only the first 262144 bytes of the command line were checked');
  assert.deepEqual(pi.checkAll(proc.pid, {runtime: 'native'}).incomplete.find(item => item.check === 'linkerIntegrity'), {check: 'linkerIntegrity', error: linker.error});
  assert.equal(pi.checkLinkerIntegrity(withEnvironment.pid, {runtime: 'native'}).error, 'Only the first 262144 bytes of the environment were checked');
  assert.equal(pi.checkLinkerIntegrity(small.pid, {runtime: 'native'}).error, undefined);
  // The limit can be set; both are then cut.
  const strict = new ProcessIntegrity({maxProcRead: 1024});
  const both = await child(t, process.execPath, [script, argument], {env: huge});
  assert.equal(strict.checkLinkerIntegrity(both.proc.pid, {runtime: 'native'}).error, 'Only the first 1024 bytes of the environment and command line were checked');
  assert.equal(strict.getProcessInfo(both.proc.pid).cmdline.join('\0').length, 1024);
});

test('a command line of about 2 MB is read only up to the limit', {skip: !linux}, async t => {
  // 15 arguments of 128 KiB less one byte, as long as Linux allows each.
  const argument = 'b'.repeat((128 * 1024) - 1);
  const script = keepAlive(t);
  const {proc} = await child(t, process.execPath, [script, ...Array.from({length: 15}).fill(argument)], {env: cleanEnvironment()});
  const full = fs.readFileSync(`/proc/${proc.pid}/cmdline`).length;
  assert.ok(full > 1_900_000, String(full));
  // No read is given a buffer larger than the limit.
  const reads = [];
  const {readSync} = fs;
  t.mock.method(fs, 'readSync', (fd, buffer, ...rest) => {
    const bytes = readSync(fd, buffer, ...rest);
    reads.push(buffer.length);
    return bytes;
  });
  const info = new ProcessIntegrity().getProcessInfo(proc.pid);
  t.mock.restoreAll();
  assert.equal(info.cmdlineTruncated, true);
  assert.equal(Buffer.byteLength(info.cmdline.join('\0')), 256 * 1024);
  assert.ok(Math.max(...reads) <= (256 * 1024) + 1, String(Math.max(...reads)));
});

test('hashExecutable hashes the running file in chunks', {skip: !linux}, async t => {
  const {proc} = await child(t, 'sleep', ['60']);
  const pi = new ProcessIntegrity();
  const binary = fs.readFileSync(fs.realpathSync(`/proc/${proc.pid}/exe`));
  assert.deepEqual(await pi.hashExecutable(proc.pid), {sha256: require('node:crypto').createHash('sha256').update(binary).digest('hex'), size: binary.length});

  // A large executable (sparse: 64 MiB of zeros) is read a chunk at a time.
  const procRoot = tempDir(t);
  const large = path.join(procRoot, 'large');
  fs.closeSync(fs.openSync(large, 'w'));
  fs.truncateSync(large, 64 * 1024 * 1024);
  fs.mkdirSync(path.join(procRoot, '4242'));
  fs.symlinkSync(large, path.join(procRoot, '4242', 'exe'));
  const sizes = [];
  const handle = await fs.promises.open(large, 'r');
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const {read} = prototype;
  t.mock.method(prototype, 'read', function (buffer, ...rest) {
    sizes.push(buffer.length);
    return read.call(this, buffer, ...rest);
  });
  const zeros = require('node:crypto').createHash('sha256');
  for (let i = 0; i < 16; i++) {
    zeros.update(Buffer.alloc(4 * 1024 * 1024));
  }

  assert.deepEqual(await new ProcessIntegrity({procRoot}).hashExecutable(4242), {sha256: zeros.digest('hex'), size: 64 * 1024 * 1024});
  assert.ok(sizes.length >= 16 && sizes.every(size => size <= 4 * 1024 * 1024), JSON.stringify(sizes));
  t.mock.restoreAll();

  // A file whose size is not what it reads (it changed while hashed).
  fs.rmSync(path.join(procRoot, '4242', 'exe'));
  fs.symlinkSync('/proc/version', path.join(procRoot, '4242', 'exe'));
  await assert.rejects(new ProcessIntegrity({procRoot}).hashExecutable(4242), /The executable changed while it was hashed/);
  await assert.rejects(new ProcessIntegrity({platform: 'darwin'}).hashExecutable(1), /Not supported on darwin/);
});

// ─── fixture /proc trees for cases a live system cannot produce on demand ──

/**
 * Build a fake /proc for pid 4242.
 */
function fakeProc(t, {maps = '', mem = [], status, stat, environ, cmdline = 'node\0app.js\0', fds = {}, net = {}, links = {}} = {}) {
  const root = tempDir(t);
  const directory = path.join(root, '4242');
  writeFiles(root, {
    stat: 'cpu 1 2 3\nbtime 1700000000\n',
    '4242/maps': maps,
    '4242/status': status ?? 'Name:\tnode\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nTracerPid:\t0\n',
    '4242/stat': stat ?? '4242 (my (weird) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 500 0 0\n',
    '4242/environ': environ ?? 'PATH=/bin\0',
    '4242/cmdline': cmdline,
    'notapid/x': '',
    ...Object.fromEntries(Object.entries(net).map(([file, content]) => [`4242/net/${file}`, content])),
  });
  const memFile = path.join(directory, 'mem');
  const fd = fs.openSync(memFile, 'w');
  for (const [position, data] of mem) {
    fs.writeSync(fd, data, 0, data.length, position);
  }

  fs.closeSync(fd);
  if (fds !== null) {
    fs.mkdirSync(path.join(directory, 'fd'));
    for (const [fdNumber, target] of Object.entries(fds)) {
      fs.symlinkSync(target, path.join(directory, 'fd', fdNumber));
    }
  }

  for (const [name, target] of Object.entries(links)) {
    fs.symlinkSync(target, path.join(directory, name));
  }

  return root;
}

test('memory map anomalies: memfd, W+X file mappings, replaced files, allowlists', {skip: !linux}, t => {
  const directory = tempDir(t);
  const lib = path.join(directory, 'lib.so');
  fs.writeFileSync(lib, 'x');
  const {ino} = fs.statSync(lib);
  const maps = [
    `1000-2000 r-xp 00000000 08:01 ${ino} ${lib}`,
    `2000-3000 rwxp 00001000 08:01 ${ino} ${lib}`,
    `3000-4000 r-xp 00000000 08:01 ${ino + 1} ${lib}`,
    '4000-5000 r-xp 00000000 00:01 77 /memfd:evil (deleted)',
    '5000-6000 rwxp 00000000 00:00 0 ',
    '6000-7000 r-xp 00000000 00:00 0 [vdso]',
    '7000-8000 r--p 00000000 08:01 5 /etc/x',
    `8000-9000 r-xp 00000000 08:01 99 ${path.join(directory, 'gone.so')}`,
    'garbage line',
    '',
  ].join('\n');
  const root = fakeProc(t, {maps});
  const pi = new ProcessIntegrity({procRoot: root, expectedLibs: ['/usr/lib/allowed.so'], maxAnonExecRegions: 1});
  const result = pi.checkMemoryMaps(4242);
  assert.deepEqual(result.anomalies.map(anomaly => anomaly.type), ['file-wx', 'replaced-backing', 'memfd-exec', 'replaced-backing', 'unexpected-lib', 'unexpected-lib']);
  assert.equal(result.summary.anonExecRegions, 2);
  assert.equal(result.summary.anonWxRegions, 1);
  assert.equal(result.summary.anonExecExcessive, true);
  assert.equal(result.summary.totalRegions, 8);
  const missing = new ProcessIntegrity({procRoot: tempDir(t)}).checkMemoryMaps(4242);
  assert.equal(missing.error, 'ENOENT');
});

test('the linker check names the executable to the runtime (`bundle exec` with the standard library\'s Bundler)', {skip: !linux}, t => {
  const environ = 'RUBYOPT=-r/usr/lib/ruby/3.2.0/bundler/setup\0RUBYLIB=\0';
  const check = links => new ProcessIntegrity({procRoot: fakeProc(t, {environ, cmdline: 'ruby\0app.rb\0', links})}).checkLinkerIntegrity(4242, {runtime: 'ruby'}).findings.map(finding => `${finding.severity} ${finding.type}`);
  assert.deepEqual(check({exe: '/usr/bin/ruby3.2'}), ['info bundler-setup']);
  // Another interpreter, or one that cannot be read: the require is not its standard library's.
  assert.deepEqual(check({exe: '/srv/ruby/bin/ruby'}), ['critical RUBYOPT-require']);
  assert.deepEqual(check({}), ['critical RUBYOPT-require']);
});

test('executable page comparison handles EOF padding, replaced files and short reads', {skip: !linux}, t => {
  const directory = tempDir(t);
  const lib = path.join(directory, 'lib.so');
  fs.writeFileSync(lib, Buffer.concat([Buffer.alloc(0x10, 1), Buffer.from('CODE'), Buffer.alloc(0x0C, 2)]));
  const other = path.join(directory, 'other.so');
  fs.writeFileSync(other, 'other');
  const {ino} = fs.statSync(lib);
  const memory = Buffer.alloc(0x40);
  Buffer.from('CODE').copy(memory, 0);
  memory.fill(2, 4, 16);
  const tampered = Buffer.from(memory);
  tampered[1] = 0x41;
  const maps = [
    // 0x40-byte mapping at file offset 0x10: 0x20 bytes of file, rest zero-filled.
    `10000-10040 r-xp 00000010 08:01 ${ino} ${lib}`,
    `20000-20040 r-xp 00000010 08:01 ${ino} ${lib}`,
    `30000-30040 r-xp 00000000 08:01 ${fs.statSync(other).ino + 1} ${other}`,
    `40000-40040 r-xp 00000000 08:01 ${ino} ${path.join(directory, 'missing.so')}`,
    `50000-50040 r-xp 00000010 08:01 ${ino} ${lib} (deleted)`,
    `ffff0000-ffff1000 r-xp 00000010 08:01 ${ino} ${lib}`,
    '',
  ].join('\n');
  const root = fakeProc(t, {maps, mem: [[0x1_00_00, memory], [0x2_00_00, tampered]]});
  const result = new ProcessIntegrity({procRoot: root}).checkExecutablePages(4242);
  assert.equal(result.matched, false);
  assert.deepEqual(result.regions.map(region => region.matched), [true, false]);
  assert.equal(result.mismatched[0].firstDifferenceOffset, 1);
  assert.deepEqual(result.skipped.map(item => item.reason), ['replaced', 'ENOENT', 'deleted', 'Short read from process memory']);
  // Regions that could not be read (unlike deleted or replaced files) make the report incomplete.
  const all = new ProcessIntegrity({procRoot: root}).checkAll(4242);
  assert.deepEqual(all.incomplete.find(item => item.check === 'executablePages'), {check: 'executablePages', error: '2 region(s) could not be compared (ENOENT, Short read from process memory)'});
  assert.equal(all.passed, false);

  const none = fakeProc(t, {maps: '1000-2000 r--p 00000000 00:00 0\n'});
  assert.equal(new ProcessIntegrity({procRoot: none}).checkExecutablePages(4242).matched, null);
  assert.equal(new ProcessIntegrity({procRoot: tempDir(t)}).checkExecutablePages(4242).error, 'ENOENT');
});

test('fixture /proc: unreadable data degrades to explicit unknowns', {skip: !linux}, t => {
  const root = fakeProc(t, {
    status: 'Name:\tx\n',
    environ: null,
    fds: null,
    links: {exe: '/usr/bin/node (deleted)', cwd: '/srv/app'},
  });
  fs.rmSync(path.join(root, '4242', 'environ'));
  fs.rmSync(path.join(root, '4242', 'cmdline'));
  const pi = new ProcessIntegrity({
    procRoot: root, run() {
      throw new Error('getconf missing');
    },
  });
  const info = pi.getProcessInfo(4242);
  assert.equal(info.exe, '/usr/bin/node');
  assert.equal(info.exeDeleted, true);
  assert.equal(info.cwd, '/srv/app');
  assert.equal(info.startTimeMs, 1_700_000_000_000 + 5000, 'CLK_TCK falls back to 100');
  assert.equal(pi.getProcessInfo(4242).startTimeMs, info.startTimeMs, 'clock ticks cached');

  const linker = pi.checkLinkerIntegrity(4242);
  assert.equal(linker.clean, null);
  assert.equal(linker.environReadable, false);
  assert.deepEqual(pi.checkTracerPid(4242), {
    supported: true, traced: null, tracerPid: null, error: 'no TracerPid in status',
  });
  assert.equal(pi.checkFileDescriptors(4242).error, 'ENOENT');
  assert.equal(pi.checkListeningSockets(4242).error, 'ENOENT');
  assert.equal(new ProcessIntegrity({procRoot: tempDir(t)}).checkTracerPid(4242).error, 'ENOENT');
  // No exe link: not treated as Node.js.
  assert.equal(new ProcessIntegrity({procRoot: tempDir(t)}).checkLinkerIntegrity(4242).environReadable, false);
  // An unreadable socket table hides listening ports.
  const sockets = fakeProc(t, {net: {tcp6: ''}});
  fs.mkdirSync(path.join(sockets, '4242', 'net', 'tcp'));
  assert.deepEqual(new ProcessIntegrity({procRoot: sockets}).checkListeningSockets(4242), {supported: true, listening: [], error: 'EISDIR'});

  const noLinks = fakeProc(t, {stat: '4242 (x) S', links: {}});
  fs.writeFileSync(path.join(noLinks, 'stat'), 'no btime here\n');
  const bare = new ProcessIntegrity({procRoot: noLinks, run: () => '250\n'}).getProcessInfo(4242);
  assert.equal(bare.exe, null);
  assert.equal(bare.exeError, 'ENOENT');
  assert.ok(Number.isNaN(bare.startTimeMs));

  // ListProcesses skips entries that vanish or are malformed
  const listRoot = fakeProc(t, {links: {cwd: '/srv/app'}});
  fs.mkdirSync(path.join(listRoot, '999'));
  assert.deepEqual(new ProcessIntegrity({procRoot: listRoot}).listProcesses({cwdPrefix: '/srv/app'}).map(item => item.pid), ['4242']);
  assert.deepEqual(new ProcessIntegrity({procRoot: listRoot}).listProcesses({cwdPrefix: '/srv/other'}), []);
  const noCwd = fakeProc(t, {});
  assert.deepEqual(new ProcessIntegrity({procRoot: noCwd}).listProcesses({cwdPrefix: '/srv'}), []);
});

test('fixture /proc: sockets are matched by inode across IPv4 and IPv6 tables', {skip: !linux}, t => {
  const header = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n';
  const root = fakeProc(t, {
    fds: {
      3: 'socket:[111]', 4: 'socket:[222]', 5: 'socket:[333]', 6: '/memfd:x (deleted)', 7: '/tmp/gone (deleted)', 8: 'pipe:[1]',
    },
    net: {
      tcp: `${header}   0: 0100007F:240D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n   1: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 333 1\n   2: 0100007F:0051 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 999 1\nshort\n`,
      tcp6: `${header}   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1\n`,
    },
  });
  const pi = new ProcessIntegrity({procRoot: root});
  assert.deepEqual(pi.checkListeningSockets(4242).listening, [
    {address: '::1', port: 443},
    {address: '127.0.0.1', port: 9229},
  ]);
  const fds = pi.checkFileDescriptors(4242);
  assert.deepEqual(fds.suspicious.map(item => item.type), ['memfd', 'deleted']);
  assert.deepEqual(fds.sockets.sort(), [111, 222, 333]);

  const noV6 = fakeProc(t, {fds: {3: 'socket:[1]'}, net: {tcp: header}});
  assert.deepEqual(new ProcessIntegrity({procRoot: noV6}).checkListeningSockets(4242).listening, []);

  // A socket fd that disappears between readdir and readlink is skipped.
  const vanishing = fakeProc(t, {fds: {}});
  fs.writeFileSync(path.join(vanishing, '4242', 'fd', '9'), 'not a link');
  assert.equal(new ProcessIntegrity({procRoot: vanishing}).checkFileDescriptors(4242).totalFds, 1);
});

// ─── other platforms (recorded tool output) ─────────────────────────

/**
 * Runner that answers from a table of recorded outputs.
 */
function recordedRun(table) {
  const calls = [];
  const run = (file, args) => {
    calls.push([file, ...args]);
    const key = Object.keys(table).find(prefix => `${file} ${args.join(' ')}`.startsWith(prefix));
    const value = key === undefined ? undefined : table[key];
    if (value === undefined || value instanceof Error) {
      throw value || new Error(`command not recorded: ${file} ${args.join(' ')}`);
    }

    return value;
  };

  run.calls = calls;
  return run;
}

test('macOS: vmmap, ps and lsof output', () => {
  const vmmap = [
    'Process:         node [4242]',
    '==== Writable regions for process 4242',
    '__TEXT                      100000000-104000000    [ 64.0M 64.0M     0K     0K] r-x/r-x SM=COW          /usr/local/bin/node',
    '__TEXT                      1a0000000-1a0100000    [  1024K 1024K     0K     0K] rwx/rwx SM=PRV          /usr/lib/evil.dylib',
    'JS JIT generated code       300000000-300100000    [  1024K    0K     0K     0K] rwx/rwx SM=NUL          ',
    '__DATA                      104000000-104100000    [  1024K    0K     0K     0K] rw-/rw- SM=COW          /usr/local/bin/node',
  ].join('\n');
  const run = recordedRun({
    'vmmap --wide 4242': vmmap,
    'ps eww -o command= -p 4242': 'node app.js PATH=/usr/bin DYLD_INSERT_LIBRARIES=/tmp/inject.dylib HOME=/x',
    'ps -o stat= -p 4242': 'SX  \n',
    'lsof -n -P -p 4242 -F fn': 'p4242\nfcwd\nn/srv/app\nf3\nn/tmp/payload (deleted)\n',
  });
  const pi = new ProcessIntegrity({platform: 'darwin', run, expectedLibs: ['/usr/local/bin/node']});
  const report = pi.checkAll(4242);
  assert.deepEqual(report.memoryMaps.libraries, ['/usr/lib/evil.dylib', '/usr/local/bin/node']);
  assert.deepEqual(report.memoryMaps.anomalies.map(anomaly => anomaly.type), ['file-wx', 'unexpected-lib']);
  assert.equal(report.memoryMaps.summary.totalRegions, 4);
  assert.deepEqual(report.linkerIntegrity.findings, [{type: 'DYLD_INSERT_LIBRARIES', value: '/tmp/inject.dylib'}]);
  assert.equal(report.tracer.traced, true);
  assert.equal(report.fileDescriptors.totalFds, 2);
  assert.deepEqual(report.fileDescriptors.suspicious, [{type: 'deleted', target: '/tmp/payload (deleted)'}]);
  assert.equal(report.executablePages.supported, false);
  assert.equal(report.listeningSockets.supported, false);
  assert.equal(report.passed, false);
  assert.deepEqual(run.calls[0], ['vmmap', '--wide', '4242']);
  assert.deepEqual(report.incomplete, [], 'every supported check ran');

  const clean = new ProcessIntegrity({platform: 'darwin', run: recordedRun({'ps eww': 'node app.js HOME=/x', 'ps -o stat=': 'S', vmmap: ''})});
  assert.equal(clean.checkLinkerIntegrity(1).clean, true);
  assert.equal(clean.checkTracerPid(1).traced, false);
  assert.deepEqual(clean.checkMemoryMaps(1).anomalies, []);

  const failing = new ProcessIntegrity({platform: 'darwin', run: recordedRun({})});
  assert.match(failing.checkMemoryMaps(1).error, /vmmap failed/);
  assert.equal(failing.checkLinkerIntegrity(1).clean, null);
  assert.equal(failing.checkTracerPid(1).traced, null);
  assert.match(failing.checkFileDescriptors(1).error, /not recorded/);
  assert.equal(failing.getProcessInfo(1).supported, false);
  assert.deepEqual(failing.listProcesses(), []);
  assert.deepEqual(failing.checkAll(1).incomplete.map(item => item.check), ['memoryMaps', 'linkerIntegrity', 'tracer', 'fileDescriptors']);
});

test('Windows: PowerShell and registry output', () => {
  const modules = 'C:\\Program Files\\nodejs\\node.exe\r\nC:\\Windows\\SYSTEM32\\ntdll.dll\r\nC:\\Temp\\inject.dll\r\n\r\n';
  const run = recordedRun({
    'powershell.exe -NoProfile -NonInteractive -Command (Get-Process -Id 7 -ErrorAction Stop).Modules': modules,
    'reg.exe query HKLM\\SOFTWARE\\Microsoft': '\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\r\n    AppInit_DLLs    REG_SZ    C:\\Temp\\inject.dll\r\n',
    'reg.exe query HKLM\\SOFTWARE\\WOW6432Node': '\r\n    AppInit_DLLs    REG_SZ    \r\n',
    'powershell.exe -NoProfile -NonInteractive -Command Add-Type': 'True\r\n',
  });
  const pi = new ProcessIntegrity({platform: 'win32', run, expectedLibs: [String.raw`C:\Program Files\nodejs\node.exe`, String.raw`C:\Windows\SYSTEM32\ntdll.dll`]});
  const report = pi.checkAll(7);
  assert.deepEqual(report.memoryMaps.anomalies, [{type: 'unexpected-lib', path: String.raw`C:\Temp\inject.dll`}]);
  assert.deepEqual(report.linkerIntegrity.findings.map(finding => finding.value), [String.raw`C:\Temp\inject.dll`]);
  assert.equal(report.tracer.traced, true);
  assert.equal(report.fileDescriptors.supported, false);
  assert.ok(run.calls.some(call => call.at(-1).includes('CheckRemoteDebuggerPresent') && call.at(-1).includes('-Id 7 ')));

  const noAllowlist = new ProcessIntegrity({platform: 'win32', run: recordedRun({'powershell.exe -NoProfile -NonInteractive -Command (Get-Process': 'a.dll\r\n', 'powershell.exe -NoProfile -NonInteractive -Command Add-Type': 'False'})});
  assert.deepEqual(noAllowlist.checkMemoryMaps(7).anomalies, []);
  assert.equal(noAllowlist.checkLinkerIntegrity(7).clean, true, 'absent registry values are clean');
  assert.equal(noAllowlist.checkTracerPid(7).traced, false);

  const failing = new ProcessIntegrity({platform: 'win32', run: recordedRun({})});
  assert.match(failing.checkMemoryMaps(7).error, /module enumeration failed/);
  assert.equal(failing.checkTracerPid(7).traced, null);
});

test('unsupported platforms say so instead of passing', () => {
  const pi = new ProcessIntegrity({platform: 'freebsd'});
  const report = pi.checkAll(1);
  for (const key of ['memoryMaps', 'executablePages', 'linkerIntegrity', 'tracer', 'fileDescriptors', 'listeningSockets']) {
    assert.equal(report[key].supported, false, key);
  }

  assert.equal(report.linkerIntegrity.clean, null);
  assert.equal(report.tracer.traced, null);
  assert.throws(() => pi.checkAll('1; rm -rf /'), /Invalid process id/);
  assert.equal(new ProcessIntegrity().platform, process.platform);
});

test('parsing helpers', () => {
  assert.equal(ProcessIntegrity.parseMapsLine('nonsense'), null);
  assert.deepEqual(ProcessIntegrity.splitNodeOptions(String.raw`  --a "b c" d\ e --x="y \" z" `), ['--a', 'b c', 'd\\', 'e', '--x=y " z']);
  assert.deepEqual(ProcessIntegrity.splitNodeOptions('""'), ['']);
  assert.deepEqual(ProcessIntegrity.splitNodeOptions(''), []);
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--max-old-space-size=1', '--loader', 'x.mjs', '--experimental-loader=y', 'app.js', '--require', 'z']), {
    preloads: ['--loader x.mjs', '--experimental-loader=y'],
    inspector: [],
    ports: [],
  });
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--inspect-brk', '--', '--require', 'x']), {preloads: [], inspector: ['--inspect-brk'], ports: []});
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--require']), {preloads: ['--require'], inspector: [], ports: []});
  // Options that configure the inspector without opening it (as Node.js 24's test runner passes).
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--inspect-port', '9230', '--inspect-publish-uid=stderr,http', '--inspect-wait=0', '--debug-port=h:x', 'app.js']), {preloads: [], inspector: ['--inspect-wait=0'], ports: [9230, 0]});
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--inspect-port']).ports, []);
  assert.equal(new ProcessIntegrity({procRoot: '/nonexistent'})._parentIsPm2('1'), false);
  // Values of options that take one are not the script.
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--disable-warning', 'DEP0040', '-r', './evil.js', 'app.js']).preloads, ['-r ./evil.js']);
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--snapshot-blob', 'snap.blob', 'app.js']).preloads, ['--snapshot-blob snap.blob']);
  // An unrecognized option may take a value: keep scanning past one positional.
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['--future-flag', 'value', '-r', 'x', 'app.js', '-r', 'y']).preloads, ['-r x']);
  // NODE_OPTIONS has no script: everything is scanned.
  assert.deepEqual(ProcessIntegrity.findNodeInjectionFlags(['stray', '-r', 'x'], {hasScript: false}).preloads, ['-r x']);
  assert.equal(ProcessIntegrity.decodeProcAddress('0100007F', false), '127.0.0.1');
  assert.equal(ProcessIntegrity.decodeProcAddress('00000000000000000000000001000000', true), '::1');
  assert.equal(ProcessIntegrity.decodeProcAddress('000080FE00000000FF000000020000FE', true), 'fe80::ff:fe00:2');
  assert.equal(ProcessIntegrity.decodeProcAddress('B80D0120010000000200000003000000', true), '2001:db8:0:1:0:2:0:3');
  assert.equal(ProcessIntegrity.decodeProcAddress('00000000000000000000000000000000', true), '::');
  assert.deepEqual(ProcessIntegrity.summarizeFindings({
    memoryMaps: {anomalies: [{type: 'file-wx', address: '1-2'}]},
    executablePages: {},
    linkerIntegrity: null,
    tracer: {traced: true},
    fileDescriptors: {},
  }), [
    {
      check: 'memoryMaps', type: 'file-wx', severity: 'critical', detail: '1-2',
    },
    {
      check: 'tracer', type: 'debugger-attached', severity: 'critical', detail: null,
    },
  ]);
});

test('fixture /proc: clock tick fallback and socket ordering on shared ports', {skip: !linux}, t => {
  const header = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n';
  const root = fakeProc(t, {
    fds: {3: 'socket:[1]', 4: 'socket:[2]', 5: 'socket:[3]'},
    net: {
      tcp: `${header}   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 1 1\n   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 3 1\n`,
      tcp6: `${header}   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 2 1\n`,
    },
  });
  const pi = new ProcessIntegrity({procRoot: root, run: () => 'not a number\n'});
  assert.deepEqual(pi.checkListeningSockets(4242).listening.map(item => item.address), ['0.0.0.0', '127.0.0.1', '::']);
  assert.equal(pi.getProcessInfo(4242).startTimeMs, 1_700_000_000_000 + 5000);
});

test('fixture /proc: start time uses /proc/uptime precision, falling back to btime', {skip: !linux}, t => {
  const precise = fakeProc(t, {});
  fs.writeFileSync(path.join(precise, 'uptime'), '100.50 200.00\n');
  const before = Date.now();
  const start = new ProcessIntegrity({procRoot: precise, run: () => '100\n'}).getProcessInfo(4242).startTimeMs;
  // Started 5 s after boot, 100.5 s of uptime: 95.5 s ago.
  assert.ok(start >= before - 95_500 - 50 && start <= Date.now() - 95_500 + 50, String(start));

  const garbage = fakeProc(t, {});
  fs.writeFileSync(path.join(garbage, 'uptime'), 'not a number\n');
  assert.equal(new ProcessIntegrity({procRoot: garbage, run: () => '100\n'}).getProcessInfo(4242).startTimeMs, 1_700_000_000_000 + 5000);
});

test('checks that cannot run for lack of permission are reported as incomplete', {skip: !linux || process.getuid() !== 0}, async t => {
  // An unprivileged user inspecting a root process: maps are readable, but
  // the environment and memory are not.
  const directory = tempDir(t);
  fs.chmodSync(directory, 0o755);
  for (const file of fs.readdirSync(path.join(__dirname, '..', 'lib')).filter(name => name.endsWith('.js'))) {
    fs.copyFileSync(path.join(__dirname, '..', 'lib', file), path.join(directory, file));
  }

  const target = spawn('sleep', ['1000'], {stdio: 'ignore'});
  t.after(() => target.kill('SIGKILL'));
  await sleep(100);
  const script = `const P = require(${JSON.stringify(path.join(directory, 'process-integrity.js'))}); process.stdout.write(JSON.stringify(new P().checkAll(${target.pid}).incomplete));`;
  const output = await new Promise((resolve, reject) => {
    const child = spawn('setpriv', ['--reuid=65534', '--regid=65534', '--clear-groups', process.execPath, '-e', script], {stdio: ['ignore', 'pipe', 'inherit'], cwd: directory});
    let text = '';
    child.stdout.on('data', chunk => {
      text += chunk;
    });
    child.on('error', reject);
    child.on('close', () => resolve(text));
  });
  const incomplete = JSON.parse(output);
  const checks = new Set(incomplete.map(item => item.check));
  assert.ok(checks.has('executablePages'), output);
  assert.ok(checks.has('linkerIntegrity'), output);
  assert.ok(checks.has('fileDescriptors'), output);
  assert.ok(incomplete.every(item => typeof item.error === 'string'));

  // With the same privileges as the target, every check runs.
  assert.deepEqual(new ProcessIntegrity().checkAll(target.pid).incomplete, []);
});

test('a process that rewrites its command line: PM2 options, and hidden startup flags', {skip: !linux}, async t => {
  const directory = tempDir(t);
  // What an injected preload could do to hide itself (PM2 does the same to name its workers).
  const retitle = path.join(directory, 'retitle.js');
  fs.writeFileSync(retitle, `process.title = 'node app.js'; ${KEEP_ALIVE}`);
  const plain = new ProcessIntegrity({ldPreloadPath: path.join(directory, 'none')});

  const hidden = await child(t, process.execPath, ['--require', retitle, retitle], {waitForOutput: false});
  await sleep(200);
  assert.equal(fs.readFileSync(`/proc/${hidden.proc.pid}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' '), 'node app.js');
  const report = plain.checkLinkerIntegrity(hidden.proc.pid);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].type, 'argv-rewritten');
  assert.match(report.findings[0].value, /^the command line was replaced \(\d+ bytes\); the options the process started with cannot be read from it$/);
  assert.equal(plain.checkAll(hidden.proc.pid).findings.find(finding => finding.type === 'argv-rewritten').severity, 'warning');

  // A title as long as the original leaves no padding, but a single argument.
  const exact = path.join(directory, 'exact.js');
  fs.writeFileSync(exact, `process.title = 'x'.repeat(Buffer.byteLength(process.argv.join(' '))); ${KEEP_ALIVE}`);
  const full = await child(t, process.execPath, [exact]);
  await sleep(200);
  const fullReport = plain.checkLinkerIntegrity(full.proc.pid);
  assert.deepEqual(fullReport.findings.map(finding => finding.type), ['argv-rewritten']);
  assert.equal(fullReport.cmdlineRewritten.hiddenBytes, 0);

  // Under PM2 the options come from its configuration, in pm2_env.
  // PM2's own names for these settings.
  const pm2Env = '{"name":"web","pm_exec_path":"/srv/app/web.js","node_args":["--max-old-space-size=4096","--require","/tmp/evil.js"],"interpreter_args":"--inspect=0.0.0.0:9229"}';
  const withPm2 = value => Object.assign(cleanEnvironment(), Object.fromEntries([['pm2_env', value]]));
  const managed = await child(t, process.execPath, [retitle], {env: withPm2(pm2Env)});
  await sleep(200);
  const managedReport = plain.checkLinkerIntegrity(managed.proc.pid);
  // PM2's settings are checked, but outside the PM2 daemon they do not
  // explain the rewritten command line.
  assert.deepEqual(managedReport.findings.map(finding => `${finding.type} ${finding.value}`.replace(/\(\d+ bytes\)/, '(n bytes)')), [
    'pm2-node_args-preload --require /tmp/evil.js',
    'pm2-node_args-inspector --inspect=0.0.0.0:9229',
    'argv-rewritten the command line was replaced (n bytes); the options the process started with cannot be read from it',
  ]);
  assert.deepEqual(managedReport.inspectorPorts, [9229]);
  assert.deepEqual(managedReport.pm2, {
    name: 'web', script: '/srv/app/web.js', nodeArgs: ['--max-old-space-size=4096', '--require', '/tmp/evil.js'], interpreterArgs: ['--inspect=0.0.0.0:9229'],
  });
  assert.ok(managedReport.cmdlineRewritten.hiddenBytes > 3);

  // PM2's fork mode: the settings as separate variables, lists joined with commas.
  // A child of the PM2 daemon (here a process that names itself like it).
  const daemon = path.join(directory, 'daemon.js');
  fs.writeFileSync(daemon, `
    process.title = 'PM2 v6.0.14: God Daemon (/home/app/.pm2)';
    const child = require('node:child_process').spawn(process.execPath, [${JSON.stringify(retitle)}], {stdio: 'ignore', env: process.env});
    console.log(child.pid);
    process.on('SIGTERM', () => { child.kill('SIGKILL'); process.exit(); });
    ${KEEP_ALIVE}`);
  const forkEnvironment = Object.assign(cleanEnvironment(), Object.fromEntries([['pm_exec_path', '/srv/app/proxy.js'], ['name', 'proxy'], ['node_args', '--max-old-space-size=100,--require,/tmp/evil.js'], ['interpreter_args', '']]));
  const managedByPm2 = await child(t, process.execPath, [daemon], {env: forkEnvironment, waitForOutput: true});
  t.after(() => {
    try {
      process.kill(Number(managedByPm2.line), 'SIGKILL');
    } catch {}
  });
  await sleep(300);
  const forkReport = plain.checkLinkerIntegrity(managedByPm2.line);
  assert.deepEqual(forkReport.findings.map(finding => `${finding.type} ${finding.value}`), ['pm2-node_args-preload --require /tmp/evil.js']);
  assert.ok(forkReport.cmdlineRewritten, 'rewritten, and explained by PM2');
  assert.deepEqual(forkReport.pm2, {
    name: 'proxy', script: '/srv/app/proxy.js', nodeArgs: ['--max-old-space-size=100', '--require', '/tmp/evil.js'], interpreterArgs: [],
  });
  assert.deepEqual(ProcessIntegrity.parsePm2Fields(Object.fromEntries([['pm_exec_path', '/x.js'], ['node_args', '--require /a.js']])), {
    name: null, script: '/x.js', nodeArgs: ['--require', '/a.js'], interpreterArgs: [],
  });
  assert.equal(ProcessIntegrity.parsePm2Fields({name: 'not pm2'}), null);

  // A clean PM2 application.
  const clean = await child(t, process.execPath, [keepAlive(t), '', ''], {env: withPm2('{"name":"api","node_args":"--max-old-space-size=4096"}')});
  const cleanReport = plain.checkLinkerIntegrity(clean.proc.pid);
  assert.deepEqual(cleanReport.findings, []);
  assert.equal(cleanReport.cmdlineRewritten, undefined, 'two empty arguments are not padding');

  assert.equal(ProcessIntegrity.parsePm2Environment('not json'), null);
  assert.equal(ProcessIntegrity.parsePm2Environment('null'), null);
  assert.equal(ProcessIntegrity.parsePm2Environment(null), null);
  assert.equal(ProcessIntegrity.parsePm2Environment('x'.repeat(5 * 1024 * 1024)), null);
  assert.deepEqual(ProcessIntegrity.parsePm2Environment('{"node_args":[1]}'), {
    name: null, script: null, nodeArgs: ['1'], interpreterArgs: [],
  });
});

test('fixture /proc: a process in another root (container or chroot) is inspected through /proc/<pid>/root', {skip: !linux}, t => {
  const rootfs = tempDir(t, 'attestium-rootfs-');
  writeFiles(rootfs, {'usr/lib/libapp.so': Buffer.concat([Buffer.from('CODE'), Buffer.alloc(0x3C, 0)]), 'tmp/.java_pid17': '', 'etc/ld.so.preload': '/evil.so\n'});
  const {ino} = fs.statSync(path.join(rootfs, 'usr/lib/libapp.so'));
  const memory = Buffer.concat([Buffer.from('CODE'), Buffer.alloc(0x3C, 0)]);
  const root = fakeProc(t, {
    maps: `10000-10040 r-xp 00000000 08:01 ${ino} /usr/lib/libapp.so\n10000-10040 r-xp 00000000 08:01 ${ino} /usr/lib/jvm/lib/server/libjvm.so\n`,
    mem: [[0x1_00_00, memory]],
    status: 'Name:\tjava\nPPid:\t1\nUid:\t0\t0\t0\t0\nTracerPid:\t0\nNSpid:\t4242\t17\n',
    links: {root: rootfs, exe: '/usr/bin/java'},
  });
  fs.mkdirSync(path.join(root, 'self'));
  fs.symlinkSync('/', path.join(root, 'self', 'root'));
  const pi = new ProcessIntegrity({procRoot: root});
  const pages = pi.checkExecutablePages(4242);
  assert.equal(pages.regions[0].matched, true, 'compared with the file inside the process\'s root');
  assert.equal(pi.checkMemoryMaps(4242).anomalies.some(anomaly => anomaly.path === '/usr/lib/libapp.so'), false);
  const report = pi.checkAll(4242);
  assert.equal(report.runtime.name, 'jvm');
  assert.deepEqual(report.linkerIntegrity.findings.map(finding => finding.type), ['jvm-attach-listener', 'ld.so.preload']);

  // Without NSpid (older kernels) the host pid is used.
  const old = fakeProc(t, {status: 'Name:\tjava\n', links: {root: rootfs, exe: '/usr/bin/java'}});
  fs.mkdirSync(path.join(old, 'self'));
  fs.symlinkSync('/', path.join(old, 'self', 'root'));
  assert.equal(new ProcessIntegrity({procRoot: old}).checkLinkerIntegrity(4242, {runtime: 'jvm'}).findings.some(finding => finding.type === 'jvm-attach-listener'), false);
  assert.equal(new ProcessIntegrity({procRoot: old})._namespacePid('4242'), '4242');
  assert.equal(new ProcessIntegrity({procRoot: tempDir(t)})._namespacePid('4242'), '4242');

  // The same root as the attester's: host paths.
  const same = fakeProc(t, {links: {root: '/'}});
  fs.mkdirSync(path.join(same, 'self'));
  fs.symlinkSync('/', path.join(same, 'self', 'root'));
  assert.equal(new ProcessIntegrity({procRoot: same})._fileRoot('4242'), '');
  assert.equal(ProcessIntegrity.inRoot('', '/x'), '/x');
  assert.equal(ProcessIntegrity.inRoot('/proc/4242/root', '/x'), '/proc/4242/root/x');
});

const hasPython = linux && (() => {
  try {
    execFileSync('python3', ['-c', ''], {stdio: 'ignore'});
    return true;
  } catch {
    return false;
  }
})();

test('a process in another root cannot make the checks read host files through its symbolic links', {skip: !linux || process.getuid() !== 0 || !hasPython}, async t => {
  const rootfs = tempDir(t, 'attestium-rootfs-');
  const host = tempDir(t);
  writeFiles(host, {shadow: 'root:$6$secret-hash:19000:0:99999:7:::\n'});
  writeFiles(rootfs, {'usr/lib/libapp.so': 'x', 'etc/preload.list': '/lib/evil.so\n'});
  const preload = path.join(rootfs, 'etc', 'ld.so.preload');
  // Read through /proc/<pid>/root, an absolute link resolves against the
  // reader's root: the host's.
  fs.symlinkSync(path.join(host, 'shadow'), preload);
  const {proc} = await child(t, 'python3', ['-c', 'import os, sys, time; os.chroot(sys.argv[1]); os.chdir("/"); print("ready", flush=True); time.sleep(600)', rootfs], {waitForOutput: true});
  const pi = new ProcessIntegrity();
  const root = pi._fileRoot(String(proc.pid));
  assert.notEqual(root, '');
  const leaked = pi.checkLinkerIntegrity(proc.pid, {runtime: 'python'});
  assert.equal(JSON.stringify(leaked).includes('secret-hash'), false, 'the host file is not read');
  assert.deepEqual(leaked.findings.filter(finding => finding.type.startsWith('ld.so.preload')), []);

  // A link inside the root is followed inside it.
  fs.unlinkSync(preload);
  fs.symlinkSync('/etc/preload.list', preload);
  assert.deepEqual(pi.checkLinkerIntegrity(proc.pid, {runtime: 'python'}).findings.filter(finding => finding.type.startsWith('ld.so.preload')), [{type: 'ld.so.preload', value: '/lib/evil.so', severity: 'critical'}]);

  // A FIFO, a directory or a huge file there is reported, never waited on or read.
  fs.unlinkSync(preload);
  execFileSync('mkfifo', [preload]);
  const fifo = pi.checkLinkerIntegrity(proc.pid, {runtime: 'python'});
  assert.deepEqual(fifo.findings.filter(finding => finding.type.startsWith('ld.so.preload')), [{type: 'ld.so.preload-unreadable', value: 'not a regular file', severity: 'warning'}]);
  assert.equal(fifo.clean, false);
  fs.unlinkSync(preload);
  fs.writeFileSync(preload, Buffer.alloc(128 * 1024, 0x61));
  assert.deepEqual(pi.checkLinkerIntegrity(proc.pid, {runtime: 'python'}).findings.filter(finding => finding.type.startsWith('ld.so.preload')).map(finding => finding.value), ['larger than any list of libraries']);
  fs.unlinkSync(preload);
  fs.mkdirSync(preload);
  assert.deepEqual(pi.checkLinkerIntegrity(proc.pid, {runtime: 'python'}).findings.filter(finding => finding.type.startsWith('ld.so.preload')).map(finding => finding.value), ['not a regular file']);

  // Files the process maps are found inside its root too.
  assert.equal(ProcessIntegrity.statIn(root, '/usr/lib/libapp.so').ino, fs.statSync(path.join(rootfs, 'usr/lib/libapp.so')).ino);
  const fd = ProcessIntegrity.openIn(root, '/usr/lib/libapp.so');
  assert.equal(fs.readFileSync(fd, 'utf8'), 'x');
  fs.closeSync(fd);
});

test('memory maps record the inode each file had when it was mapped', {skip: !linux || !hasPython}, async t => {
  const directory = tempDir(t);
  const library = path.join(directory, 'lib.so');
  fs.writeFileSync(library, Buffer.alloc(4096, 0xC3));
  const {proc} = await child(t, 'python3', ['-c', 'import mmap, sys, time; f = open(sys.argv[1], "rb"); m = mmap.mmap(f.fileno(), 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC); print("ready", flush=True); time.sleep(600)', library], {waitForOutput: true});
  const pi = new ProcessIntegrity();
  assert.ok(pi.checkExecutablePages(proc.pid).regions.some(region => region.path === library && region.matched));
  assert.equal(pi.checkMemoryMaps(proc.pid).inodes[library], fs.statSync(library).ino);
});

test('fixture /proc: runtime detection and checks when maps or the runtime name are unusual', {skip: !linux}, t => {
  const noMaps = fakeProc(t, {links: {exe: '/usr/bin/python3.12'}});
  fs.rmSync(path.join(noMaps, '4242', 'maps'));
  const report = new ProcessIntegrity({procRoot: noMaps}).checkAll(4242);
  assert.deepEqual(report.runtime, {
    name: 'python', label: 'Python', version: '3.12', by: 'executable',
  });
  assert.equal(new ProcessIntegrity({procRoot: noMaps}).checkAll(4242, {runtime: 'no-such-runtime'}).runtime.name, 'native');
  assert.equal(new ProcessIntegrity({procRoot: noMaps}).checkAll(4242, {isNode: true}).runtime.name, 'node');
  assert.equal(new ProcessIntegrity({
    procRoot: noMaps, platform: 'darwin', run() {
      throw new Error('no vmmap');
    },
  }).detectRuntime(4242).name, 'python');
  assert.equal(new ProcessIntegrity({procRoot: tempDir(t)}).detectRuntime(4242).name, 'native');
});

test('a process in a Docker container is checked against the files in its own image', {skip: !linux || process.getuid() !== 0 || !fs.existsSync('/var/run/docker.sock')}, async t => {
  let id;
  try {
    id = execFileSync('docker', ['run', '-d', '--rm', 'alpine:3.20', 'sleep', '60'], {encoding: 'utf8'}).trim();
  } catch {
    t.skip('docker cannot run containers here');
    return;
  }

  t.after(() => {
    try {
      execFileSync('docker', ['rm', '-f', id], {stdio: 'ignore'});
    } catch {}
  });
  const pid = execFileSync('docker', ['inspect', '-f', '{{.State.Pid}}', id], {encoding: 'utf8'}).trim();
  const pi = new ProcessIntegrity();
  assert.notEqual(pi._fileRoot(pid), '');
  const report = pi.checkAll(pid);
  assert.equal(report.executablePages.matched, true, JSON.stringify(report.executablePages.skipped));
  assert.ok(report.executablePages.regions.some(region => /ld-musl|busybox/.test(region.path)), 'the container\'s own musl and busybox are compared');
  assert.equal(report.passed, true, JSON.stringify(report.findings));
});

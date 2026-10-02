'use strict';

/* eslint-disable camelcase -- PM2 and .NET name these fields and variables */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const runtimes = require('../lib/runtimes');
const ProcessIntegrity = require('../lib/process-integrity');
const {tempDir, sleep} = require('./helpers');

const linux = process.platform === 'linux';

function which(command) {
  try {
    return execFileSync('which', [command], {encoding: 'utf8'}).trim();
  } catch {
    return null;
  }
}

function environment(extra = {}) {
  const result = {PATH: process.env.PATH, HOME: process.env.HOME};
  return {...result, ...extra};
}

/**
 * Start a real interpreter and wait until it has mapped its libraries (or
 * printed a line).
 */
async function start(t, command, args, options = {}) {
  const proc = spawn(command, args, {stdio: ['ignore', 'pipe', 'pipe'], env: environment(options.env), cwd: options.cwd});
  t.after(() => {
    proc.kill('SIGKILL');
  });
  if (options.ready) {
    await new Promise((resolve, reject) => {
      let output = '';
      proc.stdout.on('data', chunk => {
        output += chunk;
        if (output.includes(options.ready)) {
          resolve();
        }
      });
      proc.once('exit', code => reject(new Error(`${command} exited with ${code}`)));
    });
  } else {
    for (let i = 0; i < 100; i++) {
      await sleep(30);
      try {
        const maps = fs.readFileSync(`/proc/${proc.pid}/maps`, 'utf8');
        if (!options.library || options.library.test(maps)) {
          break;
        }
      } catch {}
    }
  }

  return proc;
}

const summary = report => report.findings.map(finding => `${finding.severity} ${finding.type} ${finding.value}`);

test('Python: detected by name and libpython, PYTHON* variables and -c code, -I ignores the environment', {skip: !linux || !which('python3')}, async t => {
  const pi = new ProcessIntegrity({ldPreloadPath: '/nonexistent'});
  const proc = await start(t, 'python3', ['-c', 'import time; print("ready", flush=True); time.sleep(30)'], {
    env: {
      PYTHONPATH: '/srv/extra', PYTHONBREAKPOINT: 'evil.hook', PYTHONWARNINGS: 'ignore::evil.Category', PYTHONSTARTUP: '/x.py',
    },
    ready: 'ready',
  });
  const report = pi.checkAll(proc.pid);
  assert.equal(report.runtime.name, 'python');
  assert.match(report.runtime.version, /^3\.\d+$/);
  assert.deepEqual(summary(report.linkerIntegrity).sort(), [
    'critical PYTHONBREAKPOINT evil.hook',
    'critical PYTHONPATH /srv/extra',
    'critical PYTHONWARNINGS-import ignore::evil.Category',
    'critical argv-code import time; print("ready", flush=True); time.sleep(30)',
    'warning PYTHONSTARTUP /x.py',
  ]);
  assert.ok(report.inspectorPorts.includes(5678), 'debugpy\'s default port is watched');

  const isolated = await start(t, 'python3', ['-I', '-c', 'import time; print("ready", flush=True); time.sleep(30)'], {env: {PYTHONPATH: '/srv/extra'}, ready: 'ready'});
  assert.deepEqual(summary(pi.checkLinkerIntegrity(isolated.pid)).map(line => line.split(' ').slice(0, 2).join(' ')), ['critical argv-code']);
});

test('JVM: agents in JAVA_TOOL_OPTIONS, error commands, and an attach made with jcmd', {skip: !linux || !which('java') || !which('jcmd')}, async t => {
  const directory = tempDir(t);
  const source = path.join(directory, 'Sleep.java');
  fs.writeFileSync(source, 'public class Sleep { public static void main(String[] a) throws Exception { System.out.println("ready"); Thread.sleep(60000); } }\n');
  const proc = await start(t, 'java', ['-XX:OnError=echo', source], {env: {JDK_JAVA_OPTIONS: '-Xmx64m -Dcom.sun.management.jmxremote.port=0 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false'}, ready: 'ready'});
  const pi = new ProcessIntegrity({ldPreloadPath: '/nonexistent'});
  const report = pi.checkAll(proc.pid);
  assert.equal(report.runtime.name, 'jvm');
  assert.equal(report.runtime.by, 'library');
  assert.deepEqual(summary(report.linkerIntegrity).sort(), [
    'critical jvm-remote-management JDK_JAVA_OPTIONS: -Dcom.sun.management.jmxremote.port=0',
    'warning inspector-random-port a debugger or management port would listen on an unpredictable port',
    'warning jvm-on-error-command argv: -XX:OnError=echo',
  ]);

  // A tool that attaches leaves the JVM's attach listener running.
  execFileSync('jcmd', [String(proc.pid), 'VM.version'], {stdio: 'ignore', env: environment()});
  const attached = summary(pi.checkLinkerIntegrity(proc.pid));
  assert.ok(attached.includes('warning jvm-attach-listener a tool attached to this JVM (agents can be loaded this way)'), attached.join('\n'));
});

test('Ruby, Perl and PHP: required libraries, include paths, inline code and ini overrides', {skip: !linux}, async t => {
  const pi = new ProcessIntegrity({ldPreloadPath: '/nonexistent'});
  if (which('ruby')) {
    const ruby = await start(t, 'ruby', ['-W0', '-rjson', '-I', '/srv/lib', '-e', 'puts "ready"; $stdout.flush; sleep 30'], {env: {RUBYLIB: '/srv/rubylib', RUBYOPT: '-rdebug/open', RUBY_DEBUG_NONSTOP: '1'}, ready: 'ready'});
    const report = pi.checkAll(ruby.pid);
    assert.equal(report.runtime.name, 'ruby');
    assert.deepEqual(summary(report.linkerIntegrity).sort(), [
      'critical RUBYLIB /srv/rubylib',
      'critical argv-code puts "ready"; $stdout.flush; sleep 30',
      'critical argv-include -I /srv/lib',
      'critical argv-require -r json',
      'critical debugger -r debug/open',
    ]);
  }

  const perl = await start(t, 'perl', ['-Mstrict', '-d:Trace', '-e', String.raw`$|=1; print "ready\n"; sleep 30`], {env: {PERL5LIB: '/srv/perl', PERL5OPT: '-MEvil'}, ready: 'ready'}).catch(() => null);
  // Devel::Trace may not be installed; without it perl refuses to start.
  if (perl) {
    assert.ok(summary(pi.checkLinkerIntegrity(perl.pid)).includes('critical debugger -d:Trace'));
  }

  const plain = await start(t, 'perl', ['-Mstrict', '-e', String.raw`$|=1; print "ready\n"; sleep 30`], {env: {PERL5LIB: '/srv/perl', PERL5OPT: '-MIO::Handle'}, ready: 'ready'});
  assert.deepEqual(summary(pi.checkLinkerIntegrity(plain.pid)).sort(), [
    'critical PERL5LIB /srv/perl',
    'critical PERL5OPT-module -MIO::Handle',
    String.raw`critical argv-code $|=1; print "ready\n"; sleep 30`,
    'critical argv-module -Mstrict',
  ]);

  if (which('php')) {
    const php = await start(t, 'php', ['-d', 'auto_prepend_file=/dev/null', '-r', String.raw`echo "ready\n"; sleep(30);`], {env: {PHP_INI_SCAN_DIR: '/srv/php.d'}, ready: 'ready'});
    const report = pi.checkAll(php.pid);
    assert.equal(report.runtime.name, 'php');
    assert.deepEqual(summary(report.linkerIntegrity).sort(), [
      'critical PHP_INI_SCAN_DIR /srv/php.d',
      String.raw`critical argv-code -r echo "ready\n"; sleep(30);`,
      'critical argv-ini -d auto_prepend_file=/dev/null',
    ]);
  }
});

test('Erlang: the BEAM is detected, and a distributed node is reported', {skip: !linux || !which('erl')}, async t => {
  const proc = await start(t, 'erl', ['-noshell', '-sname', `attestium${process.pid}`, '-eval', 'io:format("ready~n"), timer:sleep(30000).'], {env: {ERL_LIBS: '/srv/erl'}, ready: 'ready'});
  const report = new ProcessIntegrity({ldPreloadPath: '/nonexistent'}).checkAll(proc.pid);
  assert.equal(report.runtime.name, 'beam');
  assert.match(report.runtime.version, /^\d+/);
  assert.deepEqual(summary(report.linkerIntegrity).map(line => line.split(' ').slice(0, 2).join(' ')).sort(), ['critical ERL_LIBS', 'warning beam-distribution']);
  try {
    execFileSync('epmd', ['-kill'], {stdio: 'ignore'});
  } catch {}
});

test('Ruby: `bundle exec` sets Bundler\'s own RUBYOPT and RUBYLIB, which are context; anything added to them is not', {skip: !linux || !which('bundle')}, async t => {
  const directory = tempDir(t);
  fs.writeFileSync(path.join(directory, 'Gemfile'), 'source "https://rubygems.org"\n');
  const pi = new ProcessIntegrity({ldPreloadPath: '/nonexistent'});
  const proc = await start(t, 'bundle', ['exec', 'ruby', '-e', 'puts "ready"; $stdout.flush; sleep 30'], {cwd: directory, ready: 'ready'});
  const report = pi.checkAll(proc.pid);
  assert.equal(report.runtime.name, 'ruby');
  const found = summary(report.linkerIntegrity).filter(line => /^\S+ (?:bundler|RUBY)/.test(line));
  assert.equal(found.length, 2, found.join('\n'));
  assert.match(found[0], /^info bundler-setup -r\S*\/gems\/bundler-[\d.]+\/lib\/bundler\/setup$|^info bundler-setup -rbundler\/setup$/);
  assert.match(found[1], /^info bundler-rubylib \/\S+\/gems\/bundler-[\d.]+\/lib$/);
  assert.equal(report.findings.some(finding => finding.severity === 'critical' && finding.type !== 'argv-code'), false);

  // Another library on RUBYLIB, or another option in RUBYOPT, is reported as before.
  const lib = found[1].split(' ')[2];
  const added = await start(t, 'ruby', ['-e', 'puts "ready"; $stdout.flush; sleep 30'], {env: {RUBYOPT: `-r${lib}/bundler/setup -rjson`, RUBYLIB: lib}, cwd: directory, ready: 'ready'});
  assert.deepEqual(summary(pi.checkLinkerIntegrity(added.pid)).filter(line => /^\S+ (?:bundler|RUBY)/.test(line)).sort(), [
    `critical RUBYLIB ${lib}`,
    `critical RUBYOPT-require -r ${lib}/bundler/setup`,
    'critical RUBYOPT-require -r json',
  ]);
});

test('Ruby: only Bundler\'s exact values are recognized', () => {
  const lib = '/usr/local/lib/ruby/gems/3.3.0/gems/bundler-2.5.22/lib';
  const setup = runtimes.bundlerSetup;
  assert.deepEqual(setup({RUBYOPT: `-r${lib}/bundler/setup`, RUBYLIB: lib}), {lib, version: '2.5.22'});
  assert.deepEqual(setup({RUBYOPT: '-rbundler/setup', RUBYLIB: lib}), {lib, version: '2.5.22'});
  assert.deepEqual(setup({RUBYOPT: ` -r ${lib}/bundler/setup `, RUBYLIB: lib}), {lib, version: '2.5.22'});
  for (const environment of [
    {RUBYOPT: '-rbundler/setup'},
    {RUBYLIB: lib},
    {RUBYOPT: '-rbundler/setup -W0', RUBYLIB: lib},
    {RUBYOPT: '-rbundler/setup', RUBYLIB: `${lib}:/srv/lib`},
    {RUBYOPT: '-r/srv/bundler/setup', RUBYLIB: lib},
    {RUBYOPT: '-rbundler/setup', RUBYLIB: '/srv/gems/bundler-2.5.22/lib/../../evil-1.0/lib'},
    {RUBYOPT: '-rbundler/setup', RUBYLIB: '/srv/gems/./bundler-2.5.22/lib'},
    {RUBYOPT: '-rbundler/setup', RUBYLIB: 'gems/bundler-2.5.22/lib'},
    {RUBYOPT: '-rbundler/setup', RUBYLIB: '/srv/gems/evil-2.5.22/lib'},
    {RUBYOPT: '-I /srv', RUBYLIB: lib},
    {RUBYOPT: '-e bundler/setup', RUBYLIB: lib},
    {RUBYOPT: '', RUBYLIB: lib},
  ]) {
    assert.equal(setup(environment), null, JSON.stringify(environment));
  }

  const inspected = runtimes.inspectRuntime('ruby', {environment: {RUBYOPT: '-rbundler/setup', RUBYLIB: lib}, cmdline: ['ruby', 'app.rb']});
  assert.deepEqual(inspected.findings.map(finding => `${finding.severity} ${finding.type}`), ['info bundler-setup', 'info bundler-rubylib']);
  assert.deepEqual(inspected.extra.bundler, {lib, version: '2.5.22'});
});

test('Ruby: `bundle exec` with the Bundler of the standard library (Debian and Ubuntu)', () => {
  const setup = runtimes.standardBundlerSetup;
  // Bundler 2.4 in Ubuntu's ruby3.2: RUBYLIB left empty, the setup file from the interpreter's own library.
  const environment = {RUBYOPT: '-r/usr/lib/ruby/3.2.0/bundler/setup', RUBYLIB: ''};
  assert.deepEqual(setup(environment, '/usr/bin/ruby3.2'), {setup: '/usr/lib/ruby/3.2.0/bundler/setup'});
  assert.deepEqual(setup({RUBYOPT: '-r /opt/ruby-3.3.6/lib/ruby/3.3.0/bundler/setup'}, '/opt/ruby-3.3.6/bin/ruby'), {setup: '/opt/ruby-3.3.6/lib/ruby/3.3.0/bundler/setup'});
  for (const [other, exe] of [
    [environment, '/srv/app/bin/ruby3.2'],
    [environment, '/usr/bin/node'],
    [environment, undefined],
    [{...environment, RUBYLIB: '/srv/lib'}, '/usr/bin/ruby3.2'],
    [{RUBYLIB: ''}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-r/usr/lib/ruby/3.2.0/bundler/setup -W0'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-I/usr/lib/ruby/3.2.0/bundler/setup'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-r/usr/lib/ruby/3.2.0/evil'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-r/usr/lib/ruby/../../srv/3.2.0/bundler/setup'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-r/usr/lib/ruby/3.2.0/../../../../srv/x/1.0.0/bundler/setup'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-r/usr/lib/ruby/vendor_ruby/bundler/setup'}, '/usr/bin/ruby3.2'],
    [{RUBYOPT: '-rbundler/setup'}, '/usr/bin/ruby3.2'],
  ]) {
    assert.equal(setup(other, exe), null, JSON.stringify([other, exe]));
  }

  const inspected = runtimes.inspectRuntime('ruby', {environment, cmdline: ['/usr/bin/ruby3.2', 'app.rb'], exe: '/usr/bin/ruby3.2'});
  assert.deepEqual(inspected.findings.map(finding => `${finding.severity} ${finding.type}`), ['info bundler-setup']);
  assert.deepEqual(inspected.extra, {});
  // Another interpreter's library is not this one's.
  const foreign = runtimes.inspectRuntime('ruby', {environment, cmdline: ['/opt/ruby/bin/ruby', 'app.rb'], exe: '/opt/ruby/bin/ruby'});
  assert.deepEqual(foreign.findings.map(finding => `${finding.severity} ${finding.type}`), ['critical RUBYOPT-require']);
});

test('memfds: the JIT memfds of the .NET runtime and the BEAM are context, only in those runtimes', () => {
  const report = (runtime, maps, fds) => ({
    runtime: runtime ? {name: runtime} : null,
    memoryMaps: {anomalies: maps.map(file => ({type: 'memfd-exec', path: file}))},
    executablePages: {},
    linkerIntegrity: {findings: []},
    tracer: {},
    fileDescriptors: {suspicious: fds.map(target => ({type: 'memfd', target}))},
  });
  const findings = input => ProcessIntegrity.summarizeFindings(input).map(finding => `${finding.severity} ${finding.type} ${finding.detail}`);
  assert.deepEqual(findings(report('dotnet', ['/memfd:doublemapper (deleted)'], ['/memfd:doublemapper (deleted)'])), [
    'info memfd-exec /memfd:doublemapper (deleted): the .NET runtime\'s W^X double mapping of JIT code',
    'info memfd-open /memfd:doublemapper (deleted): the .NET runtime\'s W^X double mapping of JIT code',
  ]);
  assert.deepEqual(findings(report('beam', ['/memfd:vmem (deleted)'], [])), ['info memfd-exec /memfd:vmem (deleted): the BEAM JIT\'s dual mapping of generated code']);
  // Other names, the same names in other runtimes, and unknown runtimes.
  assert.deepEqual(findings(report('dotnet', ['/memfd:doublemapper2 (deleted)', '/memfd:vmem (deleted)'], ['/memfd:x'])), [
    'critical memfd-exec /memfd:doublemapper2 (deleted)',
    'critical memfd-exec /memfd:vmem (deleted)',
    'critical memfd-open /memfd:x',
  ]);
  assert.deepEqual(findings(report('beam', ['/memfd:doublemapper (deleted)'], [])), ['critical memfd-exec /memfd:doublemapper (deleted)']);
  assert.deepEqual(findings(report('node', ['/memfd:vmem'], [])), ['critical memfd-exec /memfd:vmem']);
  assert.deepEqual(findings(report(null, ['/memfd:vmem'], ['/memfd:doublemapper'])), ['critical memfd-exec /memfd:vmem', 'critical memfd-open /memfd:doublemapper']);
  assert.equal(runtimes.runtimeMemfd('dotnet', '/memfd:doublemapper'), 'the .NET runtime\'s W^X double mapping of JIT code');
  assert.equal(runtimes.runtimeMemfd('dotnet', '/tmp/doublemapper'), null);
  assert.equal(runtimes.runtimeMemfd('__proto__', '/memfd:vmem'), null);
  assert.equal(runtimes.runtimeMemfd('dotnet', '/memfd:constructor'), null);
});

test('memfds: the BEAM JIT\'s memfd is recognized in a real Erlang node, a memfd of that name elsewhere is not', {skip: !linux || !which('erl')}, async t => {
  const pi = new ProcessIntegrity({ldPreloadPath: '/nonexistent'});
  const proc = await start(t, 'erl', ['-noshell', '-eval', 'io:format("ready~n"), timer:sleep(30000).'], {ready: 'ready'});
  const report = pi.checkAll(proc.pid);
  assert.equal(report.runtime.name, 'beam');
  const memfds = report.findings.filter(finding => finding.type.startsWith('memfd'));
  // Only JIT builds map generated code from a memfd.
  if (memfds.length > 0) {
    assert.deepEqual(memfds.map(finding => [finding.type, finding.severity]), [['memfd-exec', 'info']]);
    assert.match(memfds[0].detail, /^\/memfd:vmem \(deleted\): the BEAM JIT/);
  }

  assert.equal(report.passed, true, JSON.stringify(report.findings));
  const perl = await start(t, 'perl', ['-e', String.raw`$|=1; my $n="vmem"; my $fd=syscall(${{x64: 319, arm64: 279}[process.arch] || 319},$n,0); print "ready
"; sleep 30;`], {ready: 'ready'});
  const other = pi.checkAll(perl.pid);
  assert.deepEqual(other.findings.filter(finding => finding.type.startsWith('memfd')).map(finding => [finding.type, finding.severity]), [['memfd-open', 'critical']]);
});

test('detection: libraries win over names, versions come from paths, unknown programs are native', () => {
  const detect = input => runtimes.detectRuntime(input);
  assert.deepEqual(detect({exe: '/opt/app/server', libraries: ['/usr/lib/jvm/java-21-openjdk-amd64/lib/server/libjvm.so']}), {
    name: 'jvm', label: 'JVM', version: '21', by: 'library',
  });
  assert.equal(detect({exe: '/usr/share/dotnet/dotnet', libraries: ['/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.11/libcoreclr.so']}).version, '8.0.11');
  assert.equal(detect({exe: '/usr/sbin/apache2', libraries: ['/usr/lib/apache2/modules/libphp8.3.so']}).name, 'php');
  assert.equal(detect({exe: '/usr/bin/uwsgi', libraries: ['/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0']}).version, '3.12');
  assert.equal(detect({exe: '/usr/lib/erlang/erts-13.2.2.5/bin/beam.smp'}).version, '13.2.2.5');
  assert.deepEqual(detect({exe: '/usr/local/bin/renamed', nodeRelease: true}), {
    name: 'node', label: 'Node.js', version: null, by: 'release',
  });
  assert.deepEqual(detect({exe: '/usr/local/bin/deno'}), {
    name: 'deno', label: 'Deno', version: null, by: 'executable',
  });
  assert.equal(detect({exe: '/usr/local/bin/bun'}).name, 'bun');
  assert.equal(detect({exe: '/usr/bin/ruby3.2'}).name, 'ruby');
  assert.equal(detect({exe: '/usr/bin/perl'}).version, null);
  assert.equal(detect({exe: '/usr/bin/node'}).version, null);
  assert.equal(detect({exe: null}).name, 'native');
  assert.equal(detect({exe: '/srv/app/bin/server', libraries: ['/usr/lib/libc.so.6']}).name, 'native');
});

test('Node.js: preloads and inspectors in NODE_OPTIONS, argv and PM2 settings; rewritten titles', () => {
  const inspect = (environment, cmdline, extra = {}) => runtimes.inspectRuntime('node', {
    environment, cmdline, raw: extra.raw ?? `${(cmdline || []).join('\0')}\0`, parentIsPm2: extra.parentIsPm2,
  });
  const result = inspect({
    NODE_OPTIONS: '--require /a.js --inspect-port=0', NODE_PATH: '/x', pm2_env: JSON.stringify({name: 'web', pm_exec_path: '/srv/app.js', node_args: ['--import', '/b.js', '--inspect=9230']}),
  }, ['node', '--inspect', 'app.js']);
  assert.deepEqual(result.findings.map(finding => `${finding.severity} ${finding.type} ${finding.value}`), [
    'warning NODE_PATH /x',
    'critical NODE_OPTIONS-preload --require /a.js',
    'critical argv-inspector --inspect',
    'critical pm2-node_args-preload --import /b.js',
    'critical pm2-node_args-inspector --inspect=9230',
  ]);
  assert.deepEqual(result.ports, [0, 9229, 9230]);
  assert.equal(result.extra.pm2.name, 'web');

  // Fork mode: separate variables, comma-joined lists.
  const fork = inspect({pm_exec_path: '/srv/app.js', node_args: '--require,/c.js', name: 'api'}, ['node', 'app.js']);
  assert.deepEqual(fork.findings.map(finding => finding.value), ['--require /c.js']);

  // A title that replaced the command line hides the options; under PM2 it is expected.
  const rewritten = inspect({}, ['my-title'], {raw: 'my-title\0\0\0\0\0'});
  assert.equal(rewritten.findings[0].type, 'argv-rewritten');
  const underPm2 = inspect({pm2_env: JSON.stringify({pm_exec_path: '/srv/app.js'})}, ['web'], {raw: 'web\0', parentIsPm2: () => true});
  assert.deepEqual(underPm2.findings, []);
  assert.deepEqual(underPm2.extra.cmdlineRewritten, {hiddenBytes: 0, originalBytes: 4});
  // A title like PM2's daemon's hides options like any other.
  const title = 'PM2 v6.0.14: God Daemon (/home/app/.pm2)';
  assert.equal(inspect({PM2_HOME: '/home/app/.pm2'}, [title], {raw: `${title}${'\0'.repeat(28)}`}).findings[0].type, 'argv-rewritten');
  // Unreadable command line: environment only.
  assert.deepEqual(inspect({NODE_OPTIONS: '-r x'}, null).findings.map(finding => finding.type), ['NODE_OPTIONS-preload']);

  assert.equal(runtimes.parsePm2Environment('not json'), null);
  assert.equal(runtimes.parsePm2Environment('null'), null);
  assert.equal(runtimes.parsePm2Environment(42), null);
  assert.equal(runtimes.parsePm2Environment('x'.repeat((4 * 1024 * 1024) + 1)), null);
  assert.deepEqual(runtimes.parsePm2Environment(String.raw`{"node_args":"--a \"b c\"","interpreter_args":7}`), {
    name: null, script: null, nodeArgs: ['--a', 'b c'], interpreterArgs: [],
  });
  assert.equal(runtimes.parsePm2Fields({}), null);
  assert.deepEqual(runtimes.parsePm2Fields({pm_exec_path: '/a'}), {
    name: null, script: '/a', nodeArgs: [], interpreterArgs: [],
  });
});

test('Python: option parsing edge cases', () => {
  const inspect = (environment, cmdline) => runtimes.inspectRuntime('python', {environment, cmdline}).findings.map(finding => `${finding.type} ${finding.value}`);
  assert.deepEqual(inspect({}, ['python3', '-Wignore::pkg.Warn', '-X', 'pycache_prefix=/tmp/c', '-i', '-m', 'debugpy', '--listen', '5678']), [
    'argv-warnings-import ignore::pkg.Warn',
    'argv-pycache-prefix pycache_prefix=/tmp/c',
    'argv-interactive -i',
    'debugger -m debugpy',
  ]);
  // -E ignores PYTHON* variables; -S and -s make PYTHONUSERBASE irrelevant.
  assert.deepEqual(inspect({PYTHONPATH: '/x', PYTHONHOME: '/y'}, ['python3', '-Es', 'app.py']), []);
  assert.deepEqual(inspect({PYTHONUSERBASE: '/u'}, ['python3', '-s', 'app.py']), []);
  assert.deepEqual(inspect({PYTHONUSERBASE: '/u', PYTHONNOUSERSITE: '1'}, ['python3', 'app.py']), []);
  assert.deepEqual(inspect({PYTHONUSERBASE: '/u'}, ['python3', 'app.py']), ['PYTHONUSERBASE /u']);
  assert.deepEqual(inspect({
    PYTHONBREAKPOINT: '0', PYTHONPATH: '', PYTHONINSPECT: '1', PYTHONWARNINGS: 'ignore,default::DeprecationWarning',
  }, ['python3', 'app.py']), ['PYTHONINSPECT 1']);
  assert.deepEqual(inspect({PYTHONBREAKPOINT: 'pdb.set_trace'}, ['python3', '-m', 'gunicorn', 'app:wsgi']), []);
  assert.deepEqual(inspect({DEBUGPY_LAUNCHER_PORT: '1'}, null), ['debugger debugpy environment present']);
  assert.deepEqual(inspect({}, ['python3', '-W']), []);
  assert.equal(runtimes.warningImports('error'), false);
});

test('JVM, Ruby, .NET, BEAM, PHP, Perl, Deno and Bun: option parsing', () => {
  const inspect = (runtime, environment, cmdline) => runtimes.inspectRuntime(runtime, {environment, cmdline}).findings.map(finding => `${finding.severity} ${finding.type} ${finding.value}`);

  assert.deepEqual(inspect('jvm', {
    JAVA_TOOL_OPTIONS: '-javaagent:/a.jar -agentpath:/b.so -Xbootclasspath/a:/c.jar -Djava.system.class.loader=X -XX:+EnableDynamicAgentLoading -Dcom.sun.management.jmxremote',
    _JAVA_OPTIONS: '-agentlib:jdwp=transport=dt_socket,server=y,address=*:5005',
    CLASSPATH: '/cp',
  }, ['java', '-XX:+DisableAttachMechanism', '-Dx=y', 'Main', '-javaagent:ignored']), [
    'critical jvm-javaagent JAVA_TOOL_OPTIONS: -javaagent:/a.jar',
    'critical jvm-native-agent JAVA_TOOL_OPTIONS: -agentpath:/b.so',
    'critical jvm-bootclasspath JAVA_TOOL_OPTIONS: -Xbootclasspath/a:/c.jar',
    'critical jvm-system-class-loader JAVA_TOOL_OPTIONS: -Djava.system.class.loader=X',
    'warning jvm-attach JAVA_TOOL_OPTIONS: -XX:+EnableDynamicAgentLoading',
    'critical jvm-remote-management JAVA_TOOL_OPTIONS: -Dcom.sun.management.jmxremote',
    'critical debugger _JAVA_OPTIONS: -agentlib:jdwp=transport=dt_socket,server=y,address=*:5005',
    'warning CLASSPATH /cp',
  ]);
  const jvm = runtimes.inspectRuntime('jvm', {environment: {CLASSPATH: '/cp'}, cmdline: ['java', '-cp', '/app.jar', 'Main']});
  assert.deepEqual(jvm.findings, [], 'an explicit class path overrides $CLASSPATH');
  assert.deepEqual(runtimes.inspectRuntime('jvm', {environment: {}, cmdline: ['java', '-jar', '/app.jar', '-javaagent:x']}).findings, []);
  assert.deepEqual(runtimes.inspectRuntime('jvm', {environment: {_JAVA_OPTIONS: '-agentlib:jdwp=transport=dt_socket,address=8000'}, cmdline: null}).ports, [8000]);
  assert.equal(runtimes.inspectRuntime('jvm', {environment: {}, cmdline: ['java', '-XX:+DisableAttachMechanism', 'Main']}).extra.attachDisabled, true);

  assert.deepEqual(inspect('ruby', {RUBY_DEBUG_OPEN: 'true', RUBY_DEBUG_PORT: '12345', RUBYOPT: '-W0 -I/r'}, ['ruby', '-x/tmp', 'app.rb']), [
    'critical RUBYOPT-include -I /r',
    'critical debugger RUBY_DEBUG_OPEN',
  ]);
  assert.deepEqual(runtimes.inspectRuntime('ruby', {environment: {RUBY_DEBUG_OPEN: '1'}, cmdline: null}).ports, []);
  assert.deepEqual(runtimes.inspectRuntime('ruby', {environment: {RUBY_DEBUG_OPEN: '1', RUBY_DEBUG_PORT: '4000'}, cmdline: null}).ports, [4000]);

  assert.deepEqual(inspect('dotnet', {
    DOTNET_STARTUP_HOOKS: '/hook.dll', CORECLR_ENABLE_PROFILING: '1', CORECLR_PROFILER_PATH: '/p.so', COMPlus_DiagnosticPorts: '/tmp/port', DOTNET_ADDITIONAL_DEPS: '/d',
  }, ['dotnet', 'app.dll']), [
    'critical DOTNET_STARTUP_HOOKS /hook.dll',
    'critical DOTNET_ADDITIONAL_DEPS /d',
    'critical dotnet-profiler /p.so',
    'critical dotnet-diagnostic-port /tmp/port',
  ]);
  assert.deepEqual(inspect('dotnet', {COR_ENABLE_PROFILING: '1'}, null), ['critical dotnet-profiler ']);
  assert.equal(runtimes.inspectRuntime('dotnet', {environment: {DOTNET_EnableDiagnostics: '0'}, cmdline: null}).extra.diagnosticsDisabled, true);

  assert.deepEqual(inspect('beam', {ERL_AFLAGS: '-eval "evil()" -kernel x', ERL_ZFLAGS: '-pa'}, ['beam.smp', '--', '-name', 'undefined']), [
    'critical ERL_AFLAGS-eval -eval evil()',
    'critical ERL_ZFLAGS-pa -pa',
  ]);
  assert.deepEqual(inspect('beam', {}, null), []);

  assert.deepEqual(inspect('php', {PHPRC: '/etc/x'}, ['php-fpm8.3', '-dextension=evil.so', '-d', 'memory_limit=1G', '-c', '/i.ini', '-z', '/z.so', '-B', 'code', '-f', 'app.php', '-r', 'ignored']), [
    'critical PHPRC /etc/x',
    'critical argv-ini -d extension=evil.so',
    'warning argv-ini-file -c /i.ini',
    'critical argv-zend-extension -z /z.so',
    'critical argv-code -B code',
  ]);

  assert.deepEqual(inspect('perl', {PERL5DB: 'BEGIN {evil()}', PERLLIB: '/l', PERL5OPT: '-d:NYTProf -I/i'}, ['perl', '-I', '/inc', '-ne', 'print', 'file']), [
    'critical argv-include -I/inc',
    'critical argv-code print',
    'critical debugger -d:NYTProf',
    'critical PERL5OPT-include -I/i',
    'critical PERLLIB /l',
    'critical PERL5DB BEGIN {evil()}',
  ]);

  const deno = runtimes.inspectRuntime('deno', {environment: {}, cmdline: ['deno', 'run', '--inspect=127.0.0.1:9333', 'main.ts']});
  assert.deepEqual(deno.findings.map(finding => finding.type), ['argv-inspector']);
  assert.deepEqual(deno.ports, [9229, 9333]);
  assert.deepEqual(runtimes.inspectRuntime('deno', {environment: {}, cmdline: null}).findings, []);

  const bun = runtimes.inspectRuntime('bun', {environment: {BUN_INSPECT: 'ws://x', NODE_OPTIONS: '--require /n.js'}, cmdline: ['bun', '--preload', '/p.ts', '--preload=/q.ts', '-r', '/r.ts', '--inspect', 'run', 'x.ts']});
  assert.deepEqual(bun.findings.map(finding => `${finding.type} ${finding.value}`), [
    'argv-preload --preload /p.ts',
    'argv-preload --preload=/q.ts',
    'argv-preload -r /r.ts',
    'argv-inspector --inspect',
    'BUN_INSPECT ws://x',
    'NODE_OPTIONS-preload --require /n.js',
  ]);
  assert.deepEqual(runtimes.inspectRuntime('bun', {environment: {}, cmdline: null}).ports, [6499]);
  assert.deepEqual(runtimes.inspectRuntime('bun', {environment: {}, cmdline: ['bun', '--preload']}).findings[0].value, '--preload');
});

test('every process: dynamic linker, iconv and OpenSSL variables; duplicate variables', () => {
  const result = runtimes.inspectRuntime('native', {
    environment: {LD_AUDIT: '/a.so', GCONV_PATH: '/g', OPENSSL_CONF: '/o.cnf'}, duplicates: ['LD_PRELOAD'], cmdline: ['/srv/app'],
  });
  assert.deepEqual(result.findings.map(finding => `${finding.severity} ${finding.type} ${finding.value}`), [
    'critical LD_AUDIT /a.so',
    'critical GCONV_PATH /g',
    'warning OPENSSL_CONF /o.cnf',
    'warning environment-duplicates LD_PRELOAD',
  ]);
  assert.deepEqual(runtimes.inspectRuntime('unknown-runtime', {environment: {}, cmdline: null}).findings, []);
  assert.deepEqual(runtimes.parseEnviron('A=1\0B=2\0A=3\0malformed\0=x\0'), {values: Object.assign(Object.create(null), {A: '1', B: '2'}), duplicates: ['A']});
});

test('option scanner: long options, attached values, terminal options and stray values', () => {
  const spec = {withValue: new Set(['-c', '--level', '-cp']), terminal: new Set(['-c', '--stop'])};
  assert.deepEqual(runtimes.scanOptions(['--level', '3', '--x=1', '-cp', 'a:b', '--stop', '-q'], spec), [
    {flag: '--level', value: '3'},
    {flag: '--x', value: '1'},
    {flag: '-cp', value: 'a:b'},
    {flag: '--stop', value: null},
  ]);
  assert.deepEqual(runtimes.scanOptions(['--level'], spec), [{flag: '--level', value: ''}]);
  assert.deepEqual(runtimes.scanOptions(['-cp'], spec), [{flag: '-cp', value: ''}]);
  assert.deepEqual(runtimes.scanOptions(['-c', 'code', '-q'], spec), [{flag: '-c', value: 'code'}]);
  assert.deepEqual(runtimes.scanOptions(['-', '-q'], spec), []);
  assert.deepEqual(runtimes.scanOptions(['-q', '--', '-r'], spec), [{flag: '-q', value: null}]);
  assert.deepEqual(runtimes.scanOptions(['script', '-q'], {...spec, all: true}), [{flag: '-q', value: null}]);
  const combined = {
    withValue: new Set(['-c', '-W']), terminal: new Set(['-c']), attachedOnly: new Set(['-d']), combined: true,
  };
  assert.deepEqual(runtimes.scanOptions(['-Es', '-Wx', '-W', 'y', '-d:T', '-c'], combined), [
    {flag: '-E', value: null},
    {flag: '-s', value: null},
    {flag: '-W', value: 'x'},
    {flag: '-W', value: 'y'},
    {flag: '-d', value: ':T'},
    {flag: '-c', value: ''},
  ]);
  assert.deepEqual(runtimes.scanOptions(['-sc', 'code', '-i'], combined), [{flag: '-s', value: null}, {flag: '-c', value: 'code'}]);
  assert.deepEqual(runtimes.splitOptions(String.raw`  -a "b \" c" `), ['-a', 'b " c']);
});

test('option scanner and inspectors: remaining shapes', () => {
  assert.deepEqual(runtimes.scanOptions(['-x', '-y'], {withValue: new Set(), terminal: new Set(['-x'])}), [{flag: '-x', value: null}]);
  assert.deepEqual(runtimes.inspectRuntime('php', {environment: {}, cmdline: null}).findings, []);
  assert.deepEqual(runtimes.inspectRuntime('perl', {environment: {}, cmdline: null}).findings, []);
  assert.equal(runtimes.detectRuntime({exe: null, libraries: ['/usr/lib/x86_64-linux-gnu/libruby-3.2.so.3.2.3']}).version, '3.2');
  // Without a parent check, a rewritten title under PM2 settings is reported.
  const rewritten = runtimes.inspectRuntime('node', {environment: {pm2_env: '{"pm_exec_path":"/a.js"}'}, cmdline: ['title'], raw: 'title\0'});
  assert.deepEqual(rewritten.findings.map(finding => finding.type), ['argv-rewritten']);
});

/* eslint-enable camelcase */

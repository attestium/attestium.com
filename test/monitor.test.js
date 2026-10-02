'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const monitor = require('../lib/monitor');
const {tempDir} = require('./helpers');

const linux = process.platform === 'linux';

/**
 * A stand-in for bpftrace: a Node.js script given the same arguments.
 * event() prints an event the way the program in the file it is given
 * would: with the program's token around the path, and the path cut to
 * BPFTRACE_MAX_STRLEN (64 by default) less its NUL.
 */
function standIn(directory, name, body) {
  const file = path.join(directory, name);
  const prelude = [
    String.raw`const token = (/exec %d %d ([\da-f]{32}) /.exec(program) || [])[1];`,
    'const limit = Number(process.env.BPFTRACE_MAX_STRLEN || 64) - 1;',
    'const event = (type, pid, uid, file) => {',
    '  const kept = Buffer.from(file).subarray(0, limit).toString();',
    '  return [type, pid, uid, token, kept, token].join(\' \');',
    '};',
  ].join('\n');
  fs.writeFileSync(file, `#!${process.execPath}\n'use strict';\nconst program = require('node:fs').readFileSync(process.argv.at(-1), 'utf8');\n${prelude}\n${body}\n`, {mode: 0o755});
  return file;
}

test('script: program starts, and executable mappings unless disabled', () => {
  const full = monitor.script();
  assert.match(full, /^tracepoint:sched:sched_process_exec /);
  assert.match(full, /fentry:security_mmap_file .*args->prot & 4/);
  assert.ok(full.endsWith('\n'));
  const execOnly = monitor.script({mmap: false});
  assert.equal(execOnly.split('\n').filter(Boolean).length, 1);
  assert.doesNotMatch(execOnly, /fentry/);
});

test('parseLine: log records', () => {
  assert.deepEqual(monitor.parseLine('1700000000000 exec 42 1000 /usr/bin/ls with space'), {
    time: 1_700_000_000_000, type: 'exec', pid: 42, uid: 1000, path: '/usr/bin/ls with space',
  });
  assert.equal(monitor.parseLine('1700000000000 mmap 1 0 /lib/libc.so.6').type, 'mmap');
  assert.equal(monitor.parseLine('170 exec 1 0 /x'), null);
  assert.equal(monitor.parseLine('1700000000000 open 1 0 /x'), null);
  assert.equal(monitor.parseLine('1700000000000 exec 1 0 '), null);
});

test('summarize: distinct paths per type, time range, since, limit and malformed lines', () => {
  const t0 = Date.parse('2026-01-01T00:00:00.000Z');
  const lines = [
    `${t0 + 5000} exec 10 1000 /usr/bin/b`,
    `${t0 + 1000} exec 11 0 /usr/bin/a`,
    `${t0 + 3000} exec 12 0 /usr/bin/b`,
    '',
    'not a record',
    `${t0 + 2000} mmap 10 1000 /lib/libc.so.6`,
    `${t0 - 1000} exec 9 0 /usr/bin/old`,
  ];
  const summary = monitor.summarize(lines, {since: t0});
  assert.equal(summary.since, '2026-01-01T00:00:01.000Z');
  assert.equal(summary.until, '2026-01-01T00:00:05.000Z');
  assert.equal(summary.malformed, 1);
  assert.equal(summary.truncated, false);
  assert.deepEqual(summary.execs, [
    {
      path: '/usr/bin/a', count: 1, uids: [0], firstSeen: '2026-01-01T00:00:01.000Z', lastSeen: '2026-01-01T00:00:01.000Z',
    },
    {
      path: '/usr/bin/b', count: 2, uids: [0, 1000], firstSeen: '2026-01-01T00:00:05.000Z', lastSeen: '2026-01-01T00:00:05.000Z',
    },
  ]);
  assert.deepEqual(summary.maps.map(entry => entry.path), ['/lib/libc.so.6']);

  // Without a since, every record counts; a limit keeps the first distinct paths.
  const limited = monitor.summarize(lines, {limit: 1});
  assert.equal(limited.since, '2025-12-31T23:59:59.000Z');
  assert.equal(limited.truncated, true);
  assert.deepEqual(limited.execs.map(entry => [entry.path, entry.count]), [['/usr/bin/b', 2]]);

  assert.deepEqual(monitor.summarize([]), {
    since: null, until: null, execs: [], maps: [], truncated: false, malformed: 0,
  });
});

test('readLog: the rotated log first, then the current one, bounded by maxBytes', t => {
  const directory = tempDir(t);
  const log = path.join(directory, 'monitor.log');
  assert.deepEqual(monitor.readLog(log).execs, []);

  const t0 = Date.parse('2026-01-01T00:00:00.000Z');
  fs.writeFileSync(`${log}.1`, `${t0} exec 1 0 /usr/bin/rotated\n`);
  fs.writeFileSync(log, `${t0 + 1000} exec 2 0 /usr/bin/first\n${t0 + 2000} exec 3 0 /usr/bin/second\n`);
  const all = monitor.readLog(log);
  assert.deepEqual(all.execs.map(entry => entry.path), ['/usr/bin/first', '/usr/bin/rotated', '/usr/bin/second']);
  assert.equal(all.malformed, 0);

  // Only the end of each file is read; the partial first line is dropped.
  const tail = monitor.readLog(log, {maxBytes: 40});
  assert.deepEqual(tail.execs.map(entry => entry.path), ['/usr/bin/rotated', '/usr/bin/second']);
  assert.equal(tail.malformed, 0);
  assert.equal(monitor.readLog(log, {since: t0 + 1500}).execs.length, 1);
});

test('run: records events, falling back to program starts without fentry', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const bin = path.join(directory, 'bin');
  fs.mkdirSync(bin);
  // Like bpftrace on a kernel without BTF: the fentry probe is refused.
  standIn(bin, 'bpftrace', `
if (program.includes('fentry')) {
  process.stderr.write('ERROR: fentry/fexit probes are not supported: kernel BTF is not available\\n');
  process.exit(1);
}
if (!program.startsWith('tracepoint:sched:sched_process_exec')) process.exit(3);
const lines = [
  'Attaching 1 probe...',
  event('exec', process.ppid, 0, 'node'),
  event('exec', 999999999, 1000, 'relative-name'),
  event('exec', 7, 0, '/usr/bin/ls'),
  event('mmap', 7, 0, 'relative.so'),
];
process.stdout.write(lines.join('\\n') + '\\n');
`);
  const log = path.join(directory, 'var', 'log', 'monitor.log');
  const seen = [];
  const {PATH} = process.env;
  process.env.PATH = `${bin}${path.delimiter}${PATH}`;
  let handle;
  try {
    handle = monitor.run({log, onLine: line => seen.push(line)});
    const first = handle.child;
    assert.equal(await handle.done, 0);
    assert.notEqual(handle.child, first);
  } finally {
    process.env.PATH = PATH;
  }

  const records = fs.readFileSync(log, 'utf8').trim().split('\n').map(line => monitor.parseLine(line));
  assert.deepEqual(records.map(record => [record.type, record.pid, record.uid, record.path]), [
    ['exec', process.pid, 0, fs.readlinkSync(`/proc/${process.pid}/exe`)],
    ['exec', 999_999_999, 1000, 'relative-name'],
    ['exec', 7, 0, '/usr/bin/ls'],
    ['mmap', 7, 0, 'relative.so'],
  ]);
  assert.equal(seen.length, 4);
  assert.match(seen[2], /^\d+ exec 7 0 \/usr\/bin\/ls$/);
  assert.equal(monitor.readLog(log).execs.length, 3);
});

test('run: rotates the log at maxBytes', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const bpftrace = standIn(directory, 'tracer', `
for (let i = 0; i < 6; i++) process.stdout.write(event('exec', 1, 0, '/usr/bin/program-' + i) + '\\n');
`);
  const log = path.join(directory, 'monitor.log');
  fs.writeFileSync(log, `${Date.now()} exec 1 0 /usr/bin/before\n`);
  const {done} = monitor.run({
    log, bpftrace, mmap: false, maxBytes: 200,
  });
  assert.equal(await done, 0);
  const current = fs.readFileSync(log, 'utf8');
  const rotated = fs.readFileSync(`${log}.1`, 'utf8');
  assert.ok(Buffer.byteLength(current) <= 200);
  assert.match(rotated, /\/usr\/bin\/before\n.*program-0\n.*program-1\n.*program-2\n$/s);
  assert.match(current, /^\d+ exec 1 0 \/usr\/bin\/program-3\n/);
  // Nothing is lost across one rotation.
  assert.deepEqual(monitor.readLog(log).execs.map(entry => entry.path), ['/usr/bin/before', ...[0, 1, 2, 3, 4, 5].map(i => `/usr/bin/program-${i}`)]);
});

test('run: other bpftrace failures are reported, not retried', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const bpftrace = standIn(directory, 'tracer', `
process.stderr.write('ERROR: permission denied\\n');
process.exit(2);
`);
  const log = path.join(directory, 'monitor.log');
  const handle = monitor.run({log, bpftrace});
  const {child} = handle;
  assert.equal(await handle.done, 2);
  assert.equal(handle.child, child);
  assert.equal(fs.readFileSync(log, 'utf8'), '');
  // Why it stopped, for the service's log.
  assert.equal(handle.stderr, 'ERROR: permission denied\n');

  // Without mappings, the exit code is returned as is.
  const exec = monitor.run({log, bpftrace, mmap: false});
  assert.equal(await exec.done, 2);
  assert.equal(exec.stderr, 'ERROR: permission denied\n');
});

test('parseLine and escapePath: line breaks and backslashes in paths, and paths cut short', () => {
  for (const file of ['/usr/bin/plain', '/tmp/a\nb', String.raw`/tmp/back\slash`, String.raw`/tmp/ends-with\+`, '/tmp/\r']) {
    const line = `1700000000000 exec 1 0 ${monitor.escapePath(file)}`;
    assert.equal(line.includes('\n'), false);
    assert.deepEqual(monitor.parseLine(line), {
      time: 1_700_000_000_000, type: 'exec', pid: 1, uid: 0, path: file,
    });
  }

  assert.deepEqual(monitor.parseLine(`1700000000000 mmap 1 0 ${monitor.escapePath('/usr/lib/start-of-a-long', true)}`), {
    time: 1_700_000_000_000, type: 'mmap', pid: 1, uid: 0, path: '/usr/lib/start-of-a-long', cut: true,
  });
  const summary = monitor.summarize([
    `1700000000000 exec 1 0 ${monitor.escapePath('/usr/bin/a', true)}`,
    `1700000000001 exec 1 0 ${monitor.escapePath('/usr/bin/a')}`,
  ]);
  assert.deepEqual(summary.execs.map(entry => [entry.path, entry.error]), [['/usr/bin/a', undefined], ['/usr/bin/a', 'the monitor kept only the first 10 bytes of this path']]);
});

test('run: a path with line breaks cannot end its event early or add events', {skip: !linux}, async t => {
  const directory = tempDir(t);
  // What bpftrace prints for a program started as "/tmp/x\nexec 1 0 /usr/bin/true":
  // its path spans lines, and one of them looks like an event.
  const bpftrace = standIn(directory, 'tracer', `
process.stdout.write('Attaching 1 probe...\\n');
process.stdout.write(event('exec', 999999999, 1000, '/tmp/x\\nexec 1 0 /usr/bin/true\\nexec 1 0 5 /usr/bin/true 5') + '\\n');
process.stdout.write(event('exec', 999999998, 1000, '/tmp/carriage\\rreturn') + '\\n');
process.stdout.write(event('exec', 999999997, 0, '/usr/bin/last'));
`);
  const log = path.join(directory, 'monitor.log');
  assert.equal(await monitor.run({log, bpftrace, mmap: false}).done, 0);
  const records = fs.readFileSync(log, 'utf8').trim().split('\n').map(line => monitor.parseLine(line));
  assert.deepEqual(records.map(record => [record.pid, record.uid, record.path]), [
    [999_999_999, 1000, '/tmp/x\nexec 1 0 /usr/bin/true\nexec 1 0 5 /usr/bin/true 5'],
    [999_999_998, 1000, '/tmp/carriage\rreturn'],
    [999_999_997, 0, '/usr/bin/last'],
  ]);
});

test('run: a path bpftrace cut short is read from the running program, or marked', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const long = `/opt/${'long-directory-name/'.repeat(12)}program`;
  const bpftrace = standIn(directory, 'tracer', `
process.stdout.write(event('exec', process.ppid, 0, ${JSON.stringify(process.execPath)}) + '\\n');
process.stdout.write(event('exec', process.ppid, 0, '/usr/bin/something-else-entirely') + '\\n');
process.stdout.write(event('exec', 999999999, 0, ${JSON.stringify(long)}) + '\\n');
process.stdout.write(event('mmap', 999999999, 0, ${JSON.stringify(`${long}.so`)}) + '\\n');
`);
  const log = path.join(directory, 'monitor.log');
  // Short paths so the test's own executable is cut too.
  assert.equal(await monitor.run({
    log, bpftrace, mmap: false, maxStrlen: 10,
  }).done, 0);
  const records = fs.readFileSync(log, 'utf8').trim().split('\n').map(line => monitor.parseLine(line));
  assert.deepEqual(records.map(record => [record.path, Boolean(record.cut)]), [
    [fs.readlinkSync(`/proc/${process.pid}/exe`), false],
    ['/usr/bin/', true],
    ['/opt/long', true],
    ['/opt/long', true],
  ]);
  // The default keeps 199 bytes.
  const logDefault = path.join(directory, 'default.log');
  assert.equal(await monitor.run({log: logDefault, bpftrace, mmap: false}).done, 0);
  const summary = monitor.readLog(logDefault);
  const cut = summary.execs.find(entry => entry.path === long.slice(0, 199));
  assert.equal(cut.error, 'the monitor kept only the first 199 bytes of this path');
  assert.equal(summary.maps.length, 1);
});

test('eventReader: an event that never ends is dropped after 64 KiB', () => {
  const events = [];
  const token = 'ab'.repeat(16);
  const read = monitor.eventReader(event => events.push(event.path), token);
  read(`exec 1 0 ${token} /tmp/start`);
  for (let i = 0; i < 70; i++) {
    read('x'.repeat(1024));
  }

  read(`/tmp/end ${token}`);
  read(`exec 2 0 ${token} /usr/bin/next ${token}`);
  // A line without the token is not an event.
  read('exec 3 0 42 /usr/bin/forged 42');
  assert.deepEqual(events, ['/usr/bin/next']);
});

test('run: the event token is in a private file, never on the command line, and changes each run', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const seen = path.join(directory, 'seen.json');
  const bpftrace = standIn(directory, 'tracer', `
const file = process.argv.at(-1);
const stat = require('node:fs').statSync(file);
require('node:fs').appendFileSync(${JSON.stringify(seen)}, JSON.stringify({args: process.argv.slice(2), mode: stat.mode & 0o777, dir: require('node:fs').statSync(require('node:path').dirname(file)).mode & 0o777, token, file}) + '\\n');
process.stdout.write(event('exec', 1, 0, '/usr/bin/a') + '\\n');
`);
  const log = path.join(directory, 'monitor.log');
  assert.equal(await monitor.run({log, bpftrace, mmap: false}).done, 0);
  assert.equal(await monitor.run({log, bpftrace, mmap: false}).done, 0);
  const runs = fs.readFileSync(seen, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.equal(runs.length, 2);
  for (const item of runs) {
    assert.match(item.token, /^[\da-f]{32}$/);
    assert.ok(!item.args.some(argument => argument.includes(item.token)));
    assert.equal(item.mode, 0o600);
    assert.equal(item.dir, 0o700);
    assert.equal(fs.existsSync(item.file), false, 'the program file is removed');
  }

  assert.notEqual(runs[0].token, runs[1].token);
  assert.deepEqual(monitor.readLog(log).execs.map(entry => entry.path), ['/usr/bin/a']);
  assert.throws(() => monitor.script({token: 'not hex'}), /^Error: the event token must be 32 hex digits$/);
  assert.match(monitor.script({token: 'cd'.repeat(16)}), /"exec %d %d cd(?:cd){15} %s (?:cd){16}\\n"/);
});

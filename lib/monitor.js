/**
 * Attestium - continuous monitoring between audits (eBPF)
 *
 * An audit sees the machine at one moment.  Code that ran and was removed
 * before the audit leaves no file to find.  The monitor records, with
 * eBPF (bpftrace), every program started and, where the kernel allows,
 * every file mapped executable, so the next audit reports what ran since
 * the last one.
 *
 * The log is written by root on the audited machine, so it is software
 * evidence: it shows what happened unless the machine's root user edited
 * it.  With IMA and a TPM the kernel's own measurement log gives the same
 * record with hardware backing (see ./ima).
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');

// The bpftrace program copies at most this many bytes of a path, with its final NUL
// (200 is the most bpftrace 0.20 allows; newer versions allow more).
const MAX_STRLEN = 200;
// A path longer than this is not a path.
const MAX_EVENT = 64 * 1024;

/**
 * The bpftrace program.  Executable mappings need fentry (BTF and function
 * tracing); without them only program starts are recorded.
 *
 * Each event prints a random token before and after the path.  A path may
 * hold any byte but NUL, a line break included, so a program could name
 * itself to look like a line of events of its own; the token is chosen for
 * each run and kept in a file only root can read (never on a command
 * line), so a program cannot end its event early or add one.
 *
 * @param {Object} [options]
 * @param {boolean} [options.mmap=true]
 * @param {string} [options.token] - 32 hex digits; random when not given
 * @returns {string}
 */
function script(options = {}) {
  const token = options.token || crypto.randomBytes(16).toString('hex');
  if (!/^[\da-f]{32}$/.test(token)) {
    throw new Error('the event token must be 32 hex digits');
  }

  const lines = [`tracepoint:sched:sched_process_exec { printf("exec %d %d ${token} %s ${token}\\n", pid, uid, str(args->filename)); }`];
  if (options.mmap !== false) {
    // PROT_EXEC is 4.
    lines.push(`fentry:security_mmap_file / args->file != 0 && (args->prot & 4) / { printf("mmap %d %d ${token} %s ${token}\\n", pid, uid, path(args->file->f_path)); }`);
  }

  return `${lines.join('\n')}\n`;
}

/**
 * A path as written to the log: one line, and marked when bpftrace kept only
 * its start.
 * @param {string} file
 * @param {boolean} [cut=false]
 * @returns {string}
 */
function escapePath(file, cut = false) {
  return file.replaceAll('\\', String.raw`\\`).replaceAll('\n', String.raw`\n`) + (cut ? String.raw`\+` : '');
}

/**
 * Parse one log line: "<ms> <exec|mmap> <pid> <uid> <path>".  In the path,
 * "\\" is a backslash, "\n" a line break, and a final "\+" says the path was
 * cut short.
 * @param {string} line
 * @returns {{time: number, type: string, pid: number, uid: number, path: string, cut?: boolean}|null}
 */
function parseLine(line) {
  const match = line.match(/^(\d{10,16}) (exec|mmap) (\d+) (\d+) ([^\n]+)$/);
  if (!match) {
    return null;
  }

  let cut = false;
  const file = match[5].replaceAll(/\\([\\n])|\\\+$/g, (_, character) => {
    if (character === undefined) {
      cut = true;
      return '';
    }

    return character === 'n' ? '\n' : '\\';
  });
  const event = {
    time: Number(match[1]), type: match[2], pid: Number(match[3]), uid: Number(match[4]), path: file,
  };
  if (cut) {
    event.cut = true;
  }

  return event;
}

/**
 * Reassemble bpftrace's events from its output lines (see script()).
 * @param {(event: {type: string, pid: string, uid: string, path: string}) => void} onEvent
 * @param {string} token - the token the program prints around each path
 * @returns {(line: string) => void}
 */
function eventReader(onEvent, token) {
  const start = new RegExp(`^(exec|mmap) (\\d+) (\\d+) ${token} ([^\\n]*)$`);
  const end = ` ${token}`;
  let current = null;
  return line => {
    if (current) {
      if (line.endsWith(current.end)) {
        current.parts.push(line.slice(0, -current.end.length));
        onEvent({...current, path: current.parts.join('\n')});
        current = null;
      } else {
        current.parts.push(line);
        current.size += line.length + 1;
        if (current.size > MAX_EVENT) {
          current = null;
        }
      }

      return;
    }

    const match = start.exec(line);
    if (!match) {
      return;
    }

    const event = {
      type: match[1], pid: match[2], uid: match[3], end, parts: [match[4]], size: match[4].length,
    };
    if (match[4].endsWith(end)) {
      onEvent({...event, path: match[4].slice(0, -end.length)});
    } else {
      current = event;
    }
  };
}

/**
 * Summarize log lines: each distinct path per event type, with counts.
 *
 * @param {Iterable<string>} lines
 * @param {Object} [options]
 * @param {number} [options.since=0] - ms since the epoch
 * @param {number} [options.limit=2000] - distinct paths kept per type
 * @returns {{since: number|null, until: number|null, execs: Object[], maps: Object[], truncated: boolean, malformed: number}}
 */
function summarize(lines, options = {}) {
  const since = options.since || 0;
  const limit = options.limit || 2000;
  const tables = {exec: new Map(), mmap: new Map()};
  let first = null;
  let last = null;
  let malformed = 0;
  let truncated = false;
  for (const line of lines) {
    if (line === '') {
      continue;
    }

    const event = parseLine(line);
    if (!event) {
      malformed++;
      continue;
    }

    if (event.time < since) {
      continue;
    }

    first = first === null ? event.time : Math.min(first, event.time);
    last = last === null ? event.time : Math.max(last, event.time);
    const table = tables[event.type];
    const key = `${event.cut ? 'cut' : ''}\0${event.path}`;
    let entry = table.get(key);
    if (!entry) {
      if (table.size >= limit) {
        truncated = true;
        continue;
      }

      entry = {
        path: event.path, cut: Boolean(event.cut), count: 0, uids: new Set(), firstSeen: event.time, lastSeen: event.time,
      };
      table.set(key, entry);
    }

    entry.count++;
    entry.uids.add(event.uid);
    entry.lastSeen = Math.max(entry.lastSeen, event.time);
  }

  const list = table => [...table.values()]
    .map(entry => ({
      path: entry.path,
      count: entry.count,
      uids: [...entry.uids].sort((a, b) => a - b),
      firstSeen: new Date(entry.firstSeen).toISOString(),
      lastSeen: new Date(entry.lastSeen).toISOString(),
      // Only the start of a longer path: it may name another file.
      ...(entry.cut ? {error: `the monitor kept only the first ${Buffer.byteLength(entry.path)} bytes of this path`} : {}),
    }))
    .sort((a, b) => (a.path > b.path) - (a.path < b.path) || (Boolean(a.error) - Boolean(b.error)));
  return {
    since: first === null ? null : new Date(first).toISOString(),
    until: last === null ? null : new Date(last).toISOString(),
    execs: list(tables.exec),
    maps: list(tables.mmap),
    truncated,
    malformed,
  };
}

/**
 * Read a monitor log (and its rotated predecessor) and summarize it.
 * @param {string} file
 * @param {Object} [options] - see summarize(); maxBytes bounds what is read
 * @returns {Object}
 */
function readLog(file, options = {}) {
  const maxBytes = options.maxBytes || 64 * 1024 * 1024;
  const lines = [];
  for (const candidate of [`${file}.1`, file]) {
    let text;
    try {
      const {size} = fs.statSync(candidate);
      const handle = fs.openSync(candidate, 'r');
      try {
        const length = Math.min(size, maxBytes);
        const buffer = Buffer.alloc(length);
        fs.readSync(handle, buffer, 0, length, size - length);
        text = buffer.toString('utf8');
        if (size > length) {
          text = text.slice(text.indexOf('\n') + 1);
        }
      } finally {
        fs.closeSync(handle);
      }
    } catch {
      continue;
    }

    lines.push(...text.split('\n'));
  }

  return summarize(lines, options);
}

/**
 * Run bpftrace and append its events to a log, rotating it at maxBytes.
 * Resolves when bpftrace exits.
 *
 * @param {Object} options
 * @param {string} options.log
 * @param {number} [options.maxBytes=64 MiB]
 * @param {string} [options.bpftrace='bpftrace']
 * @param {boolean} [options.mmap=true] - falls back to exec-only when the kernel lacks fentry
 * @param {(line: string) => void} [options.onLine]
 * @param {number} [options.maxStrlen=200] - BPFTRACE_MAX_STRLEN; a path this long less one byte may be cut short
 * @returns {{child: import('node:child_process').ChildProcess, done: Promise<number>}}
 */
function run(options) {
  const maxBytes = options.maxBytes || 64 * 1024 * 1024;
  const maxStrlen = options.maxStrlen || MAX_STRLEN;
  fs.mkdirSync(path.dirname(options.log), {recursive: true, mode: 0o750});
  const start = mmap => {
    const token = crypto.randomBytes(16).toString('hex');
    // The program (and so the token) in a file of a private directory.
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-monitor-'));
    const programFile = path.join(directory, 'monitor.bt');
    fs.writeFileSync(programFile, script({mmap, token}), {mode: 0o600});
    const child = spawn(options.bpftrace || 'bpftrace', ['-B', 'line', programFile], {stdio: ['ignore', 'pipe', 'pipe'], env: {...process.env, BPFTRACE_MAX_STRLEN: String(maxStrlen)}});
    // Opened synchronously, so the file exists before the next rotation
    // renames it.
    const open = () => {
      const fd = fs.openSync(options.log, 'a', 0o640);
      return {stream: fs.createWriteStream(options.log, {fd}), size: fs.fstatSync(fd).size};
    };

    let {stream, size: written} = open();
    let stderr = '';
    child.stderr.on('data', chunk => {
      stderr = (stderr + chunk).slice(-4096);
    });
    const record = event => {
      // A relative path from execve, or one bpftrace cut short, is read from
      // the new program's /proc entry while it runs: kept when it is that
      // path, or starts with what bpftrace kept.
      let file = event.path;
      let cut = Buffer.byteLength(file) >= maxStrlen - 1;
      if (event.type === 'exec' && (cut || !file.startsWith('/'))) {
        try {
          const exe = fs.readlinkSync(`/proc/${event.pid}/exe`);
          if (!file.startsWith('/') || exe.startsWith(file)) {
            file = exe;
            cut = false;
          }
        } catch {}
      }

      const line = `${Date.now()} ${event.type} ${event.pid} ${event.uid} ${escapePath(file, cut)}\n`;
      written += Buffer.byteLength(line);
      if (written > maxBytes) {
        stream.end();
        fs.renameSync(options.log, `${options.log}.1`);
        ({stream} = open());
        written = Buffer.byteLength(line);
      }

      stream.write(line);
      if (options.onLine) {
        options.onLine(line.trimEnd());
      }
    };

    // Lines end at "\n" only: a "\r" is part of a path.
    const onLine = eventReader(record, token);
    let pending = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      const lines = (pending + chunk).split('\n');
      pending = lines.pop();
      for (const line of lines) {
        onLine(line);
      }
    });
    // Done when bpftrace has exited, every line it printed is written, and
    // the log is flushed.
    const exited = new Promise(resolve => {
      child.on('close', code => {
        fs.rmSync(directory, {recursive: true, force: true});
        resolve(code);
      });
    });
    const read = new Promise(resolve => {
      child.stdout.on('end', () => {
        if (pending) {
          onLine(pending);
        }

        resolve();
      });
    });
    const done = Promise.all([exited, read]).then(([code]) => new Promise(resolve => {
      stream.end(() => resolve({code, stderr}));
    }));
    return {child, done};
  };

  // What bpftrace last printed on stderr is kept on the handle, to say why
  // it stopped.
  const handle = {child: null, done: null, stderr: ''};
  const finish = result => {
    handle.stderr = result.stderr;
    return result.code;
  };

  if (options.mmap === false) {
    const {child, done} = start(false);
    return Object.assign(handle, {child, done: done.then(result => finish(result))});
  }

  // Try with executable mappings; restart without them if bpftrace refuses.
  const first = start(true);
  handle.child = first.child;
  handle.done = first.done.then(async result => {
    if (result.code !== 0 && /fentry|kfunc|btf|available_filter_functions|not traceable/i.test(result.stderr)) {
      const second = start(false);
      handle.child = second.child;
      return finish(await second.done);
    }

    return finish(result);
  });
  return handle;
}

module.exports = {
  script, parseLine, escapePath, eventReader, summarize, readLog, run, MAX_STRLEN,
};

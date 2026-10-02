/**
 * Attestium - process integrity
 *
 * Inspects a running process rather than the files it was started from:
 *
 *   - executable memory of every file-backed mapping (the binary and all
 *     shared libraries) compared byte-for-byte with the file on disk
 *   - memory map anomalies (deleted or replaced backing files, file-backed
 *     W+X pages, unexpected libraries)
 *   - library and code injection vectors (LD_PRELOAD, LD_AUDIT,
 *     /etc/ld.so.preload, DYLD_INSERT_LIBRARIES, AppInit_DLLs) and those of
 *     the process's language runtime (see ./runtimes: NODE_OPTIONS,
 *     PYTHONPATH, JAVA_TOOL_OPTIONS agents, RUBYOPT, startup hooks, ...)
 *   - processes in containers or chroots: mapped files are read through
 *     /proc/<pid>/root, in the process's own view of the filesystem
 *   - debugger attachment, memfd/deleted file descriptors, listening sockets
 *
 * Linux is fully supported through /proc.  macOS and Windows support the
 * subset their tooling exposes; unsupported checks say so instead of
 * reporting a pass.
 *
 * Reading another process's memory needs ptrace access to it (same user
 * and a permissive kernel.yama.ptrace_scope, or CAP_SYS_PTRACE).
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {normalizePid, exists} = require('./util');
const runtimes = require('./runtimes');
const {openInRoot} = require('./file-tree');

const READ_CHUNK = 4 * 1024 * 1024;
// O_PATH (Linux): a descriptor that only names a file (a socket, for one).
const O_PATH = 0o1000_0000;
const MAX_PRELOAD = 64 * 1024;
// A process chooses its own command line and environment (together up to
// a quarter of its stack limit, which it may raise): read at most this much.
const MAX_PROC_READ = 256 * 1024;

/**
 * Read at most `max` bytes of a file, saying whether there was more.
 * @param {string} file
 * @param {number} max
 * @returns {{text: string, truncated: boolean}}
 */
function readCapped(file, max) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY);
  try {
    const buffer = Buffer.allocUnsafe(max + 1);
    const length = readUpTo(fd, buffer, max + 1, 0);
    return {text: buffer.toString('utf8', 0, Math.min(length, max)), truncated: length > max};
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Default command runner: no shell, bounded time and output.
 * @param {string} file
 * @param {string[]} args
 * @param {Object} options
 * @returns {string}
 */
function defaultRun(file, args, options = {}) {
  return execFileSync(file, args, {
    encoding: 'utf8',
    timeout: options.timeout,
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore'],
    windowsHide: true,
  });
}

/**
 * Parse one line of /proc/<pid>/maps.
 * @param {string} line
 * @returns {Object|null}
 */
function parseMapsLine(line) {
  const match = line.match(/^([\da-f]+)-([\da-f]+)\s+([rwxsp-]{4})\s+([\da-f]+)\s+([\da-f]+:[\da-f]+)\s+(\d+)\s*(.*)$/);
  if (!match) {
    return null;
  }

  const pathname = match[7].trim();
  return {
    start: BigInt(`0x${match[1]}`),
    end: BigInt(`0x${match[2]}`),
    perms: match[3],
    offset: BigInt(`0x${match[4]}`),
    dev: match[5],
    inode: Number(match[6]),
    pathname: pathname || null,
  };
}

class ProcessIntegrity {
  /**
   * @param {Object} [options]
   * @param {string[]} [options.expectedLibs] - allowed shared libraries (empty: no allowlist)
   * @param {number} [options.maxAnonExecRegions=512] - informational threshold (V8 JIT creates these)
   * @param {number} [options.timeout=10000] - command timeout (ms)
   * @param {string} [options.platform=process.platform]
   * @param {Function} [options.run] - (file, args, {timeout}) => stdout; for other platforms' tooling
   * @param {string} [options.procRoot='/proc']
   * @param {string} [options.ldPreloadPath='/etc/ld.so.preload']
   * @param {number[]} [options.inspectorPorts=[]] - listening on these ports is reported as an open
   *   debugger, in addition to the default ports of the process's runtime (9229 for Node.js)
   * @param {number} [options.maxProcRead=262144] - the most read of a process's command line or
   *   environment; a larger one is reported as truncated (and its checks as incomplete)
   */
  constructor(options = {}) {
    this.inspectorPorts = new Set(options.inspectorPorts || []);
    this.expectedLibs = new Set(options.expectedLibs || []);
    this.maxAnonExecRegions = options.maxAnonExecRegions ?? 512;
    this.timeout = options.timeout ?? 10_000;
    this.platform = options.platform || process.platform;
    this.run = options.run || defaultRun;
    this.procRoot = options.procRoot || '/proc';
    this.ldPreloadPath = options.ldPreloadPath || '/etc/ld.so.preload';
    this.maxProcRead = options.maxProcRead || MAX_PROC_READ;
  }

  _proc(pid, ...parts) {
    return path.join(this.procRoot, pid, ...parts);
  }

  /**
   * The directory a process's paths are relative to: '' when it shares the
   * attester's root, otherwise /proc/<pid>/root (a container or chroot).
   * Paths in /proc/<pid>/maps are in the process's own mount namespace.
   *
   * @param {string} pid
   * @returns {string}
   */
  _fileRoot(pid) {
    const link = this._proc(pid, 'root');
    try {
      const theirs = fs.statSync(link);
      const ours = fs.statSync(path.join(this.procRoot, 'self', 'root'));
      return theirs.dev === ours.dev && theirs.ino === ours.ino ? '' : link;
    } catch {
      return '';
    }
  }

  /**
   * A path inside a process's root, as seen by the attester.  Its symbolic
   * links resolve on the host: to open or stat a file, use openIn or statIn.
   * @param {string} root - from _fileRoot()
   * @param {string} file - absolute path in the process's namespace
   * @returns {string}
   */
  static inRoot(root, file) {
    return root ? path.join(root, file) : file;
  }

  /**
   * Open a path of a process.  In another root (a container) the path is
   * resolved inside that root: a symbolic link there, absolute or not,
   * cannot name a file of the host.  Never waits on a FIFO.
   * @param {string} root - from _fileRoot()
   * @param {string} file
   * @returns {number} a file descriptor
   */
  static openIn(root, file) {
    const flags = fs.constants.O_RDONLY | fs.constants.O_NONBLOCK;
    return root ? openInRoot(root, file, {flags}) : fs.openSync(file, flags);
  }

  /**
   * The status of a path of a process (see openIn).
   * @param {string} root
   * @param {string} file
   * @returns {fs.Stats}
   */
  static statIn(root, file) {
    if (!root) {
      return fs.statSync(file);
    }

    const fd = openInRoot(root, file, {flags: O_PATH});
    try {
      return fs.fstatSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  _exec(file, args) {
    return this.run(file, args, {timeout: this.timeout});
  }

  _unsupported(extra = {}) {
    return {supported: false, platform: this.platform, ...extra};
  }

  // ─── process discovery ────────────────────────────────────────────

  /**
   * Clock ticks per second used by /proc/<pid>/stat.
   * @returns {number}
   */
  _clockTicks() {
    if (this._ticks === undefined) {
      try {
        this._ticks = Number(this._exec('getconf', ['CLK_TCK']).trim()) || 100;
      } catch {
        this._ticks = 100;
      }
    }

    return this._ticks;
  }

  /**
   * Boot time in ms since the epoch (Linux).
   *
   * Derived from /proc/uptime (10 ms resolution) rather than the btime
   * field of /proc/stat, which is truncated to whole seconds and would
   * place process start times up to a second too early.
   *
   * @returns {number}
   */
  _bootTimeMs() {
    try {
      const uptime = Number.parseFloat(fs.readFileSync(path.join(this.procRoot, 'uptime'), 'utf8'));
      if (Number.isFinite(uptime)) {
        return Date.now() - Math.round(uptime * 1000);
      }
    } catch {}

    const stat = fs.readFileSync(path.join(this.procRoot, 'stat'), 'utf8');
    const match = stat.match(/^btime (\d+)$/m);
    return match ? Number(match[1]) * 1000 : Number.NaN;
  }

  /**
   * Basic facts about a process (Linux).
   *
   * @param {string|number} pid
   * @returns {Object}
   */
  getProcessInfo(pid) {
    pid = normalizePid(pid);
    if (this.platform !== 'linux') {
      return {pid, ...this._unsupported()};
    }

    const info = {pid, supported: true};
    const status = fs.readFileSync(this._proc(pid, 'status'), 'utf8');
    const field = name => {
      const match = status.match(new RegExp(`^${name}:\\s*(.*)$`, 'm'));
      return match ? match[1].trim() : null;
    };

    info.name = field('Name');
    info.ppid = Number(field('PPid'));
    info.uid = Number((field('Uid') || '').split(/\s+/)[0]);
    const stat = fs.readFileSync(this._proc(pid, 'stat'), 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    info.startTimeMs = this._bootTimeMs() + Math.round((Number(fields[19]) / this._clockTicks()) * 1000);
    try {
      const cmdline = readCapped(this._proc(pid, 'cmdline'), this.maxProcRead);
      info.cmdline = cmdline.text.split('\0').filter(Boolean);
      if (cmdline.truncated) {
        info.cmdlineTruncated = true;
      }
    } catch {
      info.cmdline = [];
    }

    for (const [key, link] of [['exe', 'exe'], ['cwd', 'cwd']]) {
      try {
        const target = fs.readlinkSync(this._proc(pid, link));
        info[key] = target.replace(/ \(deleted\)$/, '');
        if (target.endsWith(' (deleted)')) {
          info[`${key}Deleted`] = true;
        }
      } catch (error) {
        info[key] = null;
        info[`${key}Error`] = error.code;
      }
    }

    return info;
  }

  /**
   * SHA-256 of the file a process runs, read through /proc/<pid>/exe (the
   * running file even when its path now names another, or none) in chunks,
   * so a large executable is never held in memory (Linux).
   *
   * @param {string|number} pid
   * @returns {Promise<{sha256: string, size: number}>}
   */
  async hashExecutable(pid) {
    pid = normalizePid(pid);
    if (this.platform !== 'linux') {
      throw new Error(`Not supported on ${this.platform}`);
    }

    const handle = await fs.promises.open(this._proc(pid, 'exe'), fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    try {
      const {size} = await handle.stat();
      const hash = crypto.createHash('sha256');
      const buffer = Buffer.allocUnsafe(READ_CHUNK);
      let offset = 0;
      for (;;) {
        const {bytesRead} = await handle.read(buffer, 0, buffer.length, offset);
        if (bytesRead === 0) {
          break;
        }

        hash.update(buffer.subarray(0, bytesRead));
        offset += bytesRead;
      }

      if (offset !== size) {
        throw new Error(`The executable changed while it was hashed: ${pid}`);
      }

      return {sha256: hash.digest('hex'), size};
    } finally {
      await handle.close();
    }
  }

  /**
   * List processes (Linux), optionally filtered.
   *
   * @param {Object} [filter]
   * @param {number} [filter.uid] - owner uid
   * @param {string} [filter.cwdPrefix] - working directory prefix
   * @param {string} [filter.exe] - executable path
   * @returns {Object[]}
   */
  listProcesses(filter = {}) {
    if (this.platform !== 'linux') {
      return [];
    }

    const processes = [];
    for (const entry of fs.readdirSync(this.procRoot)) {
      if (!/^\d+$/.test(entry)) {
        continue;
      }

      let info;
      try {
        info = this.getProcessInfo(entry);
      } catch {
        continue; // Exited while listing
      }

      if (filter.uid !== undefined && info.uid !== filter.uid) {
        continue;
      }

      if (filter.exe && info.exe !== filter.exe) {
        continue;
      }

      if (filter.cwdPrefix) {
        const prefix = filter.cwdPrefix.replace(/\/+$/, '');
        if (!info.cwd || (info.cwd !== prefix && !info.cwd.startsWith(`${prefix}/`))) {
          continue;
        }
      }

      processes.push(info);
    }

    return processes.sort((a, b) => Number(a.pid) - Number(b.pid));
  }

  // ─── 1. memory maps ───────────────────────────────────────────────

  /**
   * Analyze the memory map of a process.
   *
   * Anomalies (each is a concrete reason to investigate):
   *   deleted-backing  executable mapping whose file was deleted
   *   replaced-backing executable mapping whose path now names a different file
   *                    (usually a package upgrade without a restart)
   *   memfd-exec       executable mapping of a memfd (fileless code)
   *   file-wx          file-backed mapping that is writable and executable
   *   unexpected-lib   library not in expectedLibs (only when an allowlist is set)
   *
   * Anonymous executable mappings are normal for JIT compilers such as V8
   * and are counted, not flagged, unless they exceed maxAnonExecRegions.
   *
   * @param {string|number} pid
   * @returns {{supported: boolean, regions?: Object[], anomalies: Object[], summary: Object}}
   */
  checkMemoryMaps(pid) {
    pid = normalizePid(pid);
    if (this.platform === 'linux') {
      return this._checkMemoryMapsLinux(pid);
    }

    if (this.platform === 'darwin') {
      return this._checkMemoryMapsDarwin(pid);
    }

    if (this.platform === 'win32') {
      return this._checkMemoryMapsWindows(pid);
    }

    return {...this._unsupported(), anomalies: [], summary: {}};
  }

  _checkMemoryMapsLinux(pid) {
    let raw;
    try {
      raw = fs.readFileSync(this._proc(pid, 'maps'), 'utf8');
    } catch (error) {
      return {
        supported: true, error: error.code, anomalies: [], summary: {},
      };
    }

    const root = this._fileRoot(pid);
    const anomalies = [];
    const seen = new Set();
    // One entry per kind of problem and file (a library has several mappings).
    const flag = anomaly => {
      const key = `${anomaly.type}\0${anomaly.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        anomalies.push(anomaly);
      }
    };

    const libraries = new Set();
    const inodeOf = new Map();
    let anonExec = 0;
    let anonWx = 0;
    let regions = 0;
    const inodeCache = new Map();

    for (const line of raw.split('\n')) {
      const region = parseMapsLine(line);
      if (!region) {
        continue;
      }

      regions++;
      const exec = region.perms[2] === 'x';
      const write = region.perms[1] === 'w';
      const address = `${region.start.toString(16)}-${region.end.toString(16)}`;
      const {pathname} = region;
      const fileBacked = pathname && !pathname.startsWith('[') && region.inode !== 0;

      if (!exec) {
        continue;
      }

      if (!fileBacked) {
        anonExec++;
        if (write) {
          anonWx++;
        }

        continue;
      }

      if (pathname.startsWith('/memfd:')) {
        flag({type: 'memfd-exec', address, path: pathname});
        continue;
      }

      if (pathname.endsWith(' (deleted)')) {
        flag({type: 'deleted-backing', address, path: pathname.slice(0, -' (deleted)'.length)});
        continue;
      }

      if (write) {
        flag({
          type: 'file-wx', address, path: pathname, perms: region.perms,
        });
      }

      if (!inodeCache.has(pathname)) {
        try {
          inodeCache.set(pathname, ProcessIntegrity.statIn(root, pathname).ino);
        } catch {
          inodeCache.set(pathname, null);
        }
      }

      if (inodeCache.get(pathname) !== region.inode) {
        flag({type: 'replaced-backing', address, path: pathname});
      }

      libraries.add(pathname);
      inodeOf.set(pathname, region.inode);
    }

    if (this.expectedLibs.size > 0) {
      for (const library of libraries) {
        if (!this.expectedLibs.has(library)) {
          anomalies.push({type: 'unexpected-lib', path: library});
        }
      }
    }

    return {
      supported: true,
      libraries: [...libraries].sort(),
      // The inode each file had when it was mapped, so a reader of the file
      // later can tell it is still the same file.
      inodes: Object.fromEntries([...inodeOf].sort(([a], [b]) => (a > b) - (a < b))),
      anomalies,
      summary: {
        totalRegions: regions,
        executableFiles: libraries.size,
        anonExecRegions: anonExec,
        anonWxRegions: anonWx,
        anonExecExcessive: anonExec > this.maxAnonExecRegions,
        anomalies: anomalies.length,
      },
    };
  }

  _checkMemoryMapsDarwin(pid) {
    let raw;
    try {
      raw = this._exec('vmmap', ['--wide', pid]);
    } catch (error) {
      return {
        supported: true, error: `vmmap failed: ${error.message.split('\n')[0]}`, anomalies: [], summary: {},
      };
    }

    const anomalies = [];
    const libraries = new Set();
    let regions = 0;
    for (const line of raw.split('\n')) {
      const match = line.match(/^(.+?)\s+([\da-fA-F]+)-([\da-fA-F]+)\s+\[.*?]\s+([rwx-]{3})\/([rwx-]{3})\s+SM=(\S+)\s*(.*)$/);
      if (!match) {
        continue;
      }

      regions++;
      const perms = match[4];
      const detail = match[7].trim();
      if (perms[2] !== 'x') {
        continue;
      }

      if (detail.startsWith('/')) {
        libraries.add(detail);
        if (perms[1] === 'w') {
          anomalies.push({
            type: 'file-wx', address: `${match[2]}-${match[3]}`.toLowerCase(), path: detail, perms,
          });
        }
      }
    }

    if (this.expectedLibs.size > 0) {
      for (const library of libraries) {
        if (!this.expectedLibs.has(library)) {
          anomalies.push({type: 'unexpected-lib', path: library});
        }
      }
    }

    return {
      supported: true,
      libraries: [...libraries].sort(),
      anomalies,
      summary: {totalRegions: regions, executableFiles: libraries.size, anomalies: anomalies.length},
    };
  }

  _checkMemoryMapsWindows(pid) {
    let raw;
    try {
      raw = this._exec('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `(Get-Process -Id ${pid} -ErrorAction Stop).Modules | ForEach-Object { $_.FileName }`,
      ]);
    } catch (error) {
      return {
        supported: true, error: `module enumeration failed: ${error.message.split('\n')[0]}`, anomalies: [], summary: {},
      };
    }

    const libraries = [...new Set(raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean))].sort();
    const anomalies = this.expectedLibs.size > 0
      ? libraries.filter(library => !this.expectedLibs.has(library)).map(library => ({type: 'unexpected-lib', path: library}))
      : [];
    return {
      supported: true,
      libraries,
      anomalies,
      summary: {executableFiles: libraries.length, anomalies: anomalies.length},
    };
  }

  // ─── 2. executable pages vs. disk ─────────────────────────────────

  /**
   * Compare the executable pages of every file-backed mapping with the same
   * byte range of the file on disk (Linux).  A write through ptrace or
   * /proc/<pid>/mem to a code page shows up here even though the file on
   * disk is unchanged.
   *
   * Mappings whose file was deleted or replaced cannot be compared and are
   * listed separately (see checkMemoryMaps).
   *
   * @param {string|number} pid
   * @returns {{supported: boolean, matched: boolean|null, regions: Object[], mismatched: Object[], skipped: Object[]}}
   */
  checkExecutablePages(pid) {
    pid = normalizePid(pid);
    if (this.platform !== 'linux') {
      return {
        ...this._unsupported(), matched: null, regions: [], mismatched: [], skipped: [],
      };
    }

    const result = {
      supported: true, matched: null, regions: [], mismatched: [], skipped: [],
    };
    let maps;
    let memFd;
    try {
      maps = fs.readFileSync(this._proc(pid, 'maps'), 'utf8');
      memFd = fs.openSync(this._proc(pid, 'mem'), 'r');
    } catch (error) {
      result.error = error.code;
      return result;
    }

    const root = this._fileRoot(pid);
    try {
      for (const line of maps.split('\n')) {
        const region = parseMapsLine(line);
        if (!region || region.perms[2] !== 'x' || !region.pathname || region.inode === 0
          || region.pathname.startsWith('[') || region.pathname.startsWith('/memfd:')) {
          continue;
        }

        const address = `${region.start.toString(16)}-${region.end.toString(16)}`;
        if (region.pathname.endsWith(' (deleted)')) {
          result.skipped.push({address, path: region.pathname, reason: 'deleted'});
          continue;
        }

        let fileFd;
        try {
          fileFd = ProcessIntegrity.openIn(root, region.pathname);
          if (fs.fstatSync(fileFd).ino !== region.inode) {
            result.skipped.push({address, path: region.pathname, reason: 'replaced'});
            continue;
          }

          const size = Number(region.end - region.start);
          const memoryHash = crypto.createHash('sha256');
          const diskHash = crypto.createHash('sha256');
          const memoryBuffer = Buffer.alloc(Math.min(size, READ_CHUNK));
          const diskBuffer = Buffer.alloc(Math.min(size, READ_CHUNK));
          let firstDifference = null;
          for (let done = 0; done < size;) {
            const length = Math.min(READ_CHUNK, size - done);
            readFully(memFd, memoryBuffer, length, Number(region.start) + done);
            // Bytes past the end of the file are zero-filled in memory.
            diskBuffer.fill(0, 0, length);
            readUpTo(fileFd, diskBuffer, length, Number(region.offset) + done);
            memoryHash.update(memoryBuffer.subarray(0, length));
            diskHash.update(diskBuffer.subarray(0, length));
            if (firstDifference === null && !memoryBuffer.subarray(0, length).equals(diskBuffer.subarray(0, length))) {
              for (let i = 0; i < length; i++) {
                if (memoryBuffer[i] !== diskBuffer[i]) {
                  firstDifference = done + i;
                  break;
                }
              }
            }

            done += length;
          }

          const entry = {
            address,
            path: region.pathname,
            offset: region.offset.toString(16),
            size,
            memorySha256: memoryHash.digest('hex'),
            diskSha256: diskHash.digest('hex'),
          };
          entry.matched = entry.memorySha256 === entry.diskSha256;
          result.regions.push(entry);
          if (!entry.matched) {
            result.mismatched.push({...entry, firstDifferenceOffset: firstDifference});
          }
        } catch (error) {
          result.skipped.push({address, path: region.pathname, reason: error.code || error.message});
        } finally {
          if (fileFd !== undefined) {
            fs.closeSync(fileFd);
          }
        }
      }
    } finally {
      fs.closeSync(memFd);
    }

    result.matched = result.regions.length > 0 ? result.mismatched.length === 0 : null;
    return result;
  }

  // ─── 3. injection vectors ─────────────────────────────────────────

  /**
   * Detect the language runtime a process runs, from its executable's name
   * and the shared libraries it maps (Linux).
   *
   * @param {string|number} pid
   * @param {Object} [options]
   * @param {string[]} [options.libraries] - mapped files, when already read
   * @param {boolean} [options.nodeRelease] - the executable carries an official Node.js release URL
   * @returns {{name: string, label: string, version: string|null, by: string}}
   */
  detectRuntime(pid, options = {}) {
    pid = normalizePid(pid);
    let exe = null;
    try {
      exe = fs.readlinkSync(this._proc(pid, 'exe')).replace(/ \(deleted\)$/, '');
    } catch {}

    const libraries = options.libraries || (this.platform === 'linux' ? this.checkMemoryMaps(pid).libraries || [] : []);
    return runtimes.detectRuntime({exe, libraries, nodeRelease: options.nodeRelease});
  }

  /**
   * Check library and code injection vectors: the dynamic linker's, and the
   * process's language runtime's (environment variables, options, debug
   * ports).
   *
   * @param {string|number} pid
   * @param {Object} [options]
   * @param {string} [options.runtime] - runtime profile name (default: detected)
   * @param {boolean} [options.isNode] - shorthand for runtime 'node'
   * @returns {Object} `clean` is false when any injection vector is present
   */
  checkLinkerIntegrity(pid, options = {}) {
    pid = normalizePid(pid);
    if (this.platform === 'linux') {
      const runtime = options.runtime || (options.isNode ? 'node' : this.detectRuntime(pid).name);
      return this._checkLinkerLinux(pid, runtime);
    }

    if (this.platform === 'darwin') {
      return this._checkLinkerDarwin(pid);
    }

    if (this.platform === 'win32') {
      return this._checkLinkerWindows();
    }

    return {...this._unsupported(), clean: null};
  }

  /**
   * Whether a process's parent is the PM2 daemon ("PM2 vX.Y.Z: God Daemon").
   * @param {string} pid
   * @returns {boolean}
   */
  _parentIsPm2(pid) {
    try {
      const ppid = fs.readFileSync(this._proc(pid, 'status'), 'utf8').match(/^PPid:\s+(\d+)$/m)[1];
      return /^PM2 v[\d.]+: God Daemon /.test(readCapped(this._proc(ppid, 'cmdline'), 4096).text);
    } catch {
      return false;
    }
  }

  /**
   * The process's id in its own PID namespace (a container's view).
   * @param {string} pid
   * @returns {string}
   */
  _namespacePid(pid) {
    try {
      const match = fs.readFileSync(this._proc(pid, 'status'), 'utf8').match(/^NSpid:\s+([\d\s]+)$/m);
      return match[1].trim().split(/\s+/).pop();
    } catch {
      return pid;
    }
  }

  _checkLinkerLinux(pid, runtime) {
    const result = {
      supported: true, clean: true, findings: [], runtime,
    };
    let environment = {};
    let duplicates = [];
    const truncated = [];
    try {
      const environ = readCapped(this._proc(pid, 'environ'), this.maxProcRead);
      ({values: environment, duplicates} = runtimes.parseEnviron(environ.text));
      if (environ.truncated) {
        truncated.push('environment');
      }

      result.environReadable = true;
    } catch (error) {
      result.environReadable = false;
      result.clean = null;
      result.error = error.code;
    }

    if (environment.LD_LIBRARY_PATH !== undefined) {
      result.ldLibraryPath = environment.LD_LIBRARY_PATH;
    }

    let raw = '';
    let cmdline = null;
    try {
      const read = readCapped(this._proc(pid, 'cmdline'), this.maxProcRead);
      raw = read.text;
      cmdline = raw.split('\0').filter(Boolean);
      if (read.truncated) {
        truncated.push('command line');
      }
    } catch {}

    // What was not read was not checked.
    if (truncated.length > 0) {
      result.clean = null;
      result.error = `Only the first ${this.maxProcRead} bytes of the ${truncated.join(' and ')} were checked`;
    }

    let exe;
    try {
      exe = fs.readlinkSync(this._proc(pid, 'exe'));
    } catch {}

    const inspection = runtimes.inspectRuntime(runtime, {
      environment, duplicates, cmdline, raw, exe, parentIsPm2: () => this._parentIsPm2(pid),
    });
    for (const finding of inspection.findings) {
      result.findings.push(finding);
      if (finding.severity !== 'info') {
        result.clean = false;
      }
    }

    if (inspection.extra.pm2) {
      result.pm2 = inspection.extra.pm2;
    }

    if (inspection.extra.cmdlineRewritten) {
      result.cmdlineRewritten = inspection.extra.cmdlineRewritten;
    }

    result.inspectorPorts = inspection.ports;
    // Port 0: a debugger or management port (a Node.js inspector opened
    // later with SIGUSR1, JMX) takes any free port, which the
    // listening-socket check cannot recognize.
    if (inspection.ports[0] === 0) {
      result.findings.push({type: 'inspector-random-port', value: 'a debugger or management port would listen on an unpredictable port', severity: 'warning'});
      result.clean = false;
    }

    // A JVM that has accepted an attach request (jcmd, or an agent loaded
    // at runtime) has an attach socket in its temporary directory.
    if (runtime === 'jvm') {
      const nspid = this._namespacePid(pid);
      if (this._existsIn(pid, `/tmp/.java_pid${nspid}`)) {
        result.findings.push({type: 'jvm-attach-listener', value: 'a tool attached to this JVM (agents can be loaded this way)', severity: 'warning'});
        result.clean = false;
      }
    }

    let preload = null;
    try {
      preload = this._readPreload(pid);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        result.findings.push({type: 'ld.so.preload-unreadable', value: error.code || error.message, severity: 'warning'});
        result.clean = false;
      }
    }

    if (preload) {
      result.findings.push({type: 'ld.so.preload', value: preload, severity: 'critical'});
      result.clean = false;
    }

    return result;
  }

  /**
   * Whether a path exists in a process's root (see openIn).
   * @param {string} pid
   * @param {string} file
   * @returns {boolean}
   */
  _existsIn(pid, file) {
    const root = this._fileRoot(pid);
    if (!root) {
      return exists(file);
    }

    try {
      fs.closeSync(openInRoot(root, file, {flags: O_PATH}));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * The libraries the dynamic linker of a process's root preloads into
   * every program (ld.so.preload), as one line.
   * @param {string} pid
   * @returns {string}
   */
  _readPreload(pid) {
    const fd = ProcessIntegrity.openIn(this._fileRoot(pid), this.ldPreloadPath);
    try {
      const stats = fs.fstatSync(fd);
      if (!stats.isFile() || stats.size > MAX_PRELOAD) {
        throw new Error(stats.isFile() ? 'larger than any list of libraries' : 'not a regular file');
      }

      const buffer = Buffer.alloc(stats.size);
      const length = fs.readSync(fd, buffer, 0, stats.size, 0);
      return buffer.subarray(0, length).toString('utf8')
        .split('\n')
        .map(line => line.replace(/#.*$/, '').trim())
        .filter(Boolean)
        .join(' ');
    } finally {
      fs.closeSync(fd);
    }
  }

  _checkLinkerDarwin(pid) {
    const result = {supported: true, clean: true, findings: []};
    try {
      // `ps eww` appends the environment after the command for processes we may inspect.
      const output = this._exec('ps', ['eww', '-o', 'command=', '-p', pid]);
      const match = output.match(/(?:^|\s)DYLD_INSERT_LIBRARIES=(\S+)/);
      if (match) {
        result.findings.push({type: 'DYLD_INSERT_LIBRARIES', value: match[1]});
        result.clean = false;
      }
    } catch (error) {
      result.clean = null;
      result.error = error.message.split('\n')[0];
    }

    return result;
  }

  _checkLinkerWindows() {
    const result = {supported: true, clean: true, findings: []};
    for (const key of [
      String.raw`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
      String.raw`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
    ]) {
      let output;
      try {
        output = this._exec('reg.exe', ['query', key, '/v', 'AppInit_DLLs']);
      } catch {
        continue; // Key or value absent
      }

      const match = output.match(/AppInit_DLLs\s+REG_SZ\s+(.*)$/m);
      if (match && match[1].trim()) {
        result.findings.push({type: 'AppInit_DLLs', value: match[1].trim(), key});
        result.clean = false;
      }
    }

    return result;
  }

  // ─── 4. debugger attachment ───────────────────────────────────────

  /**
   * @param {string|number} pid
   * @returns {{supported: boolean, traced: boolean|null, tracerPid?: number|null}}
   */
  checkTracerPid(pid) {
    pid = normalizePid(pid);
    if (this.platform === 'linux') {
      try {
        const status = fs.readFileSync(this._proc(pid, 'status'), 'utf8');
        const match = status.match(/^TracerPid:\s*(\d+)/m);
        if (!match) {
          return {
            supported: true, traced: null, tracerPid: null, error: 'no TracerPid in status',
          };
        }

        const tracerPid = Number(match[1]);
        return {supported: true, traced: tracerPid !== 0, tracerPid};
      } catch (error) {
        return {
          supported: true, traced: null, tracerPid: null, error: error.code,
        };
      }
    }

    if (this.platform === 'darwin') {
      try {
        // BSD ps: state flag "X" means the process is being traced or debugged.
        const state = this._exec('ps', ['-o', 'stat=', '-p', pid]).trim();
        return {supported: true, traced: state.includes('X'), state};
      } catch (error) {
        return {supported: true, traced: null, error: error.message.split('\n')[0]};
      }
    }

    if (this.platform === 'win32') {
      const script = [
        'Add-Type -TypeDefinition \'using System;using System.Runtime.InteropServices;',
        'public static class Dbg{[DllImport("kernel32.dll",SetLastError=true)]',
        'public static extern bool CheckRemoteDebuggerPresent(IntPtr h,ref bool p);}\';',
        `$p=Get-Process -Id ${pid} -ErrorAction Stop;$d=$false;`,
        'if(-not [Dbg]::CheckRemoteDebuggerPresent($p.Handle,[ref]$d)){throw "CheckRemoteDebuggerPresent failed"};',
        '$d',
      ].join('');
      try {
        const output = this._exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]).trim();
        return {supported: true, traced: /^true$/i.test(output)};
      } catch (error) {
        return {supported: true, traced: null, error: error.message.split('\n')[0]};
      }
    }

    return {...this._unsupported(), traced: null};
  }

  // ─── 5. file descriptors and sockets ──────────────────────────────

  /**
   * Suspicious open files: memfd objects (fileless payloads) and deleted
   * files held open.
   *
   * @param {string|number} pid
   * @returns {{supported: boolean, totalFds: number, suspicious: Object[]}}
   */
  checkFileDescriptors(pid) {
    pid = normalizePid(pid);
    if (this.platform === 'linux') {
      const result = {
        supported: true, totalFds: 0, suspicious: [], sockets: [],
      };
      let fds;
      try {
        fds = fs.readdirSync(this._proc(pid, 'fd'));
      } catch (error) {
        return {...result, error: error.code};
      }

      result.totalFds = fds.length;
      for (const fd of fds) {
        let target;
        try {
          target = fs.readlinkSync(this._proc(pid, 'fd', fd));
        } catch {
          continue; // Closed between readdir and readlink
        }

        if (target.startsWith('/memfd:')) {
          result.suspicious.push({fd: Number(fd), type: 'memfd', target});
        } else if (target.endsWith(' (deleted)')) {
          result.suspicious.push({fd: Number(fd), type: 'deleted', target});
        } else {
          const socket = target.match(/^socket:\[(\d+)]$/);
          if (socket) {
            result.sockets.push(Number(socket[1]));
          }
        }
      }

      return result;
    }

    if (this.platform === 'darwin') {
      try {
        const output = this._exec('lsof', ['-n', '-P', '-p', pid, '-F', 'fn']);
        const names = output.split('\n').filter(line => line.startsWith('n')).map(line => line.slice(1));
        return {
          supported: true,
          totalFds: output.split('\n').filter(line => line.startsWith('f')).length,
          suspicious: names.filter(name => name.endsWith(' (deleted)')).map(target => ({type: 'deleted', target})),
        };
      } catch (error) {
        return {
          supported: true, totalFds: 0, suspicious: [], error: error.message.split('\n')[0],
        };
      }
    }

    return {...this._unsupported(), totalFds: 0, suspicious: []};
  }

  /**
   * TCP ports a process is listening on (Linux).  Useful for spotting an
   * activated Node.js inspector (SIGUSR1 opens 127.0.0.1:9229 at runtime).
   *
   * @param {string|number} pid
   * @returns {{supported: boolean, listening: Array<{address: string, port: number}>}}
   */
  checkListeningSockets(pid) {
    pid = normalizePid(pid);
    if (this.platform !== 'linux') {
      return {...this._unsupported(), listening: []};
    }

    const fds = this.checkFileDescriptors(pid);
    if (fds.error) {
      return {supported: true, listening: [], error: fds.error};
    }

    const inodes = new Set(fds.sockets);
    const listening = [];
    let unreadable = null;
    for (const [file, v6] of [['tcp', false], ['tcp6', true]]) {
      let table;
      try {
        table = fs.readFileSync(this._proc(pid, 'net', file), 'utf8');
      } catch (error) {
        // Tcp6 is absent when IPv6 is disabled; anything else hides sockets.
        if (error.code !== 'ENOENT') {
          unreadable = error.code;
        }

        continue;
      }

      for (const line of table.split('\n').slice(1)) {
        const columns = line.trim().split(/\s+/);
        if (columns.length < 10 || columns[3] !== '0A' || !inodes.has(Number(columns[9]))) {
          continue;
        }

        const [hexAddress, hexPort] = columns[1].split(':');
        listening.push({address: decodeProcAddress(hexAddress, v6), port: Number.parseInt(hexPort, 16)});
      }
    }

    listening.sort((a, b) => a.port - b.port || (a.address > b.address) - (a.address < b.address));
    return unreadable ? {supported: true, listening, error: unreadable} : {supported: true, listening};
  }

  // ─── everything ───────────────────────────────────────────────────

  /**
   * Run every check for one process.
   *
   * @param {string|number} pid
   * @param {Object} [options]
   * @param {boolean} [options.isNode] - shorthand for runtime 'node'
   * @param {string} [options.runtime] - runtime profile name (default: detected)
   * @param {boolean} [options.nodeRelease] - the executable carries an official Node.js release URL (for detection)
   * @returns {Object}
   */
  checkAll(pid, options = {}) {
    pid = normalizePid(pid);
    const memoryMaps = this.checkMemoryMaps(pid);
    let runtime = null;
    if (this.platform === 'linux') {
      if (options.runtime || options.isNode) {
        const profile = runtimes.PROFILES[options.runtime || 'node'] || runtimes.NATIVE;
        runtime = {
          name: profile.name, label: profile.label, version: null, by: 'caller',
        };
      } else {
        runtime = this.detectRuntime(pid, {libraries: memoryMaps.libraries || [], nodeRelease: options.nodeRelease});
      }
    }

    const report = {
      pid,
      platform: this.platform,
      timestamp: new Date().toISOString(),
      runtime,
      memoryMaps,
      executablePages: this.checkExecutablePages(pid),
      linkerIntegrity: this.checkLinkerIntegrity(pid, runtime ? {runtime: runtime.name} : options),
      tracer: this.checkTracerPid(pid),
      fileDescriptors: this.checkFileDescriptors(pid),
      listeningSockets: this.checkListeningSockets(pid),
    };
    // Configured ports, the runtime's default debug ports, and any port the
    // process's options give a debugger.
    report.inspectorPorts = [...new Set([...this.inspectorPorts, ...(report.linkerIntegrity.inspectorPorts || [])])].sort((a, b) => a - b);
    report.findings = summarizeFindings(report);
    // Checks that could not run (usually permissions): a clean result is
    // only meaningful when this list is empty.
    report.incomplete = INSPECTIONS
      .filter(name => report[name].supported !== false && report[name].error)
      .map(name => ({check: name, error: report[name].error}));
    const unreadable = report.executablePages.skipped.filter(item => item.reason !== 'deleted' && item.reason !== 'replaced');
    if (unreadable.length > 0) {
      report.incomplete.push({check: 'executablePages', error: `${unreadable.length} region(s) could not be compared (${[...new Set(unreadable.map(item => item.reason))].join(', ')})`});
    }

    report.passed = !report.findings.some(finding => finding.severity === 'critical') && report.incomplete.length === 0;
    return report;
  }
}

/**
 * Read up to `length` bytes, stopping early at end of file.
 * @returns {number} bytes read
 */
function readUpTo(fd, buffer, length, position) {
  let done = 0;
  while (done < length) {
    const bytes = fs.readSync(fd, buffer, done, length - done, position + done);
    if (bytes === 0) {
      break;
    }

    done += bytes;
  }

  return done;
}

/**
 * Read exactly `length` bytes of process memory.
 */
function readFully(fd, buffer, length, position) {
  if (readUpTo(fd, buffer, length, position) !== length) {
    throw new Error('Short read from process memory');
  }
}

/**
 * Decode an address from /proc/net/tcp{,6}.
 * @param {string} hex
 * @param {boolean} v6
 * @returns {string}
 */
function decodeProcAddress(hex, v6) {
  const bytes = Buffer.from(hex, 'hex');
  // Each 32-bit word is stored in host (little-endian) order.
  for (let i = 0; i < bytes.length; i += 4) {
    bytes.subarray(i, i + 4).reverse();
  }

  if (!v6) {
    return [...bytes].join('.');
  }

  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(bytes.readUInt16BE(i));
  }

  // RFC 5952: compress the longest run (length >= 2) of zero groups.
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }

    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }

    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }

    i = j;
  }

  const parts = groups.map(group => group.toString(16));
  if (bestStart === -1) {
    return parts.join(':');
  }

  return `${parts.slice(0, bestStart).join(':')}::${parts.slice(bestStart + bestLength).join(':')}`;
}

const WARNING_TYPES = new Set(['deleted-backing', 'replaced-backing']);

/**
 * Turn a checkAll() report into a flat list of findings.  An empty list
 * means nothing suspicious was observed by the checks that could run.
 *
 * Severity "critical" means code or code-loading was altered or an
 * injection path is open.  Severity "warning" means the running code can no
 * longer be compared with disk (typically a library upgraded without a
 * restart), which blocks verification but is not itself evidence of
 * tampering.
 *
 * @param {Object} report
 * @returns {Array<{check: string, type: string, severity: string, detail: *}>}
 */
const INSPECTIONS = ['memoryMaps', 'executablePages', 'linkerIntegrity', 'tracer', 'fileDescriptors', 'listeningSockets'];

function summarizeFindings(report) {
  const findings = [];
  const add = (check, type, detail, severity) => {
    findings.push({
      check, type, severity: severity || (WARNING_TYPES.has(type) ? 'warning' : 'critical'), detail,
    });
  };

  // The runtime's own JIT memfds (named in its profile) are context.
  const runtime = report.runtime ? report.runtime.name : null;
  const memfd = (check, type, target) => {
    const owned = runtimes.runtimeMemfd(runtime, target);
    add(check, type, owned ? `${target}: ${owned}` : target, owned ? 'info' : undefined);
  };

  for (const anomaly of report.memoryMaps.anomalies) {
    if (anomaly.type === 'memfd-exec') {
      memfd('memoryMaps', anomaly.type, anomaly.path);
    } else {
      add('memoryMaps', anomaly.type, anomaly.path || anomaly.address);
    }
  }

  for (const mismatch of report.executablePages.mismatched || []) {
    add('executablePages', 'code-modified-in-memory', `${mismatch.path} @ ${mismatch.address}`);
  }

  for (const finding of (report.linkerIntegrity && report.linkerIntegrity.findings) || []) {
    add('linkerIntegrity', finding.type, finding.value, finding.severity);
  }

  if (report.tracer.traced === true) {
    add('tracer', 'debugger-attached', report.tracer.tracerPid ?? null);
  }

  for (const suspicious of report.fileDescriptors.suspicious || []) {
    if (suspicious.type === 'memfd') {
      memfd('fileDescriptors', 'memfd-open', suspicious.target);
    }
  }

  const inspectorPorts = new Set(report.inspectorPorts || []);
  for (const socket of (report.listeningSockets && report.listeningSockets.listening) || []) {
    if (inspectorPorts.has(socket.port)) {
      add('listeningSockets', 'inspector-listening', `${socket.address}:${socket.port}`);
    }
  }

  return findings;
}

ProcessIntegrity.parseMapsLine = parseMapsLine;
ProcessIntegrity.splitNodeOptions = runtimes.splitOptions;
ProcessIntegrity.findNodeInjectionFlags = runtimes.findNodeInjectionFlags;
ProcessIntegrity.parsePm2Environment = runtimes.parsePm2Environment;
ProcessIntegrity.parsePm2Fields = runtimes.parsePm2Fields;
ProcessIntegrity.decodeProcAddress = decodeProcAddress;
ProcessIntegrity.summarizeFindings = summarizeFindings;

module.exports = ProcessIntegrity;

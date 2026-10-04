'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const zlib = require('node:zlib');
const {execFileSync, spawn} = require('node:child_process');

// Windows has no POSIX file modes, permissions, FIFOs or Unix sockets, and
// its symbolic links need a privilege and keep targets with backslashes:
// tests of those run on Linux and macOS.
const windows = process.platform === 'win32';
const needsPosix = windows && 'needs POSIX symbolic links, file modes and permissions';

/**
 * Give the owner access to everything under a directory again (a test may
 * have taken it away), without following symbolic links.
 */
function makeAccessible(directory) {
  fs.chmodSync(directory, 0o700);
  for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      makeAccessible(full);
    } else if (!entry.isSymbolicLink()) {
      fs.chmodSync(full, 0o600);
    }
  }
}

/**
 * Temporary directory removed after the test.
 */
function tempDir(t, prefix = 'attestium-test-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => {
    // Windows refuses to remove a file another program has open for a moment.
    const remove = () => fs.rmSync(directory, {recursive: true, force: true, maxRetries: windows ? 10 : 0});
    try {
      remove();
    } catch {
      makeAccessible(directory);
      remove();
    }
  });
  return directory;
}

// The longest path a system call takes, with the final NUL: a longer one
// can be made from relative paths, but not opened by its full path.
// Windows takes paths of any length.
const PATH_MAX = {linux: 4096, darwin: 1024}[process.platform];

/**
 * A temporary directory that may hold paths longer than PATH_MAX, removed
 * with find, which does not build full paths.
 */
function deepTempDir(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-deep-')));
  t.after(() => {
    execFileSync('find', [directory, '-delete']);
  });
  return directory;
}

/**
 * A file whose full path is longer than PATH_MAX, so it is listed but no
 * program can open it by that path.  Returns the directory holding it.
 *
 * @param {string} parent
 * @param {string} [name]
 * @returns {string}
 */
function unreadableEntry(parent, name = 'f'.repeat(250)) {
  let directory = parent;
  while (directory.length < PATH_MAX - 196) {
    directory = path.join(directory, 'd'.repeat(Math.min(200, PATH_MAX - 146 - directory.length)));
  }

  fs.mkdirSync(directory, {recursive: true});
  execFileSync('touch', [name], {cwd: directory});
  return directory;
}

/**
 * Write a map of relative path -> content under a directory.
 */
function writeFiles(root, files) {
  for (const [relativePath, content] of Object.entries(files)) {
    const full = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(full), {recursive: true});
    fs.writeFileSync(full, content);
  }
}

/**
 * @param {net.Server} server
 * @param {number} port
 * @param {string} host
 * @returns {Promise<void>}
 */
function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

/**
 * Servers on both loopback addresses a name can resolve to, on one port:
 * 127.0.0.1, and ::1 where the system has it ("localhost" is ::1 first on
 * macOS).
 *
 * @param {() => net.Server} create
 * @returns {Promise<net.Server[]>} 127.0.0.1's first
 */
async function listenOnLoopback(create) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const v4 = create();
    await listen(v4, 0, '127.0.0.1');
    const v6 = create();
    try {
      await listen(v6, v4.address().port, '::1');
      return [v4, v6];
    } catch (error) {
      if (error.code !== 'EADDRINUSE') {
        // No IPv6 loopback: names resolve to 127.0.0.1 only.
        return [v4];
      }

      await new Promise(resolve => {
        v4.close(resolve);
      });
    }
  }

  throw new Error('No port free on both loopback addresses');
}

/**
 * Local HTTP server.  `routes` maps a path to a handler (req, res) or to
 * {status, body, headers}.  Unknown paths get 404.
 */
async function startServer(t, routes = {}) {
  const requests = [];
  const handle = (request, response) => {
    requests.push({url: request.url, headers: request.headers});
    const route = routes[request.url.split('?')[0]];
    if (typeof route === 'function') {
      route(request, response);
      return;
    }

    if (!route) {
      response.writeHead(404);
      response.end('not found');
      return;
    }

    response.writeHead(route.status || 200, route.headers || {});
    response.end(route.body);
  };

  const servers = await listenOnLoopback(() => http.createServer(handle));
  t.after(() => Promise.all(servers.map(server => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }))));
  return {
    url: `http://127.0.0.1:${servers[0].address().port}`, routes, requests, server: servers[0],
  };
}

const CRC_TABLE = Array.from({length: 256}, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xED_B8_83_20 ^ (c >>> 1) : c >>> 1;
  }

  return c >>> 0;
});

function crc32(data) {
  let crc = 0xFF_FF_FF_FF;
  for (const byte of data) {
    crc = CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
  }

  return (crc ^ 0xFF_FF_FF_FF) >>> 0;
}

/**
 * A stored (uncompressed) zip.  An entry's `descriptor` ('signed' or
 * 'unsigned') writes its sizes and CRC in a data descriptor after the data,
 * with or without the descriptor's optional signature.
 * @param {Array<{name: string, data: string|Buffer, descriptor?: string}>} entries
 * @param {string} [comment]
 * @returns {Buffer}
 */
function makeZip(entries, comment = '') {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const {name, data: raw, descriptor} of entries) {
    const data = Buffer.from(raw);
    const nameBytes = Buffer.from(name);
    const crc = crc32(data);
    const flags = descriptor ? 0x08 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04_03_4B_50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(descriptor ? 0 : crc, 14);
    local.writeUInt32LE(descriptor ? 0 : data.length, 18);
    local.writeUInt32LE(descriptor ? 0 : data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const parts = [local, nameBytes, data];
    if (descriptor) {
      const trailer = Buffer.alloc(12);
      trailer.writeUInt32LE(crc, 0);
      trailer.writeUInt32LE(data.length, 4);
      trailer.writeUInt32LE(data.length, 8);
      if (descriptor === 'signed') {
        parts.push(Buffer.from([0x50, 0x4B, 0x07, 0x08]));
      }

      parts.push(trailer);
    }

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02_01_4B_50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);
    const entry = Buffer.concat(parts);
    locals.push(entry);
    offset += entry.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06_05_4B_50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(Buffer.byteLength(comment), 20);
  return Buffer.concat([...locals, directory, end, Buffer.from(comment)]);
}

// A fixed time for archive members, so archives are the same on every run.
const ARCHIVE_TIME = 1_700_000_000;

/**
 * @param {Buffer} block
 * @param {number} offset
 * @param {number} length - of the field, with its final NUL
 * @param {number} value
 */
function writeOctal(block, offset, length, value) {
  block.write(`${value.toString(8).padStart(length - 1, '0')}\0`, offset, length, 'latin1');
}

/**
 * One tar header block.
 */
function tarHeader({name, type, size = 0, mode, linkname = '', prefix = '', gnu}) {
  const block = Buffer.alloc(512);
  block.write(name, 0, 100, 'utf8');
  writeOctal(block, 100, 8, mode);
  writeOctal(block, 108, 8, 0);
  writeOctal(block, 116, 8, 0);
  writeOctal(block, 124, 12, size);
  writeOctal(block, 136, 12, ARCHIVE_TIME);
  block.write(type, 156, 1, 'latin1');
  block.write(linkname, 157, 100, 'utf8');
  // GNU tar's own magic, or POSIX ustar's (pax and ustar).
  block.write(gnu ? 'ustar  \0' : 'ustar\u000000', 257, 8, 'latin1');
  block.write(prefix, 345, 155, 'utf8');
  block.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of block) {
    sum += byte;
  }

  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'latin1');
  return block;
}

/**
 * Data, padded to whole blocks.
 * @param {Buffer} data
 * @returns {Buffer[]}
 */
function tarData(data) {
  const padding = (512 - (data.length % 512)) % 512;
  return [data, Buffer.alloc(padding)];
}

/**
 * A pax extended header record: "<length> key=value\n", where the length
 * counts the whole record, its own digits included.
 */
function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 1;
  while (String(length).length + Buffer.byteLength(body) !== length) {
    length++;
  }

  return `${length}${body}`;
}

/**
 * Split a name for a ustar header: prefix (at most 155 bytes), "/", and
 * name (at most 100 bytes).
 * @returns {{prefix: string, name: string}|null}
 */
function ustarSplit(name) {
  if (Buffer.byteLength(name) <= 100) {
    return {prefix: '', name};
  }

  for (let index = name.indexOf('/'); index !== -1; index = name.indexOf('/', index + 1)) {
    const prefix = name.slice(0, index);
    const rest = name.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(rest) <= 100 && rest) {
      return {prefix, name: rest};
    }
  }

  return null;
}

/**
 * The blocks of one member, with its long name or link target the format's
 * way.
 * @returns {Buffer[]}
 */
function tarMember(name, {type, mode, data = Buffer.alloc(0), linkname = ''}, format) {
  const gnu = format === 'gnu';
  const blocks = [];
  let header = {name, linkname, prefix: ''};
  const longName = Buffer.byteLength(name) > 100;
  const longLink = Buffer.byteLength(linkname) > 100;
  if (gnu) {
    for (const [long, value, flag] of [[longName, name, 'L'], [longLink, linkname, 'K']]) {
      if (long) {
        const text = Buffer.from(`${value}\0`);
        blocks.push(tarHeader({
          name: '././@LongLink', type: flag, size: text.length, mode: 0o644, gnu,
        }), ...tarData(text));
      }
    }
  } else if (format === 'pax' && (longName || longLink)) {
    const records = Buffer.from((longName ? paxRecord('path', name) : '') + (longLink ? paxRecord('linkpath', linkname) : ''));
    blocks.push(tarHeader({
      name: `PaxHeader/${name.split('/').findLast(Boolean)}`.slice(0, 100), type: 'x', size: records.length, mode: 0o644,
    }), ...tarData(records));
  } else {
    const split = ustarSplit(name);
    if (!split || longLink) {
      throw new Error(`${name} is too long for a ustar archive`);
    }

    header = {...split, linkname};
  }

  blocks.push(tarHeader({
    ...header, type, size: data.length, mode, gnu,
  }), ...tarData(data));
  return blocks;
}

/**
 * A tar archive, written as the tar programs and npm write them, so tests
 * need no tar program (GNU tar's options differ from bsdtar's on macOS and
 * Windows).  Directories get their own members, as tar adds them.  Long
 * names are written the format's way: "gnu" in ././@LongLink members, "pax"
 * in extended headers, "ustar" split into the prefix field (and an error
 * if they do not fit).
 *
 * @param {Object<string, string|Buffer>} files - path -> content
 * @param {Object} [options]
 * @param {'gnu'|'pax'|'ustar'} [options.format='gnu']
 * @param {Object<string, string>} [options.symlinks] - path -> target
 * @param {Object<string, string>} [options.hardlinks] - path -> the member it links to
 * @returns {Buffer}
 */
function makeTar(files, {format = 'gnu', symlinks = {}, hardlinks = {}} = {}) {
  const entries = new Map();
  const add = (name, entry) => {
    const parts = name.split('/');
    for (let depth = 1; depth < parts.length; depth++) {
      const directory = `${parts.slice(0, depth).join('/')}/`;
      if (!entries.has(directory)) {
        entries.set(directory, {type: '5', mode: 0o755});
      }
    }

    entries.set(name, entry);
  };

  for (const [name, content] of Object.entries(files)) {
    add(name, {type: '0', mode: 0o644, data: Buffer.from(content)});
  }

  for (const [name, target] of Object.entries(symlinks)) {
    add(name, {type: '2', mode: 0o777, linkname: target});
  }

  for (const [name, target] of Object.entries(hardlinks)) {
    add(name, {type: '1', mode: 0o644, linkname: target});
  }

  // Members in name order (a directory before what it holds), and each hard
  // link after the member it names.
  const names = [...entries.keys()].filter(name => entries.get(name).type !== '1').sort();
  names.push(...Object.keys(hardlinks));
  const blocks = names.flatMap(name => tarMember(name, entries.get(name), format));
  // Two zero blocks end the archive, padded to whole 10 KiB records as tar does.
  const body = Buffer.concat([...blocks, Buffer.alloc(1024)]);
  return Buffer.concat([body, Buffer.alloc((10_240 - (body.length % 10_240)) % 10_240)]);
}

/**
 * The same, compressed with gzip.  (`t` is unused; callers pass it.)
 */
function makeTarGz(t, files, options) {
  return zlib.gzipSync(makeTar(files, options));
}

/**
 * Whether a program the tests may run is on PATH.  On Windows the tests run
 * none: the Windows builds of git, OpenSSL, GnuPG and the Unix tools differ
 * in paths, configuration and line endings, so the tests that need them
 * run on Linux and macOS.
 */
function which(command) {
  if (windows) {
    return false;
  }

  for (const directory of (process.env.PATH || '').split(path.delimiter).filter(Boolean)) {
    try {
      const file = path.join(directory, command);
      if (fs.statSync(file).isFile()) {
        fs.accessSync(file, fs.constants.X_OK);
        return true;
      }
    } catch {}
  }

  return false;
}

/**
 * Whether openssl is OpenSSL: the tests make certificates and timestamps
 * with its req, x509, ts and cms commands, which LibreSSL (macOS's own
 * openssl) lacks in part.
 */
const hasOpenssl = which('openssl') && (() => {
  try {
    return execFileSync('openssl', ['version'], {encoding: 'utf8'}).startsWith('OpenSSL ');
  } catch {
    return false;
  }
})();

const hasTpmSimulator = process.platform === 'linux' && which('swtpm') && which('tpm2_quote');

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const {port} = server.address();
  await new Promise(resolve => {
    server.close(resolve);
  });
  return port;
}

/**
 * Start a fresh software TPM (swtpm) for a test file.
 * @returns {Promise<{tcti: string, port: number}>}
 */
async function portIsFree(port) {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
    return true;
  } catch {
    return false;
  } finally {
    server.close();
  }
}

async function portOpens(port) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
          socket.destroy();
          resolve();
        });
        socket.on('error', reject);
      });
      return true;
    } catch {
      await new Promise(resolve => {
        setTimeout(resolve, 100);
      });
    }
  }

  return false;
}

/**
 * A software TPM on two consecutive free ports (the swtpm TCTI always uses
 * port + 1 as the control channel), retried when a test running in
 * parallel takes one of them first.
 */
async function startSwtpm(t) {
  const state = tempDir(t, 'attestium-swtpm-');
  for (let attempt = 0; attempt < 10; attempt++) {
    const port = await freePort();
    if (!(await portIsFree(port + 1))) {
      continue;
    }

    const child = spawn('swtpm', [
      'socket',
      '--tpm2',
      '--tpmstate',
      `dir=${state}`,
      '--server',
      `type=tcp,port=${port},bindaddr=127.0.0.1`,
      '--ctrl',
      `type=tcp,port=${port + 1},bindaddr=127.0.0.1`,
      '--flags',
      'not-need-init,startup-clear',
    ], {stdio: 'ignore'});
    let exited = false;
    child.once('exit', () => {
      exited = true;
    });
    t.after(() => {
      child.kill('SIGKILL');
    });
    if (await portOpens(port)) {
      // A simulator that lost a port race exits right away.
      await new Promise(resolve => {
        setTimeout(resolve, 100);
      });
      if (!exited) {
        return {tcti: `swtpm:host=127.0.0.1,port=${port}`, port};
      }
    }

    child.kill('SIGKILL');
  }

  throw new Error('swtpm did not start');
}

const sleep = ms => new Promise(resolve => {
  setTimeout(resolve, ms);
});

module.exports = {
  tempDir,
  writeFiles,
  windows,
  needsPosix,
  PATH_MAX,
  deepTempDir,
  unreadableEntry,
  listenOnLoopback,
  startServer,
  makeZip,
  makeTar,
  makeTarGz,
  which,
  hasOpenssl,
  hasTpmSimulator,
  startSwtpm,
  freePort,
  sleep,
};

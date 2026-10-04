/**
 * Attestium - file tree hashing
 *
 * Walks a directory without following symbolic links, hashes every
 * regular file with SHA-256, and also computes the git blob object id so
 * results can be compared with a git tree.  Symbolic links are recorded
 * (never followed), so a link cannot pull files from outside the root into
 * the manifest or send the walker into a loop.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {promisify} = require('node:util');
const {sha256} = require('./util');

// Looked up on each call, so tests can observe reads.
const open = (...args) => promisify(fs.open)(...args);
const close = fd => promisify(fs.close)(fd);
const fstat = fd => promisify(fs.fstat)(fd);
const read = (...args) => promisify(fs.read)(...args);

const CHUNK_SIZE = 1024 * 1024;
// O_NOFOLLOW makes open() fail on a symbolic link instead of following it,
// and O_NONBLOCK keeps it from waiting for a writer on a FIFO.  Windows has
// neither (and no POSIX symlink race to guard against).
/* c8 ignore next */
const OPEN_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
// Linux: directories are followed through open descriptors (/proc/self/fd),
// so one replaced by a symbolic link during a walk is not followed.
const LINUX = process.platform === 'linux';
// O_PATH (Linux): names a directory without opening it for reading, so one
// that can only be searched can still be walked through.
const O_PATH = 0o1000_0000;
const MAX_LINKS = 40;
// Linux's PATH_MAX, with the final NUL.
const PATH_MAX = 4096;

/**
 * An open descriptor's path: every lookup through it starts at the file it
 * was opened on, whatever now holds its old name.
 * @param {number} fd
 * @returns {string}
 */
function fdPath(fd) {
  return `/proc/self/fd/${fd}`;
}

/**
 * Open a file inside a root directory the way a process whose root it is
 * would find it: symbolic links (absolute or relative) and ".." resolve
 * inside the root, so no path a process controls leads out of it.  Each
 * step starts from an open directory, so a directory replaced by a link
 * while the path is followed is not followed.  Linux.
 *
 * @param {string} root - a trusted directory, such as /proc/<pid>/root; '' for /
 * @param {string} file - a path inside the root
 * @param {Object} [options]
 * @param {number} [options.flags] - for the file itself (default: read, never waiting on a FIFO); O_NOFOLLOW is added
 * @param {boolean} [options.rootOwnedLinks=false] - follow only links owned by root (a path another user chose)
 * @returns {number} a file descriptor
 */
function openInRoot(root, file, options = {}) {
  const flags = (options.flags ?? (fs.constants.O_RDONLY | fs.constants.O_NONBLOCK)) | fs.constants.O_NOFOLLOW;
  const stack = [fs.openSync(root || '/', O_PATH | fs.constants.O_DIRECTORY)];
  const at = name => `${fdPath(stack.at(-1))}/${name}`;
  const pending = String(file).split('/').reverse();
  let links = 0;
  try {
    while (pending.length > 0) {
      const name = pending.pop();
      if (name === '' || name === '.') {
        continue;
      }

      if (name === '..') {
        if (stack.length > 1) {
          fs.closeSync(stack.pop());
        }

        continue;
      }

      const stats = fs.lstatSync(at(name));
      if (stats.isSymbolicLink()) {
        if (++links > MAX_LINKS) {
          throw Object.assign(new Error(`Too many symbolic links: ${file}`), {code: 'ELOOP'});
        }

        if (options.rootOwnedLinks && stats.uid !== 0) {
          throw new Error(`A symbolic link not owned by root: ${file}`);
        }

        const target = fs.readlinkSync(at(name));
        if (target.startsWith('/')) {
          while (stack.length > 1) {
            fs.closeSync(stack.pop());
          }
        }

        pending.push(...target.split('/').reverse());
        continue;
      }

      if (pending.every(item => item === '' || item === '.')) {
        return fs.openSync(at(name), flags);
      }

      stack.push(fs.openSync(at(name), O_PATH | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW));
    }

    // The path names the root, or a directory above it.
    return fs.openSync(fdPath(stack.at(-1)), flags & ~fs.constants.O_NOFOLLOW);
  } finally {
    for (const fd of stack) {
      fs.closeSync(fd);
    }
  }
}

/**
 * Git blob object id (SHA-1) for a buffer.
 * @param {Buffer|string} content
 * @returns {string}
 */
function gitBlobId(content) {
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return crypto.createHash('sha1')
    .update(`blob ${buffer.length}\0`)
    .update(buffer)
    .digest('hex');
}

/**
 * Hash a regular file.  Reads in chunks so large files are not buffered in
 * memory, and fails if the file changes size while it is being read.  Never
 * follows a symbolic link as the last component, and refuses anything but a
 * regular file (a FIFO would wait for a writer, a device never ends).
 *
 * @param {string} filePath
 * @param {Object} [options]
 * @param {string} [options.root] - resolve filePath inside this root (see openInRoot)
 * @param {boolean} [options.rootOwnedLinks] - see openInRoot
 * @param {number} [options.inode] - the file must be this inode (a mapped file whose path may have changed)
 * @returns {Promise<{sha256: string, gitBlobId: string, size: number}>}
 */
async function hashFile(filePath, options = {}) {
  const fd = options.root === undefined ? await open(filePath, OPEN_FLAGS) : openInRoot(options.root, filePath, options);
  try {
    const stats = await fstat(fd);
    if (!stats.isFile()) {
      throw new Error(`Not a regular file: ${filePath}`);
    }

    if (options.inode !== undefined && stats.ino !== options.inode) {
      throw new Error(`Replaced since it was mapped: ${filePath}`);
    }

    const {size} = stats;
    const sha = crypto.createHash('sha256');
    const blob = crypto.createHash('sha1').update(`blob ${size}\0`);
    const buffer = Buffer.allocUnsafe(Math.min(CHUNK_SIZE, Math.max(size, 1)));
    let offset = 0;
    while (offset <= size) {
      const {bytesRead} = await read(fd, buffer, 0, buffer.length, offset);
      if (bytesRead === 0) {
        break;
      }

      const chunk = buffer.subarray(0, bytesRead);
      sha.update(chunk);
      blob.update(chunk);
      offset += bytesRead;
    }

    if (offset !== size) {
      throw new Error(`File changed while hashing: ${filePath}`);
    }

    return {sha256: sha.digest('hex'), gitBlobId: blob.digest('hex'), size};
  } finally {
    await close(fd);
  }
}

/**
 * Convert a glob pattern to a RegExp anchored at both ends.
 *
 *   `**` followed by `/` matches zero or more directories
 *   `**` elsewhere matches anything (including `/`)
 *   `*`  matches anything except `/`
 *   `?`  matches one character except `/`
 *
 * Every other character is matched literally.
 *
 * @param {string} pattern
 * @returns {RegExp}
 */
function globToRegExp(pattern) {
  let source = '';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        if (pattern[i + 2] === '/') {
          source += '(?:.*/)?';
          i += 2;
        } else {
          source += '.*';
          i += 1;
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);
    }
  }

  return new RegExp(`^${source}$`);
}

/**
 * Build a matcher from glob patterns.
 * @param {string[]} patterns
 * @returns {(relativePath: string) => boolean}
 */
function createMatcher(patterns = []) {
  const regexes = patterns.map(pattern => globToRegExp(pattern));
  return relativePath => regexes.some(regex => regex.test(relativePath));
}

/**
 * Convert a platform path to a forward-slash relative path.
 * @param {string} root
 * @param {string} fullPath
 * @returns {string}
 */
function toPosixRelative(root, fullPath) {
  return path.relative(root, fullPath).split(path.sep).join('/');
}

/**
 * A directory to walk: on Linux an open descriptor, so what is listed and
 * opened below it is inside this directory even if its path changes.
 * @param {string} directory
 * @param {Object} [options] - root and rootOwnedLinks: resolve directory inside root (see openInRoot)
 * @returns {Promise<{path: string, fd: number|null}>}
 */
async function openDirectory(directory, options = {}) {
  /* c8 ignore next 3 - other systems follow paths */
  if (!LINUX) {
    return {path: directory, fd: null};
  }

  const flags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY;
  const fd = options.root === undefined ? await open(directory, flags) : openInRoot(options.root, directory, {...options, flags});
  return {path: fdPath(fd), fd};
}

/**
 * A subdirectory of an open directory, never through a symbolic link.
 * @param {{path: string, fd: number|null}} parent
 * @param {string} name
 * @returns {Promise<{path: string, fd: number|null}>}
 */
async function openSubdirectory(parent, name) {
  /* c8 ignore next 3 - other systems follow paths */
  if (!LINUX) {
    return {path: path.join(parent.path, name), fd: null};
  }

  const fd = await open(`${parent.path}/${name}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  return {path: fdPath(fd), fd};
}

/**
 * @param {{fd: number|null}} directory
 * @returns {Promise<void>}
 */
async function closeDirectory(directory) {
  if (directory.fd !== null) {
    await close(directory.fd);
  }
}

/**
 * The status of an open directory.
 * @param {{path: string, fd: number|null}} directory
 * @returns {Promise<fs.Stats>}
 */
async function statDirectory(directory) {
  /* c8 ignore next 3 - other systems follow paths */
  if (directory.fd === null) {
    return fs.promises.stat(directory.path);
  }

  return fstat(directory.fd);
}

/**
 * Walk a directory and hash its contents.
 *
 * Symbolic links are recorded, never followed, and on Linux each directory
 * is entered through its parent's open descriptor, so a directory replaced
 * by a link during the walk cannot lead it elsewhere.
 *
 * Each directory listed is also returned with its times ('.' for the top):
 * adding, removing or renaming an entry changes both, so a file that was
 * added and removed again still shows in its directory.
 *
 * @param {string} root
 * @param {Object} [options]
 * @param {(relativePath: string, isDirectory: boolean) => boolean} [options.exclude]
 *   Return true to skip an entry (directories are checked with a trailing slash-free path).
 * @param {number} [options.concurrency=16]
 * @param {string} [options.root] - resolve the directory inside this root (see openInRoot)
 * @param {boolean} [options.rootOwnedLinks] - see openInRoot
 * @param {boolean} [options.hash=true] - false: only the path, type and times of each entry, without reading files or links
 * @returns {Promise<{entries: Object[], directories: Array<{path: string, ctimeMs: number, mtimeMs: number}>, errors: Object[]}>}
 */
async function walkTree(root, options = {}) {
  const exclude = options.exclude || (() => false);
  const concurrency = options.concurrency || 16;
  const hash = options.hash !== false;
  const results = [];
  const directories = [];
  const listErrors = [];
  const fileErrors = [];
  // At most `concurrency` files open at once.
  let active = 0;
  const waiting = [];
  const limited = async task => {
    if (active < concurrency) {
      active++;
    } else {
      await new Promise(resolve => {
        waiting.push(resolve);
      });
    }

    try {
      return await task();
    } finally {
      // Hand the slot to the next task waiting, if any.
      if (waiting.length > 0) {
        waiting.shift()();
      } else {
        active--;
      }
    }
  };

  // A path no program could open by name is reported, as it was before
  // walks went through descriptors.
  const absoluteRoot = path.resolve(root);
  const tooLong = relativePath => Buffer.byteLength(absoluteRoot) + 1 + Buffer.byteLength(relativePath) >= PATH_MAX;
  const nameTooLong = () => Object.assign(new Error('name too long'), {code: 'ENAMETOOLONG'});
  const describe = async (directory, dirent, relativePath) => {
    const fullPath = `${directory.path}/${dirent.name}`;
    try {
      if (tooLong(relativePath)) {
        throw nameTooLong();
      }

      const stats = await fs.promises.lstat(fullPath);
      if (!hash) {
        return {
          path: relativePath, type: dirent.isSymbolicLink() ? 'symlink' : 'file', ctimeMs: stats.ctimeMs, mtimeMs: stats.mtimeMs,
        };
      }

      if (dirent.isSymbolicLink()) {
        const target = await fs.promises.readlink(fullPath);
        return {
          path: relativePath,
          type: 'symlink',
          mode: '120000',
          target,
          size: Buffer.byteLength(target),
          sha256: sha256(target),
          gitBlobId: gitBlobId(target),
          ctimeMs: stats.ctimeMs,
          mtimeMs: stats.mtimeMs,
        };
      }

      const hashes = await hashFile(fullPath);
      return {
        path: relativePath,
        type: 'file',
        mode: (stats.mode & 0o100) ? '100755' : '100644',
        size: hashes.size,
        sha256: hashes.sha256,
        gitBlobId: hashes.gitBlobId,
        ctimeMs: stats.ctimeMs,
        mtimeMs: stats.mtimeMs,
      };
    } catch (error) {
      fileErrors.push({path: relativePath, error: error.code || error.message});
      return null;
    }
  };

  const visit = async (directory, relative) => {
    let dirents;
    let stats;
    try {
      dirents = await fs.promises.readdir(directory.path, {withFileTypes: true});
      stats = await statDirectory(directory);
    } catch (error) {
      listErrors.push({path: relative || '.', error: error.code});
      return;
    }

    directories.push({path: relative || '.', ctimeMs: stats.ctimeMs, mtimeMs: stats.mtimeMs});
    dirents.sort((a, b) => (a.name > b.name) - (a.name < b.name));
    const pending = [];
    for (const dirent of dirents) {
      const relativePath = relative ? `${relative}/${dirent.name}` : dirent.name;
      if (dirent.isDirectory()) {
        if (!exclude(relativePath, true)) {
          let child;
          try {
            if (tooLong(relativePath)) {
              throw nameTooLong();
            }

            child = await openSubdirectory(directory, dirent.name);
          } catch (error) {
            listErrors.push({path: relativePath, error: error.code});
            continue;
          }

          try {
            await visit(child, relativePath);
          } finally {
            await closeDirectory(child);
          }
        }
      } else if (exclude(relativePath, false)) {
        continue;
      } else if (dirent.isSocket()) {
        // A socket has no content: opening it fails (ENXIO), so nothing can
        // be read or loaded from it.  Servers leave them in their
        // directories (Puma's tmp/sockets, gunicorn, PostgreSQL's /run).
        continue;
      } else if (dirent.isSymbolicLink() || dirent.isFile()) {
        const slot = results.length;
        results.push(null);
        pending.push(limited(() => describe(directory, dirent, relativePath)).then(entry => {
          results[slot] = entry;
        }));
      } else {
        // A FIFO or device: never read (a FIFO would wait for a writer),
        // but reported, since a program may still read or load it.
        fileErrors.push({path: relativePath, error: 'ENOTFILE'});
      }
    }

    // The directory stays open until its files are read.
    await Promise.all(pending);
  };

  let top;
  try {
    top = await openDirectory(absoluteRoot, options);
  } catch (error) {
    return {entries: [], directories: [], errors: [{path: '.', error: error.code || error.message}]};
  }

  try {
    await visit(top, '');
  } finally {
    await closeDirectory(top);
  }

  return {entries: results.filter(Boolean), directories, errors: [...listErrors, ...fileErrors]};
}

/**
 * Digest of a set of files: SHA-256 over sorted `path\0sha256\n` lines, or
 * `path\0sha256\0symlink\n` for an entry of type "symlink" (whose sha256 is
 * that of its target).  Independent of walk order, mode and timestamps.
 *
 * @param {Array<{path: string, sha256: string, type?: string}>} entries
 * @returns {string}
 */
function manifestDigest(entries) {
  // A symbolic link and a file whose content equals its target differ.
  const lines = entries
    .map(entry => `${entry.path}\0${entry.sha256}${entry.type === 'symlink' ? '\0symlink' : ''}\n`)
    .sort();
  return sha256(lines.join(''));
}

module.exports = {
  gitBlobId,
  hashFile,
  openInRoot,
  openDirectory,
  openSubdirectory,
  closeDirectory,
  globToRegExp,
  createMatcher,
  toPosixRelative,
  walkTree,
  manifestDigest,
};

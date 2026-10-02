/**
 * Attestium - minimal tar reader
 *
 * Reads POSIX ustar archives with GNU long-name and long-link ('L', 'K')
 * and pax ('x': path, linkpath, size) extensions, which covers the
 * official Node.js release archives and npm package tarballs.  Only reads; never writes anything to disk.
 *
 * @license MIT
 */

'use strict';

const zlib = require('node:zlib');

const BLOCK = 512;

/**
 * @param {Buffer} buffer
 * @param {number} start
 * @param {number} length
 * @returns {string}
 */
function readString(buffer, start, length) {
  const slice = buffer.subarray(start, start + length);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString('utf8');
}

/**
 * @param {Buffer} buffer
 * @param {number} start
 * @param {number} length
 * @returns {number}
 */
function readOctal(buffer, start, length) {
  // GNU base-256 encoding for large values (high bit set)
  if (buffer[start] & 0x80) {
    let value = 0;
    for (let i = start + 1; i < start + length; i++) {
      value = (value * 256) + buffer[i];
    }

    return value;
  }

  const text = readString(buffer, start, length).trim();
  if (text === '') {
    return 0;
  }

  if (!/^[0-7]+$/.test(text)) {
    throw new Error(`Invalid octal field in tar header: ${JSON.stringify(text)}`);
  }

  return Number.parseInt(text, 8);
}

/**
 * @param {Buffer} header
 * @returns {boolean}
 */
function verifyChecksum(header) {
  const expected = readOctal(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) {
    sum += (i >= 148 && i < 156) ? 32 : header[i];
  }

  return sum === expected;
}

/**
 * Parse pax extended header records ("<len> key=value\n").
 * @param {Buffer} data
 * @returns {Object<string,string>}
 */
function parsePax(data) {
  const records = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) {
      break;
    }

    const length = Number.parseInt(data.subarray(offset, space).toString('utf8'), 10);
    if (!Number.isInteger(length) || length <= 0 || offset + length > data.length) {
      throw new Error('Malformed pax header');
    }

    const record = data.subarray(space + 1, offset + length - 1).toString('utf8');
    const equals = record.indexOf('=');
    if (equals > 0) {
      records[record.slice(0, equals)] = record.slice(equals + 1);
    }

    offset += length;
  }

  return records;
}

/**
 * Iterate the entries of an uncompressed tar archive.
 *
 * @param {Buffer} buffer
 * @returns {Array<{name: string, type: string, size: number, data: Buffer, linkName: string}>}
 */
function readTar(buffer) {
  const entries = [];
  let offset = 0;
  let longName = null;
  let pax = null;

  let longLink = null;
  const isZero = block => block.every(byte => byte === 0);

  while (offset + BLOCK <= buffer.length) {
    const header = buffer.subarray(offset, offset + BLOCK);
    if (isZero(header)) {
      // Two zero blocks end an archive.  Readers disagree about a lone zero
      // block followed by more entries (some stop, npm's reads on), so an
      // archive that has one means different files to different tools.
      const next = buffer.subarray(offset + BLOCK, offset + (2 * BLOCK));
      if (next.length === BLOCK && !isZero(next)) {
        throw new Error(`Tar archive has entries after a zero block at offset ${offset}`);
      }

      break;
    }

    if (!verifyChecksum(header)) {
      throw new Error(`Tar header checksum mismatch at offset ${offset}`);
    }

    let size = readOctal(header, 124, 12);
    if (pax && pax.size !== undefined) {
      // A pax size (files of 8 GiB and more) replaces the header's.
      if (!/^\d{1,15}$/.test(pax.size)) {
        throw new Error('Invalid pax size');
      }

      size = Number(pax.size);
    }

    const typeFlag = String.fromCodePoint(header[156] || 48);
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) {
      throw new Error('Truncated tar archive');
    }

    const data = buffer.subarray(dataStart, dataEnd);
    offset = dataStart + (Math.ceil(size / BLOCK) * BLOCK);

    if (typeFlag === 'L') {
      longName = readString(data, 0, data.length);
      continue;
    }

    if (typeFlag === 'K') {
      longLink = readString(data, 0, data.length);
      continue;
    }

    if (typeFlag === 'x') {
      pax = parsePax(data);
      continue;
    }

    if (typeFlag === 'g') {
      continue;
    }

    let name = readString(header, 0, 100);
    // POSIX ustar and pax headers ("ustar\0") have a name prefix; GNU
    // headers ("ustar  ") keep other fields in the same place.
    if (header.subarray(257, 263).toString('latin1') === 'ustar\0') {
      const prefix = readString(header, 345, 155);
      if (prefix) {
        name = `${prefix}/${name}`;
      }
    }

    if (longName !== null) {
      name = longName;
    }

    if (pax && pax.path) {
      name = pax.path;
    }

    entries.push({
      name,
      type: typeFlag,
      mode: readOctal(header, 100, 8),
      size,
      data,
      linkName: pax && pax.linkpath ? pax.linkpath : (longLink ?? readString(header, 157, 100)),
    });
    longName = null;
    longLink = null;
    pax = null;
  }

  return entries;
}

/**
 * Normalize an archive member path.  Returns null for paths that escape the
 * archive root or are otherwise unsafe.
 *
 * @param {string} name
 * @returns {string|null}
 */
function safeMemberPath(name) {
  const parts = [];
  for (const part of name.replaceAll('\\', '/').split('/')) {
    if (part === '' || part === '.') {
      continue;
    }

    if (part === '..') {
      return null;
    }

    parts.push(part);
  }

  return parts.length > 0 ? parts.join('/') : null;
}

/**
 * Read regular files (and hard links to them) from a gzipped tar archive.
 *
 * @param {Buffer} gzipped
 * @param {Object} [options]
 * @param {boolean} [options.stripFirstComponent=false]
 * @param {number} [options.maxUncompressedBytes=1 GiB]
 * @returns {Map<string, Buffer>} path -> content (later duplicates win)
 */
function readGzipTarFiles(gzipped, options = {}) {
  const maxOutputLength = options.maxUncompressedBytes || (1024 * 1024 * 1024);
  const tar = zlib.gunzipSync(gzipped, {maxOutputLength});
  const files = new Map();
  const memberPath = raw => {
    let name = safeMemberPath(raw);
    if (name && options.stripFirstComponent) {
      const slash = name.indexOf('/');
      name = slash === -1 ? null : name.slice(slash + 1);
    }

    return name;
  };

  for (const entry of readTar(tar)) {
    // Regular files, contiguous files, and hard links to earlier members.
    let {data} = entry;
    if (entry.type === '1') {
      data = files.get(memberPath(entry.linkName));
    } else if ((entry.type !== '0' && entry.type !== '7') || entry.name.endsWith('/')) {
      // Old archives mark a directory as a file whose name ends in "/".
      continue;
    }

    const name = memberPath(entry.name);
    if (name && data) {
      files.set(name, data);
    }
  }

  return files;
}

module.exports = {
  readTar,
  readGzipTarFiles,
  safeMemberPath,
  parsePax,
};

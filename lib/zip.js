/**
 * Attestium - minimal zip reader
 *
 * Reads the archives package registries serve: Python wheels, NuGet
 * packages, Java archives and Composer dist archives.  Stored and deflated
 * members, ZIP64 sizes and offsets, CRC-32 checked.  Member names are
 * normalized and names that escape the archive are skipped.  Only reads.
 *
 * @license MIT
 */

'use strict';

const zlib = require('node:zlib');
const {safeMemberPath} = require('./tar');

const EOCD = 0x06_05_4B_50;
const EOCD64 = 0x06_06_4B_50;
const EOCD64_LOCATOR = 0x07_06_4B_50;
const CENTRAL = 0x02_01_4B_50;
const LOCAL = 0x04_03_4B_50;

let crcTable = null;

/**
 * CRC-32 (IEEE), as zip uses.
 * @param {Buffer} data
 * @returns {number}
 */
function crc32(data) {
  if (!crcTable) {
    crcTable = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? 0xED_B8_83_20 ^ (c >>> 1) : c >>> 1;
      }

      crcTable[n] = c;
    }
  }

  let crc = -1;
  for (const byte of data) {
    crc = crcTable[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
  }

  return (crc ^ -1) >>> 0;
}

/**
 * List a zip archive's members from its central directory.
 *
 * @param {Buffer} buffer
 * @returns {Array<{name: string, method: number, compressedSize: number, size: number, crc: number, localOffset: number, directory: boolean, external: number}>}
 */
function listZip(buffer) {
  // The end-of-central-directory record is within the last 64 KiB + 22 bytes.
  let end = -1;
  for (let index = buffer.length - 22; index >= Math.max(0, buffer.length - 65_557); index--) {
    if (buffer.readUInt32LE(index) === EOCD) {
      end = index;
      break;
    }
  }

  if (end === -1) {
    throw new Error('Not a zip archive (no end of central directory)');
  }

  let count = buffer.readUInt16LE(end + 10);
  let size = buffer.readUInt32LE(end + 12);
  let offset = buffer.readUInt32LE(end + 16);
  if ((count === 0xFF_FF || size === 0xFF_FF_FF_FF || offset === 0xFF_FF_FF_FF) && end >= 20 && buffer.readUInt32LE(end - 20) === EOCD64_LOCATOR) {
    const record = Number(buffer.readBigUInt64LE(end - 12));
    if (record + 56 > buffer.length || buffer.readUInt32LE(record) !== EOCD64) {
      throw new Error('Malformed ZIP64 end of central directory');
    }

    count = Number(buffer.readBigUInt64LE(record + 32));
    size = Number(buffer.readBigUInt64LE(record + 40));
    offset = Number(buffer.readBigUInt64LE(record + 48));
  }

  if (offset + size > buffer.length) {
    throw new Error('Zip central directory out of range');
  }

  const entries = [];
  let cursor = offset;
  for (let index = 0; index < count; index++) {
    if (cursor + 46 > buffer.length || buffer.readUInt32LE(cursor) !== CENTRAL) {
      throw new Error('Malformed zip central directory');
    }

    const method = buffer.readUInt16LE(cursor + 10);
    const crc = buffer.readUInt32LE(cursor + 16);
    let compressedSize = buffer.readUInt32LE(cursor + 20);
    let uncompressedSize = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const external = buffer.readUInt32LE(cursor + 38);
    let localOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8');
    // ZIP64 extra field: the 64-bit values of the fields set to 0xFFFFFFFF, in order.
    let extra = cursor + 46 + nameLength;
    const extraEnd = extra + extraLength;
    while (extra + 4 <= extraEnd) {
      const id = buffer.readUInt16LE(extra);
      const length = buffer.readUInt16LE(extra + 2);
      if (id === 0x00_01) {
        let field = extra + 4;
        const next = () => {
          const value = Number(buffer.readBigUInt64LE(field));
          field += 8;
          return value;
        };

        if (uncompressedSize === 0xFF_FF_FF_FF) {
          uncompressedSize = next();
        }

        if (compressedSize === 0xFF_FF_FF_FF) {
          compressedSize = next();
        }

        if (localOffset === 0xFF_FF_FF_FF) {
          localOffset = next();
        }
      }

      extra += 4 + length;
    }

    entries.push({
      name, method, compressedSize, size: uncompressedSize, crc, localOffset, directory: name.endsWith('/'), external,
    });
    cursor = extraEnd + commentLength;
  }

  return entries;
}

/**
 * Read one member's contents.
 * @param {Buffer} buffer
 * @param {Object} entry - from listZip
 * @param {number} maxBytes
 * @returns {Buffer}
 */
function readMember(buffer, entry, maxBytes) {
  const at = entry.localOffset;
  if (at + 30 > buffer.length || buffer.readUInt32LE(at) !== LOCAL) {
    throw new Error(`Malformed zip local header for ${entry.name}`);
  }

  const nameLength = buffer.readUInt16LE(at + 26);
  const start = at + 30 + nameLength + buffer.readUInt16LE(at + 28);
  // Tools that read local headers in order and tools that read the central
  // directory must see the same member.
  const localName = buffer.subarray(at + 30, Math.min(at + 30 + nameLength, buffer.length)).toString('utf8');
  if (localName !== entry.name) {
    throw new Error(`Zip member ${entry.name}: its local header names ${localName}`);
  }

  const localMethod = buffer.readUInt16LE(at + 8);
  if (localMethod !== entry.method) {
    throw new Error(`Zip member ${entry.name}: its local header has compression method ${localMethod}, the central directory ${entry.method}`);
  }

  if (start + entry.compressedSize > buffer.length) {
    throw new Error(`Zip member ${entry.name} out of range`);
  }

  if (entry.size > maxBytes) {
    throw new Error(`Zip member ${entry.name} is too large`);
  }

  const raw = buffer.subarray(start, start + entry.compressedSize);
  let data;
  if (entry.method === 0) {
    data = raw;
  } else if (entry.method === 8) {
    data = zlib.inflateRawSync(raw, {maxOutputLength: Math.max(entry.size, 1)});
  } else {
    throw new Error(`Unsupported zip compression method ${entry.method} for ${entry.name}`);
  }

  if (data.length !== entry.size || crc32(data) !== entry.crc) {
    throw new Error(`Zip member ${entry.name} failed its CRC check`);
  }

  return data;
}

/**
 * Read every file of a zip archive.
 *
 * @param {Buffer} buffer
 * @param {Object} [options]
 * @param {boolean} [options.stripFirstComponent=false]
 * @param {number} [options.maxUncompressedBytes=1 GiB]
 * @param {(name: string) => boolean} [options.filter] - read only members whose (normalized) name passes
 * @returns {Map<string, Buffer>} path -> content
 */
function readZipFiles(buffer, options = {}) {
  const maxTotal = options.maxUncompressedBytes || (1024 * 1024 * 1024);
  const {filter} = options;
  const files = new Map();
  let total = 0;
  for (const entry of listZip(buffer)) {
    if (entry.directory) {
      continue;
    }

    let name = safeMemberPath(entry.name);
    if (name && options.stripFirstComponent) {
      const slash = name.indexOf('/');
      name = slash === -1 ? null : name.slice(slash + 1);
    }

    if (!name || (filter && !filter(name))) {
      continue;
    }

    total += entry.size;
    if (total > maxTotal) {
      throw new Error('Zip archive expands beyond the size limit');
    }

    files.set(name, readMember(buffer, entry, maxTotal));
  }

  return files;
}

module.exports = {
  crc32, listZip, readZipFiles, readMember,
};

/**
 * Attestium - ELF reading, and the build metadata compilers embed
 *
 *   Go      every binary carries its module list with go.sum hashes and its
 *           build settings (VCS revision, -trimpath, CGO) in .go.buildinfo
 *   Rust    binaries built with cargo-auditable carry their crate list,
 *           compressed, in .dep-v0
 *
 * The metadata is written by the build, so it proves nothing on its own: a
 * binary is verified by its hash (a reproduced build or an attested
 * artifact).  It lets a verifier check that the dependencies inside the
 * binary are the ones the repository's lockfile pins.
 *
 * Only reads; bounds-checked throughout, since binaries come from the
 * audited machine.
 *
 * @license MIT
 */

'use strict';

const zlib = require('node:zlib');

const ELF_MAGIC = Buffer.from([0x7F, 0x45, 0x4C, 0x46]);

const MAX_SECTION_NAME = 256;

/**
 * Parse ELF section headers.
 *
 * @param {Buffer} buffer
 * @returns {{class: 32|64, littleEndian: boolean, machine: number, type: number, sections: Array<{name: string, type: number, offset: number, size: number, addr: bigint}>}}
 */
function parseElf(buffer) {
  if (buffer.length < 52 || !buffer.subarray(0, 4).equals(ELF_MAGIC)) {
    throw new Error('Not an ELF file');
  }

  const elfClass = buffer[4] === 2 ? 64 : (buffer[4] === 1 ? 32 : 0);
  if (!elfClass) {
    throw new Error('Unknown ELF class');
  }

  const littleEndian = buffer[5] === 1;
  if (!littleEndian && buffer[5] !== 2) {
    throw new Error('Unknown ELF byte order');
  }

  const u16 = offset => (littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset));
  const u32 = offset => (littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  const u64 = offset => (littleEndian ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset));
  const word = offset => (elfClass === 64 ? u64(offset) : BigInt(u32(offset)));
  const toNumber = value => {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('ELF offset out of range');
    }

    return Number(value);
  };

  const header = elfClass === 64
    ? {
      shoff: toNumber(u64(0x28)), shentsize: u16(0x3A), shnum: u16(0x3C), shstrndx: u16(0x3E),
    }
    : {
      shoff: u32(0x20), shentsize: u16(0x2E), shnum: u16(0x30), shstrndx: u16(0x32),
    };
  const type = u16(0x10);
  const machine = u16(0x12);
  const minimum = elfClass === 64 ? 0x40 : 0x28;
  if (header.shnum > 0 && (header.shentsize < minimum || header.shoff + (header.shnum * header.shentsize) > buffer.length)) {
    throw new Error('ELF section headers out of range');
  }

  const raw = [];
  for (let index = 0; index < header.shnum; index++) {
    const base = header.shoff + (index * header.shentsize);
    raw.push(elfClass === 64
      ? {
        nameOffset: u32(base), type: u32(base + 4), addr: u64(base + 0x10), offset: toNumber(u64(base + 0x18)), size: toNumber(u64(base + 0x20)),
      }
      : {
        nameOffset: u32(base), type: u32(base + 4), addr: BigInt(u32(base + 0x0C)), offset: u32(base + 0x10), size: u32(base + 0x14),
      });
  }

  const strings = raw[header.shstrndx];
  const sections = raw.map(section => {
    let name = '';
    if (strings && strings.offset + strings.size <= buffer.length) {
      // Names are short: a table with no NUL in it is not searched to its
      // end once for each of up to 65,535 sections.
      const table = buffer.subarray(strings.offset, strings.offset + strings.size);
      const candidate = table.subarray(section.nameOffset, section.nameOffset + MAX_SECTION_NAME);
      const end = candidate.indexOf(0);
      name = section.nameOffset < table.length ? (end === -1 ? candidate : candidate.subarray(0, end)).toString('latin1') : '';
    }

    return {
      name, type: section.type, offset: section.offset, size: section.size, addr: section.addr,
    };
  });

  return {
    class: elfClass, littleEndian, machine, type, sections, word,
  };
}

/**
 * The contents of a named section, or null.  SHT_NOBITS sections have none.
 * @param {Buffer} buffer
 * @param {Object} elf - from parseElf
 * @param {string} name
 * @returns {Buffer|null}
 */
function sectionData(buffer, elf, name) {
  const section = elf.sections.find(item => item.name === name);
  if (!section || section.type === 8) {
    return null;
  }

  if (section.offset + section.size > buffer.length) {
    throw new Error(`ELF section ${name} out of range`);
  }

  return buffer.subarray(section.offset, section.offset + section.size);
}

// ─── Go ────────────────────────────────────────────────────────────────

const GO_MAGIC = Buffer.from('ÿ Go buildinf:', 'latin1');
const GO_MODINFO_START = Buffer.from('3077af0c9274080241e1c107e6d618e6', 'hex');
const GO_MODINFO_END = Buffer.from('f932433186182072008242104116d8f2', 'hex');

/**
 * Read an unsigned LEB128 varint.
 * @returns {[number, number]} value and bytes used
 */
function readUvarint(buffer, offset) {
  let value = 0;
  let shift = 0;
  for (let index = offset; index < buffer.length && index < offset + 10; index++) {
    const byte = buffer[index];
    value += (byte & 0x7F) * (2 ** shift);
    if ((byte & 0x80) === 0) {
      return [value, index - offset + 1];
    }

    shift += 7;
  }

  throw new Error('Malformed varint in Go build information');
}

/**
 * Parse the module information string (as printed by `go version -m`).
 * @param {string} text
 * @returns {{path: string|null, main: Object|null, deps: Object[], settings: Object<string,string>}}
 */
function parseGoModInfo(text) {
  const info = {
    path: null, main: null, deps: [], settings: {},
  };
  let last = null;
  for (const line of text.split('\n')) {
    const fields = line.split('\t');
    switch (fields[0]) {
      case 'path': {
        info.path = fields[1] ?? null;
        break;
      }

      case 'mod': {
        info.main = {path: fields[1], version: fields[2] || null, sum: fields[3] || null};
        last = info.main;
        break;
      }

      case 'dep': {
        last = {path: fields[1], version: fields[2] || null, sum: fields[3] || null};
        info.deps.push(last);
        break;
      }

      case '=>': {
        if (last) {
          last.replace = {path: fields[1], version: fields[2] || null, sum: fields[3] || null};
        }

        break;
      }

      case 'build': {
        const setting = fields.slice(1).join('\t');
        const equals = setting.indexOf('=');
        if (equals > 0) {
          info.settings[setting.slice(0, equals)] = setting.slice(equals + 1).replace(/^"(.*)"$/, '$1');
        }

        break;
      }

      default:
    }
  }

  return info;
}

/**
 * Go build information embedded in a binary (Go 1.18 and later).
 *
 * @param {Buffer} buffer - the executable
 * @returns {{goVersion: string, path: string|null, main: Object|null, deps: Object[], settings: Object}|null}
 *   null when the binary is not a Go binary
 */
function goBuildInfo(buffer) {
  let blob = null;
  try {
    const elf = parseElf(buffer);
    blob = sectionData(buffer, elf, '.go.buildinfo');
  } catch {}

  // Other formats, or stripped section headers: the header is 16-byte
  // aligned in the data segment.
  if (!blob) {
    let index = buffer.indexOf(GO_MAGIC);
    while (index !== -1 && index % 16 !== 0) {
      index = buffer.indexOf(GO_MAGIC, index + 1);
    }

    if (index === -1) {
      return null;
    }

    blob = buffer.subarray(index);
  }

  if (blob.length < 32 || !blob.subarray(0, GO_MAGIC.length).equals(GO_MAGIC)) {
    return null;
  }

  const flags = blob[15];
  if ((flags & 0x2) === 0) {
    // Go 1.17 and earlier stored pointers to the strings instead.
    return {
      goVersion: null, path: null, main: null, deps: [], settings: {}, unsupported: 'Go 1.17 or earlier (no inline build information)',
    };
  }

  let offset = 32;
  const readString = () => {
    const [length, used] = readUvarint(blob, offset);
    offset += used;
    if (offset + length > blob.length) {
      throw new Error('Go build information is truncated');
    }

    const value = blob.subarray(offset, offset + length);
    offset += length;
    return value;
  };

  const goVersion = readString().toString('utf8');
  let modinfo = readString();
  if (modinfo.length >= 33 && modinfo.subarray(0, 16).equals(GO_MODINFO_START) && modinfo.subarray(-16).equals(GO_MODINFO_END)) {
    modinfo = modinfo.subarray(16, -16);
  }

  return {goVersion, ...parseGoModInfo(modinfo.toString('utf8'))};
}

// ─── Rust (cargo-auditable) ────────────────────────────────────────────

/**
 * The crate list cargo-auditable embeds.
 *
 * @param {Buffer} buffer - the executable
 * @returns {Array<{name: string, version: string, source: string, kind: string, root: boolean}>|null}
 *   null when the binary carries none
 */
function cargoAuditable(buffer) {
  let data;
  try {
    data = sectionData(buffer, parseElf(buffer), '.dep-v0');
  } catch {
    return null;
  }

  if (!data) {
    return null;
  }

  const json = JSON.parse(zlib.inflateSync(data, {maxOutputLength: 16 * 1024 * 1024}).toString('utf8'));
  if (!json || !Array.isArray(json.packages)) {
    throw new Error('Malformed cargo-auditable data');
  }

  return json.packages.map(item => ({
    name: String(item.name),
    version: String(item.version),
    source: String(item.source ?? 'unknown'),
    kind: item.kind === 'build' ? 'build' : 'runtime',
    root: item.root === true,
  }));
}

module.exports = {
  parseElf,
  sectionData,
  goBuildInfo,
  parseGoModInfo,
  cargoAuditable,
  readUvarint,
};

/**
 * Attestium - Linux IMA measurement log
 *
 * With IMA enabled, the kernel hashes files as they are executed, mapped
 * executable, or (depending on policy) read, appends each measurement to a
 * log, and extends the hash into a TPM PCR (10 by default).  Entries cannot
 * be removed from the PCR, so a verifier that
 *
 *   1. checks a TPM quote of PCR 10 (see ./tpm.js), and
 *   2. replays this log and gets the same PCR value,
 *
 * can trust the log's list of measured file hashes even if the machine's
 * root user is hostile.  Whether a given file is measured depends entirely
 * on the IMA policy in force.
 *
 * Supports the binary log (binary_runtime_measurements) for the ima-ng,
 * ima-sig and ima-buf templates, and replays sha1 and sha256 PCR banks.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');

const DEFAULT_LOG = '/sys/kernel/security/ima/binary_runtime_measurements';
const SUPPORTED_TEMPLATES = new Set(['ima-ng', 'ima-sig', 'ima-buf']);
const DIGEST_SIZES = {
  sha1: 20, sha256: 32, sha384: 48, sha512: 64,
};

/**
 * Split template data into its length-prefixed fields.
 * @param {Buffer} data
 * @param {boolean} littleEndian
 * @returns {Buffer[]}
 */
function splitFields(data, littleEndian) {
  const fields = [];
  let offset = 0;
  while (offset < data.length) {
    if (offset + 4 > data.length) {
      throw new Error('Truncated IMA template field');
    }

    const length = littleEndian ? data.readUInt32LE(offset) : data.readUInt32BE(offset);
    offset += 4;
    if (offset + length > data.length) {
      throw new Error('Truncated IMA template field');
    }

    fields.push(data.subarray(offset, offset + length));
    offset += length;
  }

  return fields;
}

/**
 * Decode a d-ng field ("<algo>:\0<digest>").
 * @param {Buffer} field
 * @returns {{algorithm: string, digest: string}}
 */
function decodeDigestField(field) {
  const separator = field.indexOf(':\0');
  if (separator === -1) {
    // Old format without an algorithm prefix is always SHA-1.
    return {algorithm: 'sha1', digest: field.toString('hex')};
  }

  return {
    algorithm: field.subarray(0, separator).toString('ascii'),
    digest: field.subarray(separator + 2).toString('hex'),
  };
}

/**
 * Parse a binary IMA measurement log.
 *
 * @param {Buffer} buffer
 * @param {Object} [options]
 * @param {boolean} [options.littleEndian=true] - false for logs exported with ima_canonical_fmt on big-endian hosts
 * @returns {Array<Object>}
 */
function parseBinaryLog(buffer, options = {}) {
  const littleEndian = options.littleEndian !== false;
  const u32 = offset => (littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  const entries = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 28 > buffer.length) {
      throw new Error('Truncated IMA log entry header');
    }

    const pcr = u32(offset);
    const templateDigest = buffer.subarray(offset + 4, offset + 24).toString('hex');
    const nameLength = u32(offset + 24);
    offset += 28;
    if (nameLength > 255 || offset + nameLength + 4 > buffer.length) {
      throw new Error('Malformed IMA template name');
    }

    const templateName = buffer.subarray(offset, offset + nameLength).toString('ascii');
    offset += nameLength;
    const dataLength = u32(offset);
    offset += 4;
    if (offset + dataLength > buffer.length) {
      throw new Error('Truncated IMA template data');
    }

    const templateData = buffer.subarray(offset, offset + dataLength);
    offset += dataLength;

    const entry = {
      pcr, templateName, templateDigest, templateData,
    };
    if (SUPPORTED_TEMPLATES.has(templateName)) {
      const fields = splitFields(templateData, littleEndian);
      const {algorithm, digest} = decodeDigestField(fields[0] || Buffer.alloc(0));
      entry.fileHashAlgorithm = algorithm;
      entry.fileHash = digest;
      entry.path = (fields[1] || Buffer.alloc(0)).toString('utf8').replace(/\0+$/, '');
    }

    entry.violation = /^0+$/.test(templateDigest);
    entries.push(entry);
  }

  return entries;
}

/**
 * Replay a log into a PCR value.
 *
 * @param {Object[]} entries - from parseBinaryLog()
 * @param {string} [bank='sha256']
 * @param {number} [pcr=10]
 * @returns {string} hex PCR value
 */
function replay(entries, bank = 'sha256', pcr = 10) {
  return replaySteps(entries, bank, pcr).at(-1).value;
}

/**
 * The PCR value after each entry of a log (entries for other PCRs leave it
 * unchanged).  Step 0 is the initial all-zero value.
 *
 * @returns {Array<{count: number, value: string}>}
 */
function replaySteps(entries, bank, pcr) {
  const size = DIGEST_SIZES[bank];
  if (!size) {
    throw new TypeError(`Unsupported bank: ${bank}`);
  }

  let value = Buffer.alloc(size);
  const steps = [{count: 0, value: value.toString('hex')}];
  for (const [index, entry] of entries.entries()) {
    if (entry.pcr !== pcr) {
      continue;
    }

    let digest;
    if (entry.violation) {
      digest = Buffer.alloc(size, 0xFF);
    } else if (bank === 'sha1' && entry.templateName === 'ima') {
      // The legacy template's digest is taken from the log: only the
      // original "ima" template is replayed this way, so renaming an
      // entry's template cannot hide it.
      digest = Buffer.from(entry.templateDigest, 'hex');
    } else if (SUPPORTED_TEMPLATES.has(entry.templateName)) {
      digest = crypto.createHash(bank).update(entry.templateData).digest();
    } else {
      throw new Error(`Cannot replay template "${entry.templateName}" into the ${bank} bank`);
    }

    value = crypto.createHash(bank).update(value).update(digest).digest();
    steps.push({count: index + 1, value: value.toString('hex')});
  }

  return steps;
}

/**
 * The entries a quoted PCR value accounts for.
 *
 * The log keeps growing after a quote, so it is replayed entry by entry
 * until the running value equals the quoted one; the entries up to that
 * point are backed by the TPM, and later ones are not.
 *
 * @param {Object[]} entries - from parseBinaryLog()
 * @param {string} quoted - hex PCR value from a verified quote
 * @param {string} [bank='sha256']
 * @param {number} [pcr=10]
 * @returns {Object[]|null} the backed prefix of `entries`, or null if no prefix replays to `quoted`
 */
function backedEntries(entries, quoted, bank = 'sha256', pcr = 10) {
  const target = String(quoted).toLowerCase();
  const step = replaySteps(entries, bank, pcr).find(item => item.value === target);
  return step ? entries.slice(0, step.count) : null;
}

/**
 * Measured hashes per path, from the entries extended into one PCR.
 *
 * Entries for other PCRs and violation entries (whose template data the
 * PCR does not cover) are skipped, so only what a quote of that PCR backs
 * is returned.  So are ima-buf entries: they measure buffers (keys, the
 * kexec command line), named by their source, which is not a file (a
 * keyring's name can be any path).
 *
 * @param {Object[]} entries
 * @param {Object} [options]
 * @param {number} [options.pcr=10]
 * @returns {Map<string, {algorithm: string, hash: string, count: number, hashes: string[]}>}
 */
function measurementsByPath(entries, options = {}) {
  const pcr = options.pcr ?? 10;
  const map = new Map();
  for (const entry of entries) {
    if (!entry.path || entry.pcr !== pcr || entry.violation || entry.templateName === 'ima-buf') {
      continue;
    }

    const previous = map.get(entry.path);
    map.set(entry.path, {
      algorithm: entry.fileHashAlgorithm,
      hash: entry.fileHash,
      count: previous ? previous.count + 1 : 1,
      hashes: previous ? [...new Set([...previous.hashes, entry.fileHash])] : [entry.fileHash],
    });
  }

  return map;
}

/**
 * Read the binary log from securityfs (requires root or CAP_DAC_READ_SEARCH
 * on most systems).
 *
 * @param {string} [file]
 * @returns {Buffer}
 */
function readLog(file = DEFAULT_LOG) {
  return fs.readFileSync(file);
}

module.exports = {
  DEFAULT_LOG,
  parseBinaryLog,
  replay,
  backedEntries,
  measurementsByPath,
  readLog,
  decodeDigestField,
  splitFields,
};

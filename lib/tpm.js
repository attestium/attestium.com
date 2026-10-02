/**
 * Attestium - TPM 2.0 attestation
 *
 * Attester side: creates a persistent Attestation Key (AK) under the
 * Endorsement Key and produces signed quotes of PCR values with
 * tpm2-tools.  Verifier side: parses TPMS_ATTEST and checks the quote in
 * pure Node.js (signature, magic, type, nonce, PCR digest), so the
 * verifying machine needs no TPM software.
 *
 * What a verified quote proves: a key held by the TPM signed the listed
 * PCR values together with your nonce, after you created the nonce.  It
 * binds a report to the platform's measured state.  It proves nothing
 * about the platform unless the AK public key is trusted (pinned at
 * enrollment, or certified through the EK certificate chain) and the PCR
 * values are compared with known-good values or an event log.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const yaml = require('js-yaml');
const {sha256, exists} = require('./util');

const TPM_GENERATED_VALUE = 0xFF_54_43_47;
const TPM_ST_ATTEST_QUOTE = 0x80_18;
const HASH_ALGORITHMS = {
  0x00_04: 'sha1',
  0x00_0B: 'sha256',
  0x00_0C: 'sha384',
  0x00_0D: 'sha512',
};
const HASH_SIZES = {
  sha1: 20, sha256: 32, sha384: 48, sha512: 64,
};

/**
 * Promise wrapper around execFile with a bounded buffer.
 */
function defaultRun(file, args, options) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {...options, maxBuffer: 8 * 1024 * 1024}, (error, stdout, stderr) => {
      if (error) {
        error.message = `${file} failed: ${String(stderr || error.message).trim().split('\n').pop()}`;
        reject(error);
        return;
      }

      resolve(stdout);
    });
  });
}

/**
 * @param {number[]} pcrs
 * @returns {number[]}
 */
function normalizePcrList(pcrs) {
  if (!Array.isArray(pcrs) || pcrs.length === 0) {
    throw new TypeError('PCR list must be a non-empty array');
  }

  const list = [...new Set(pcrs)].sort((a, b) => a - b);
  for (const pcr of list) {
    if (!Number.isInteger(pcr) || pcr < 0 || pcr > 23) {
      throw new TypeError(`Invalid PCR index: ${pcr}`);
    }
  }

  return list;
}

/**
 * @param {string} bank
 * @returns {string}
 */
function normalizeBank(bank) {
  if (!Object.hasOwn(HASH_SIZES, bank)) {
    throw new TypeError(`Unsupported PCR bank: ${bank}`);
  }

  return bank;
}

/**
 * Validate an AK handle ("0x81xxxxxx", persistent owner range).
 * @param {string} handle
 * @returns {string}
 */
function normalizeHandle(handle) {
  if (typeof handle !== 'string' || !/^0x81[\da-fA-F]{6}$/.test(handle)) {
    throw new TypeError(`Invalid persistent handle: ${handle}`);
  }

  return handle.toLowerCase();
}

/**
 * Parse PCR values from tpm2-tools YAML output (tpm2_pcrread / tpm2_quote).
 * @param {string} text
 * @returns {Object<string, Object<string, string>>} bank -> index -> hex
 */
function parsePcrYaml(text) {
  const document = yaml.load(text, {schema: yaml.FAILSAFE_SCHEMA}) || {};
  const source = document.pcrs || document;
  const banks = {};
  for (const [bank, values] of Object.entries(source)) {
    if (!Object.hasOwn(HASH_SIZES, bank) || !values || typeof values !== 'object') {
      continue;
    }

    banks[bank] = {};
    for (const [index, value] of Object.entries(values)) {
      banks[bank][String(Number(index))] = String(value).replace(/^0x/i, '').toLowerCase();
    }
  }

  return banks;
}

/**
 * Parse a TPMS_ATTEST structure produced by TPM2_Quote.
 *
 * @param {Buffer} buffer
 * @returns {Object}
 */
function parseAttest(buffer) {
  let offset = 0;
  const need = count => {
    if (offset + count > buffer.length) {
      throw new Error('Truncated TPMS_ATTEST');
    }
  };

  const u8 = () => {
    need(1);
    return buffer.readUInt8(offset++);
  };

  const u16 = () => {
    need(2);
    const value = buffer.readUInt16BE(offset);
    offset += 2;
    return value;
  };

  const u32 = () => {
    need(4);
    const value = buffer.readUInt32BE(offset);
    offset += 4;
    return value;
  };

  const u64 = () => {
    need(8);
    const value = buffer.readBigUInt64BE(offset);
    offset += 8;
    return value.toString();
  };

  const tpm2b = () => {
    const size = u16();
    need(size);
    const value = buffer.subarray(offset, offset + size);
    offset += size;
    return value;
  };

  const magic = u32();
  const type = u16();
  const qualifiedSigner = tpm2b();
  const extraData = tpm2b();
  const clockInfo = {
    clock: u64(), resetCount: u32(), restartCount: u32(), safe: u8() === 1,
  };
  const firmwareVersion = u64();
  if (magic !== TPM_GENERATED_VALUE) {
    throw new Error('TPMS_ATTEST magic is not TPM_GENERATED_VALUE');
  }

  if (type !== TPM_ST_ATTEST_QUOTE) {
    throw new Error(`TPMS_ATTEST type 0x${type.toString(16)} is not a quote`);
  }

  const selections = [];
  const count = u32();
  if (count > 16) {
    throw new Error('Too many PCR selections');
  }

  for (let i = 0; i < count; i++) {
    const algorithm = u16();
    const size = u8();
    need(size);
    const bitmap = buffer.subarray(offset, offset + size);
    offset += size;
    const pcrs = [];
    for (let byte = 0; byte < size; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[byte] & (1 << bit)) {
          pcrs.push((byte * 8) + bit);
        }
      }
    }

    selections.push({bank: HASH_ALGORITHMS[algorithm] || `0x${algorithm.toString(16)}`, pcrs});
  }

  const pcrDigest = tpm2b();
  if (offset !== buffer.length) {
    throw new Error('Trailing bytes after TPMS_ATTEST');
  }

  return {
    magic,
    type,
    qualifiedSigner: qualifiedSigner.toString('hex'),
    extraData: extraData.toString('hex'),
    clockInfo,
    firmwareVersion,
    selections,
    pcrDigest: pcrDigest.toString('hex'),
  };
}

/**
 * Verify a quote produced by Tpm#quote().
 *
 * @param {Object} input
 * @param {Object} input.quote - {message, signature, hashAlg, pcrs}
 * @param {string} input.publicKey - trusted AK public key (PEM)
 * @param {string} input.nonce - expected qualifying data (hex)
 * @param {Object<string, Object<string,string>>} [input.expectedPcrs] - bank -> index -> hex that must match
 * @returns {{valid: boolean, errors: string[], attest?: Object, pcrs?: Object}}
 */
function verifyQuote({quote, publicKey, nonce, expectedPcrs}) {
  const errors = [];
  let attest;
  try {
    const message = Buffer.from(quote.message, 'base64');
    const signature = Buffer.from(quote.signature, 'base64');
    const hashAlg = quote.hashAlg || 'sha256';
    // The quote says which hash it was signed with; SHA-1 is not accepted.
    if (!Object.hasOwn(HASH_SIZES, hashAlg) || hashAlg === 'sha1') {
      throw new Error(`Unsupported signature hash ${hashAlg}`);
    }

    if (typeof nonce !== 'string' || !/^(?:[\da-fA-F]{2}){1,64}$/.test(nonce)) {
      throw new Error('A nonce (hex) is required to verify a quote');
    }

    const key = crypto.createPublicKey(publicKey);
    // Tpm2-tools' "plain" format is PKCS#1 v1.5 for RSA and DER for ECDSA.
    const signatureOk = crypto.verify(hashAlg, message, key, signature);
    if (!signatureOk) {
      errors.push('Quote signature does not verify with the trusted attestation key');
    }

    attest = parseAttest(message);
    if (attest.extraData !== String(nonce).toLowerCase()) {
      errors.push('Quote nonce does not match (stale or replayed quote)');
    }

    // Recompute the PCR digest from the reported values.
    const reported = quote.pcrs || {};
    const concatenated = [];
    for (const selection of attest.selections) {
      if (!Object.hasOwn(HASH_SIZES, selection.bank)) {
        errors.push(`Unsupported PCR bank in quote: ${selection.bank}`);
        continue;
      }

      for (const pcr of selection.pcrs) {
        const value = reported[selection.bank] && reported[selection.bank][String(pcr)];
        // Lowercase hex only: one encoding per value (Buffer.from would
        // silently stop at the first character that is not hex).
        if (typeof value !== 'string' || value.length !== HASH_SIZES[selection.bank] * 2 || !/^[\da-f]+$/.test(value)) {
          errors.push(`Missing or malformed value for PCR ${selection.bank}:${pcr}`);
          continue;
        }

        concatenated.push(Buffer.from(value, 'hex'));
      }
    }

    // Values the quote does not cover must not be reported alongside it,
    // nor under a second name ("010" beside "10").
    for (const [bank, values] of Object.entries(reported)) {
      const selected = attest.selections.find(selection => selection.bank === bank);
      for (const index of Object.keys(values || {})) {
        if (!selected || !selected.pcrs.includes(Number(index)) || String(Number(index)) !== index) {
          errors.push(`PCR ${bank}:${index} was reported but not quoted`);
        }
      }
    }

    const digest = crypto.createHash(hashAlg).update(Buffer.concat(concatenated)).digest('hex');
    if (digest !== attest.pcrDigest) {
      errors.push('Reported PCR values do not match the signed PCR digest');
    }

    for (const [bank, values] of Object.entries(expectedPcrs || {})) {
      const selected = attest.selections.find(selection => selection.bank === bank);
      for (const [index, expected] of Object.entries(values)) {
        if (!selected || !selected.pcrs.includes(Number(index))) {
          errors.push(`PCR ${bank}:${index} was not quoted`);
        } else if (reported[bank][String(Number(index))] !== String(expected).toLowerCase().replace(/^0x/, '')) {
          errors.push(`PCR ${bank}:${index} differs from the expected value`);
        }
      }
    }
  } catch (error) {
    errors.push(error.message);
  }

  return {
    valid: errors.length === 0, errors, attest, pcrs: quote && quote.pcrs,
  };
}

class Tpm {
  /**
   * @param {Object} [options]
   * @param {string} [options.tcti] - TCTI string (e.g. "device:/dev/tpmrm0", "swtpm:port=2321")
   * @param {string} [options.akHandle='0x81010002'] - persistent AK handle
   * @param {number} [options.timeout=30000]
   * @param {Function} [options.run] - (file, args, execOptions) => Promise<stdout>
   * @param {string[]} [options.devices] - device nodes checked when no TCTI is set
   */
  constructor(options = {}) {
    this.tcti = options.tcti || null;
    this.akHandle = normalizeHandle(options.akHandle || '0x81010002');
    this.timeout = options.timeout ?? 30_000;
    this.run = options.run || defaultRun;
    this.devices = options.devices || ['/dev/tpmrm0', '/dev/tpm0'];
  }

  _env() {
    const env = {...process.env};
    if (this.tcti) {
      env.TPM2TOOLS_TCTI = this.tcti;
    }

    return env;
  }

  _tool(name, args, options = {}) {
    return this.run(name, args, {env: this._env(), timeout: this.timeout, cwd: options.cwd});
  }

  async _withTemporaryDirectory(callback) {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'attestium-tpm-'));
    try {
      return await callback(directory);
    } finally {
      await fs.promises.rm(directory, {recursive: true, force: true});
    }
  }

  /**
   * Whether a TPM 2.0 is reachable with tpm2-tools.
   * @returns {Promise<{available: boolean, reason?: string}>}
   */
  async checkAvailability() {
    if (!this.tcti && !this.devices.some(device => exists(device))) {
      return {available: false, reason: 'No TPM device node present'};
    }

    try {
      const output = await this._tool('tpm2_getcap', ['properties-fixed']);
      const family = output.match(/TPM2_PT_FAMILY_INDICATOR:[\s\S]*?value:\s*"([^"]+)"/);
      return {available: true, family: family ? family[1] : null};
    } catch (error) {
      return {available: false, reason: error.code === 'ENOENT' ? 'tpm2-tools not installed' : error.message};
    }
  }

  /**
   * @returns {Promise<boolean>}
   */
  async isAvailable() {
    return (await this.checkAvailability()).available;
  }

  /**
   * Read the public part of the persistent AK.
   * @param {string} [handle]
   * @returns {Promise<{handle: string, publicKey: string, keyId: string}>}
   */
  async getAttestationKey(handle = this.akHandle) {
    handle = normalizeHandle(handle);
    return this._withTemporaryDirectory(async directory => {
      const file = path.join(directory, 'ak.pem');
      await this._tool('tpm2_readpublic', ['-c', handle, '-f', 'pem', '-o', file]);
      const publicKey = await fs.promises.readFile(file, 'utf8');
      return {
        handle,
        publicKey,
        keyId: sha256(crypto.createPublicKey(publicKey).export({type: 'spki', format: 'der'})),
      };
    });
  }

  /**
   * Create an AK under the EK and make it persistent.  Run once per machine
   * (enrollment); publish the returned public key so verifiers can pin it.
   *
   * @param {Object} [options]
   * @param {string} [options.handle]
   * @param {string} [options.algorithm='rsa'] - 'rsa' or 'ecc'
   * @param {boolean} [options.replace=false] - evict an existing key at the handle first
   * @returns {Promise<{handle: string, publicKey: string, keyId: string}>}
   */
  async createAttestationKey(options = {}) {
    const handle = normalizeHandle(options.handle || this.akHandle);
    const algorithm = options.algorithm || 'rsa';
    if (algorithm !== 'rsa' && algorithm !== 'ecc') {
      throw new TypeError(`Unsupported AK algorithm: ${algorithm}`);
    }

    let exists = true;
    try {
      await this.getAttestationKey(handle);
    } catch {
      exists = false;
    }

    if (exists && !options.replace) {
      throw new Error(`A key already exists at ${handle}; pass {replace: true} to replace it`);
    }

    await this._withTemporaryDirectory(async directory => {
      if (exists) {
        await this._tool('tpm2_evictcontrol', ['-C', 'o', '-c', handle]);
      }

      const file = name => path.join(directory, name);
      await this._tool('tpm2_createek', ['-c', file('ek.ctx'), '-G', algorithm, '-u', file('ek.pub')]);
      await this._flushTransient();
      await this._tool('tpm2_createak', [
        '-C',
        file('ek.ctx'),
        '-c',
        file('ak.ctx'),
        '-G',
        algorithm,
        '-g',
        'sha256',
        '-s',
        algorithm === 'rsa' ? 'rsassa' : 'ecdsa',
        '-u',
        file('ak.pub'),
        '-n',
        file('ak.name'),
      ]);
      await this._flushTransient();
      await this._tool('tpm2_evictcontrol', ['-C', 'o', '-c', file('ak.ctx'), handle]);
      await this._flushTransient();
    });

    return this.getAttestationKey(handle);
  }

  async _flushTransient() {
    // Without a resource manager (e.g. a raw device or simulator) transient
    // objects and sessions accumulate; flushing is harmless with one.
    for (const flag of ['-t', '-s']) {
      try {
        await this._tool('tpm2_flushcontext', [flag]);
      } catch {}
    }
  }

  /**
   * The AK's public area (TPM2B_PUBLIC), for enrollment: the verifier
   * checks its attributes and computes its name from it.
   * @param {string} [handle]
   * @returns {Promise<string>} base64
   */
  async getAttestationKeyPublicArea(handle = this.akHandle) {
    handle = normalizeHandle(handle);
    return this._withTemporaryDirectory(async directory => {
      const file = path.join(directory, 'ak.tpm2b');
      await this._tool('tpm2_readpublic', ['-c', handle, '-f', 'tss', '-o', file]);
      return (await fs.promises.readFile(file)).toString('base64');
    });
  }

  /**
   * The endorsement key's public area and, when the manufacturer stored one,
   * its certificate.
   *
   * @param {Object} [options]
   * @param {string} [options.algorithm='rsa'] - 'rsa' or 'ecc' (default templates)
   * @returns {Promise<{algorithm: string, publicArea: string, certificate: string|null}>} base64 fields
   */
  async getEndorsement(options = {}) {
    const algorithm = options.algorithm || 'rsa';
    if (algorithm !== 'rsa' && algorithm !== 'ecc') {
      throw new TypeError(`Unsupported EK algorithm: ${algorithm}`);
    }

    return this._withTemporaryDirectory(async directory => {
      const file = name => path.join(directory, name);
      await this._tool('tpm2_createek', ['-c', file('ek.ctx'), '-G', algorithm, '-u', file('ek.pub'), '-f', 'tss']);
      await this._flushTransient();
      let certificate = null;
      // Low-range indexes: RSA 2048 and ECC P-256 EK certificates (TCG).
      try {
        await this._tool('tpm2_nvread', [algorithm === 'rsa' ? '0x1c00002' : '0x1c0000a', '-C', 'o', '-o', file('ek.crt')]);
        const raw = await fs.promises.readFile(file('ek.crt'));
        // The NV area may be larger than the certificate.
        const {parseElement} = require('./asn1');
        certificate = raw.subarray(0, parseElement(raw).end).toString('base64');
      } catch {}

      return {algorithm, publicArea: (await fs.promises.readFile(file('ek.pub'))).toString('base64'), certificate};
    });
  }

  /**
   * ActivateCredential: recover the secret a verifier encrypted to this
   * TPM's EK for the AK (see ./tpm-identity makeCredential).
   *
   * @param {Object} options
   * @param {string} options.credential - base64 (tpm2-tools credential file)
   * @param {string} [options.algorithm='rsa'] - the EK the credential was made for
   * @param {string} [options.handle] - the AK
   * @returns {Promise<string>} the secret, base64
   */
  async activateCredential({credential, algorithm = 'rsa', handle}) {
    handle = normalizeHandle(handle || this.akHandle);
    const blob = Buffer.from(String(credential), 'base64');
    if (blob.length < 12 || blob.length > 4096 || blob.readUInt32BE(0) !== 0xBA_DC_C0_DE) {
      throw new TypeError('Not a credential blob');
    }

    return this._withTemporaryDirectory(async directory => {
      const file = name => path.join(directory, name);
      await fs.promises.writeFile(file('credential'), blob);
      await this._tool('tpm2_createek', ['-c', file('ek.ctx'), '-G', algorithm === 'ecc' ? 'ecc' : 'rsa', '-u', file('ek.pub')]);
      // The EK's default policy: PolicySecret with the endorsement hierarchy.
      await this._tool('tpm2_startauthsession', ['--policy-session', '-S', file('session.ctx')]);
      try {
        await this._tool('tpm2_policysecret', ['-S', file('session.ctx'), '-c', 'e']);
        await this._tool('tpm2_activatecredential', ['-c', handle, '-C', file('ek.ctx'), '-i', file('credential'), '-o', file('secret'), '-P', `session:${file('session.ctx')}`]);
      } finally {
        try {
          await this._tool('tpm2_flushcontext', [file('session.ctx')]);
        } catch {}

        await this._flushTransient();
      }

      return (await fs.promises.readFile(file('secret'))).toString('base64');
    });
  }

  /**
   * Produce a quote over PCR values, qualified by a nonce.
   *
   * @param {Object} options
   * @param {string} options.nonce - hex, at most 32 bytes (hash it first if longer)
   * @param {number[]} [options.pcrs=[0,1,2,3,4,5,6,7]]
   * @param {string} [options.bank='sha256']
   * @param {string} [options.handle]
   * @returns {Promise<{keyId: string, handle: string, hashAlg: string, message: string, signature: string, pcrs: Object}>}
   */
  async quote({nonce, pcrs = [0, 1, 2, 3, 4, 5, 6, 7], bank = 'sha256', handle}) {
    if (typeof nonce !== 'string' || !/^(?:[\da-fA-F]{2}){1,32}$/.test(nonce)) {
      throw new TypeError('Quote nonce must be 1 to 32 bytes of hex');
    }

    const list = normalizePcrList(pcrs);
    bank = normalizeBank(bank);
    handle = normalizeHandle(handle || this.akHandle);
    const key = await this.getAttestationKey(handle);
    return this._withTemporaryDirectory(async directory => {
      const file = name => path.join(directory, name);
      const output = await this._tool('tpm2_quote', [
        '-c',
        handle,
        '-l',
        `${bank}:${list.join(',')}`,
        '-q',
        nonce.toLowerCase(),
        '-m',
        file('quote.msg'),
        '-s',
        file('quote.sig'),
        '-o',
        file('quote.pcrs'),
        '-g',
        'sha256',
        '-f',
        'plain',
      ]);
      await this._flushTransient();
      return {
        keyId: key.keyId,
        handle,
        hashAlg: 'sha256',
        message: (await fs.promises.readFile(file('quote.msg'))).toString('base64'),
        signature: (await fs.promises.readFile(file('quote.sig'))).toString('base64'),
        pcrs: parsePcrYaml(output),
      };
    });
  }

  /**
   * Read PCR values.
   * @param {number[]} [pcrs]
   * @param {string} [bank='sha256']
   * @returns {Promise<Object<string,string>>} index -> hex
   */
  async readPcrs(pcrs = [0, 1, 2, 3, 4, 5, 6, 7], bank = 'sha256') {
    const list = normalizePcrList(pcrs);
    bank = normalizeBank(bank);
    const output = await this._tool('tpm2_pcrread', [`${bank}:${list.join(',')}`]);
    return parsePcrYaml(output)[bank] || {};
  }

  /**
   * Extend a PCR (for application-level measurements, e.g. PCR 23).
   * @param {number} pcr
   * @param {string} bank
   * @param {string} digest - hex, length of the bank's hash
   */
  async extendPcr(pcr, bank, digest) {
    const [index] = normalizePcrList([pcr]);
    bank = normalizeBank(bank);
    if (typeof digest !== 'string' || !new RegExp(`^[\\da-fA-F]{${HASH_SIZES[bank] * 2}}$`).test(digest)) {
      throw new TypeError(`Digest must be ${HASH_SIZES[bank]} bytes of hex for ${bank}`);
    }

    await this._tool('tpm2_pcrextend', [`${index}:${bank}=${digest.toLowerCase()}`]);
  }

  /**
   * Random bytes from the TPM's generator.
   * @param {number} [length=32]
   * @returns {Promise<Buffer>}
   */
  async getRandom(length = 32) {
    if (!Number.isInteger(length) || length < 1 || length > 64) {
      throw new TypeError('Length must be an integer between 1 and 64');
    }

    const output = await this._tool('tpm2_getrandom', ['--hex', String(length)]);
    const bytes = Buffer.from(output.trim(), 'hex');
    if (bytes.length !== length) {
      throw new Error('tpm2_getrandom returned the wrong number of bytes');
    }

    return bytes;
  }
}

Tpm.verifyQuote = verifyQuote;
Tpm.parseAttest = parseAttest;
Tpm.parsePcrYaml = parsePcrYaml;
Tpm.HASH_SIZES = HASH_SIZES;

module.exports = Tpm;

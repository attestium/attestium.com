/**
 * Attestium - TPM identity: endorsement key certificates and credential
 * activation (verifier side, pure Node.js)
 *
 * A pinned attestation key (AK) says "this is the same TPM as before".
 * Enrollment with the endorsement key (EK) says "this is a real TPM from a
 * known manufacturer (or cloud provider), and the AK lives in it":
 *
 *   1. the EK certificate, stored in the TPM by its manufacturer, must chain
 *      to a trusted manufacturer CA, and certify the TPM's EK public key
 *   2. the AK's public area must describe a restricted signing key that
 *      cannot leave the TPM (fixedTPM, fixedParent, sensitiveDataOrigin)
 *   3. MakeCredential encrypts a random secret to the EK, bound to the AK's
 *      name; only that TPM, holding that AK, can decrypt it with
 *      ActivateCredential.  Getting the secret back proves both.
 *
 * Supports the default EK templates: RSA 2048 and ECC NIST P-256, with
 * SHA-256 and AES-128-CFB.
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const asn1 = require('./asn1');

const TPM_ALG = {
  RSA: 0x00_01, SHA256: 0x00_0B, NULL: 0x00_10, ECC: 0x00_23, AES: 0x00_06, CFB: 0x00_43,
};
const ATTRIBUTE = {
  fixedTPM: 1 << 1, fixedParent: 1 << 4, sensitiveDataOrigin: 1 << 5, userWithAuth: 1 << 6, restricted: 1 << 16, decrypt: 1 << 17, sign: 1 << 18,
};
const CURVES = {0x00_03: {name: 'prime256v1', size: 32, oid: '2a8648ce3d030107'}};

/**
 * Parse a TPM2B_PUBLIC (as tpm2_readpublic -o writes it, and as
 * tpm2_createek -u writes it).
 *
 * @param {Buffer} buffer
 * @returns {{type: string, nameAlg: number, attributes: number, key: crypto.KeyObject, name: Buffer, symmetric: {algorithm: number, keyBits: number, mode: number}|null, curve: number|null, raw: Buffer}}
 */
function parseTpmPublic(buffer) {
  let offset = 0;
  const need = count => {
    if (offset + count > buffer.length) {
      throw new Error('Truncated TPM2B_PUBLIC');
    }
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

  const sized = () => {
    const size = u16();
    need(size);
    const value = buffer.subarray(offset, offset + size);
    offset += size;
    return value;
  };

  const size = u16();
  if (size + 2 !== buffer.length) {
    throw new Error('TPM2B_PUBLIC size does not match');
  }

  const start = offset;
  const type = u16();
  const nameAlg = u16();
  const attributes = u32();
  sized(); // AuthPolicy
  const symmetricAlgorithm = u16();
  let symmetric = null;
  if (symmetricAlgorithm !== TPM_ALG.NULL) {
    symmetric = {algorithm: symmetricAlgorithm, keyBits: u16(), mode: u16()};
  }

  const scheme = u16();
  if (scheme !== TPM_ALG.NULL) {
    u16();
  }

  let key;
  let curve = null;
  if (type === TPM_ALG.RSA) {
    const bits = u16();
    const exponent = u32() || 65_537;
    const modulus = sized();
    if (modulus.length * 8 !== bits) {
      throw new Error('RSA modulus size does not match');
    }

    key = crypto.createPublicKey({
      key: {
        kty: 'RSA', n: modulus.toString('base64url'), e: Buffer.from(exponent.toString(16).padStart(8, '0'), 'hex').toString('base64url'),
      },
      format: 'jwk',
    });
  } else if (type === TPM_ALG.ECC) {
    curve = u16();
    const kdf = u16();
    if (kdf !== TPM_ALG.NULL) {
      u16();
    }

    const x = sized();
    const y = sized();
    const info = CURVES[curve];
    if (!info) {
      throw new Error(`Unsupported ECC curve 0x${curve.toString(16)}`);
    }

    key = crypto.createPublicKey({
      key: {
        kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url'),
      },
      format: 'jwk',
    });
  } else {
    throw new Error(`Unsupported TPM key type 0x${type.toString(16)}`);
  }

  if (offset !== buffer.length) {
    throw new Error('Trailing data after TPMT_PUBLIC');
  }

  if (nameAlg !== TPM_ALG.SHA256) {
    throw new Error('Only SHA-256 name algorithms are supported');
  }

  const publicArea = buffer.subarray(start);
  const name = Buffer.concat([Buffer.from([0x00, 0x0B]), crypto.createHash('sha256').update(publicArea).digest()]);
  return {
    type: type === TPM_ALG.RSA ? 'rsa' : 'ecc', nameAlg, attributes, key, name, symmetric, curve, raw: buffer,
  };
}

/**
 * Whether a public area describes an attestation key: a restricted signing
 * key created in, and unable to leave, the TPM.
 * @param {Object} parsed - from parseTpmPublic
 * @returns {string[]} problems (empty when it is one)
 */
function attestationKeyProblems(parsed) {
  const problems = [];
  for (const name of ['fixedTPM', 'fixedParent', 'sensitiveDataOrigin', 'restricted', 'sign']) {
    if ((parsed.attributes & ATTRIBUTE[name]) === 0) {
      problems.push(`${name} is not set`);
    }
  }

  if (parsed.attributes & ATTRIBUTE.decrypt) {
    problems.push('decrypt is set');
  }

  return problems;
}

/**
 * TPM key derivation function KDFa (SP 800-108 counter mode, HMAC-SHA256).
 */
function kdfa(key, label, contextU, contextV, bits) {
  const blocks = [];
  let produced = 0;
  for (let counter = 1; produced < bits / 8; counter++) {
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    const bitsBytes = Buffer.alloc(4);
    bitsBytes.writeUInt32BE(bits);
    const block = crypto.createHmac('sha256', key).update(counterBytes).update(Buffer.from(`${label}\0`, 'latin1')).update(contextU).update(contextV).update(bitsBytes).digest();
    blocks.push(block);
    produced += block.length;
  }

  return Buffer.concat(blocks).subarray(0, bits / 8);
}

/**
 * TPM key derivation function KDFe (SP 800-56A, SHA-256), for ECC seeds.
 */
function kdfe(z, label, partyU, partyV, bits) {
  const blocks = [];
  let produced = 0;
  for (let counter = 1; produced < bits / 8; counter++) {
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    const block = crypto.createHash('sha256').update(counterBytes).update(z).update(Buffer.from(`${label}\0`, 'latin1')).update(partyU).update(partyV).digest();
    blocks.push(block);
    produced += block.length;
  }

  return Buffer.concat(blocks).subarray(0, bits / 8);
}

const sized = data => {
  const size = Buffer.alloc(2);
  size.writeUInt16BE(data.length);
  return Buffer.concat([size, data]);
};

/**
 * MakeCredential: a secret only the TPM holding `ek` can recover, and only
 * for the object named `akName`.  Returns the file tpm2_activatecredential
 * reads (-i).
 *
 * @param {Object} input
 * @param {Object} input.ek - from parseTpmPublic (the TPM's EK)
 * @param {Buffer} input.akName
 * @param {Buffer} input.secret - up to 32 bytes
 * @returns {Buffer}
 */
function makeCredential({ek, akName, secret}) {
  if (!ek.symmetric || ek.symmetric.algorithm !== TPM_ALG.AES || ek.symmetric.keyBits !== 128 || ek.symmetric.mode !== TPM_ALG.CFB) {
    throw new Error('Only EKs with AES-128-CFB are supported');
  }

  if (secret.length > 32) {
    throw new Error('The secret is at most 32 bytes');
  }

  let seed;
  let encryptedSecret;
  if (ek.type === 'rsa') {
    seed = crypto.randomBytes(32);
    encryptedSecret = crypto.publicEncrypt({
      key: ek.key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from('IDENTITY\0', 'latin1'),
    }, seed);
  } else {
    const ephemeral = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const z = crypto.diffieHellman({privateKey: ephemeral.privateKey, publicKey: ek.key});
    const ephemeralJwk = ephemeral.publicKey.export({format: 'jwk'});
    const ekJwk = ek.key.export({format: 'jwk'});
    const ephemeralX = Buffer.from(ephemeralJwk.x, 'base64url');
    seed = kdfe(z, 'IDENTITY', ephemeralX, Buffer.from(ekJwk.x, 'base64url'), 256);
    encryptedSecret = Buffer.concat([sized(ephemeralX), sized(Buffer.from(ephemeralJwk.y, 'base64url'))]);
  }

  const symmetricKey = kdfa(seed, 'STORAGE', akName, Buffer.alloc(0), 128);
  const hmacKey = kdfa(seed, 'INTEGRITY', Buffer.alloc(0), Buffer.alloc(0), 256);
  const cipher = crypto.createCipheriv('aes-128-cfb', symmetricKey, Buffer.alloc(16));
  const encryptedIdentity = Buffer.concat([cipher.update(sized(secret)), cipher.final()]);
  const integrity = crypto.createHmac('sha256', hmacKey).update(encryptedIdentity).update(akName).digest();
  const idObject = sized(Buffer.concat([sized(integrity), encryptedIdentity]));
  const header = Buffer.alloc(8);
  header.writeUInt32BE(0xBA_DC_C0_DE, 0);
  header.writeUInt32BE(1, 4);
  return Buffer.concat([header, idObject, sized(encryptedSecret)]);
}

/**
 * Whether a certificate may issue certificates: basicConstraints cA, and
 * keyCertSign when it has a keyUsage extension (RFC 5280, 4.2.1.3, 4.2.1.9).
 *
 * @param {crypto.X509Certificate} certificate
 * @returns {boolean}
 */
function isCertificateAuthority(certificate) {
  if (!certificate.ca) {
    return false;
  }

  const keyUsage = asn1.certificateExtensions(certificate.raw).get('2.5.29.15');
  if (!keyUsage) {
    return true;
  }

  // A BIT STRING: the count of unused bits, then bit 0 (digitalSignature)
  // as the high bit of the first byte; keyCertSign is bit 5.
  const bits = asn1.content(asn1.parse(keyUsage.value));
  return bits.length > 1 && (bits[1] & 0x04) !== 0;
}

/**
 * Verify an EK certificate chain and that it certifies `ekKey`.  Every
 * intermediate must be a CA allowed to sign certificates.
 *
 * @param {Object} input
 * @param {Buffer} input.certificate - DER
 * @param {crypto.KeyObject} input.ekKey
 * @param {crypto.X509Certificate[]} input.roots - trusted manufacturer CAs
 * @param {crypto.X509Certificate[]} [input.intermediates]
 * @returns {{subject: string, issuer: string, chain: string[]}}
 */
function verifyEkCertificate({certificate, ekKey, roots, intermediates = []}) {
  const leaf = new crypto.X509Certificate(certificate);
  const leafKey = leaf.publicKey.export({type: 'spki', format: 'der'});
  if (!leafKey.equals(ekKey.export({type: 'spki', format: 'der'}))) {
    throw new Error('The EK certificate is for a different key than the TPM\'s EK');
  }

  const now = Date.now();
  const chain = [leaf];
  let current = leaf;
  for (let depth = 0; depth < 8; depth++) {
    const root = roots.find(candidate => current.checkIssued(candidate) && current.verify(candidate.publicKey));
    if (root) {
      chain.push(root);
      for (const link of chain.slice(1)) {
        if (now < Date.parse(link.validFrom) || now > Date.parse(link.validTo)) {
          throw new Error(`A CA certificate in the EK chain is not currently valid: ${link.subject.split('\n').join(', ')}`);
        }
      }

      // EK certificates often carry no usable validity; only the CAs are checked.
      return {subject: leaf.subject, issuer: leaf.issuer, chain: chain.map(link => link.subject.split('\n').join(', '))};
    }

    const parent = intermediates.find(candidate => isCertificateAuthority(candidate) && current.checkIssued(candidate) && current.verify(candidate.publicKey));
    if (!parent || chain.includes(parent)) {
      break;
    }

    chain.push(parent);
    current = parent;
  }

  throw new Error('The EK certificate does not chain to a trusted TPM manufacturer CA');
}

module.exports = {
  parseTpmPublic,
  attestationKeyProblems,
  makeCredential,
  verifyEkCertificate,
  isCertificateAuthority,
  kdfa,
  kdfe,
  ATTRIBUTE,
};

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const identity = require('../lib/tpm-identity');
const {tempDir, hasOpenssl} = require('./helpers');

const ALG = {
  RSA: 0x00_01, SHA1: 0x00_04, SHA256: 0x00_0B, NULL: 0x00_10, ECC: 0x00_23, AES: 0x00_06, CFB: 0x00_43, RSASSA: 0x00_14, KDF1: 0x00_20,
};
const {ATTRIBUTE} = identity;
const AK_ATTRIBUTES = ATTRIBUTE.fixedTPM | ATTRIBUTE.fixedParent | ATTRIBUTE.sensitiveDataOrigin | ATTRIBUTE.userWithAuth | ATTRIBUTE.restricted | ATTRIBUTE.sign;
const EK_ATTRIBUTES = ATTRIBUTE.fixedTPM | ATTRIBUTE.fixedParent | ATTRIBUTE.sensitiveDataOrigin | ATTRIBUTE.restricted | ATTRIBUTE.decrypt;

const u16 = value => {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
};

const u32 = value => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
};

const sized = data => Buffer.concat([u16(data.length), data]);

/**
 * A TPM2B_PUBLIC in the TPM's wire format.
 */
function publicArea({
  type = 'rsa', nameAlg = ALG.SHA256, attributes = EK_ATTRIBUTES, symmetric = [ALG.AES, 128, ALG.CFB], scheme = null, key, curve = 0x00_03, kdf = null, trailing = Buffer.alloc(0), size = null,
}) {
  const typeId = {rsa: ALG.RSA, ecc: ALG.ECC}[type] ?? type;
  const parts = [
    u16(typeId),
    u16(nameAlg),
    u32(attributes),
    sized(Buffer.alloc(32)),
    symmetric ? Buffer.concat(symmetric.map(value => u16(value))) : u16(ALG.NULL),
    scheme ? Buffer.concat([u16(scheme[0]), u16(scheme[1])]) : u16(ALG.NULL),
  ];
  const jwk = key.export({format: 'jwk'});
  if (type === 'rsa') {
    const modulus = Buffer.from(jwk.n, 'base64url');
    const exponent = Number.parseInt(Buffer.from(jwk.e, 'base64url').toString('hex'), 16);
    parts.push(u16(modulus.length * 8), u32(exponent === 65_537 ? 0 : exponent), sized(modulus));
  } else if (type === 'ecc') {
    parts.push(u16(curve), kdf ? Buffer.concat([u16(kdf[0]), u16(kdf[1])]) : u16(ALG.NULL), sized(Buffer.from(jwk.x, 'base64url')), sized(Buffer.from(jwk.y, 'base64url')));
  }

  const body = Buffer.concat([...parts, trailing]);
  return Buffer.concat([u16(size ?? body.length), body]);
}

const rsaKey = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const eccKey = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
const spki = key => key.export({type: 'spki', format: 'der'});

test('kdfa and kdfe: known answers (OpenSSL KBKDF counter mode and SSKDF)', () => {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const none = Buffer.alloc(0);
  assert.equal(identity.kdfa(key, 'STORAGE', Buffer.from('000b', 'hex'), Buffer.from('0102', 'hex'), 128).toString('hex'), 'a889755b2f86d140a821afc0272ab93b');
  // More than one HMAC block, truncated to the requested size.
  assert.equal(identity.kdfa(key, 'INTEGRITY', none, none, 520).toString('hex'), '7dafa373893777b31b17cb30ce771741db80d9f34b47ee8ad27ab3931d0ebbadb81d2a665e2458fa1add33fe132072316e02d6a9bc5ea325914c9b42fae8eda9e3');
  assert.equal(identity.kdfe(key, 'IDENTITY', Buffer.from('aabb', 'hex'), Buffer.from('ccdd', 'hex'), 256).toString('hex'), '2f3c20005613f7c41bc27f110dac6074bb8054bb79ddf228ab2ccfb5cb86ed27');
  assert.equal(identity.kdfe(key, 'IDENTITY', Buffer.from('aabb', 'hex'), Buffer.from('ccdd', 'hex'), 384).toString('hex'), '2f3c20005613f7c41bc27f110dac6074bb8054bb79ddf228ab2ccfb5cb86ed27d9c99d80426dbe98623a6d7a3765aba3');
});

test('parseTpmPublic: RSA and ECC keys, names and symmetric parameters', () => {
  const rsaArea = publicArea({type: 'rsa', key: rsaKey.publicKey});
  const rsa = identity.parseTpmPublic(rsaArea);
  assert.equal(rsa.type, 'rsa');
  assert.equal(rsa.nameAlg, ALG.SHA256);
  assert.deepEqual(rsa.symmetric, {algorithm: ALG.AES, keyBits: 128, mode: ALG.CFB});
  assert.equal(rsa.curve, null);
  assert.ok(spki(rsa.key).equals(spki(rsaKey.publicKey)));
  assert.deepEqual(rsa.name, Buffer.concat([u16(ALG.SHA256), crypto.createHash('sha256').update(rsaArea.subarray(2)).digest()]));
  assert.equal(rsa.raw, rsaArea);

  // A signing key: no symmetric algorithm, a scheme, and a non-default exponent.
  const signing = crypto.generateKeyPairSync('rsa', {modulusLength: 1024, publicExponent: 0x1_00_00_01});
  const parsed = identity.parseTpmPublic(publicArea({
    type: 'rsa', key: signing.publicKey, symmetric: null, scheme: [ALG.RSASSA, ALG.SHA256], attributes: AK_ATTRIBUTES,
  }));
  assert.equal(parsed.symmetric, null);
  assert.ok(spki(parsed.key).equals(spki(signing.publicKey)));
  assert.equal(parsed.key.export({format: 'jwk'}).e, 'AQAAAQ');

  const ecc = identity.parseTpmPublic(publicArea({type: 'ecc', key: eccKey.publicKey, kdf: [ALG.KDF1, ALG.SHA256]}));
  assert.equal(ecc.type, 'ecc');
  assert.equal(ecc.curve, 3);
  assert.ok(spki(ecc.key).equals(spki(eccKey.publicKey)));
});

test('parseTpmPublic: malformed and unsupported public areas', () => {
  const rsaArea = publicArea({type: 'rsa', key: rsaKey.publicKey});
  assert.throws(() => identity.parseTpmPublic(Buffer.alloc(1)), /Truncated TPM2B_PUBLIC/);
  assert.throws(() => identity.parseTpmPublic(rsaArea.subarray(0, 100)), /size does not match/);
  assert.throws(() => identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey, size: 20}).subarray(0, 22)), /Truncated TPM2B_PUBLIC/);
  assert.throws(() => identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey, trailing: Buffer.from([0])})), /Trailing data/);
  assert.throws(() => identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey, nameAlg: ALG.SHA1})), /Only SHA-256 name algorithms/);
  assert.throws(() => identity.parseTpmPublic(publicArea({type: 'ecc', key: eccKey.publicKey, curve: 0x00_04})), /Unsupported ECC curve 0x4/);
  assert.throws(() => identity.parseTpmPublic(publicArea({type: 0x00_08, key: rsaKey.publicKey})), /Unsupported TPM key type 0x8/);

  // A modulus that is not the declared size.
  const bad = Buffer.from(rsaArea);
  const bitsOffset = 2 + 2 + 2 + 4 + 34 + 6 + 2;
  bad.writeUInt16BE(1024, bitsOffset);
  assert.throws(() => identity.parseTpmPublic(bad), /RSA modulus size does not match/);
});

test('attestationKeyProblems: a restricted signing key that cannot leave the TPM', () => {
  const ak = identity.parseTpmPublic(publicArea({
    type: 'ecc', key: eccKey.publicKey, symmetric: null, attributes: AK_ATTRIBUTES,
  }));
  assert.deepEqual(identity.attestationKeyProblems(ak), []);
  const ek = identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey}));
  assert.deepEqual(identity.attestationKeyProblems(ek), ['sign is not set', 'decrypt is set']);
  assert.deepEqual(identity.attestationKeyProblems({attributes: 0}), [
    'fixedTPM is not set', 'fixedParent is not set', 'sensitiveDataOrigin is not set', 'restricted is not set', 'sign is not set',
  ]);
});

test('makeCredential: the tpm2-tools credential format, and unsupported EKs', () => {
  const ek = identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey}));
  const akName = Buffer.concat([u16(ALG.SHA256), crypto.randomBytes(32)]);
  const blob = identity.makeCredential({ek, akName, secret: Buffer.alloc(32, 7)});
  assert.equal(blob.readUInt32BE(0), 0xBA_DC_C0_DE);
  assert.equal(blob.readUInt32BE(4), 1);
  // IdObject: integrity HMAC and the encrypted secret, then the encrypted seed.
  const idObjectSize = blob.readUInt16BE(8);
  assert.equal(idObjectSize, 2 + 32 + 2 + 32);
  const seed = blob.subarray(10 + idObjectSize + 2);
  assert.equal(blob.readUInt16BE(10 + idObjectSize), 256);
  const decrypted = crypto.privateDecrypt({
    key: rsaKey.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from('IDENTITY\0', 'latin1'),
  }, seed);
  assert.equal(decrypted.length, 32);

  // ECC: the seed is an ephemeral point.
  const eccEk = identity.parseTpmPublic(publicArea({type: 'ecc', key: eccKey.publicKey}));
  const eccBlob = identity.makeCredential({ek: eccEk, akName, secret: Buffer.from('secret')});
  const eccSeed = eccBlob.subarray(10 + eccBlob.readUInt16BE(8));
  assert.equal(eccSeed.readUInt16BE(0), 2 + 32 + 2 + 32);

  assert.throws(() => identity.makeCredential({ek: identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey, symmetric: null})), akName, secret: Buffer.alloc(1)}), /Only EKs with AES-128-CFB/);
  for (const symmetric of [[0x00_25, 128, ALG.CFB], [ALG.AES, 256, ALG.CFB], [ALG.AES, 128, 0x00_44]]) {
    assert.throws(() => identity.makeCredential({ek: identity.parseTpmPublic(publicArea({type: 'rsa', key: rsaKey.publicKey, symmetric})), akName, secret: Buffer.alloc(1)}), /Only EKs with AES-128-CFB/);
  }

  assert.throws(() => identity.makeCredential({ek, akName, secret: Buffer.alloc(33)}), /at most 32 bytes/);
});

/**
 * A manufacturer CA, an intermediate CA and an EK certificate, made with
 * OpenSSL.  With `expired`, the root's validity ended long ago.
 */
function makeCa(t, {expired = false} = {}) {
  const cwd = tempDir(t, 'attestium-ekca-');
  const openssl = args => execFileSync('openssl', args, {cwd, stdio: ['ignore', 'pipe', 'pipe']});
  for (const name of ['root', 'intermediate', 'ek']) {
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`]);
    openssl(['req', '-new', '-key', `${name}.key`, '-subj', `/CN=${expired ? 'expired ' : ''}${name}`, '-out', `${name}.csr`]);
  }

  fs.writeFileSync(path.join(cwd, 'ca.ext'), 'basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n');
  if (expired) {
    fs.writeFileSync(path.join(cwd, 'ca.cnf'), '[ca]\ndefault_ca = d\n[d]\ndatabase = index.txt\nnew_certs_dir = .\nserial = serial\ndefault_md = sha256\npolicy = p\n[p]\ncommonName = supplied\n[v3]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n');
    fs.writeFileSync(path.join(cwd, 'index.txt'), '');
    fs.writeFileSync(path.join(cwd, 'serial'), '01\n');
    openssl(['ca', '-batch', '-config', 'ca.cnf', '-selfsign', '-keyfile', 'root.key', '-in', 'root.csr', '-out', 'root.pem', '-startdate', '20000101000000Z', '-enddate', '20010101000000Z', '-extensions', 'v3', '-notext']);
  } else {
    openssl(['x509', '-req', '-in', 'root.csr', '-signkey', 'root.key', '-days', '30', '-extfile', 'ca.ext', '-out', 'root.pem']);
  }

  openssl(['x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '30', '-extfile', 'ca.ext', '-out', 'intermediate.pem']);
  openssl(['x509', '-req', '-in', 'ek.csr', '-CA', 'intermediate.pem', '-CAkey', 'intermediate.key', '-CAcreateserial', '-days', '30', '-outform', 'DER', '-out', 'ek.der']);
  // The intermediate's key and name, certified by the root as an end
  // entity, and as a CA that may not sign certificates.
  fs.writeFileSync(path.join(cwd, 'end-entity.ext'), 'basicConstraints = critical,CA:FALSE\n');
  fs.writeFileSync(path.join(cwd, 'no-cert-sign.ext'), 'basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature\n');
  fs.writeFileSync(path.join(cwd, 'no-key-usage.ext'), 'basicConstraints = critical,CA:TRUE\n');
  for (const name of ['end-entity', 'no-cert-sign', 'no-key-usage']) {
    openssl(['x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '30', '-extfile', `${name}.ext`, '-out', `${name}.pem`]);
  }

  const certificate = name => new crypto.X509Certificate(fs.readFileSync(path.join(cwd, `${name}.pem`)));
  return {
    root: certificate('root'),
    intermediate: certificate('intermediate'),
    endEntity: certificate('end-entity'),
    noCertSign: certificate('no-cert-sign'),
    noKeyUsage: certificate('no-key-usage'),
    certificate: fs.readFileSync(path.join(cwd, 'ek.der')),
    ekKey: crypto.createPublicKey(fs.readFileSync(path.join(cwd, 'ek.key'))),
  };
}

test('verifyEkCertificate: chains, keys and CA validity', {skip: !hasOpenssl}, t => {
  const {
    root, intermediate, endEntity, noCertSign, noKeyUsage, certificate, ekKey,
  } = makeCa(t);
  const other = makeCa(t);
  assert.deepEqual(identity.verifyEkCertificate({
    certificate, ekKey, roots: [other.root, root], intermediates: [other.intermediate, intermediate],
  }), {subject: 'CN=ek', issuer: 'CN=intermediate', chain: ['CN=ek', 'CN=intermediate', 'CN=root']});
  // A trusted intermediate is enough.
  assert.deepEqual(identity.verifyEkCertificate({certificate, ekKey, roots: [intermediate]}).chain, ['CN=ek', 'CN=intermediate']);

  assert.throws(() => identity.verifyEkCertificate({certificate, ekKey: other.ekKey, roots: [root]}), /for a different key than the TPM's EK/);
  // Without the intermediate, or with only another manufacturer's CAs.
  assert.throws(() => identity.verifyEkCertificate({certificate, ekKey, roots: [root]}), /does not chain to a trusted TPM manufacturer CA/);
  assert.throws(() => identity.verifyEkCertificate({
    certificate, ekKey, roots: [other.root], intermediates: [intermediate, root],
  }), /does not chain to a trusted TPM manufacturer CA/);
  // A self-signed CA among the intermediates ends the search.
  assert.throws(() => identity.verifyEkCertificate({
    certificate: intermediate.raw, ekKey: intermediate.publicKey, roots: [other.root], intermediates: [root],
  }), /does not chain/);

  // Intermediates must be CAs allowed to sign certificates: the same key
  // and name, certified by the root as an end entity or without
  // keyCertSign, does not make a chain.
  assert.equal(identity.isCertificateAuthority(intermediate), true);
  assert.equal(identity.isCertificateAuthority(endEntity), false);
  assert.equal(identity.isCertificateAuthority(noCertSign), false);
  // A CA without a keyUsage extension may sign.
  assert.deepEqual(identity.verifyEkCertificate({
    certificate, ekKey, roots: [root], intermediates: [noKeyUsage],
  }).chain, ['CN=ek', 'CN=intermediate', 'CN=root']);
  for (const notCa of [endEntity, noCertSign]) {
    assert.throws(() => identity.verifyEkCertificate({
      certificate, ekKey, roots: [root], intermediates: [notCa],
    }), /does not chain to a trusted TPM manufacturer CA/, notCa.subject);
  }

  const expired = makeCa(t, {expired: true});
  assert.throws(() => identity.verifyEkCertificate({
    certificate: expired.certificate, ekKey: expired.ekKey, roots: [expired.root], intermediates: [expired.intermediate],
  }), /not currently valid: CN=expired root/);
});

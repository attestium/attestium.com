'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const Tpm = require('../lib/tpm');
const identity = require('../lib/tpm-identity');
const {hasTpmSimulator} = require('./helpers');
const {hasTpmCertificates, startSwtpm} = require('./system-helpers');

const spki = key => (typeof key === 'string' ? crypto.createPublicKey(key) : key).export({type: 'spki', format: 'der'});

test('TPM enrollment: EK certificate, attestation key and credential activation', {skip: !hasTpmCertificates}, async t => {
  const {tcti, ca} = await startSwtpm(t, {ekCertificate: true});
  const tpm = new Tpm({tcti});

  // The endorsement key and the certificate its manufacturer stored.
  await assert.rejects(tpm.getEndorsement({algorithm: 'dsa'}), /Unsupported EK algorithm: dsa/);
  const endorsement = await tpm.getEndorsement();
  assert.equal(endorsement.algorithm, 'rsa');
  const ek = identity.parseTpmPublic(Buffer.from(endorsement.publicArea, 'base64'));
  assert.equal(ek.type, 'rsa');
  assert.deepEqual(ek.symmetric, {algorithm: 0x00_06, keyBits: 128, mode: 0x00_43});
  assert.deepEqual(identity.attestationKeyProblems(ek), ['sign is not set', 'decrypt is set']);
  const certificate = Buffer.from(endorsement.certificate, 'base64');
  // The NV area's padding is not part of the certificate.
  assert.equal(new crypto.X509Certificate(certificate).raw.length, certificate.length);
  const roots = [new crypto.X509Certificate(fs.readFileSync(ca.root))];
  const intermediates = [new crypto.X509Certificate(fs.readFileSync(ca.issuer))];
  const verified = identity.verifyEkCertificate({
    certificate, ekKey: ek.key, roots, intermediates,
  });
  assert.equal(verified.chain.length, 3);
  assert.throws(() => identity.verifyEkCertificate({certificate, ekKey: ek.key, roots}), /does not chain/);

  const eccEndorsement = await tpm.getEndorsement({algorithm: 'ecc'});
  const eccEk = identity.parseTpmPublic(Buffer.from(eccEndorsement.publicArea, 'base64'));
  assert.equal(eccEk.type, 'ecc');
  if (eccEndorsement.certificate) {
    identity.verifyEkCertificate({
      certificate: Buffer.from(eccEndorsement.certificate, 'base64'), ekKey: eccEk.key, roots, intermediates,
    });
  }

  // Attestation keys: restricted signing keys whose names bind credentials.
  const rsaAk = await tpm.createAttestationKey();
  const eccAk = await tpm.createAttestationKey({handle: '0x81010003', algorithm: 'ecc'});
  const rsaArea = identity.parseTpmPublic(Buffer.from(await tpm.getAttestationKeyPublicArea(), 'base64'));
  const eccArea = identity.parseTpmPublic(Buffer.from(await tpm.getAttestationKeyPublicArea('0x81010003'), 'base64'));
  assert.deepEqual(identity.attestationKeyProblems(rsaArea), []);
  assert.deepEqual(identity.attestationKeyProblems(eccArea), []);
  assert.ok(spki(rsaArea.key).equals(spki(rsaAk.publicKey)));
  assert.ok(spki(eccArea.key).equals(spki(eccAk.publicKey)));
  await assert.rejects(tpm.getAttestationKeyPublicArea('0x81010009'), /tpm2_readpublic failed/);

  // MakeCredential in Node.js, ActivateCredential in the TPM.
  for (const [ekArea, algorithm, akArea, handle] of [[ek, 'rsa', rsaArea, undefined], [eccEk, 'ecc', eccArea, '0x81010003'], [ek, 'rsa', eccArea, '0x81010003']]) {
    const secret = crypto.randomBytes(32);
    const credential = identity.makeCredential({ek: ekArea, akName: akArea.name, secret}).toString('base64');
    assert.equal(await tpm.activateCredential({credential, algorithm, handle}), secret.toString('base64'));
  }

  // A credential for another key, or for another TPM's EK, is not activated.
  const forRsaAk = identity.makeCredential({ek, akName: rsaArea.name, secret: Buffer.from('x')}).toString('base64');
  await assert.rejects(tpm.activateCredential({credential: forRsaAk, handle: '0x81010003'}), /tpm2_activatecredential failed/);
  const otherEk = {...ek, key: crypto.generateKeyPairSync('rsa', {modulusLength: 2048}).publicKey};
  const forOtherTpm = identity.makeCredential({ek: otherEk, akName: rsaArea.name, secret: Buffer.from('x')}).toString('base64');
  await assert.rejects(tpm.activateCredential({credential: forOtherTpm}), /tpm2_activatecredential failed/);
  // The TPM still works after failed activations.
  const secret = crypto.randomBytes(16);
  assert.equal(await tpm.activateCredential({credential: identity.makeCredential({ek, akName: rsaArea.name, secret}).toString('base64')}), secret.toString('base64'));
});

test('TPM enrollment: a TPM without an EK certificate', {skip: !hasTpmSimulator}, async t => {
  const {tcti} = await startSwtpm(t);
  const flushed = [];
  // The real tools, except that the policy session is already gone when
  // it is flushed (as when the TPM flushed it after use).
  const run = (file, args, options) => new Promise((resolve, reject) => {
    if (file === 'tpm2_flushcontext' && args[0].endsWith('session.ctx')) {
      flushed.push(args[0]);
      reject(new Error('tpm2_flushcontext failed: no such session'));
      return;
    }

    execFile(file, args, options, (error, stdout) => (error ? reject(error) : resolve(stdout)));
  });
  const tpm = new Tpm({tcti, run});
  const endorsement = await tpm.getEndorsement({algorithm: 'ecc'});
  assert.equal(endorsement.certificate, null);
  const ek = identity.parseTpmPublic(Buffer.from(endorsement.publicArea, 'base64'));
  assert.equal(ek.curve, 3);
  assert.equal((await tpm.getEndorsement()).certificate, null);

  await tpm.createAttestationKey({algorithm: 'ecc'});
  const ak = identity.parseTpmPublic(Buffer.from(await tpm.getAttestationKeyPublicArea(), 'base64'));
  const secret = crypto.randomBytes(32);
  const credential = identity.makeCredential({ek, akName: ak.name, secret}).toString('base64');
  assert.equal(await tpm.activateCredential({credential, algorithm: 'ecc'}), secret.toString('base64'));
  assert.equal(flushed.length, 1);
});

test('activateCredential: only credential blobs are accepted', async () => {
  const tpm = new Tpm({tcti: 'swtpm:host=127.0.0.1,port=1'});
  const blob = Buffer.alloc(16);
  await assert.rejects(tpm.activateCredential({credential: blob.toString('base64')}), /Not a credential blob/);
  blob.writeUInt32BE(0xBA_DC_C0_DE, 0);
  await assert.rejects(tpm.activateCredential({credential: blob.subarray(0, 11).toString('base64')}), /Not a credential blob/);
  await assert.rejects(tpm.activateCredential({credential: Buffer.concat([blob, Buffer.alloc(4096)]).toString('base64')}), /Not a credential blob/);
  await assert.rejects(tpm.activateCredential({credential: blob.toString('base64'), handle: '0x01'}), /Invalid persistent handle/);
});

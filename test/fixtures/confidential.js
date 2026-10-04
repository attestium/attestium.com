'use strict';

/**
 * Confidential VM reports signed by a private chain, for tests: an SEV-SNP
 * report signed by a "VCEK" under a test ARK and ASK, and a TDX quote
 * signed by a quoting enclave key under a test PCK chain.  The layouts are
 * the real ones; only the keys are not AMD's or Intel's.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const helpers = require('../helpers');

function openssl(args, cwd) {
  return helpers.openssl(args, {cwd});
}

/**
 * A root, an intermediate and a leaf, with extra leaf extensions; a
 * sibling, another intermediate the root signed; and the intermediate's
 * key and name in a certificate the root signed as not a CA.
 * @returns {{root: crypto.X509Certificate, intermediate: crypto.X509Certificate, sibling: crypto.X509Certificate, endEntity: crypto.X509Certificate, leaf: crypto.X509Certificate, leafKey: crypto.KeyObject, pem: Object}}
 */
function chain({curve, leafExtensions = []}) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'confidential-fixture-'));
  try {
    for (const name of ['root', 'intermediate', 'sibling', 'leaf']) {
      openssl(['ecparam', '-name', curve, '-genkey', '-noout', '-out', `${name}.key`], cwd);
    }

    const ca = 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n';
    fs.writeFileSync(path.join(cwd, 'ca.ext'), ca);
    fs.writeFileSync(path.join(cwd, 'leaf.ext'), `basicConstraints=critical,CA:FALSE\n${leafExtensions.join('\n')}\n`);
    openssl(['req', '-new', '-x509', '-key', 'root.key', '-out', 'root.pem', '-days', '3650', '-subj', '/CN=test root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], cwd);
    openssl(['req', '-new', '-key', 'intermediate.key', '-out', 'intermediate.csr', '-subj', '/CN=test intermediate'], cwd);
    openssl(['x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'intermediate.pem', '-days', '3650', '-extfile', 'ca.ext'], cwd);
    openssl(['req', '-new', '-key', 'sibling.key', '-out', 'sibling.csr', '-subj', '/CN=test sibling'], cwd);
    openssl(['x509', '-req', '-in', 'sibling.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'sibling.pem', '-days', '3650', '-extfile', 'ca.ext'], cwd);
    // The intermediate's key and name, certified as an end entity.
    openssl(['x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'end-entity.pem', '-days', '3650', '-extfile', 'leaf.ext'], cwd);
    openssl(['req', '-new', '-key', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=test leaf'], cwd);
    openssl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'intermediate.pem', '-CAkey', 'intermediate.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '3650', '-extfile', 'leaf.ext'], cwd);
    const read = name => fs.readFileSync(path.join(cwd, name), 'utf8');
    return {
      root: new crypto.X509Certificate(read('root.pem')),
      intermediate: new crypto.X509Certificate(read('intermediate.pem')),
      sibling: new crypto.X509Certificate(read('sibling.pem')),
      endEntity: new crypto.X509Certificate(read('end-entity.pem')),
      leaf: new crypto.X509Certificate(read('leaf.pem')),
      leafKey: crypto.createPrivateKey(read('leaf.key')),
      pem: {root: read('root.pem'), intermediate: read('intermediate.pem'), leaf: read('leaf.pem')},
    };
  } finally {
    fs.rmSync(cwd, {recursive: true, force: true});
  }
}

/**
 * An SEV-SNP report (version 3, a Milan processor).
 *
 * @param {Object} input
 * @param {Buffer} input.reportData - 64 bytes
 * @param {string} [input.measurement] - 96 hex characters
 * @param {boolean} [input.debug=false]
 * @param {boolean} [input.withAuxblob=true] - include the VCEK (or VLEK) in a host certificate table
 * @param {'vcek'|'vlek'} [input.key='vcek'] - the kind of key that signs: a VCEK
 *   chains through the ASK, a VLEK through the ASVK (the chain's intermediate;
 *   its sibling is the other one)
 * @returns {{report: Buffer, auxblob: Buffer|null, vcek: Buffer, roots: Object, measurement: string}}
 */
function snpReport({reportData, measurement = 'ab'.repeat(48), debug = false, withAuxblob = true, key = 'vcek'}) {
  const tcb = {
    bootloader: 3, tee: 0, snp: 8, microcode: 115,
  };
  const chipId = crypto.randomBytes(64);
  const certificates = chain({
    curve: 'secp384r1',
    leafExtensions: [
      `1.3.6.1.4.1.3704.1.3.1=ASN1:INTEGER:${tcb.bootloader}`,
      `1.3.6.1.4.1.3704.1.3.2=ASN1:INTEGER:${tcb.tee}`,
      `1.3.6.1.4.1.3704.1.3.3=ASN1:INTEGER:${tcb.snp}`,
      `1.3.6.1.4.1.3704.1.3.8=ASN1:INTEGER:${tcb.microcode}`,
      `1.3.6.1.4.1.3704.1.4=ASN1:FORMAT:HEX,OCTETSTRING:${chipId.toString('hex')}`,
    ],
  });
  const report = Buffer.alloc(0x4_A0);
  report.writeUInt32LE(3, 0x00);
  report.writeBigUInt64LE(0x3_00_00n | (debug ? 1n << 19n : 0n), 0x08);
  report.writeUInt32LE(1, 0x34);
  report.writeUInt32LE((key === 'vlek' ? 1 : 0) << 2, 0x48);
  const tcbValue = BigInt(tcb.bootloader) | (BigInt(tcb.tee) << 8n) | (BigInt(tcb.snp) << 48n) | (BigInt(tcb.microcode) << 56n);
  report.writeBigUInt64LE(tcbValue, 0x38);
  reportData.copy(report, 0x50);
  Buffer.from(measurement, 'hex').copy(report, 0x90);
  report.writeBigUInt64LE(tcbValue, 0x1_80);
  report[0x1_88] = 0x19;
  report[0x1_89] = 0x01;
  chipId.copy(report, 0x1_A0);
  const signature = crypto.sign('sha384', report.subarray(0, 0x2_A0), {key: certificates.leafKey, dsaEncoding: 'ieee-p1363'});
  Buffer.from(signature.subarray(0, 48)).reverse().copy(report, 0x2_A0);
  Buffer.from(signature.subarray(48)).reverse().copy(report, 0x2_A0 + 72);
  let auxblob = null;
  if (withAuxblob) {
    // One entry (the VCEK) and a terminating zero entry.
    const der = certificates.leaf.raw;
    auxblob = Buffer.alloc(48 + der.length);
    const guid = (key === 'vlek' ? 'a8074bc2-a25a-483e-aae6-39c045a0b8a1' : '63da758d-e664-4564-adc5-f4b93be8accd').split('-');
    Buffer.concat([
      Buffer.from(guid[0], 'hex').reverse(), Buffer.from(guid[1], 'hex').reverse(), Buffer.from(guid[2], 'hex').reverse(), Buffer.from(guid[3], 'hex'), Buffer.from(guid[4], 'hex'),
    ]).copy(auxblob, 0);
    auxblob.writeUInt32LE(48, 16);
    auxblob.writeUInt32LE(der.length, 20);
    der.copy(auxblob, 48);
  }

  return {
    report,
    auxblob,
    vcek: certificates.leaf.raw,
    roots: {
      Milan: key === 'vlek'
        ? {ark: certificates.root, ask: certificates.sibling, asvk: certificates.intermediate}
        : {ark: certificates.root, ask: certificates.intermediate, asvk: certificates.sibling},
    },
    measurement,
    chipId,
    tcb,
    certificates,
  };
}

/**
 * A TDX quote (version 4).
 *
 * @param {Object} input
 * @param {Buffer} input.reportData
 * @param {string} [input.mrTd]
 * @param {string} [input.mrConfigId]
 * @param {string} [input.mrOwner]
 * @param {boolean} [input.debug=false]
 * @returns {{quote: Buffer, root: crypto.X509Certificate}}
 */
function tdxQuote({reportData, mrTd = 'cd'.repeat(48), mrConfigId = '00'.repeat(48), mrOwner = '00'.repeat(48), debug = false}) {
  const certificates = chain({curve: 'prime256v1'});
  const header = Buffer.alloc(48);
  header.writeUInt16LE(4, 0);
  header.writeUInt16LE(2, 2);
  header.writeUInt32LE(0x81, 4);
  const body = Buffer.alloc(584);
  body.writeBigUInt64LE(debug ? 1n : 0n, 120);
  Buffer.from(mrTd, 'hex').copy(body, 136);
  Buffer.from(mrConfigId, 'hex').copy(body, 184);
  Buffer.from(mrOwner, 'hex').copy(body, 232);
  reportData.copy(body, 520);
  const signed = Buffer.concat([header, body]);

  const attestation = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const point = attestation.publicKey.export({type: 'spki', format: 'der'}).subarray(-64);
  const authData = Buffer.from('auth');
  const qeReport = Buffer.alloc(384);
  // Intel's TD quoting enclave: attributes, MRSIGNER, ISVPRODID and ISVSVN.
  Buffer.from('15000000000000000700000000000000', 'hex').copy(qeReport, 48);
  Buffer.from('dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5', 'hex').copy(qeReport, 128);
  qeReport.writeUInt16LE(2, 256);
  qeReport.writeUInt16LE(4, 258);
  crypto.createHash('sha256').update(point).update(authData).digest().copy(qeReport, 320);
  const p1363 = key => ({key, dsaEncoding: 'ieee-p1363'});
  const qeSignature = crypto.sign('sha256', qeReport, p1363(certificates.leafKey));
  const pem = Buffer.from(`${certificates.pem.leaf}${certificates.pem.intermediate}${certificates.pem.root}`);
  const inner = Buffer.alloc(6);
  inner.writeUInt16LE(5, 0);
  inner.writeUInt32LE(pem.length, 2);
  const authLength = Buffer.alloc(2);
  authLength.writeUInt16LE(authData.length, 0);
  const certification = Buffer.concat([qeReport, qeSignature, authLength, authData, inner, pem]);
  const certificationHeader = Buffer.alloc(6);
  certificationHeader.writeUInt16LE(6, 0);
  certificationHeader.writeUInt32LE(certification.length, 2);
  const quoteSignature = crypto.sign('sha256', signed, p1363(attestation.privateKey));
  const signatureData = Buffer.concat([quoteSignature, point, certificationHeader, certification]);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(signatureData.length, 0);
  return {quote: Buffer.concat([signed, length, signatureData]), root: certificates.root};
}

module.exports = {snpReport, tdxQuote, chain};

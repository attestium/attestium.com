'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const confidential = require('../lib/confidential');
const {snpReport, chain} = require('./fixtures/confidential');
const {tempDir, writeFiles, hasOpenssl} = require('./helpers');

const samples = path.join(__dirname, 'fixtures', 'confidential');
const sample = name => fs.readFileSync(path.join(samples, name));

const guidBytes = guid => {
  const parts = guid.split('-');
  return Buffer.concat([
    Buffer.from(parts[0], 'hex').reverse(), Buffer.from(parts[1], 'hex').reverse(), Buffer.from(parts[2], 'hex').reverse(), Buffer.from(parts[3], 'hex'), Buffer.from(parts[4], 'hex'),
  ]);
};

/**
 * A host certificate table: entries (GUID, offset, length), then the data.
 */
function certificateTable(entries, {terminator = true} = {}) {
  const headers = [];
  const data = [];
  const headerSize = (entries.length + (terminator ? 1 : 0)) * 24;
  let offset = headerSize;
  for (const {guid, content, start, length} of entries) {
    const header = Buffer.alloc(24);
    guidBytes(guid).copy(header, 0);
    header.writeUInt32LE(start ?? offset, 16);
    header.writeUInt32LE(length ?? content.length, 20);
    headers.push(header);
    data.push(content);
    offset += content.length;
  }

  if (terminator) {
    headers.push(Buffer.alloc(24));
  }

  return Buffer.concat([...headers, ...data]);
}

/**
 * A TDX quote signed by a private PCK chain, with every layout choice open.
 */
function tdxQuote({
  reportData, certificates, version = 4, bodyType = 2, attestationKeyType = 2, teeType = 0x81, certificationType = 6, innerType = 5, debug = false, pem, binding, qe = {},
}) {
  const header = Buffer.alloc(48);
  header.writeUInt16LE(version, 0);
  header.writeUInt16LE(attestationKeyType, 2);
  header.writeUInt32LE(teeType, 4);
  const body = Buffer.alloc(bodyType === 3 ? 648 : 584);
  body.writeBigUInt64LE(debug ? 1n : 0n, 120);
  Buffer.alloc(48, 0xCD).copy(body, 136);
  reportData.copy(body, 520);
  let descriptor = Buffer.alloc(0);
  if (version === 5) {
    descriptor = Buffer.alloc(6);
    descriptor.writeUInt16LE(bodyType, 0);
    descriptor.writeUInt32LE(body.length, 2);
  }

  const signed = Buffer.concat([header, descriptor, body]);
  const attestation = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const point = attestation.publicKey.export({type: 'spki', format: 'der'}).subarray(-64);
  const authData = Buffer.from('auth');
  const qeReport = Buffer.alloc(384);
  // Intel's TD quoting enclave, unless a test says otherwise.
  Buffer.from(qe.miscselect ?? '00000000', 'hex').copy(qeReport, 16);
  Buffer.from(qe.attributes ?? '15000000000000000700000000000000', 'hex').copy(qeReport, 48);
  Buffer.from(qe.mrsigner ?? confidential.TD_QE_IDENTITY.mrsigner, 'hex').copy(qeReport, 128);
  qeReport.writeUInt16LE(qe.isvprodid ?? 2, 256);
  qeReport.writeUInt16LE(4, 258);
  (binding || crypto.createHash('sha256').update(point).update(authData).digest()).copy(qeReport, 320);
  const p1363 = key => ({key, dsaEncoding: 'ieee-p1363'});
  const qeSignature = crypto.sign('sha256', qeReport, p1363(certificates.leafKey));
  const chainPem = Buffer.from(pem ?? `${certificates.pem.leaf}${certificates.pem.intermediate}${certificates.pem.root}`);
  const inner = Buffer.alloc(6);
  inner.writeUInt16LE(innerType, 0);
  inner.writeUInt32LE(chainPem.length, 2);
  const authLength = Buffer.alloc(2);
  authLength.writeUInt16LE(authData.length, 0);
  const certification = Buffer.concat([qeReport, qeSignature, authLength, authData, inner, chainPem]);
  const certificationHeader = Buffer.alloc(6);
  certificationHeader.writeUInt16LE(certificationType, 0);
  certificationHeader.writeUInt32LE(certification.length, 2);
  const signatureData = Buffer.concat([crypto.sign('sha256', signed, p1363(attestation.privateKey)), point, certificationHeader, certification]);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(signatureData.length, 0);
  return Buffer.concat([signed, length, signatureData]);
}

const expected = crypto.randomBytes(64);

// ─── attester: configfs-tsm ─────────────────────────────────────────────

test('reportData: SHA-512 over the nonce and the evidence digest', () => {
  const nonce = 'ab'.repeat(32);
  const digest = 'cd'.repeat(32);
  assert.deepEqual(confidential.reportData(nonce, digest), crypto.createHash('sha512').update(Buffer.from(nonce + digest, 'hex')).digest());
  assert.equal(confidential.TSM_ROOT, '/sys/kernel/config/tsm/report');
});

test('collectReport: an existing report entry', t => {
  const entry = tempDir(t);
  assert.throws(() => confidential.collectReport(Buffer.alloc(32), {entry}), /Report data must be 64 bytes/);
  assert.throws(() => confidential.collectReport('x'.repeat(64), {entry}), TypeError);

  writeFiles(entry, {provider: 'sev_guest\n', outblob: 'report', auxblob: 'certificates'});
  assert.deepEqual(confidential.collectReport(expected, {entry}), {provider: 'sev_guest', report: Buffer.from('report'), auxblob: Buffer.from('certificates')});
  assert.deepEqual(fs.readFileSync(path.join(entry, 'inblob')), expected);

  // No certificates from the host.
  writeFiles(entry, {auxblob: ''});
  assert.equal(confidential.collectReport(expected, {entry}).auxblob, null);
  fs.rmSync(path.join(entry, 'auxblob'));
  assert.equal(confidential.collectReport(expected, {entry}).auxblob, null);

  // A generation that did not advance by one: another request changed the report.
  writeFiles(entry, {generation: '4\n'});
  assert.throws(() => confidential.collectReport(expected, {entry}), /changed by another request/);
  assert.ok(fs.existsSync(entry));
});

test('collectReport: a report entry created and removed in configfs', t => {
  const root = tempDir(t);
  // Configfs semantics: a new entry comes with its attributes, writing
  // inblob generates the report and advances the generation, and rmdir
  // removes the entry with its attributes.
  const created = [];
  const {mkdirSync, writeFileSync, rmdirSync} = fs;
  const inRoot = file => typeof file === 'string' && file.startsWith(`${root}${path.sep}`);
  t.mock.method(fs, 'mkdirSync', (file, ...rest) => {
    mkdirSync(file, ...rest);
    if (inRoot(file)) {
      created.push(file);
      writeFileSync(path.join(file, 'provider'), 'tdx_guest\n');
      writeFileSync(path.join(file, 'generation'), '0\n');
    }
  });
  t.mock.method(fs, 'writeFileSync', (file, data, ...rest) => {
    writeFileSync(file, data, ...rest);
    if (inRoot(file) && path.basename(file) === 'inblob') {
      const entry = path.dirname(file);
      writeFileSync(path.join(entry, 'outblob'), Buffer.concat([Buffer.from('quote:'), data]));
      writeFileSync(path.join(entry, 'generation'), `${Number(fs.readFileSync(path.join(entry, 'generation'), 'utf8')) + 1}\n`);
    }
  });
  t.mock.method(fs, 'rmdirSync', (file, ...rest) => (inRoot(file) ? fs.rmSync(file, {recursive: true}) : rmdirSync(file, ...rest)));

  const result = confidential.collectReport(expected, {root});
  assert.equal(result.provider, 'tdx_guest');
  assert.deepEqual(result.report, Buffer.concat([Buffer.from('quote:'), expected]));
  assert.equal(result.auxblob, null);
  assert.equal(created.length, 1);
  assert.match(path.basename(created[0]), new RegExp(`^attestium-${process.pid}-[\\da-f]{8}$`));
  assert.deepEqual(fs.readdirSync(root), []);

  // A missing configfs.
  assert.throws(() => confidential.collectReport(expected, {root: path.join(root, 'missing')}), /ENOENT/);
});

// ─── AMD SEV-SNP ────────────────────────────────────────────────────────

test('parseSnpReport, snpProduct and tcbParts', () => {
  assert.throws(() => confidential.parseSnpReport(Buffer.alloc(0x4_9F)), /too short/);
  const report = Buffer.alloc(0x4_A0);
  report.writeUInt32LE(3, 0);
  report.writeBigUInt64LE((1n << 19n) | (1n << 18n), 0x08);
  report.writeUInt32LE(5 << 2, 0x48);
  report[0x1_88] = 0x19;
  report[0x1_89] = 0x11;
  report[0x1_8A] = 0x01;
  const parsed = confidential.parseSnpReport(report);
  assert.equal(parsed.version, 3);
  assert.equal(parsed.debugAllowed, true);
  assert.equal(parsed.migrationAgentAllowed, true);
  assert.equal(parsed.signingKey, 5);
  assert.deepEqual(parsed.cpuid, {family: 0x19, model: 0x11, stepping: 1});
  assert.equal(confidential.snpProduct(parsed), 'Genoa');
  assert.equal(confidential.snpProduct({cpuid: {family: 0x19, model: 0x01}}), 'Milan');
  assert.equal(confidential.snpProduct({cpuid: {family: 0x1A, model: 0x02}}), 'Turin');
  assert.equal(confidential.snpProduct({cpuid: {family: 0x17, model: 0x31}}), null);

  // Version 2 reports do not say which processor they come from.
  const real = confidential.parseSnpReport(sample('snp.bin'));
  assert.equal(real.version, 2);
  assert.equal(real.cpuid, null);
  assert.equal(confidential.snpProduct(real), null);
  assert.equal(real.debugAllowed, true);

  const tcb = 0x44_05_00_00_00_00_00_02n;
  assert.deepEqual(confidential.tcbParts(tcb, 'Milan'), {
    bootloader: 2, tee: 0, snp: 5, microcode: 0x44,
  });
  assert.deepEqual(confidential.tcbParts(0x44_00_00_00_07_03_02_01n, 'Turin'), {
    fmc: 1, bootloader: 2, tee: 3, snp: 7, microcode: 0x44,
  });
});

test('parseCertificateTable: the host certificate table', () => {
  assert.deepEqual(confidential.parseCertificateTable(null), {});
  const table = certificateTable([
    {guid: 'c0b406a4-a803-4952-9743-3fb6014cd0ae', content: Buffer.from('ark')},
    {guid: '4ab7b379-bbac-4fe4-a02f-05aef327c782', content: Buffer.from('ask')},
    {guid: '00000000-0000-0000-0000-000000000001', content: Buffer.from('unknown')},
    {guid: 'a8074bc2-a25a-483e-aae6-39c045a0b8a1', content: Buffer.from('vlek')},
  ]);
  assert.deepEqual(confidential.parseCertificateTable(table), {ark: Buffer.from('ark'), ask: Buffer.from('ask'), vlek: Buffer.from('vlek')});

  // Without a terminating entry, and with an entry pointing past the end.
  const unterminated = certificateTable([
    {guid: '63da758d-e664-4564-adc5-f4b93be8accd', content: Buffer.from('vcek')},
    {
      guid: 'c0b406a4-a803-4952-9743-3fb6014cd0ae', content: Buffer.from('ark'), start: 40, length: 100,
    },
  ], {terminator: false});
  assert.deepEqual(confidential.parseCertificateTable(unterminated), {vcek: Buffer.from('vcek')});
  assert.deepEqual(confidential.parseCertificateTable(Buffer.alloc(10)), {});
});

test('vcekClaims and vcekUrl', () => {
  // AMD's VCEK: the hardware id is the raw extension value.
  const vcek = new crypto.X509Certificate(sample('vcek.der'));
  const claims = confidential.vcekClaims(vcek);
  assert.deepEqual(claims.tcb, {
    bootloader: 2, tee: 0, snp: 5, microcode: 68,
  });
  const parsed = confidential.parseSnpReport(sample('snp.bin'));
  assert.deepEqual(claims.chipId, parsed.chipId);

  assert.equal(confidential.vcekUrl(parsed, 'Milan'), `https://kdsintf.amd.com/vcek/v1/Milan/${parsed.chipId.toString('hex')}?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68`);
  assert.equal(confidential.vcekUrl(parsed, 'Turin', 'https://kds.example'), `https://kds.example/vcek/v1/Turin/${parsed.chipId.subarray(0, 8).toString('hex')}?fmcSPL=2&blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=68`);
});

test('vcekClaims: a certificate without AMD extensions', {skip: !hasOpenssl}, () => {
  const {leaf} = chain({curve: 'prime256v1'});
  assert.deepEqual(confidential.vcekClaims(leaf), {tcb: {}, chipId: null});
});

test('verifySnpReport: AMD\'s sample report chains to the shipped roots but allows debugging', () => {
  const report = sample('snp.bin');
  const parsed = confidential.parseSnpReport(report);
  assert.throws(() => confidential.verifySnpReport({report, reportData: parsed.reportData, vcek: sample('vcek.der')}), /policy allows debugging/);
  assert.throws(() => confidential.verifySnpReport({report, reportData: expected, vcek: sample('vcek.der')}), /does not bind this nonce/);
  assert.throws(() => confidential.verifyConfidential({provider: 'sev_guest', report: report.toString('base64')}, parsed.reportData), /No VCEK certificate/);
  const roots = confidential.amdRoots();
  assert.deepEqual(Object.keys(roots), ['Milan', 'Genoa', 'Turin']);
  assert.match(roots.Genoa.ark.subject, /ARK-Genoa/);
});

test('verifySnpReport: reports signed by a private AMD-style chain', {skip: !hasOpenssl}, () => {
  const fixture = snpReport({reportData: expected});
  const {report, vcek, roots} = fixture;
  const result = confidential.verifySnpReport({
    report, reportData: expected, vcek, roots,
  });
  assert.equal(result.product, 'Milan');
  assert.equal(result.key, 'vcek');
  assert.equal(result.measurement, fixture.measurement);
  assert.deepEqual(result.tcb, {
    bootloader: 3, tee: 0, snp: 8, microcode: 115,
  });

  // From the host's certificate table, with the host's ASK.
  const other = snpReport({reportData: expected, withAuxblob: false});
  const withAsk = {vcek, ask: roots.Milan.ask.raw};
  assert.equal(confidential.verifySnpReport({
    report, reportData: expected, certificates: withAsk, roots: {Turin: other.roots.Milan, Milan: roots.Milan},
  }).product, 'Milan');
  // A host ASK that is not the root's.
  assert.throws(() => confidential.verifySnpReport({
    report, reportData: expected, certificates: {vcek, ask: other.roots.Milan.ask.raw}, roots,
  }), /does not chain to an AMD root/);
  // A VCEK from another chain.
  assert.throws(() => confidential.verifySnpReport({
    report, reportData: expected, vcek: other.vcek, roots,
  }), /The VCEK certificate does not chain to an AMD root/);
  assert.throws(() => confidential.verifySnpReport({report, reportData: expected, vcek}), /does not chain to an AMD root/);

  const modified = (offset, write) => {
    const copy = Buffer.from(report);
    write(copy, offset);
    return copy;
  };

  assert.throws(() => confidential.verifySnpReport({
    report: modified(0x34, (copy, offset) => copy.writeUInt32LE(2, offset)), reportData: expected, vcek, roots,
  }), /Unsupported SEV-SNP signature algorithm 2/);
  assert.throws(() => confidential.verifySnpReport({
    report: modified(0x1_80, (copy, offset) => {
      copy[offset] = 9;
    }),
    reportData: expected,
    vcek,
    roots,
  }), /different TCB \(bootloader 3, report 9\)/);
  assert.throws(() => confidential.verifySnpReport({
    report: modified(0x1_A0, (copy, offset) => {
      copy[offset] ^= 1;
    }),
    reportData: expected,
    vcek,
    roots,
  }), /for a different chip/);
  assert.throws(() => confidential.verifySnpReport({
    report: modified(0x90, (copy, offset) => {
      copy[offset] ^= 1;
    }),
    reportData: expected,
    vcek,
    roots,
  }), /signature does not verify/);

  // A report that says a VLEK signed it: a VCEK (under the ASK) is not one.
  const vlekReport = modified(0x48, (copy, offset) => copy.writeUInt32LE(1 << 2, offset));
  assert.throws(() => confidential.verifySnpReport({report: vlekReport, reportData: expected, roots}), /No VLEK certificate/);
  assert.throws(() => confidential.verifySnpReport({
    report: vlekReport, reportData: expected, certificates: {vlek: vcek}, roots,
  }), /The VLEK certificate does not chain to an AMD root/);
  // Signed by neither (7: an unsigned report).
  assert.throws(() => confidential.verifySnpReport({
    report: modified(0x48, (copy, offset) => copy.writeUInt32LE(7 << 2, offset)), reportData: expected, vcek, roots,
  }), /not signed by a VCEK or VLEK \(signing key 7\)/);

  const debug = snpReport({reportData: expected, debug: true});
  assert.throws(() => confidential.verifySnpReport({
    report: debug.report, reportData: expected, vcek: debug.vcek, roots: debug.roots,
  }), /policy allows debugging/);

  // Evidence as the attester sends it.
  const evidence = {provider: 'sev_guest', report: report.toString('base64'), auxblob: fixture.auxblob.toString('base64')};
  assert.deepEqual(confidential.verifyConfidential(evidence, expected, {roots}), {
    type: 'sev-snp',
    measurement: fixture.measurement,
    product: 'Milan',
    key: 'vcek',
    tcb: {
      bootloader: 3, tee: 0, snp: 8, microcode: 115,
    },
    policy: '0x30000',
    vmpl: 0,
  });
  assert.equal(confidential.verifyConfidential({provider: 'sev_guest', report: evidence.report}, expected, {roots, vcek}).type, 'sev-snp');
});

test('verifySnpReport: a policy that allows a migration agent is refused unless allowed', {skip: !hasOpenssl}, () => {
  const fixture = snpReport({reportData: expected});
  const {vcek, roots} = fixture;
  // The same VM launched with MIGRATE_MA set (policy bit 18), signed by its VCEK.
  const report = Buffer.from(fixture.report);
  report.writeBigUInt64LE(report.readBigUInt64LE(0x08) | (1n << 18n), 0x08);
  const signature = crypto.sign('sha384', report.subarray(0, 0x2_A0), {key: fixture.certificates.leafKey, dsaEncoding: 'ieee-p1363'});
  Buffer.from(signature.subarray(0, 48)).reverse().copy(report, 0x2_A0);
  Buffer.from(signature.subarray(48)).reverse().copy(report, 0x2_A0 + 72);
  assert.equal(confidential.parseSnpReport(report).migrationAgentAllowed, true);

  assert.throws(() => confidential.verifySnpReport({
    report, reportData: expected, vcek, roots,
  }), /policy allows a migration agent/);
  const evidence = {provider: 'sev_guest', report: report.toString('base64')};
  assert.throws(() => confidential.verifyConfidential(evidence, expected, {vcek, roots}), /policy allows a migration agent/);
  assert.equal(confidential.verifySnpReport({
    report, reportData: expected, vcek, roots, allowMigrationAgent: true,
  }).measurement, fixture.measurement);
  assert.equal(confidential.verifyConfidential(evidence, expected, {vcek, roots, allowMigrationAgent: true}).policy, '0x70000');
});

test('the shipped ASVKs are AMD\'s, signed by the pinned ARKs', () => {
  for (const [product, {ark, ask, asvk}] of Object.entries(confidential.amdRoots())) {
    assert.match(asvk.subject, new RegExp(`CN=SEV-VLEK-${product}$`), product);
    assert.match(ask.subject, new RegExp(`CN=SEV-${product}$`), product);
    assert.ok(asvk.ca && asvk.checkIssued(ark) && asvk.verify(ark.publicKey), product);
    assert.ok(!asvk.raw.equals(ask.raw), product);
  }
});

test('verifySnpReport: VLEK-signed reports chain through the ASVK', {skip: !hasOpenssl}, () => {
  const fixture = snpReport({reportData: expected, key: 'vlek'});
  const {report, vcek: vlek, roots} = fixture;
  assert.equal(confidential.parseSnpReport(report).signingKey, 1);

  // From the host's certificate table (the VLEK entry), as the attester sends it.
  const evidence = {provider: 'sev_guest', report: report.toString('base64'), auxblob: fixture.auxblob.toString('base64')};
  const result = confidential.verifyConfidential(evidence, expected, {roots});
  assert.equal(result.key, 'vlek');
  assert.equal(result.product, 'Milan');
  assert.equal(result.measurement, fixture.measurement);
  assert.equal(confidential.verifySnpReport({
    report, reportData: expected, vcek: vlek, roots,
  }).key, 'vlek');

  // The host's ASK entry holds the ASVK on VLEK hosts.
  assert.equal(confidential.verifySnpReport({
    report, reportData: expected, certificates: {vlek, ask: roots.Milan.asvk.raw}, roots,
  }).key, 'vlek');
  // An ASK there, or no ASVK to chain to, is refused.
  assert.throws(() => confidential.verifySnpReport({
    report, reportData: expected, certificates: {vlek, ask: roots.Milan.ask.raw}, roots,
  }), /The VLEK certificate does not chain to an AMD root/);
  assert.throws(() => confidential.verifySnpReport({
    report, reportData: expected, vcek: vlek, roots: {Milan: {ark: roots.Milan.ark, ask: roots.Milan.ask}},
  }), /The VLEK certificate does not chain to an AMD root/);
  // Nor is the real AMD chain a match for a private one.
  assert.throws(() => confidential.verifySnpReport({report, reportData: expected, vcek: vlek}), /does not chain to an AMD root/);

  // A VCEK report cannot chain through the ASVK, even from the host's table.
  const vcekFixture = snpReport({reportData: expected});
  assert.throws(() => confidential.verifySnpReport({
    report: vcekFixture.report, reportData: expected, certificates: {vcek: vcekFixture.vcek, ask: vcekFixture.roots.Milan.asvk.raw}, roots: vcekFixture.roots,
  }), /The VCEK certificate does not chain to an AMD root/);
  // A host intermediate the ARK signed that is not a CA is refused.
  assert.throws(() => confidential.verifySnpReport({
    report: vcekFixture.report, reportData: expected, certificates: {vcek: vcekFixture.vcek, ask: vcekFixture.certificates.endEntity.raw}, roots: vcekFixture.roots,
  }), /The VCEK certificate does not chain to an AMD root/);
});

// ─── Intel TDX ──────────────────────────────────────────────────────────

test('verifyTdxQuote: Intel\'s sample quote verifies to the shipped root', () => {
  const quote = sample('tdx.dat');
  const parsed = confidential.parseTdxQuote(quote);
  assert.equal(parsed.version, 4);
  assert.equal(parsed.pckChain.length, 3);
  const result = confidential.verifyTdxQuote({quote, reportData: parsed.td.reportData});
  assert.match(result.pckSubject, /CN=Intel SGX PCK Certificate/);
  assert.equal(result.td.mrTd, parsed.td.mrTd);
  assert.equal(result.td.debug, false);
  const evidence = confidential.verifyConfidential({provider: 'tdx_guest', report: quote.toString('base64')}, parsed.td.reportData);
  assert.equal(evidence.type, 'tdx');
  assert.equal(evidence.measurement, parsed.td.mrTd);
  assert.equal(evidence.rtmr.length, 4);
  assert.throws(() => confidential.verifyTdxQuote({quote, reportData: expected}), /does not bind this nonce/);

  // The quote signature covers the TD's measurements.
  const tampered = Buffer.from(quote);
  tampered[48 + 136] ^= 1;
  assert.throws(() => confidential.verifyTdxQuote({quote: tampered, reportData: parsed.td.reportData}), /The TDX quote signature does not verify/);
});

test('parseTdxQuote and verifyTdxQuote: layouts and failures', {skip: !hasOpenssl}, () => {
  const certificates = chain({curve: 'prime256v1'});
  const other = chain({curve: 'prime256v1'});
  const {root} = certificates;
  const quote = options => tdxQuote({reportData: expected, certificates, ...options});

  const v4 = confidential.verifyTdxQuote({quote: quote(), reportData: expected, root});
  assert.equal(v4.td.mrTd, 'cd'.repeat(48));
  assert.equal(v4.pckSubject, 'CN=test leaf');
  // Version 5, with TDX 1.0 and TDX 1.5 bodies.
  for (const bodyType of [2, 3]) {
    const parsed = confidential.parseTdxQuote(quote({version: 5, bodyType}));
    assert.equal(parsed.version, 5);
    assert.deepEqual(parsed.td.reportData, expected);
    assert.equal(confidential.verifyTdxQuote({quote: quote({version: 5, bodyType}), reportData: expected, root}).td.mrTd, 'cd'.repeat(48));
  }

  assert.throws(() => confidential.parseTdxQuote(quote({teeType: 0})), /Not a TDX quote/);
  assert.throws(() => confidential.parseTdxQuote(quote({version: 5, bodyType: 1})), /Unsupported TDX quote body type 1/);
  assert.throws(() => confidential.parseTdxQuote(quote({version: 3})), /Unsupported TDX quote version 3/);
  assert.throws(() => confidential.parseTdxQuote(quote({certificationType: 5})), /Unsupported TDX certification data type 5/);
  assert.throws(() => confidential.parseTdxQuote(quote({innerType: 3})), /Unsupported PCK certification data type 3/);

  assert.throws(() => confidential.verifyTdxQuote({quote: quote({attestationKeyType: 3}), reportData: expected, root}), /Unsupported TDX attestation key type/);
  assert.throws(() => confidential.verifyTdxQuote({quote: quote(), reportData: expected}), /does not end at Intel's SGX root CA/);
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({pem: certificates.pem.root}), reportData: expected, root}), /does not end at Intel's SGX root CA/);
  // A chain naming the root, but whose intermediate the root did not issue.
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({pem: `${certificates.pem.leaf}${other.pem.intermediate}${certificates.pem.root}`}), reportData: expected, root}), /PCK certificate chain does not verify/);
  // A quoting enclave report signed by another platform.
  assert.throws(() => confidential.verifyTdxQuote({quote: tdxQuote({reportData: expected, certificates: {...certificates, leafKey: other.leafKey}}), reportData: expected, root}), /not signed by the platform's PCK/);
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({binding: Buffer.alloc(32)}), reportData: expected, root}), /does not bind the attestation key/);
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({debug: true}), reportData: expected, root}), /TD is in debug mode/);

  const evidence = confidential.verifyConfidential({provider: 'tdx_guest', report: quote().toString('base64')}, expected, {root});
  assert.deepEqual(Object.keys(evidence), ['type', 'measurement', 'qeSvn', 'rtmr', 'teeTcbSvn', 'mrConfigId', 'mrOwner']);
  assert.equal(evidence.qeSvn, 4);
});

test('verifyTdxQuote: the quoting enclave must be Intel\'s', {skip: !hasOpenssl}, () => {
  // The PCK signs the report of any enclave allowed the provisioning key; a
  // host's own "quoting enclave" could then sign any TD report it likes.
  const certificates = chain({curve: 'prime256v1'});
  const {root} = certificates;
  const quote = qe => tdxQuote({reportData: expected, certificates, qe});
  assert.equal(confidential.verifyTdxQuote({quote: quote({}), reportData: expected, root}).qeSvn, 4);
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({mrsigner: 'ab'.repeat(32)}), reportData: expected, root}), /not made by Intel's TDX quoting enclave \(mrsigner differ\)/);
  // The SGX quoting enclave (ISVPRODID 1) does not quote TDs.
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({isvprodid: 1}), reportData: expected, root}), /\(isvprodid differ\)/);
  // A debug enclave's attestation key can be read by the host.
  assert.throws(() => confidential.verifyTdxQuote({quote: quote({attributes: '17000000000000000700000000000000'}), reportData: expected, root}), /\(attributes differ\)/);
  const miscselect = quote({miscselect: '01000000'}).toString('base64');
  assert.throws(() => confidential.verifyConfidential({provider: 'tdx_guest', report: miscselect}, expected, {root}), /\(miscselect differ\)/);
  // Another identity can be required.
  const qeIdentity = {...confidential.TD_QE_IDENTITY, mrsigner: 'ab'.repeat(32)};
  const own = quote({mrsigner: 'ab'.repeat(32)}).toString('base64');
  assert.equal(confidential.verifyConfidential({provider: 'tdx_guest', report: own}, expected, {root, qeIdentity}).type, 'tdx');
});

test('verifyConfidential: unknown providers', () => {
  assert.throws(() => confidential.verifyConfidential({provider: 'arm_cca_guest', report: ''}, expected), /Unsupported confidential computing provider arm_cca_guest/);
});

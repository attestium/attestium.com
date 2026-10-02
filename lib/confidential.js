/**
 * Attestium - confidential virtual machines (AMD SEV-SNP, Intel TDX)
 *
 * In a confidential VM the hardware measures the VM's initial memory at
 * launch and signs a report that binds 64 bytes chosen by the guest.  The
 * host operator cannot read the guest's memory or forge the report.
 *
 *   attester  asks the kernel for a report over (nonce, evidence digest)
 *             through configfs-tsm (/sys/kernel/config/tsm/report, Linux
 *             6.7+), with the certificates the host provides
 *   verifier  checks the report's signature up to the vendor's root
 *             (AMD's ARK, Intel's SGX root CA, shipped in ./data), that it
 *             binds this nonce and evidence, that debugging is off, and
 *             reports the launch measurement to compare with the expected
 *             one
 *
 * SEV-SNP: the report is signed by the chip's VCEK, or by a VLEK (a key
 * AMD issues to a cloud provider and the provider loads into its chips).
 * The certificate comes from the host (auxblob) or AMD's key distribution
 * service, and its TCB values must match the report's.  A VCEK chains
 * through the ASK, a VLEK through the ASVK, to the product's ARK.
 *
 * TDX: the quote is signed by the quoting enclave's attestation key, which
 * the QE report binds; the QE report is signed by the platform's PCK, whose
 * certificate chain is in the quote.  The platform's TCB level (Intel's TCB
 * info) is reported, not evaluated.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const asn1 = require('./asn1');
const vendorRoots = require('./data/vendor-roots');

const TSM_ROOT = '/sys/kernel/config/tsm/report';

// ─── attester ──────────────────────────────────────────────────────────

/**
 * Get a report from the kernel through configfs-tsm.
 *
 * @param {Buffer} reportData - 64 bytes bound into the report
 * @param {Object} [options]
 * @param {string} [options.entry] - an existing report directory (created by root at boot)
 * @param {string} [options.root=TSM_ROOT]
 * @returns {{provider: string, report: Buffer, auxblob: Buffer|null}}
 */
function collectReport(reportData, options = {}) {
  if (!Buffer.isBuffer(reportData) || reportData.length !== 64) {
    throw new TypeError('Report data must be 64 bytes');
  }

  const root = options.root || TSM_ROOT;
  let {entry} = options;
  let created = false;
  if (!entry) {
    entry = path.join(root, `attestium-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
    fs.mkdirSync(entry);
    created = true;
  }

  try {
    const generationBefore = readGeneration(entry);
    fs.writeFileSync(path.join(entry, 'inblob'), reportData);
    const report = fs.readFileSync(path.join(entry, 'outblob'));
    // Another writer between our write and read would change the generation.
    if (generationBefore !== null && readGeneration(entry) !== generationBefore + 1) {
      throw new Error('The report was changed by another request; retry');
    }

    let auxblob = null;
    try {
      auxblob = fs.readFileSync(path.join(entry, 'auxblob'));
      if (auxblob.length === 0) {
        auxblob = null;
      }
    } catch {}

    return {provider: fs.readFileSync(path.join(entry, 'provider'), 'utf8').trim(), report, auxblob};
  } finally {
    if (created) {
      fs.rmdirSync(entry);
    }
  }
}

function readGeneration(entry) {
  try {
    return Number(fs.readFileSync(path.join(entry, 'generation'), 'utf8').trim());
  } catch {
    return null;
  }
}

/**
 * The 64 bytes an attester binds: SHA-512(nonce || evidence digest).
 * @param {string} nonce - hex
 * @param {string} digest - hex
 * @returns {Buffer}
 */
function reportData(nonce, digest) {
  return crypto.createHash('sha512').update(Buffer.from(nonce, 'hex')).update(Buffer.from(digest, 'hex')).digest();
}

// ─── AMD SEV-SNP ───────────────────────────────────────────────────────

const SNP_REPORT_SIZE = 0x4_A0;
const SNP_SIGNED_SIZE = 0x2_A0;
const GUIDS = {
  'c0b406a4-a803-4952-9743-3fb6014cd0ae': 'ark',
  '4ab7b379-bbac-4fe4-a02f-05aef327c782': 'ask',
  '63da758d-e664-4564-adc5-f4b93be8accd': 'vcek',
  'a8074bc2-a25a-483e-aae6-39c045a0b8a1': 'vlek',
};

/**
 * Parse an SEV-SNP attestation report.
 * @param {Buffer} report
 * @returns {Object}
 */
function parseSnpReport(report) {
  if (report.length < SNP_REPORT_SIZE) {
    throw new Error('SEV-SNP report is too short');
  }

  const version = report.readUInt32LE(0x00);
  const hex = (offset, length) => report.subarray(offset, offset + length).toString('hex');
  const parsed = {
    version,
    guestSvn: report.readUInt32LE(0x04),
    policy: report.readBigUInt64LE(0x08),
    familyId: hex(0x10, 16),
    imageId: hex(0x20, 16),
    vmpl: report.readUInt32LE(0x30),
    signatureAlgorithm: report.readUInt32LE(0x34),
    currentTcb: report.readBigUInt64LE(0x38),
    platformInfo: report.readBigUInt64LE(0x40),
    signingKey: (report.readUInt32LE(0x48) >> 2) & 0x7,
    reportData: report.subarray(0x50, 0x90),
    measurement: hex(0x90, 48),
    hostData: hex(0xC0, 32),
    idKeyDigest: hex(0xE0, 48),
    authorKeyDigest: hex(0x1_10, 48),
    reportId: hex(0x1_40, 32),
    reportedTcb: report.readBigUInt64LE(0x1_80),
    cpuid: version >= 3 ? {family: report[0x1_88], model: report[0x1_89], stepping: report[0x1_8A]} : null,
    chipId: report.subarray(0x1_A0, 0x1_E0),
    committedTcb: report.readBigUInt64LE(0x1_E0),
    launchTcb: report.readBigUInt64LE(0x1_F8),
    signature: {r: report.subarray(0x2_A0, 0x2_A0 + 72), s: report.subarray(0x2_A0 + 72, 0x2_A0 + 144)},
  };
  parsed.debugAllowed = ((parsed.policy >> 19n) & 1n) === 1n;
  parsed.migrationAgentAllowed = ((parsed.policy >> 18n) & 1n) === 1n;
  return parsed;
}

/**
 * The product a report comes from, when the report says (version 3+).
 * @returns {'Milan'|'Genoa'|'Turin'|null}
 */
function snpProduct(parsed) {
  if (!parsed.cpuid) {
    return null;
  }

  const {family, model} = parsed.cpuid;
  if (family === 0x19) {
    return model >= 0x10 ? 'Genoa' : 'Milan';
  }

  return family === 0x1A ? 'Turin' : null;
}

/**
 * TCB component values of a TCB_VERSION, by product layout.
 */
function tcbParts(tcb, product) {
  const byte = index => Number((tcb >> BigInt(index * 8)) & 0xFFn);
  if (product === 'Turin') {
    return {
      fmc: byte(0), bootloader: byte(1), tee: byte(2), snp: byte(3), microcode: byte(7),
    };
  }

  return {
    bootloader: byte(0), tee: byte(1), snp: byte(6), microcode: byte(7),
  };
}

/**
 * Certificates from the host's certificate table (auxblob).
 * @param {Buffer|null} auxblob
 * @returns {Object<string, Buffer>} ark, ask, vcek, vlek (DER)
 */
function parseCertificateTable(auxblob) {
  const certificates = {};
  if (!auxblob) {
    return certificates;
  }

  for (let offset = 0; offset + 24 <= auxblob.length; offset += 24) {
    const guid = auxblob.subarray(offset, offset + 16);
    if (guid.every(byte => byte === 0)) {
      break;
    }

    // GUIDs are stored in their mixed-endian binary form.
    const text = [
      Buffer.from(guid.subarray(0, 4)).reverse().toString('hex'),
      Buffer.from(guid.subarray(4, 6)).reverse().toString('hex'),
      Buffer.from(guid.subarray(6, 8)).reverse().toString('hex'),
      guid.subarray(8, 10).toString('hex'),
      guid.subarray(10, 16).toString('hex'),
    ].join('-');
    const start = auxblob.readUInt32LE(offset + 16);
    const length = auxblob.readUInt32LE(offset + 20);
    if (GUIDS[text] && start + length <= auxblob.length) {
      certificates[GUIDS[text]] = auxblob.subarray(start, start + length);
    }
  }

  return certificates;
}

const VCEK_OIDS = {
  '1.3.6.1.4.1.3704.1.3.1': 'bootloader',
  '1.3.6.1.4.1.3704.1.3.2': 'tee',
  '1.3.6.1.4.1.3704.1.3.3': 'snp',
  '1.3.6.1.4.1.3704.1.3.8': 'microcode',
  '1.3.6.1.4.1.3704.1.3.9': 'fmc',
};

/**
 * The TCB values and chip id a VCEK certificate is issued for.
 */
function vcekClaims(certificate) {
  const extensions = asn1.certificateExtensions(certificate.raw);
  const tcb = {};
  for (const [oid, name] of Object.entries(VCEK_OIDS)) {
    const extension = extensions.get(oid);
    if (extension) {
      tcb[name] = Number(asn1.integer(asn1.parse(extension.value)));
    }
  }

  const hwid = extensions.get('1.3.6.1.4.1.3704.1.4');
  let chipId = null;
  if (hwid) {
    chipId = hwid.value[0] === 0x04 ? asn1.content(asn1.parse(hwid.value)) : hwid.value;
  }

  return {tcb, chipId};
}

/**
 * AMD's shipped certificates: product -> {ark, ask, asvk}.
 * @returns {Object<string, {ark: crypto.X509Certificate, ask: crypto.X509Certificate, asvk: crypto.X509Certificate}>}
 */
function amdRoots() {
  const roots = {};
  for (const product of ['Milan', 'Genoa', 'Turin']) {
    roots[product] = {
      ark: new crypto.X509Certificate(vendorRoots.amd[product].ark),
      ask: new crypto.X509Certificate(vendorRoots.amd[product].ask),
      asvk: new crypto.X509Certificate(vendorRoots.amd[product].asvk),
    };
  }

  return roots;
}

/**
 * The intermediate that signs a key of this kind under a product's ARK:
 * the ASK for a VCEK, the ASVK for a VLEK.  The host's certificate table
 * holds either in its ASK entry; one given there is used instead, when the
 * ARK signed it and it is not the pinned intermediate of the other kind.
 *
 * @returns {crypto.X509Certificate|null}
 */
function snpIntermediate(root, keyName, hostIntermediate) {
  const pinned = keyName === 'vlek' ? root.asvk : root.ask;
  const other = keyName === 'vlek' ? root.ask : root.asvk;
  const intermediate = hostIntermediate || pinned;
  if (!intermediate || (other && intermediate.raw.equals(other.raw))) {
    return null;
  }

  return intermediate.ca && intermediate.checkIssued(root.ark) && intermediate.verify(root.ark.publicKey) ? intermediate : null;
}

/**
 * The guest policy must keep the host out of the VM's memory.
 */
function checkSnpPolicy(parsed, allowMigrationAgent) {
  if (parsed.debugAllowed) {
    throw new Error('The VM\'s policy allows debugging (the host can read its memory)');
  }

  // A migration agent, chosen by the host at launch and not named in the
  // report, can export the VM's memory.
  if (parsed.migrationAgentAllowed && !allowMigrationAgent) {
    throw new Error('The VM\'s policy allows a migration agent (the host can associate one that exports its memory)');
  }
}

/**
 * Verify an SEV-SNP report.
 *
 * @param {Object} input
 * @param {Buffer} input.report
 * @param {Buffer} input.reportData - the 64 bytes the report must bind
 * @param {Buffer} [input.vcek] - the VCEK or VLEK certificate (DER); default: from input.certificates
 * @param {Object<string, Buffer>} [input.certificates] - from parseCertificateTable
 * @param {Object} [input.roots] - product -> {ark, ask, asvk} (default: AMD's, shipped)
 * @param {boolean} [input.allowMigrationAgent=false] - accept a policy that lets the host associate a migration agent
 * @returns {{product: string, measurement: string, parsed: Object, tcb: Object, key: string}}
 */
function verifySnpReport({
  report, reportData: expected, vcek, certificates = {}, roots = amdRoots(), allowMigrationAgent = false,
}) {
  const parsed = parseSnpReport(report);
  if (parsed.signatureAlgorithm !== 1) {
    throw new Error(`Unsupported SEV-SNP signature algorithm ${parsed.signatureAlgorithm}`);
  }

  if (!parsed.reportData.equals(expected)) {
    throw new Error('The SEV-SNP report does not bind this nonce and evidence');
  }

  // SIGNING_KEY: 0 VCEK, 1 VLEK, 7 none (an unsigned report).
  const keyName = {0: 'vcek', 1: 'vlek'}[parsed.signingKey];
  if (!keyName) {
    throw new Error(`The SEV-SNP report is not signed by a VCEK or VLEK (signing key ${parsed.signingKey})`);
  }

  const der = vcek || certificates[keyName];
  if (!der) {
    throw new Error(`No ${keyName.toUpperCase()} certificate for the report (the host provides none; fetch it from AMD's KDS)`);
  }

  const certificate = new crypto.X509Certificate(der);
  const hostIntermediate = certificates.ask ? new crypto.X509Certificate(certificates.ask) : null;
  let product = null;
  for (const [name, root] of Object.entries(roots)) {
    const intermediate = snpIntermediate(root, keyName, hostIntermediate);
    if (intermediate && certificate.checkIssued(intermediate) && certificate.verify(intermediate.publicKey)) {
      product = name;
      break;
    }
  }

  if (!product) {
    throw new Error(`The ${keyName.toUpperCase()} certificate does not chain to an AMD root`);
  }

  const claims = vcekClaims(certificate);
  const reported = tcbParts(parsed.reportedTcb, product);
  for (const [name, value] of Object.entries(claims.tcb)) {
    if (reported[name] !== undefined && reported[name] !== value) {
      throw new Error(`The certificate is for a different TCB (${name} ${value}, report ${reported[name]})`);
    }
  }

  if (keyName === 'vcek' && claims.chipId && !parsed.chipId.subarray(0, claims.chipId.length).equals(claims.chipId)) {
    throw new Error('The certificate is for a different chip');
  }

  // ECDSA P-384 with SHA-384; r and s are little-endian, 72 bytes each.
  const component = value => Buffer.from(value.subarray(0, 48)).reverse();
  const signature = Buffer.concat([component(parsed.signature.r), component(parsed.signature.s)]);
  const valid = crypto.verify('sha384', report.subarray(0, SNP_SIGNED_SIZE), {key: certificate.publicKey, dsaEncoding: 'ieee-p1363'}, signature);
  if (!valid) {
    throw new Error('The SEV-SNP report signature does not verify');
  }

  checkSnpPolicy(parsed, allowMigrationAgent);

  return {
    product, measurement: parsed.measurement, parsed, tcb: reported, key: keyName,
  };
}

/**
 * The VCEK URL at AMD's key distribution service for a report.
 * @param {Object} parsed - from parseSnpReport
 * @param {string} product
 * @param {string} [base='https://kdsintf.amd.com']
 * @returns {string}
 */
function vcekUrl(parsed, product, base = 'https://kdsintf.amd.com') {
  const tcb = tcbParts(parsed.reportedTcb, product);
  const hwid = product === 'Turin' ? parsed.chipId.subarray(0, 8).toString('hex') : parsed.chipId.toString('hex');
  const query = product === 'Turin'
    ? `fmcSPL=${tcb.fmc}&blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`
    : `blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`;
  return `${base}/vcek/v1/${product}/${hwid}?${query}`;
}

// ─── Intel TDX ─────────────────────────────────────────────────────────

/**
 * Parse a TDX quote (versions 4 and 5).
 * @param {Buffer} quote
 * @returns {Object}
 */
function parseTdxQuote(quote) {
  const version = quote.readUInt16LE(0);
  const attestationKeyType = quote.readUInt16LE(2);
  const teeType = quote.readUInt32LE(4);
  if (teeType !== 0x81) {
    throw new Error('Not a TDX quote');
  }

  let offset = 48;
  let bodySize = 584;
  if (version === 5) {
    const bodyType = quote.readUInt16LE(offset);
    bodySize = quote.readUInt32LE(offset + 2);
    offset += 6;
    if (![2, 3].includes(bodyType)) {
      throw new Error(`Unsupported TDX quote body type ${bodyType}`);
    }
  } else if (version !== 4) {
    throw new Error(`Unsupported TDX quote version ${version}`);
  }

  const body = quote.subarray(offset, offset + bodySize);
  const signed = quote.subarray(0, offset + bodySize);
  const hex = (start, length) => body.subarray(start, start + length).toString('hex');
  const td = {
    teeTcbSvn: hex(0, 16),
    mrSeam: hex(16, 48),
    mrSignerSeam: hex(64, 48),
    seamAttributes: hex(112, 8),
    tdAttributes: body.readBigUInt64LE(120),
    xfam: hex(128, 8),
    mrTd: hex(136, 48),
    mrConfigId: hex(184, 48),
    mrOwner: hex(232, 48),
    mrOwnerConfig: hex(280, 48),
    rtmr: [hex(328, 48), hex(376, 48), hex(424, 48), hex(472, 48)],
    reportData: body.subarray(520, 584),
  };
  td.debug = (td.tdAttributes & 1n) === 1n;

  let cursor = offset + bodySize;
  const signatureLength = quote.readUInt32LE(cursor);
  cursor += 4;
  const signatureData = quote.subarray(cursor, cursor + signatureLength);
  const quoteSignature = signatureData.subarray(0, 64);
  const attestationKey = signatureData.subarray(64, 128);
  const certificationType = signatureData.readUInt16LE(128);
  const certificationSize = signatureData.readUInt32LE(130);
  const certification = signatureData.subarray(134, 134 + certificationSize);
  if (certificationType !== 6) {
    throw new Error(`Unsupported TDX certification data type ${certificationType}`);
  }

  const qeReport = certification.subarray(0, 384);
  const qeReportSignature = certification.subarray(384, 448);
  const authLength = certification.readUInt16LE(448);
  const qeAuthData = certification.subarray(450, 450 + authLength);
  let inner = 450 + authLength;
  const innerType = certification.readUInt16LE(inner);
  const innerSize = certification.readUInt32LE(inner + 2);
  inner += 6;
  if (innerType !== 5) {
    throw new Error(`Unsupported PCK certification data type ${innerType}`);
  }

  const pem = certification.subarray(inner, inner + innerSize).toString('utf8');
  const pckChain = [...pem.matchAll(/-{5}BEGIN CERTIFICATE-{5}[\s\S]+?-{5}END CERTIFICATE-{5}/g)].map(match => new crypto.X509Certificate(match[0]));
  return {
    version, attestationKeyType, td, signed, quoteSignature, attestationKey, qeReport, qeReportSignature, qeAuthData, pckChain,
  };
}

/**
 * Intel's TDX quoting enclave identity (the "TD_QE" identity Intel's PCS
 * publishes).  The PCK signs a report of any enclave that may use the
 * provisioning key, and a platform owner with flexible launch control can
 * grant that to an enclave of its own; only a report from Intel's quoting
 * enclave makes its attestation key Intel's.
 */
const TD_QE_IDENTITY = {
  mrsigner: 'dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5',
  isvprodid: 2,
  attributes: '11000000000000000000000000000000',
  attributesMask: 'fbffffffffffffff0000000000000000',
  miscselect: '00000000',
  miscselectMask: 'ffffffff',
};

/**
 * Problems with a quoting enclave report's identity (SGX REPORT body).
 * @param {Buffer} qeReport - 384 bytes
 * @param {Object} identity - like TD_QE_IDENTITY (hex fields)
 * @returns {string[]}
 */
function qeIdentityProblems(qeReport, identity) {
  const problems = [];
  const masked = (value, mask) => Buffer.from(value.map((byte, index) => byte & mask[index]));
  const hex = value => Buffer.from(value, 'hex');
  if (!masked(qeReport.subarray(16, 20), hex(identity.miscselectMask)).equals(hex(identity.miscselect))) {
    problems.push('miscselect');
  }

  if (!masked(qeReport.subarray(48, 64), hex(identity.attributesMask)).equals(hex(identity.attributes))) {
    problems.push('attributes');
  }

  if (!qeReport.subarray(128, 160).equals(hex(identity.mrsigner))) {
    problems.push('mrsigner');
  }

  if (qeReport.readUInt16LE(256) !== identity.isvprodid) {
    problems.push('isvprodid');
  }

  return problems;
}

/**
 * Verify a TDX quote.
 *
 * @param {Object} input
 * @param {Buffer} input.quote
 * @param {Buffer} input.reportData
 * @param {crypto.X509Certificate} [input.root] - default: Intel's SGX root CA (shipped)
 * @param {Object} [input.qeIdentity] - the quoting enclave identity required (default: Intel's TD_QE)
 * @returns {{td: Object, pckSubject: string, qeSvn: number}}
 */
function verifyTdxQuote({
  quote, reportData: expected, root = new crypto.X509Certificate(vendorRoots.intelSgxRoot), qeIdentity = TD_QE_IDENTITY,
}) {
  const parsed = parseTdxQuote(quote);
  if (parsed.attestationKeyType !== 2) {
    throw new Error('Unsupported TDX attestation key type');
  }

  if (!parsed.td.reportData.equals(expected)) {
    throw new Error('The TDX quote does not bind this nonce and evidence');
  }

  // PCK chain: leaf, intermediate CA, Intel's root.
  const chain = parsed.pckChain;
  if (chain.length < 2 || !chain.at(-1).raw.equals(root.raw)) {
    throw new Error('The PCK certificate chain does not end at Intel\'s SGX root CA');
  }

  for (let index = 0; index < chain.length; index++) {
    const parent = chain[index + 1] || root;
    if (!chain[index].checkIssued(parent) || !chain[index].verify(parent.publicKey)) {
      throw new Error('The PCK certificate chain does not verify');
    }
  }

  const p1363 = key => ({key, dsaEncoding: 'ieee-p1363'});
  if (!crypto.verify('sha256', parsed.qeReport, p1363(chain[0].publicKey), parsed.qeReportSignature)) {
    throw new Error('The quoting enclave report is not signed by the platform\'s PCK');
  }

  const identityProblems = qeIdentityProblems(parsed.qeReport, qeIdentity);
  if (identityProblems.length > 0) {
    throw new Error(`The quote was not made by Intel's TDX quoting enclave (${identityProblems.join(', ')} differ)`);
  }

  // The QE report binds the attestation key and its authentication data.
  const binding = crypto.createHash('sha256').update(parsed.attestationKey).update(parsed.qeAuthData).digest();
  if (!parsed.qeReport.subarray(320, 352).equals(binding)) {
    throw new Error('The quoting enclave report does not bind the attestation key');
  }

  const attestationKey = crypto.createPublicKey({key: Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Buffer.from([4]), parsed.attestationKey]), format: 'der', type: 'spki'});
  if (!crypto.verify('sha256', parsed.signed, p1363(attestationKey), parsed.quoteSignature)) {
    throw new Error('The TDX quote signature does not verify');
  }

  if (parsed.td.debug) {
    throw new Error('The TD is in debug mode (the host can read its memory)');
  }

  return {td: parsed.td, pckSubject: chain[0].subject, qeSvn: parsed.qeReport.readUInt16LE(258)};
}

/**
 * Verify confidential VM evidence of either kind.
 *
 * @param {{provider: string, report: string, auxblob?: string}} evidence - base64 fields
 * @param {Buffer} expected - report data
 * @param {Object} [options] - {vcek, roots, allowMigrationAgent, root, qeIdentity}
 * @returns {Object} {type, measurement, ...}
 */
function verifyConfidential(evidence, expected, options = {}) {
  const report = Buffer.from(evidence.report, 'base64');
  if (evidence.provider === 'sev_guest') {
    const certificates = parseCertificateTable(evidence.auxblob ? Buffer.from(evidence.auxblob, 'base64') : null);
    const result = verifySnpReport({
      report, reportData: expected, certificates, vcek: options.vcek, roots: options.roots, allowMigrationAgent: options.allowMigrationAgent,
    });
    return {
      type: 'sev-snp', measurement: result.measurement, product: result.product, key: result.key, tcb: result.tcb, policy: `0x${result.parsed.policy.toString(16)}`, vmpl: result.parsed.vmpl,
    };
  }

  if (evidence.provider === 'tdx_guest') {
    const result = verifyTdxQuote({
      quote: report, reportData: expected, root: options.root, qeIdentity: options.qeIdentity,
    });
    return {
      type: 'tdx', measurement: result.td.mrTd, qeSvn: result.qeSvn, rtmr: result.td.rtmr, teeTcbSvn: result.td.teeTcbSvn, mrConfigId: result.td.mrConfigId, mrOwner: result.td.mrOwner,
    };
  }

  throw new Error(`Unsupported confidential computing provider ${String(evidence.provider).slice(0, 40)}`);
}

module.exports = {
  TSM_ROOT,
  collectReport,
  reportData,
  parseSnpReport,
  snpProduct,
  tcbParts,
  parseCertificateTable,
  vcekClaims,
  verifySnpReport,
  vcekUrl,
  parseTdxQuote,
  verifyTdxQuote,
  verifyConfidential,
  amdRoots,
  TD_QE_IDENTITY,
};

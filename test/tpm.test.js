'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Tpm = require('../lib/tpm');
const ima = require('../lib/ima');
const {tempDir, hasTpmSimulator, startSwtpm, freePort} = require('./helpers');

const nonce = () => crypto.randomBytes(32).toString('hex');

// ─── TPM (software TPM, real tpm2-tools) ────────────────────────────

test('TPM attestation keys, quotes and verification', {skip: !hasTpmSimulator}, async t => {
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  assert.deepEqual(await tpm.checkAvailability(), {available: true, family: '2.0'});
  assert.equal(await tpm.isAvailable(), true);

  await assert.rejects(tpm.getAttestationKey(), /tpm2_readpublic failed/);
  const rsa = await tpm.createAttestationKey();
  assert.match(rsa.publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(rsa.handle, '0x81010002');
  await assert.rejects(tpm.createAttestationKey(), /already exists/);
  const replaced = await tpm.createAttestationKey({replace: true});
  assert.notEqual(replaced.keyId, rsa.keyId);
  assert.deepEqual(await tpm.getAttestationKey(), replaced);
  const ecc = await tpm.createAttestationKey({handle: '0x81010003', algorithm: 'ecc'});
  assert.equal(crypto.createPublicKey(ecc.publicKey).asymmetricKeyType, 'ec');

  for (const [key, handle] of [[replaced, undefined], [ecc, '0x81010003']]) {
    const value = nonce();
    const quote = await tpm.quote({nonce: value, pcrs: [7, 0, 10, 7], handle});
    assert.equal(quote.keyId, key.keyId);
    assert.deepEqual(Object.keys(quote.pcrs.sha256), ['0', '7', '10']);
    const result = Tpm.verifyQuote({quote, publicKey: key.publicKey, nonce: value.toUpperCase()});
    assert.deepEqual(result.errors, []);
    assert.equal(result.valid, true);
    assert.deepEqual(result.attest.selections, [{bank: 'sha256', pcrs: [0, 7, 10]}]);
    assert.equal(result.attest.clockInfo.safe, true);

    // Replayed quote (different nonce) is rejected.
    assert.deepEqual(Tpm.verifyQuote({quote, publicKey: key.publicKey, nonce: nonce()}).errors, ['Quote nonce does not match (stale or replayed quote)']);

    // A forged PCR value does not match the signed digest.
    const forged = structuredClone(quote);
    forged.pcrs.sha256['7'] = 'ab'.repeat(32);
    assert.deepEqual(Tpm.verifyQuote({quote: forged, publicKey: key.publicKey, nonce: value}).errors, ['Reported PCR values do not match the signed PCR digest']);

    // Some other key cannot vouch for this quote.
    const other = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'}).publicKey.export({type: 'spki', format: 'pem'});
    assert.deepEqual(Tpm.verifyQuote({quote, publicKey: other, nonce: value}).errors, ['Quote signature does not verify with the trusted attestation key']);
  }

  // Expected PCR policy
  const value = nonce();
  const quote = await tpm.quote({nonce: value, pcrs: [0, 1]});
  const zero = '00'.repeat(32);
  assert.equal(Tpm.verifyQuote({
    quote, publicKey: replaced.publicKey, nonce: value, expectedPcrs: {sha256: {0: zero, 1: `0x${zero}`}},
  }).valid, true);
  assert.deepEqual(Tpm.verifyQuote({
    quote, publicKey: replaced.publicKey, nonce: value, expectedPcrs: {sha256: {1: 'ff'.repeat(32), 5: zero}, sha1: {0: zero}},
  }).errors, [
    'PCR sha256:1 differs from the expected value',
    'PCR sha256:5 was not quoted',
    'PCR sha1:0 was not quoted',
  ]);

  // Malformed inputs
  const missing = structuredClone(quote);
  delete missing.pcrs.sha256['1'];
  assert.ok(Tpm.verifyQuote({quote: missing, publicKey: replaced.publicKey, nonce: value}).errors.includes('Missing or malformed value for PCR sha256:1'));
  assert.ok(Tpm.verifyQuote({quote: {...quote, pcrs: undefined}, publicKey: replaced.publicKey, nonce: value}).errors.includes('Missing or malformed value for PCR sha256:0'));
  assert.deepEqual(Tpm.verifyQuote({quote: {...quote, hashAlg: 'md5'}, publicKey: replaced.publicKey, nonce: value}).errors, ['Unsupported signature hash md5']);
  assert.deepEqual(Tpm.verifyQuote({quote: {...quote, hashAlg: undefined}, publicKey: replaced.publicKey, nonce: value}).errors, []);
  assert.equal(Tpm.verifyQuote({quote: {...quote, message: 'AAAA'}, publicKey: replaced.publicKey, nonce: value}).valid, false);
  assert.equal(Tpm.verifyQuote({quote: null, publicKey: replaced.publicKey, nonce: value}).valid, false);

  // PCR reads, extends and randomness
  await tpm.extendPcr(16, 'sha256', 'AB'.repeat(32));
  const expected = crypto.createHash('sha256').update(Buffer.alloc(32)).update(Buffer.from('ab'.repeat(32), 'hex')).digest('hex');
  assert.deepEqual(await tpm.readPcrs([16]), {16: expected});
  assert.equal((await tpm.readPcrs()).constructor, Object);
  assert.equal((await tpm.getRandom(16)).length, 16);
  assert.equal((await tpm.getRandom()).length, 32);
});

test('TPM input validation and unavailability', async t => {
  const tpm = new Tpm({devices: []});
  assert.deepEqual(await tpm.checkAvailability(), {available: false, reason: 'No TPM device node present'});
  await assert.rejects(tpm.quote({nonce: 'xyz'}), /1 to 32 bytes/);
  await assert.rejects(tpm.quote({nonce: 'aa'.repeat(33)}), /1 to 32 bytes/);
  await assert.rejects(tpm.quote({nonce: 'aa', pcrs: []}), /non-empty array/);
  await assert.rejects(tpm.quote({nonce: 'aa', pcrs: [24]}), /Invalid PCR index: 24/);
  await assert.rejects(tpm.quote({nonce: 'aa', pcrs: [1.5]}), /Invalid PCR index/);
  await assert.rejects(tpm.quote({nonce: 'aa', bank: 'md5'}), /Unsupported PCR bank/);
  await assert.rejects(tpm.quote({nonce: 'aa', handle: '0x80000000'}), /Invalid persistent handle/);
  await assert.rejects(tpm.extendPcr(16, 'sha256', 'abc'), /32 bytes of hex/);
  await assert.rejects(tpm.getRandom(0), /between 1 and 64/);
  await assert.rejects(tpm.getRandom(65), /between 1 and 64/);
  await assert.rejects(tpm.createAttestationKey({algorithm: 'dsa'}), /Unsupported AK algorithm/);
  assert.throws(() => new Tpm({akHandle: 'x; rm -rf /'}), /Invalid persistent handle/);

  const port = await freePort();
  const closed = await new Tpm({tcti: `swtpm:host=127.0.0.1,port=${port}`, timeout: 10_000}).checkAvailability();
  assert.equal(closed.available, false);
  assert.match(closed.reason, /tpm2_getcap failed/);

  const originalPath = process.env.PATH;
  process.env.PATH = tempDir(t);
  try {
    assert.deepEqual(await new Tpm({tcti: 'swtpm:port=1'}).checkAvailability(), {available: false, reason: 'tpm2-tools not installed'});
  } finally {
    process.env.PATH = originalPath;
  }

  // Tools that misbehave are not trusted.
  const short = new Tpm({tcti: 'x', run: async () => 'abcd\n'});
  await assert.rejects(short.getRandom(4), /wrong number of bytes/);
  const flushFails = new Tpm({
    tcti: 'x',
    async run(file) {
      if (file === 'tpm2_flushcontext') {
        throw new Error('no resource manager');
      }

      return '';
    },
  });
  await flushFails._flushTransient();
});

test('TPMS_ATTEST parsing rejects anything that is not a well-formed quote', () => {
  const build = ({magic = 0xFF_54_43_47, type = 0x80_18, count = 1, trailing = Buffer.alloc(0), select = [0x81, 0x00, 0x00]} = {}) => {
    const parts = [];
    const u16 = value => {
      const buffer = Buffer.alloc(2);
      buffer.writeUInt16BE(value);
      parts.push(buffer);
    };

    const u32 = value => {
      const buffer = Buffer.alloc(4);
      buffer.writeUInt32BE(value);
      parts.push(buffer);
    };

    u32(magic);
    u16(type);
    u16(2);
    parts.push(Buffer.from([0, 0x0B]));
    u16(2);
    parts.push(Buffer.from('aa55', 'hex'), Buffer.alloc(8), Buffer.alloc(8), Buffer.from([0]), Buffer.alloc(8));
    u32(count);
    for (let i = 0; i < Math.min(count, 2); i++) {
      u16(i === 0 ? 0x00_0B : 0x00_99);
      parts.push(Buffer.from([select.length]), Buffer.from(select));
    }

    u16(32);
    parts.push(Buffer.alloc(32), trailing);
    return Buffer.concat(parts);
  };

  const parsed = Tpm.parseAttest(build({count: 2}));
  assert.deepEqual(parsed.selections, [{bank: 'sha256', pcrs: [0, 7]}, {bank: '0x99', pcrs: [0, 7]}]);
  assert.equal(parsed.extraData, 'aa55');
  assert.equal(parsed.clockInfo.safe, false);
  assert.throws(() => Tpm.parseAttest(build({magic: 1})), /TPM_GENERATED_VALUE/);
  assert.throws(() => Tpm.parseAttest(build({type: 0x80_17})), /is not a quote/);
  assert.throws(() => Tpm.parseAttest(build({count: 17})), /Too many PCR selections/);
  assert.throws(() => Tpm.parseAttest(build({trailing: Buffer.from([1])})), /Trailing bytes/);
  assert.throws(() => Tpm.parseAttest(build().subarray(0, 20)), /Truncated/);
  assert.throws(() => Tpm.parseAttest(Buffer.alloc(3)), /Truncated/);
  const truncatedSelect = build();
  assert.throws(() => Tpm.parseAttest(truncatedSelect.subarray(0, -34)), /Truncated/);

  assert.deepEqual(Tpm.parsePcrYaml('sha256:\n  0 : 0xAB\n  10: 0xcd\nmd5:\n  0: 0x00\nsha1: nope\n'), {sha256: {0: 'ab', 10: 'cd'}});
  assert.deepEqual(Tpm.parsePcrYaml(''), {});
});

// ─── IMA log replay ─────────────────────────────────────────────────

/**
 * Encode template fields ([u32 length][data])*.
 */
function fields(parts, littleEndian = true) {
  return Buffer.concat(parts.flatMap(part => {
    const length = Buffer.alloc(4);
    if (littleEndian) {
      length.writeUInt32LE(part.length);
    } else {
      length.writeUInt32BE(part.length);
    }

    return [length, part];
  }));
}

function digestField(algorithm, digest) {
  return Buffer.concat([Buffer.from(`${algorithm}:\0`), digest]);
}

/**
 * Encode one binary log entry.
 */
function entry({pcr = 10, template = 'ima-ng', data, digest, littleEndian = true}) {
  const u32 = value => {
    const buffer = Buffer.alloc(4);
    if (littleEndian) {
      buffer.writeUInt32LE(value);
    } else {
      buffer.writeUInt32BE(value);
    }

    return buffer;
  };

  const templateDigest = digest || crypto.createHash('sha1').update(data).digest();
  return Buffer.concat([u32(pcr), templateDigest, u32(template.length), Buffer.from(template), u32(data.length), data]);
}

test('IMA log replay reproduces the TPM PCR 10 value and exposes file measurements', {skip: !hasTpmSimulator}, async t => {
  const fileHash = name => crypto.createHash('sha256').update(name).digest();
  const records = [
    {data: fields([digestField('sha256', fileHash('boot_aggregate')), Buffer.from('boot_aggregate\0')])},
    {data: fields([digestField('sha256', fileHash('node v1')), Buffer.from('/usr/bin/node\0')])},
    {template: 'ima-sig', data: fields([digestField('sha256', fileHash('libc')), Buffer.from('/usr/lib/libc.so.6\0'), Buffer.from('0302abcd', 'hex')])},
    {template: 'ima-buf', data: fields([digestField('sha256', fileHash('cmdline')), Buffer.from('kexec-cmdline\0'), Buffer.from('ro quiet')])},
    {data: fields([digestField('sha256', fileHash('node v2')), Buffer.from('/usr/bin/node\0')])},
    {data: fields([digestField('sha256', fileHash('violated')), Buffer.from('/var/log/x\0')]), digest: Buffer.alloc(20)},
    {pcr: 11, data: fields([digestField('sha256', fileHash('other pcr')), Buffer.from('/other\0')])},
  ];
  const log = Buffer.concat(records.map(record => entry(record)));
  const directory = tempDir(t);
  const logFile = path.join(directory, 'binary_runtime_measurements');
  fs.writeFileSync(logFile, log);

  const entries = ima.parseBinaryLog(ima.readLog(logFile));
  assert.equal(entries.length, 7);
  assert.equal(entries[1].path, '/usr/bin/node');
  assert.equal(entries[2].templateName, 'ima-sig');
  assert.equal(entries[5].violation, true);

  // Extend a real TPM exactly as the kernel does, then compare with the replay.
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  for (const item of entries.filter(value => value.pcr === 10)) {
    for (const bank of ['sha1', 'sha256']) {
      const size = Tpm.HASH_SIZES[bank];
      const digest = item.violation ? 'ff'.repeat(size) : crypto.createHash(bank).update(item.templateData).digest('hex');
      await tpm.extendPcr(10, bank, digest);
    }
  }

  assert.equal(ima.replay(entries, 'sha256'), (await tpm.readPcrs([10], 'sha256'))['10']);
  assert.equal(ima.replay(entries, 'sha1'), (await tpm.readPcrs([10], 'sha1'))['10']);
  assert.equal(ima.replay(entries), ima.replay(entries, 'sha256', 10));

  // Quoted and verified end to end.
  await tpm.createAttestationKey();
  const key = await tpm.getAttestationKey();
  const value = nonce();
  const quote = await tpm.quote({nonce: value, pcrs: [10]});
  assert.equal(Tpm.verifyQuote({
    quote, publicKey: key.publicKey, nonce: value, expectedPcrs: {sha256: {10: ima.replay(entries)}},
  }).valid, true);

  // Dropping an entry from the log (hiding a measurement) breaks the match.
  const hidden = entries.filter(item => item.fileHash !== fileHash('node v2').toString('hex'));
  assert.equal(Tpm.verifyQuote({
    quote, publicKey: key.publicKey, nonce: value, expectedPcrs: {sha256: {10: ima.replay(hidden)}},
  }).valid, false);

  const byPath = ima.measurementsByPath(entries);
  assert.deepEqual(byPath.get('/usr/bin/node'), {
    algorithm: 'sha256',
    hash: fileHash('node v2').toString('hex'),
    count: 2,
    hashes: [fileHash('node v1').toString('hex'), fileHash('node v2').toString('hex')],
  });
  assert.equal(byPath.get('/usr/lib/libc.so.6').hash, fileHash('libc').toString('hex'));
  // Only what the quoted PCR covers: not other PCRs, not violation entries.
  assert.equal(byPath.has('/other'), false);
  assert.equal(byPath.has('/var/log/x'), false);
  assert.equal(ima.measurementsByPath(entries, {pcr: 11}).get('/other').hash, fileHash('other pcr').toString('hex'));

  // The log keeps growing after a quote: the prefix that replays to the
  // quoted value is what the TPM backs.
  const quoted = quote.pcrs.sha256['10'];
  assert.equal(ima.backedEntries(entries, quoted).length, 6, 'up to the last PCR 10 entry');
  const later = ima.parseBinaryLog(entry({data: fields([digestField('sha256', fileHash('later')), Buffer.from('/usr/bin/later\0')])}));
  const grown = [...entries, ...later];
  assert.equal(ima.backedEntries(grown, quoted.toUpperCase()).length, 6);
  assert.equal(ima.measurementsByPath(ima.backedEntries(grown, quoted)).has('/usr/bin/later'), false);
  assert.equal(ima.backedEntries(grown, 'ab'.repeat(32)), null);
  assert.equal(ima.backedEntries([], '00'.repeat(32)).length, 0);
});

test('IMA log parsing: legacy templates, big-endian logs and malformed input', () => {
  const legacyDigest = crypto.randomBytes(20);
  const legacy = entry({template: 'ima', data: Buffer.concat([legacyDigest, Buffer.from('/sbin/init\0')]), digest: legacyDigest});
  const oldDigestField = entry({data: fields([crypto.randomBytes(20), Buffer.from('/bin/sh\0')])});
  const entries = ima.parseBinaryLog(Buffer.concat([legacy, oldDigestField]));
  assert.equal(entries[0].path, undefined);
  assert.equal(entries[1].fileHashAlgorithm, 'sha1');
  const expected = crypto.createHash('sha1').update(Buffer.alloc(20)).update(legacyDigest).digest();
  const expectedBoth = crypto.createHash('sha1').update(expected).update(crypto.createHash('sha1').update(entries[1].templateData).digest()).digest('hex');
  assert.equal(ima.replay(entries, 'sha1'), expectedBoth);
  assert.throws(() => ima.replay(entries, 'sha256'), /Cannot replay template "ima"/);
  assert.throws(() => ima.replay(entries, 'md5'), /Unsupported bank/);
  // Renaming a template cannot make the SHA-1 replay take a digest from the log.
  const renamed = ima.parseBinaryLog(entry({template: 'xx-ng', data: Buffer.from('x'), digest: crypto.randomBytes(20)}));
  assert.throws(() => ima.replay(renamed, 'sha1'), /Cannot replay template "xx-ng" into the sha1 bank/);
  assert.equal(ima.measurementsByPath(entries).size, 1);

  const bigEndian = entry({littleEndian: false, data: fields([digestField('sha256', Buffer.alloc(32, 1)), Buffer.from('/be\0')], false)});
  assert.equal(ima.parseBinaryLog(bigEndian, {littleEndian: false})[0].path, '/be');

  const good = entry({data: fields([digestField('sha256', Buffer.alloc(32)), Buffer.from('/x\0')])});
  assert.throws(() => ima.parseBinaryLog(good.subarray(0, 10)), /Truncated IMA log entry header/);
  const badName = Buffer.from(good);
  badName.writeUInt32LE(300, 24);
  assert.throws(() => ima.parseBinaryLog(badName), /Malformed IMA template name/);
  assert.throws(() => ima.parseBinaryLog(good.subarray(0, -1)), /Truncated IMA template data/);
  const badField = entry({data: Buffer.from([10, 0, 0, 0, 1])});
  assert.throws(() => ima.parseBinaryLog(badField), /Truncated IMA template field/);
  const shortField = entry({data: Buffer.from([1, 0])});
  assert.throws(() => ima.parseBinaryLog(shortField), /Truncated IMA template field/);
  const emptyFields = ima.parseBinaryLog(entry({data: Buffer.alloc(0)}))[0];
  assert.equal(emptyFields.path, '');
  assert.equal(ima.DEFAULT_LOG, '/sys/kernel/security/ima/binary_runtime_measurements');
});

test('IMA buffer measurements are not file measurements', () => {
  const fileHash = name => crypto.createHash('sha256').update(name).digest();
  // A keyring can be named like a file; with a KEY_CHECK rule its keys are
  // measured as ima-buf entries under that name (here: the genuine program's
  // contents, loaded as a key after a modified program ran).
  const entries = ima.parseBinaryLog(Buffer.concat([
    entry({data: fields([digestField('sha256', fileHash('modified')), Buffer.from('/srv/app/server.js\0')])}),
    entry({template: 'ima-buf', data: fields([digestField('sha256', fileHash('genuine')), Buffer.from('/srv/app/server.js\0'), Buffer.from('genuine')])}),
    entry({template: 'ima-buf', data: fields([digestField('sha256', fileHash('ro quiet')), Buffer.from('kexec-cmdline\0'), Buffer.from('ro quiet')])}),
  ]));
  assert.equal(entries[1].path, '/srv/app/server.js');
  const byPath = ima.measurementsByPath(entries);
  assert.deepEqual([...byPath.keys()], ['/srv/app/server.js']);
  assert.deepEqual(byPath.get('/srv/app/server.js'), {
    algorithm: 'sha256', hash: fileHash('modified').toString('hex'), count: 1, hashes: [fileHash('modified').toString('hex')],
  });
});

test('quote verification with a self-made signer covers unusual quote shapes', () => {
  // A quote is just a signed TPMS_ATTEST; build one to exercise the verifier.
  const keys = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
  const publicKey = keys.publicKey.export({type: 'spki', format: 'pem'});
  const make = selections => {
    const parts = [Buffer.from('ff54434780180000000220aa', 'hex').subarray(0, 6), Buffer.from([0, 0]), Buffer.from([0, 1, 0xAA]), Buffer.alloc(8 + 4 + 4 + 1 + 8)];
    const count = Buffer.alloc(4);
    count.writeUInt32BE(selections.length);
    parts.push(count);
    for (const {algorithm, bitmap} of selections) {
      const id = Buffer.alloc(2);
      id.writeUInt16BE(algorithm);
      parts.push(id, Buffer.from([bitmap.length]), Buffer.from(bitmap));
    }

    const digest = crypto.createHash('sha256').update(Buffer.alloc(32)).digest();
    parts.push(Buffer.from([0, 32]), digest);
    const message = Buffer.concat(parts);
    return {message: message.toString('base64'), signature: crypto.sign('sha256', message, keys.privateKey).toString('base64'), hashAlg: 'sha256'};
  };

  const unknownBank = make([{algorithm: 0x00_99, bitmap: [1]}]);
  assert.deepEqual(Tpm.verifyQuote({quote: {...unknownBank, pcrs: {}}, publicKey, nonce: 'aa'}).errors, [
    'Unsupported PCR bank in quote: 0x99',
    'Reported PCR values do not match the signed PCR digest',
  ]);
  const good = make([{algorithm: 0x00_0B, bitmap: [1]}]);
  assert.equal(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: '00'.repeat(32)}}}, publicKey, nonce: 'AA'}).valid, true);
  assert.deepEqual(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: '00'}}}, publicKey, nonce: 'aa'}).errors.slice(0, 1), ['Missing or malformed value for PCR sha256:0']);

  // Values outside the signed selection cannot ride along with a valid quote.
  assert.deepEqual(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: '00'.repeat(32), 10: 'ab'.repeat(32)}, sha1: {10: 'cd'.repeat(20)}, sha384: null}}, publicKey, nonce: 'aa'}).errors, [
    'PCR sha256:10 was reported but not quoted',
    'PCR sha1:10 was reported but not quoted',
  ]);
  // A quoted PCR reported a second time under another spelling, with
  // another value, next to its real value.
  assert.deepEqual(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: '00'.repeat(32), '00': 'ab'.repeat(32), ' 0': 'cd'.repeat(32)}}}, publicKey, nonce: 'aa'}).errors, [
    'PCR sha256:00 was reported but not quoted',
    'PCR sha256: 0 was reported but not quoted',
  ]);
  // Values that are not lowercase hex (Buffer.from(value, 'hex') would decode "AB" and "ab" alike).
  for (const value of [`${'00'.repeat(31)}zz`, `${'00'.repeat(31)}AB`, `0x${'0'.repeat(62)}`]) {
    assert.ok(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: value}}}, publicKey, nonce: 'aa'}).errors.includes('Missing or malformed value for PCR sha256:0'), value);
  }

  // SHA-1 signatures and missing nonces are refused.
  assert.deepEqual(Tpm.verifyQuote({quote: {...good, hashAlg: 'sha1', pcrs: {sha256: {0: '00'.repeat(32)}}}, publicKey, nonce: 'aa'}).errors, ['Unsupported signature hash sha1']);
  for (const nonce of ['', undefined, 'xyz', 'a']) {
    assert.deepEqual(Tpm.verifyQuote({quote: {...good, pcrs: {sha256: {0: '00'.repeat(32)}}}, publicKey, nonce}).errors, ['A nonce (hex) is required to verify a quote']);
  }
});

test('TPM tool output without optional fields', async () => {
  const tpm = new Tpm({tcti: 'fake', run: async file => (file === 'tpm2_getcap' ? 'TPM2_PT_MANUFACTURER: IBM\n' : '')});
  assert.deepEqual(await tpm.checkAvailability(), {available: true, family: null});
  assert.deepEqual(await tpm.readPcrs([0]), {});
});

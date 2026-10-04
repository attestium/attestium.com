'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const asn1 = require('../lib/asn1');
const {getAuthority, signingCertificate} = require('./fixtures/sigstore');
const {hasOpenssl} = require('./helpers');

/**
 * DER encoding of one element: tag byte(s), definite length, content.
 */
function der(tag, ...parts) {
  const body = Buffer.concat(parts.map(part => (Buffer.isBuffer(part) ? part : Buffer.from(part))));
  let length;
  if (body.length < 0x80) {
    length = Buffer.from([body.length]);
  } else {
    const bytes = [];
    for (let value = body.length; value > 0; value = Math.floor(value / 256)) {
      bytes.unshift(value % 256);
    }

    length = Buffer.from([0x80 | bytes.length, ...bytes]);
  }

  return Buffer.concat([Buffer.from(Array.isArray(tag) ? tag : [tag]), length, body]);
}

const sequence = (...parts) => der(0x30, ...parts);
const hex = value => Buffer.from(value.replaceAll(' ', ''), 'hex');

test('parse reads primitive and constructed elements', () => {
  const buffer = sequence(der(0x02, [0x05]), der(0x04, 'abc'), sequence());
  const element = asn1.parse(buffer);
  assert.strictEqual(element.tag, 16);
  assert.strictEqual(element.tagClass, 0);
  assert.strictEqual(element.constructed, true);
  assert.strictEqual(element.children.length, 3);
  assert.strictEqual(asn1.integer(element.children[0]), 5n);
  assert.strictEqual(asn1.content(element.children[1]).toString(), 'abc');
  assert.deepStrictEqual(element.children[2].children, []);
  assert.deepStrictEqual(asn1.raw(element.children[1]), der(0x04, 'abc'));
  assert.strictEqual(element.children[1].children, null);
});

test('parse reads long lengths and context-specific tags', () => {
  const long = Buffer.alloc(300, 7);
  const element = asn1.parse(der(0xA3, der(0x04, long)));
  assert.strictEqual(element.tagClass, 2);
  assert.strictEqual(element.tag, 3);
  assert.strictEqual(asn1.content(element.children[0]).length, 300);
});

test('parse reads high tag numbers', () => {
  // [APPLICATION 200]: 0x5F then 0x81 0x48 (1*128 + 72)
  const element = asn1.parse(Buffer.from([0x5F, 0x81, 0x48, 0x01, 0xFF]));
  assert.strictEqual(element.tagClass, 1);
  assert.strictEqual(element.tag, 200);
  assert.strictEqual(element.contentStart, 4);
});

test('parse rejects malformed DER', () => {
  const cases = [
    [Buffer.from([0x04]), /truncated/],
    [Buffer.from([0x1F, 0x81]), /tag truncated/],
    [Buffer.from([0x30, 0x80, 0x00, 0x00]), /Indefinite/],
    [Buffer.from([0x04, 0x87, 1, 2, 3, 4, 5, 6, 7]), /length out of range/],
    [Buffer.from([0x04, 0x82, 0x01]), /length out of range/],
    [Buffer.from([0x04, 0x05, 0x01]), /exceeds its container/],
    [Buffer.from([0x04, 0x01, 0x01, 0x00]), /Trailing data/],
    // A child whose header runs past its parent.
    [Buffer.from([0x30, 0x03, 0x1F, 0x81, 0x01]), /truncated/],
    [Buffer.from([0x30, 0x02, 0x1F, 0x81, 0x01]), /truncated/],
  ];
  for (const [buffer, pattern] of cases) {
    assert.throws(() => asn1.parse(buffer), error => error instanceof asn1.Asn1Error && pattern.test(error.message), buffer.toString('hex'));
  }
});

test('parse limits nesting depth', () => {
  let nested = Buffer.alloc(0);
  for (let depth = 0; depth < 65; depth++) {
    nested = sequence(nested);
  }

  assert.strictEqual(asn1.parse(nested).tag, 16);
  assert.throws(() => asn1.parse(sequence(nested)), /nesting too deep/);
});

test('parseElement parses within a window', () => {
  const buffer = Buffer.concat([der(0x04, 'x'), der(0x02, [0x01])]);
  const second = asn1.parseElement(buffer, 3);
  assert.strictEqual(second.start, 3);
  assert.strictEqual(asn1.integer(second), 1n);
  assert.throws(() => asn1.parseElement(buffer, 0, 2), /exceeds its container/);
});

test('oid decodes object identifiers', () => {
  // 1.2.840.113549.1.7.2 (CMS signed data)
  assert.strictEqual(asn1.oid(asn1.parse(hex('06 09 2a 86 48 86 f7 0d 01 07 02'))), '1.2.840.113549.1.7.2');
  // 2.5.29.17 (subjectAltName)
  assert.strictEqual(asn1.oid(asn1.parse(hex('06 03 55 1d 11'))), '2.5.29.17');
  // 2.999.3: the first subidentifier (1079) is 80 + 999
  assert.strictEqual(asn1.oid(asn1.parse(hex('06 03 88 37 03'))), '2.999.3');
  // 0.9.2342 (a first arc of 0)
  assert.strictEqual(asn1.oid(asn1.parse(hex('06 03 09 92 26'))), '0.9.2342');
});

test('oid rejects other elements and truncated identifiers', () => {
  assert.throws(() => asn1.oid(asn1.parse(der(0x04, [0x2A]))), /Not an OBJECT IDENTIFIER/);
  assert.throws(() => asn1.oid(asn1.parse(Buffer.from([0x06, 0x00]))), /Not an OBJECT IDENTIFIER/);
  assert.throws(() => asn1.oid(asn1.parse(hex('06 02 2a 86'))), /truncated OBJECT IDENTIFIER/);
});

test('text decodes the string types', () => {
  assert.strictEqual(asn1.text(asn1.parse(der(0x0C, Buffer.from('héllo ✓')))), 'héllo ✓');
  assert.strictEqual(asn1.text(asn1.parse(der(0x13, 'Printable'))), 'Printable');
  assert.strictEqual(asn1.text(asn1.parse(der(0x14, Buffer.from([0x54, 0xE9])))), 'Té');
  assert.strictEqual(asn1.text(asn1.parse(der(0x16, 'ia5@example.com'))), 'ia5@example.com');
  assert.strictEqual(asn1.text(asn1.parse(der(0x1A, 'visible'))), 'visible');
  // BMPString: UTF-16 big endian
  assert.strictEqual(asn1.text(asn1.parse(der(0x1E, Buffer.from([0x00, 0x41, 0x04, 0x14])))), 'AД');
  assert.throws(() => asn1.text(asn1.parse(der(0x04, 'octets'))), /Not a string \(tag 4\)/);
});

test('integer decodes signed big-endian values', () => {
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, [0x00]))), 0n);
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, [0x7F]))), 127n);
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, [0x00, 0x80]))), 128n);
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, [0xFF]))), -1n);
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, [0x80, 0x00]))), -32_768n);
  const big = crypto.randomBytes(20);
  big[0] &= 0x7F;
  assert.strictEqual(asn1.integer(asn1.parse(der(0x02, big))), BigInt(`0x${big.toString('hex')}`));
  assert.throws(() => asn1.integer(asn1.parse(der(0x02, []))), /Not an INTEGER/);
  assert.throws(() => asn1.integer(asn1.parse(der(0x04, [1]))), /Not an INTEGER/);
});

test('time decodes UTCTime and GeneralizedTime', () => {
  assert.strictEqual(asn1.time(asn1.parse(der(0x17, '490101000000Z'))).toISOString(), '2049-01-01T00:00:00.000Z');
  assert.strictEqual(asn1.time(asn1.parse(der(0x17, '500101000000Z'))).toISOString(), '1950-01-01T00:00:00.000Z');
  assert.strictEqual(asn1.time(asn1.parse(der(0x17, '991231235959Z'))).toISOString(), '1999-12-31T23:59:59.000Z');
  assert.strictEqual(asn1.time(asn1.parse(der(0x18, '20260930122306Z'))).toISOString(), '2026-09-30T12:23:06.000Z');
  assert.strictEqual(asn1.time(asn1.parse(der(0x18, '20260930122306.25Z'))).toISOString(), '2026-09-30T12:23:06.250Z');
  for (const buffer of [der(0x17, '2601011200Z'), der(0x18, '20260930122306+0100'), der(0x18, '260930122306Z'), der(0x04, '20260930122306Z')]) {
    assert.throws(() => asn1.time(asn1.parse(buffer)), /Not a time/);
  }
});

test('certificateExtensions reads a real certificate', {skip: !hasOpenssl && 'OpenSSL is not installed'}, () => {
  const {ca} = getAuthority();
  const certificate = signingCertificate({repository: 'octo/app', commit: 'c'.repeat(40)});
  const extensions = asn1.certificateExtensions(certificate.der);
  assert.strictEqual(extensions.get('2.5.29.19').critical, true);
  assert.strictEqual(extensions.get('2.5.29.37').critical, false);
  assert.strictEqual(asn1.text(asn1.parse(extensions.get('1.3.6.1.4.1.57264.1.13').value)), 'c'.repeat(40));
  const san = asn1.parse(extensions.get('2.5.29.17').value);
  assert.strictEqual(asn1.content(san.children[0]).toString(), 'https://github.com/octo/app/.github/workflows/release.yml@refs/heads/main');
  // The certificate authority's own key usage is critical, too.
  assert.strictEqual(asn1.certificateExtensions(ca.root.der).get('2.5.29.15').critical, true);
});

test('certificateExtensions reads an explicit non-critical flag', () => {
  // TBSCertificate [3] { Extensions { Extension { oid, critical FALSE, value } } }
  const extension = sequence(hex('06 03 55 1d 13'), der(0x01, [0x00]), der(0x04, sequence()));
  const certificate = sequence(sequence(der(0x02, [1]), der(0xA3, sequence(extension))));
  const extensions = asn1.certificateExtensions(certificate);
  assert.deepStrictEqual([...extensions.keys()], ['2.5.29.19']);
  assert.strictEqual(extensions.get('2.5.29.19').critical, false);
  assert.deepStrictEqual(extensions.get('2.5.29.19').value, sequence());
});

test('certificateExtensions of a version 1 certificate is empty', () => {
  // A TBSCertificate without the version field (version 1), which cannot
  // carry extensions: serial, signature algorithm, issuer, validity,
  // subject, key.
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const ecdsaWithSha256 = sequence(hex('06 08 2a 86 48 ce 3d 04 03 02'));
  const name = sequence(der(0x31, sequence(hex('06 03 55 04 03'), der(0x0C, 'v1'))));
  const tbs = sequence(der(0x02, [1]), ecdsaWithSha256, name, sequence(der(0x17, '250101000000Z'), der(0x17, '350101000000Z')), name, publicKey.export({type: 'spki', format: 'der'}));
  const signature = crypto.sign('sha256', tbs, privateKey);
  const v1 = sequence(tbs, ecdsaWithSha256, der(0x03, Buffer.from([0]), signature));
  const certificate = new crypto.X509Certificate(v1);
  assert.strictEqual(certificate.subject, 'CN=v1');
  assert.ok(certificate.verify(publicKey));
  assert.strictEqual(asn1.certificateExtensions(v1).size, 0);
});

test('reads a real RFC 3161 timestamp response', () => {
  const response = fs.readFileSync(path.join(__dirname, 'fixtures/sigstore-data/tsa-response.tsr'));
  const parsed = asn1.parse(response);
  // TimeStampResp: PKIStatusInfo (granted), then a CMS ContentInfo.
  assert.strictEqual(asn1.integer(parsed.children[0].children[0]), 0n);
  assert.strictEqual(asn1.oid(parsed.children[1].children[0]), '1.2.840.113549.1.7.2');
});

test('certificateExtensions refuses duplicate and malformed extensions', () => {
  const certificateWith = (...extensions) => sequence(sequence(der(0x02, [1]), der(0xA3, sequence(...extensions))));
  const claim = value => sequence(hex('06 0a 2b 06 01 04 01 83 bf 30 01 0d'), der(0x04, der(0x0C, value)));
  // Two source commits: a reader keeping the first and one keeping the last disagree.
  assert.throws(() => asn1.certificateExtensions(certificateWith(claim('a'.repeat(40)), claim('b'.repeat(40)))), /Duplicate certificate extension 1\.3\.6\.1\.4\.1\.57264\.1\.13/);
  assert.strictEqual(asn1.certificateExtensions(certificateWith(claim('a'.repeat(40)))).size, 1);
  for (const extension of [
    sequence(hex('06 03 55 1d 13')),
    sequence(hex('06 03 55 1d 13'), der(0x0C, 'not an octet string')),
    sequence(hex('06 03 55 1d 13'), der(0x02, [1]), der(0x04, sequence())),
    sequence(hex('06 03 55 1d 13'), der(0x01, [0, 0]), der(0x04, sequence())),
    sequence(hex('06 03 55 1d 13'), der(0x01, [0xFF]), der(0x04, sequence()), der(0x04, sequence())),
    der(0x04, 'x'),
  ]) {
    assert.throws(() => asn1.certificateExtensions(certificateWith(extension)), /Malformed certificate extension/);
  }

  assert.throws(() => asn1.certificateExtensions(sequence(sequence(der(0x02, [1]), der(0xA3, der(0x04, 'x'))))), /Malformed certificate extensions/);
  assert.throws(() => asn1.certificateExtensions(sequence(sequence(der(0x02, [1]), der(0xA3)))), /Malformed certificate extensions/);
});

test('time refuses dates that do not exist', () => {
  for (const buffer of [der(0x18, '20260230000000Z'), der(0x17, '261301000000Z'), der(0x18, '20260930246000Z'), der(0x18, '20260930235960Z')]) {
    assert.throws(() => asn1.time(asn1.parse(buffer)), /Not a time/);
  }

  assert.strictEqual(asn1.time(asn1.parse(der(0x18, '20240229235959Z'))).toISOString(), '2024-02-29T23:59:59.000Z');
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {execFileSync} = require('node:child_process');
const {
  crc32, listZip, readZipFiles, readMember,
} = require('../lib/zip');
const {tempDir, writeFiles, which} = require('./helpers');

const hasPython = which('python3');
const hasZip = which('zip');

/**
 * Write a zip with Python's zipfile.  `members` is a list of
 * [name, text, compression] where compression is a zipfile constant name.
 */
function pythonZip(t, members, {extraScript = ''} = {}) {
  const output = path.join(tempDir(t, 'attestium-zip-'), 'archive.zip');
  const script = [
    'import json, sys, zipfile',
    'members = json.loads(sys.argv[2])',
    'with zipfile.ZipFile(sys.argv[1], "w") as archive:',
    '    for name, text, compression in members:',
    '        archive.writestr(name, text, compress_type=getattr(zipfile, compression))',
    extraScript,
  ].join('\n');
  execFileSync('python3', ['-c', script, output, JSON.stringify(members)]);
  return fs.readFileSync(output);
}

/**
 * A hand-built zip for malformed and ZIP64 cases.  Each entry may override
 * the sizes and offset its central directory record states and carry an
 * extra field; the end record's fields may be overridden too.
 */
function craftZip(entries, {end = {}, prefix = Buffer.alloc(0)} = {}) {
  const locals = [];
  const centrals = [];
  let offset = prefix.length;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const raw = Buffer.from(entry.data || '');
    const method = entry.method ?? 0;
    const data = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const crc = entry.crc ?? crc32(raw);
    // The local header may name the member differently (a crafted archive).
    const localName = Buffer.from(entry.localName ?? entry.name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04_03_4B_50, 0);
    local.writeUInt16LE(entry.localMethod ?? method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(localName.length, 26);
    locals.push(local, localName, data);

    const extra = entry.extra || Buffer.alloc(0);
    const comment = Buffer.from(entry.comment || '');
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02_01_4B_50, 0);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(entry.compressedSize ?? data.length, 20);
    central.writeUInt32LE(entry.size ?? raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt16LE(comment.length, 32);
    central.writeUInt32LE(entry.external ?? 0, 38);
    central.writeUInt32LE(entry.localOffset ?? offset, 42);
    centrals.push(central, name, extra, comment);
    offset += 30 + localName.length + data.length;
  }

  const directory = Buffer.concat(centrals);
  const record = Buffer.alloc(22);
  record.writeUInt32LE(0x06_05_4B_50, 0);
  record.writeUInt16LE(end.count ?? entries.length, 8);
  record.writeUInt16LE(end.count ?? entries.length, 10);
  record.writeUInt32LE(end.size ?? directory.length, 12);
  record.writeUInt32LE(end.offset ?? offset, 16);
  return Buffer.concat([prefix, ...locals, directory, record]);
}

function zip64Extra(...values) {
  const extra = Buffer.alloc(4 + (8 * values.length));
  extra.writeUInt16LE(0x00_01, 0);
  extra.writeUInt16LE(8 * values.length, 2);
  for (const [index, value] of values.entries()) {
    extra.writeBigUInt64LE(BigInt(value), 4 + (8 * index));
  }

  return extra;
}

test('crc32 matches known values', () => {
  assert.equal(crc32(Buffer.alloc(0)), 0);
  assert.equal(crc32(Buffer.from('123456789')), 0xCB_F4_39_26);
  assert.equal(crc32(Buffer.from('The quick brown fox jumps over the lazy dog')), 0x41_4F_A3_39);
});

test('reads stored and deflated members written by Python', {skip: !hasPython && 'needs python3'}, t => {
  const text = 'print("hello")\n'.repeat(50);
  const buffer = pythonZip(t, [
    ['pkg/', '', 'ZIP_STORED'],
    ['pkg/__init__.py', text, 'ZIP_DEFLATED'],
    ['pkg/data.txt', 'stored\n', 'ZIP_STORED'],
    ['pkg/empty.txt', '', 'ZIP_DEFLATED'],
    ['pkg-1.0.dist-info/RECORD', 'pkg/__init__.py,,\n', 'ZIP_DEFLATED'],
  ]);
  const entries = listZip(buffer);
  assert.deepEqual(entries.map(entry => [entry.name, entry.method, entry.directory]), [
    ['pkg/', 0, true],
    ['pkg/__init__.py', 8, false],
    ['pkg/data.txt', 0, false],
    ['pkg/empty.txt', 8, false],
    ['pkg-1.0.dist-info/RECORD', 8, false],
  ]);
  assert.ok(entries[1].compressedSize < entries[1].size);
  assert.equal(readMember(buffer, entries[1], 1_000_000).toString(), text);

  const files = readZipFiles(buffer);
  assert.deepEqual([...files.keys()], ['pkg/__init__.py', 'pkg/data.txt', 'pkg/empty.txt', 'pkg-1.0.dist-info/RECORD']);
  assert.equal(files.get('pkg/data.txt').toString(), 'stored\n');
  assert.equal(files.get('pkg/empty.txt').length, 0);

  const filtered = readZipFiles(buffer, {filter: name => name.endsWith('.py')});
  assert.deepEqual([...filtered.keys()], ['pkg/__init__.py']);

  const stripped = readZipFiles(buffer, {stripFirstComponent: true});
  assert.deepEqual([...stripped.keys()], ['__init__.py', 'data.txt', 'empty.txt', 'RECORD']);

  assert.throws(() => readZipFiles(buffer, {maxUncompressedBytes: 100}), /expands beyond the size limit/);
  assert.throws(() => readMember(buffer, entries[1], 10), /pkg\/__init__\.py is too large/);
});

test('member names are normalized and names that escape are skipped', {skip: !hasPython && 'needs python3'}, t => {
  const buffer = pythonZip(t, [
    ['../evil.txt', 'x', 'ZIP_STORED'],
    ['a/../../evil.txt', 'x', 'ZIP_STORED'],
    ['./top.txt', 'top', 'ZIP_STORED'],
    [String.raw`dir//nested\file.txt`, 'nested', 'ZIP_STORED'],
    ['.', 'nothing', 'ZIP_STORED'],
  ]);
  const files = readZipFiles(buffer);
  assert.deepEqual([...files.keys()], ['top.txt', 'dir/nested/file.txt']);
  const stripped = readZipFiles(buffer, {stripFirstComponent: true});
  assert.deepEqual([...stripped.keys()], ['nested/file.txt'], 'top-level files have no first component to strip');
});

test('compression methods other than stored and deflate are rejected', {skip: !hasPython && 'needs python3'}, t => {
  const buffer = pythonZip(t, [['a.txt', 'bzip2 data', 'ZIP_BZIP2']]);
  assert.equal(listZip(buffer)[0].method, 12);
  assert.throws(() => readZipFiles(buffer), /Unsupported zip compression method 12 for a\.txt/);
});

test('ZIP64 end of central directory (more than 65535 members)', {skip: !hasPython && 'needs python3'}, t => {
  const output = path.join(tempDir(t), 'many.zip');
  execFileSync('python3', ['-c', [
    'import sys, zipfile',
    'with zipfile.ZipFile(sys.argv[1], "w") as archive:',
    '    for index in range(65537):',
    '        archive.writestr("f/%d" % index, str(index))',
  ].join('\n'), output]);
  const buffer = fs.readFileSync(output);
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4B, 0x05, 0x06]));
  assert.equal(buffer.readUInt16LE(end + 10), 0xFF_FF, 'the classic record defers to ZIP64');
  const entries = listZip(buffer);
  assert.equal(entries.length, 65_537);
  assert.equal(entries.at(-1).name, 'f/65536');
  assert.equal(readMember(buffer, entries.at(-1), 100).toString(), '65536');

  // A ZIP64 locator that points outside the file, or at something else.
  const outside = Buffer.from(buffer);
  outside.writeBigUInt64LE(BigInt(buffer.length), end - 12);
  assert.throws(() => listZip(outside), /Malformed ZIP64 end of central directory/);
  const elsewhere = Buffer.from(buffer);
  elsewhere.writeBigUInt64LE(0n, end - 12);
  assert.throws(() => listZip(elsewhere), /Malformed ZIP64 end of central directory/);
});

test('archives written by the zip command, including forced ZIP64', {skip: !hasZip && 'needs zip'}, t => {
  const directory = tempDir(t);
  writeFiles(directory, {
    'src/a.txt': 'alpha\n'.repeat(100),
    'src/b.bin': Buffer.from([0, 1, 2, 3]),
  });
  for (const flags of [[], ['-fz'], ['-0']]) {
    const output = path.join(tempDir(t), 'archive.zip');
    execFileSync('zip', ['-q', '-r', ...flags, output, 'src'], {cwd: directory});
    const buffer = fs.readFileSync(output);
    const files = readZipFiles(buffer, {stripFirstComponent: true});
    assert.deepEqual([...files.keys()].sort(), ['a.txt', 'b.bin']);
    assert.equal(files.get('a.txt').toString(), 'alpha\n'.repeat(100));
    assert.deepEqual([...files.get('b.bin')], [0, 1, 2, 3]);
    assert.ok(listZip(buffer).some(entry => entry.directory && entry.name === 'src/'));
  }
});

test('ZIP64 extra fields replace sizes and offsets set to 0xFFFFFFFF', () => {
  const realOffset = 30 + 'first.txt'.length + 'first'.length;
  const compressed = zlib.deflateRawSync(Buffer.from('large file')).length;
  const withExtra = craftZip([
    {name: 'first.txt', data: 'first', extra: Buffer.from([0x55, 0x54, 1, 0, 0])},
    {
      name: 'big.txt',
      data: 'large file',
      method: 8,
      size: 0xFF_FF_FF_FF,
      compressedSize: 0xFF_FF_FF_FF,
      localOffset: 0xFF_FF_FF_FF,
      extra: Buffer.concat([Buffer.from([0x0A, 0, 0, 0]), zip64Extra(10, compressed, realOffset)]),
      comment: 'a comment',
    },
  ]);
  const entries = listZip(withExtra);
  assert.deepEqual(entries[1], {
    name: 'big.txt', method: 8, compressedSize: compressed, size: 10, crc: crc32(Buffer.from('large file')), localOffset: realOffset, directory: false, external: 0,
  });
  assert.equal(readZipFiles(withExtra).get('big.txt').toString(), 'large file');
  const noExtra = craftZip([{name: 'big.txt', data: 'x', size: 0xFF_FF_FF_FF}]);
  assert.equal(listZip(noExtra)[0].size, 0xFF_FF_FF_FF, 'without the extra field the values stay as stated');

  // Only the fields set to 0xFFFFFFFF are in the extra field.
  const partial = craftZip([{
    name: 'x.txt', data: 'abc', size: 0xFF_FF_FF_FF, extra: zip64Extra(3),
  }]);
  assert.equal(readZipFiles(partial).get('x.txt').toString(), 'abc');
});

test('malformed archives are rejected', () => {
  assert.throws(() => listZip(Buffer.alloc(10)), /Not a zip archive/);
  assert.throws(() => listZip(Buffer.alloc(100)), /Not a zip archive/);

  assert.deepEqual(listZip(craftZip([])), [], 'an empty archive');
  // 0xFFFF members with no room for a ZIP64 locator, or no locator.
  assert.throws(() => listZip(craftZip([], {end: {count: 0xFF_FF}})), /Malformed zip central directory/);
  assert.throws(() => listZip(craftZip([], {end: {count: 0xFF_FF}, prefix: Buffer.alloc(40)})), /Malformed zip central directory/);
  assert.throws(() => listZip(craftZip([], {end: {size: 0xFF_FF_FF_FF}, prefix: Buffer.alloc(40)})), /central directory out of range/);
  assert.throws(() => listZip(craftZip([], {end: {offset: 0xFF_FF_FF_FF}, prefix: Buffer.alloc(40)})), /central directory out of range/);
  assert.throws(() => listZip(craftZip([{name: 'a', data: 'a'}], {end: {count: 2}})), /Malformed zip central directory/);
  assert.throws(() => listZip(craftZip([{name: 'a', data: 'a'}], {end: {offset: 0}})), /Malformed zip central directory/);

  const badLocal = craftZip([{name: 'a.txt', data: 'a', localOffset: 5}]);
  assert.throws(() => readZipFiles(badLocal), /Malformed zip local header for a\.txt/);
  const pastEnd = craftZip([{name: 'a.txt', data: 'a', localOffset: 1_000_000}]);
  assert.throws(() => readZipFiles(pastEnd), /Malformed zip local header/);
  const tooLong = craftZip([{name: 'a.txt', data: 'a', compressedSize: 1_000_000}]);
  assert.throws(() => readZipFiles(tooLong), /Zip member a\.txt out of range/);

  const badCrc = craftZip([{name: 'a.txt', data: 'abc', crc: 1}]);
  assert.throws(() => readZipFiles(badCrc), /a\.txt failed its CRC check/);
  const wrongSize = craftZip([{name: 'a.txt', data: 'abc', size: 2}]);
  assert.throws(() => readZipFiles(wrongSize), /failed its CRC check/);
  const inflateLimit = craftZip([{
    name: 'a.txt', data: 'abcdef', method: 8, size: 2,
  }]);
  assert.throws(() => readZipFiles(inflateLimit), /cannot create a buffer larger than|rangeerror|buffer/i);
  const emptyDeflated = craftZip([{name: 'e.txt', data: '', method: 8}]);
  assert.equal(readZipFiles(emptyDeflated).get('e.txt').length, 0);
});

test('a member whose local header disagrees with the central directory is refused', () => {
  // Installers that stream local headers (uv before 0.8.6) and ones that
  // read the central directory would install different files.
  const renamed = craftZip([{name: 'pkg/__init__.py', localName: 'pkg/evil.py', data: 'import os\n'}]);
  assert.throws(() => readZipFiles(renamed), /pkg\/__init__\.py: its local header names pkg\/evil\.py/);
  const method = craftZip([{name: 'a.py', data: 'x', localMethod: 8}]);
  assert.throws(() => readZipFiles(method), /a\.py: its local header has compression method 8, the central directory 0/);
  assert.deepEqual([...readZipFiles(craftZip([{name: 'a.py', data: 'x'}])).keys()], ['a.py']);
});

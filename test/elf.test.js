'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {execFileSync} = require('node:child_process');
const {
  parseElf, sectionData, goBuildInfo, parseGoModInfo, cargoAuditable, readUvarint,
} = require('../lib/elf');
const {tempDir, which} = require('./helpers');
const {
  hasGo, hasCargoAuditable, goProject, cargoProject, makeElf,
} = require('./fixtures/formats/binaries');

const GO_MAGIC = Buffer.from('ÿ Go buildinf:', 'latin1');
const MODINFO_START = Buffer.from('3077af0c9274080241e1c107e6d618e6', 'hex');
const MODINFO_END = Buffer.from('f932433186182072008242104116d8f2', 'hex');

function varint(value) {
  const bytes = [];
  while (value >= 0x80) {
    bytes.push((value & 0x7F) | 0x80);
    value = Math.floor(value / 128);
  }

  bytes.push(value);
  return Buffer.from(bytes);
}

/**
 * The .go.buildinfo layout of Go 1.18 and later: magic, pointer size,
 * flags, padding to 32 bytes, then length-prefixed strings.
 */
function goBlob(strings, flags = 2) {
  const head = Buffer.alloc(32);
  GO_MAGIC.copy(head);
  head[14] = 8;
  head[15] = flags;
  return Buffer.concat([head, ...strings.flatMap(value => {
    const data = Buffer.from(value);
    return [varint(data.length), data];
  })]);
}

const MODINFO = [
  'path\texample.com/app',
  'mod\texample.com/app\tv1.0.0\th1:main=',
  'dep\texample.com/lib\tv1.2.0\th1:lib=',
  '',
].join('\n');

test('parseElf reads section headers of 64-bit little- and big-endian files', () => {
  for (const le of [true, false]) {
    const buffer = makeElf({le, sections: [{name: '.text', data: Buffer.from('code')}, {name: '.bss', type: 8, size: 4096}]});
    const elf = parseElf(buffer);
    assert.equal(elf.class, 64);
    assert.equal(elf.littleEndian, le);
    assert.equal(elf.type, 2);
    assert.equal(elf.machine, 62);
    assert.deepEqual(elf.sections.map(section => section.name), ['', '.text', '.bss', '.shstrtab']);
    assert.equal(elf.sections[1].addr, 0x10_01n);
    assert.equal(sectionData(buffer, elf, '.text').toString(), 'code');
    assert.equal(sectionData(buffer, elf, '.bss'), null, 'SHT_NOBITS has no contents');
    assert.equal(sectionData(buffer, elf, '.missing'), null);
    assert.equal(elf.word(0x28), BigInt(buffer.length - (4 * 64)), 'word() reads a native-size word');
  }
});

test('parseElf reads 32-bit files', () => {
  for (const le of [true, false]) {
    const buffer = makeElf({cls: 32, le, sections: [{name: '.data', data: Buffer.from('abc')}]});
    const elf = parseElf(buffer);
    assert.equal(elf.class, 32);
    assert.equal(elf.sections[1].name, '.data');
    assert.equal(elf.sections[1].addr, 0x10_01n);
    assert.equal(sectionData(buffer, elf, '.data').toString(), 'abc');
    assert.equal(typeof elf.word(0x20), 'bigint');
  }
});

test('parseElf rejects what is not a well-formed ELF file', () => {
  assert.throws(() => parseElf(Buffer.alloc(10)), /Not an ELF file/);
  assert.throws(() => parseElf(Buffer.alloc(64)), /Not an ELF file/);
  assert.throws(() => parseElf(makeElf({ident: Buffer.from([0x7F, 0x45, 0x4C, 0x46, 3])})), /Unknown ELF class/);
  assert.throws(() => parseElf(makeElf({ident: Buffer.from([0x7F, 0x45, 0x4C, 0x46, 2, 0])})), /Unknown ELF byte order/);
  assert.throws(() => parseElf(makeElf({header: {shoff: 2n ** 60n}})), /ELF offset out of range/);
  assert.throws(() => parseElf(makeElf({header: {shentsize: 16}})), /section headers out of range/);
  assert.throws(() => parseElf(makeElf({header: {shnum: 500}})), /section headers out of range/);
  assert.throws(() => parseElf(makeElf({sections: [{name: '.x', offset: 2n ** 60n}]})), /ELF offset out of range/);

  const outside = makeElf({sections: [{name: '.x', data: Buffer.from('x'), size: 1_000_000}]});
  assert.throws(() => sectionData(outside, parseElf(outside), '.x'), /ELF section \.x out of range/);
});

test('parseElf leaves names empty when the name table is missing or broken', () => {
  assert.deepEqual(parseElf(makeElf({header: {shnum: 0}})).sections, [], 'no section headers');

  const noTable = parseElf(makeElf({sections: [{name: '.a'}], header: {shstrndx: 99}}));
  assert.deepEqual(noTable.sections.map(section => section.name), ['', '', '']);

  // Name table beyond the end of the file.
  const buffer = makeElf({sections: [{name: '.a'}]});
  const elf = parseElf(buffer);
  const tableHeader = elf.sections.length - 1;
  const shoff = Number(buffer.readBigUInt64LE(0x28));
  buffer.writeBigUInt64LE(BigInt(buffer.length), shoff + (tableHeader * 64) + 0x18);
  assert.deepEqual(parseElf(buffer).sections.map(section => section.name), ['', '', '']);

  // A name offset past the table, and a name that runs to the table's end.
  const names = parseElf(makeElf({sections: [{name: '.far', nameOffset: 1000}, {name: '.tail', nameOffset: 2}]}));
  assert.equal(names.sections[1].name, '');
  assert.equal(names.sections[2].name, 'far');
  const unterminated = makeElf({sections: [{name: '.a'}]});
  const tableOffset = parseElf(unterminated).sections.at(-1);
  unterminated[tableOffset.offset + tableOffset.size - 1] = 0x21;
  assert.equal(parseElf(unterminated).sections.at(-1).name, '.shstrtab!');
});

test('parseElf reads names in bounded time when the name table has no NUL', () => {
  // 65,535 section headers that all name the start of an 8 MiB table without a NUL.
  const shnum = 0xFF_FF;
  const tableOffset = 64 + (shnum * 64);
  const tableSize = 8 * 1024 * 1024;
  const buffer = Buffer.alloc(tableOffset + tableSize, 0x41);
  buffer.fill(0, 0, tableOffset);
  Buffer.from([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1]).copy(buffer);
  buffer.writeBigUInt64LE(64n, 0x28);
  buffer.writeUInt16LE(64, 0x3A);
  buffer.writeUInt16LE(shnum, 0x3C);
  buffer.writeUInt16LE(0, 0x3E);
  buffer.writeBigUInt64LE(BigInt(tableOffset), 64 + 0x18);
  buffer.writeBigUInt64LE(BigInt(tableSize), 64 + 0x20);
  const started = Date.now();
  const elf = parseElf(buffer);
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  assert.equal(elf.sections.length, shnum);
  assert.equal(elf.sections[0].name, 'A'.repeat(256));
});

test('readUvarint decodes LEB128 and rejects malformed input', () => {
  assert.deepEqual(readUvarint(Buffer.from([0x05]), 0), [5, 1]);
  assert.deepEqual(readUvarint(Buffer.from([0x00, 0x96, 0x01]), 1), [150, 2]);
  assert.throws(() => readUvarint(Buffer.from([0x80, 0x80]), 0), /Malformed varint/);
  assert.throws(() => readUvarint(Buffer.alloc(12, 0xFF), 0), /Malformed varint/);
});

test('parseGoModInfo reads the lines go version -m prints', () => {
  const info = parseGoModInfo([
    'path',
    '=>\t../orphan\t(devel)',
    'mod\texample.com/app',
    'dep\texample.com/a\tv1.0.0\th1:a=',
    '=>\texample.com/fork\tv1.0.1\th1:fork=',
    'dep\texample.com/local\tv0.0.0',
    '=>\t../local',
    'dep\texample.com/bare',
    'build\t-ldflags="-s -w"',
    'build\tGOOS=linux',
    'build\tnoequals',
    'build\t=value',
    'build\tweird=a\tb',
    'unknown\tline',
  ].join('\n'));
  assert.equal(info.path, null);
  assert.deepEqual(info.main, {path: 'example.com/app', version: null, sum: null});
  assert.deepEqual(info.deps, [
    {
      path: 'example.com/a', version: 'v1.0.0', sum: 'h1:a=', replace: {path: 'example.com/fork', version: 'v1.0.1', sum: 'h1:fork='},
    },
    {
      path: 'example.com/local', version: 'v0.0.0', sum: null, replace: {path: '../local', version: null, sum: null},
    },
    {path: 'example.com/bare', version: null, sum: null},
  ]);
  assert.deepEqual(info.settings, {'-ldflags': '-s -w', GOOS: 'linux', weird: 'a\tb'});
});

test('goBuildInfo reads crafted build information in and outside ELF sections', () => {
  const blob = goBlob(['go1.22.0', Buffer.concat([MODINFO_START, Buffer.from(MODINFO), MODINFO_END])]);
  for (const le of [true, false]) {
    const elf = makeElf({le, sections: [{name: '.go.buildinfo', data: blob}]});
    const info = goBuildInfo(elf);
    assert.equal(info.goVersion, 'go1.22.0');
    assert.equal(info.path, 'example.com/app');
    assert.deepEqual(info.main, {path: 'example.com/app', version: 'v1.0.0', sum: 'h1:main='});
    assert.equal(info.deps[0].sum, 'h1:lib=');
  }

  // Not an ELF file: the header is found at a 16-byte boundary, skipping
  // a copy of the magic that is not aligned.
  const unaligned = Buffer.concat([Buffer.alloc(3), GO_MAGIC, Buffer.alloc(48 - 3 - GO_MAGIC.length), goBlob(['go1.21.0', MODINFO])]);
  assert.equal(unaligned.indexOf(GO_MAGIC), 3);
  assert.equal(goBuildInfo(unaligned).goVersion, 'go1.21.0');
  assert.equal(goBuildInfo(unaligned).deps[0].path, 'example.com/lib', 'module information without sentinels');
  assert.equal(goBuildInfo(Buffer.concat([Buffer.alloc(3), GO_MAGIC, Buffer.alloc(40)])), null, 'only unaligned copies');

  assert.equal(goBuildInfo(Buffer.from('plain text, not a binary')), null);
  assert.equal(goBuildInfo(makeElf({sections: [{name: '.text', data: Buffer.from('x')}]})), null);
  assert.equal(goBuildInfo(makeElf({sections: [{name: '.go.buildinfo', data: GO_MAGIC}]})), null, 'too short');
  assert.equal(goBuildInfo(makeElf({sections: [{name: '.go.buildinfo', data: Buffer.alloc(64)}]})), null, 'no magic');
  assert.equal(goBuildInfo(Buffer.concat([GO_MAGIC, Buffer.alloc(10)])), null, 'too short outside ELF');

  const old = goBuildInfo(goBlob([], 0));
  assert.match(old.unsupported, /Go 1\.17 or earlier/);
  assert.deepEqual(old.deps, []);

  assert.throws(() => goBuildInfo(Buffer.concat([goBlob(['go1.22.0']), Buffer.from([50, 0x41])])), /truncated/);
  assert.throws(() => goBuildInfo(Buffer.concat([goBlob([]), Buffer.alloc(10, 0x80)])), /Malformed varint/);
});

test('cargoAuditable reads crafted .dep-v0 sections', () => {
  const section = value => makeElf({sections: [{name: '.dep-v0', data: zlib.deflateSync(Buffer.from(JSON.stringify(value)))}]});
  assert.deepEqual(cargoAuditable(section({
    packages: [
      {
        name: 'app', version: '0.1.0', source: 'local', root: true,
      },
      {
        name: 'cc', version: '1.0.0', source: 'crates.io', kind: 'build',
      },
      {name: 'odd', version: 1},
    ],
  })), [
    {
      name: 'app', version: '0.1.0', source: 'local', kind: 'runtime', root: true,
    },
    {
      name: 'cc', version: '1.0.0', source: 'crates.io', kind: 'build', root: false,
    },
    {
      name: 'odd', version: '1', source: 'unknown', kind: 'runtime', root: false,
    },
  ]);
  assert.throws(() => cargoAuditable(section(null)), /Malformed cargo-auditable data/);
  assert.throws(() => cargoAuditable(section({packages: 'x'})), /Malformed cargo-auditable data/);
  assert.throws(() => cargoAuditable(makeElf({sections: [{name: '.dep-v0', data: Buffer.from('not zlib')}]})), /incorrect header check/);
  assert.equal(cargoAuditable(makeElf()), null);
  assert.equal(cargoAuditable(Buffer.from('not an ELF file at all, just some text here to be long enough')), null);
  const outside = makeElf({sections: [{name: '.dep-v0', data: Buffer.from('x'), size: 1_000_000}]});
  assert.equal(cargoAuditable(outside), null, 'a section out of range is no data');
});

test('Go binaries: build information, VCS stamping and -trimpath', {skip: !hasGo && 'needs go, git and zip'}, t => {
  const project = goProject(t);
  const binary = project.build('app', ['-trimpath']);
  const elf = parseElf(binary);
  assert.equal(elf.class, 64);
  assert.equal(elf.littleEndian, true);
  assert.equal(sectionData(binary, elf, '.bss'), null);

  const info = goBuildInfo(binary);
  assert.match(info.goVersion, /^go1\.\d+/);
  assert.equal(info.path, 'example.com/app');
  assert.equal(info.main.path, 'example.com/app');
  const lib = info.deps.find(dependency => dependency.path === 'example.com/lib');
  assert.equal(lib.version, 'v1.0.0');
  const goSum = fs.readFileSync(path.join(project.app, 'go.sum'), 'utf8');
  assert.ok(goSum.includes(`example.com/lib v1.0.0 ${lib.sum}`), 'the hash go.sum pins');
  const dep = info.deps.find(dependency => dependency.path === 'example.com/dep');
  assert.equal(dep.replace.path, '../dep');
  assert.equal(info.settings['-trimpath'], 'true');
  assert.equal(info.settings['vcs.revision'], project.commit);
  assert.equal(info.settings['vcs.modified'], 'false');
  assert.equal(info.settings.CGO_ENABLED, '0');

  // Section headers removed: the header is found by searching.
  const stripped = Buffer.from(binary);
  stripped.writeUInt16LE(0, 0x3C);
  assert.deepEqual(parseElf(stripped).sections, []);
  assert.deepEqual(goBuildInfo(stripped), info);

  // A Go binary carries no cargo-auditable data.
  assert.equal(cargoAuditable(binary), null);

  const noVcs = goBuildInfo(project.build('app-novcs', ['-buildvcs=false']));
  assert.equal(noVcs.settings['vcs.revision'], undefined);
  assert.equal(noVcs.settings['-trimpath'], undefined);

  fs.writeFileSync(path.join(project.app, 'extra.go'), 'package main\n');
  const dirty = goBuildInfo(project.build('app-dirty'));
  assert.equal(dirty.settings['vcs.modified'], 'true');
});

test('Go binaries for a 32-bit big-endian target', {skip: !hasGo && 'needs go, git and zip'}, t => {
  const project = goProject(t);
  const binary = project.build('app-mips', ['-trimpath'], {GOARCH: 'mips'});
  const elf = parseElf(binary);
  assert.equal(elf.class, 32);
  assert.equal(elf.littleEndian, false);
  assert.equal(elf.machine, 8);
  const info = goBuildInfo(binary);
  assert.equal(info.settings.GOARCH, 'mips');
  assert.equal(info.deps.find(dependency => dependency.path === 'example.com/lib').version, 'v1.0.0');
});

test('cargo-auditable binaries list their crates', {skip: !hasCargoAuditable && 'needs cargo-auditable'}, t => {
  const {binary} = cargoProject(t);
  const crates = cargoAuditable(binary);
  const byName = Object.fromEntries(crates.map(crate => [crate.name, crate]));
  assert.deepEqual(byName.app, {
    name: 'app', version: '0.1.0', source: 'local', kind: 'runtime', root: true,
  });
  assert.deepEqual(byName.helper, {
    name: 'helper', version: '0.2.0', source: 'local', kind: 'runtime', root: false,
  });
  assert.equal(byName.builder.kind, 'build');
  assert.equal(goBuildInfo(binary), null, 'not a Go binary');
});

test('a .dep-v0 section added with objcopy', {skip: !(hasGo && which('objcopy')) && 'needs go, git, zip and objcopy'}, t => {
  const project = goProject(t);
  project.build('host', ['-trimpath']);
  const directory = tempDir(t);
  const data = path.join(directory, 'dep.bin');
  fs.writeFileSync(data, zlib.deflateSync(JSON.stringify({packages: [{name: 'serde', version: '1.0.0', source: 'crates.io'}]})));
  const output = path.join(directory, 'with-deps');
  execFileSync('objcopy', ['--add-section', `.dep-v0=${data}`, path.join(project.root, 'host'), output]);
  assert.deepEqual(cargoAuditable(fs.readFileSync(output)), [{
    name: 'serde', version: '1.0.0', source: 'crates.io', kind: 'runtime', root: false,
  }]);
});

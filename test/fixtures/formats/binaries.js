'use strict';

/**
 * Real binaries for the ELF and compiled-ecosystem tests, built offline:
 *
 *   Go     a module in a git repository with a dependency served by a local
 *          module proxy (file:// GOPROXY, so go.sum pins a real hash) and a
 *          dependency replaced by a local directory
 *   Rust   a crate built with cargo-auditable, with a runtime and a
 *          build-only path dependency
 */

const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {tempDir, writeFiles, which} = require('../../helpers');

const hasGo = which('go') && which('git') && which('zip');
const hasCargoAuditable = which('cargo') && which('cargo-auditable');

const GIT_ENV = {
  GIT_AUTHOR_NAME: 'test',
  GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'test',
  GIT_COMMITTER_EMAIL: 'test@example.com',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
};

/**
 * @returns {{root: string, app: string, commit: string, build: (output: string, args?: string[], env?: Object) => Buffer}}
 */
function goProject(t) {
  const root = tempDir(t, 'attestium-go-');
  const env = {
    ...process.env,
    ...GIT_ENV,
    GOPROXY: `file://${path.join(root, 'proxy')}`,
    GOSUMDB: 'off',
    GOFLAGS: '-mod=mod -modcacherw',
    GOTOOLCHAIN: 'local',
    GOWORK: 'off',
    CGO_ENABLED: '0',
    GOMODCACHE: path.join(root, 'modcache'),
    GOPATH: path.join(root, 'gopath'),
  };
  const run = (command, args, cwd, extra = {}) => execFileSync(command, args, {cwd, env: {...env, ...extra}, stdio: ['ignore', 'pipe', 'pipe']});

  // A module version as a proxy serves it (the zip holds no directory entries).
  const lib = 'example.com/lib@v1.0.0';
  writeFiles(path.join(root, 'stage'), {
    [`${lib}/go.mod`]: 'module example.com/lib\n\ngo 1.18\n',
    [`${lib}/lib.go`]: 'package lib\n\nfunc Name() string { return "lib" }\n',
  });
  writeFiles(path.join(root, 'proxy', 'example.com', 'lib', '@v'), {
    list: 'v1.0.0\n',
    'v1.0.0.info': '{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}',
    'v1.0.0.mod': 'module example.com/lib\n\ngo 1.18\n',
  });
  run('zip', ['-qrD', path.join(root, 'proxy', 'example.com', 'lib', '@v', 'v1.0.0.zip'), 'example.com'], path.join(root, 'stage'));

  writeFiles(root, {
    'repo/dep/go.mod': 'module example.com/dep\n\ngo 1.18\n',
    'repo/dep/dep.go': 'package dep\n\nfunc Hello() string { return "hi" }\n',
    'repo/app/go.mod': 'module example.com/app\n\ngo 1.18\n\nrequire (\n\texample.com/dep v0.0.0\n\texample.com/lib v1.0.0\n)\n\nreplace example.com/dep => ../dep\n',
    'repo/app/main.go': 'package main\n\nimport (\n\t"fmt"\n\n\t"example.com/dep"\n\t"example.com/lib"\n)\n\nfunc main() { fmt.Println(dep.Hello(), lib.Name()) }\n',
  });
  const app = path.join(root, 'repo', 'app');
  run('go', ['mod', 'tidy'], app);
  run('git', ['init', '--quiet'], path.join(root, 'repo'));
  run('git', ['add', '-A'], path.join(root, 'repo'));
  run('git', ['commit', '--quiet', '--no-gpg-sign', '-m', 'init'], path.join(root, 'repo'));
  const commit = run('git', ['rev-parse', 'HEAD'], app).toString().trim();

  return {
    root,
    app,
    commit,
    build(output, args = [], extra = {}) {
      const file = path.join(root, output);
      run('go', ['build', ...args, '-o', file, '.'], app, extra);
      return fs.readFileSync(file);
    },
  };
}

/**
 * @returns {{dir: string, binary: Buffer, file: string}}
 */
function cargoProject(t) {
  const root = tempDir(t, 'attestium-cargo-');
  writeFiles(root, {
    'helper/Cargo.toml': '[package]\nname = "helper"\nversion = "0.2.0"\nedition = "2021"\n',
    'helper/src/lib.rs': 'pub fn value() -> u8 { 1 }\n',
    'builder/Cargo.toml': '[package]\nname = "builder"\nversion = "0.3.0"\nedition = "2021"\n',
    'builder/src/lib.rs': 'pub fn value() -> u8 { 2 }\n',
    'app/Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nhelper = { path = "../helper" }\n\n[build-dependencies]\nbuilder = { path = "../builder" }\n',
    'app/src/main.rs': 'fn main() { println!("{}", helper::value()); }\n',
    'app/build.rs': 'fn main() { builder::value(); }\n',
  });
  const dir = path.join(root, 'app');
  execFileSync('cargo', ['auditable', 'build', '--offline', '--quiet'], {
    cwd: dir, env: {...process.env, CARGO_TARGET_DIR: path.join(root, 'target')}, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const file = path.join(root, 'target', 'debug', 'app');
  return {dir, file, binary: fs.readFileSync(file)};
}

/**
 * A minimal ELF file: header, section contents, a section name table and
 * section headers.  Fields can be overridden to make malformed files.
 *
 * @param {Object} [options]
 * @param {32|64} [options.cls=64]
 * @param {boolean} [options.le=true]
 * @param {Array<{name: string, type?: number, data?: Buffer, offset?: number|bigint, size?: number, nameOffset?: number}>} [options.sections]
 * @param {Object} [options.header] - shoff, shentsize, shnum, shstrndx overrides
 * @param {Buffer} [options.ident] - replaces the first bytes of e_ident
 * @returns {Buffer}
 */
function makeElf({cls = 64, le = true, sections = [], header = {}, ident} = {}) {
  const headerSize = cls === 64 ? 64 : 52;
  const entrySize = cls === 64 ? 64 : 40;
  let nameTable = Buffer.from([0]);
  const nameOffsets = [0];
  for (const section of [...sections, {name: '.shstrtab'}]) {
    nameOffsets.push(nameTable.length);
    nameTable = Buffer.concat([nameTable, Buffer.from(`${section.name}\0`, 'latin1')]);
  }

  const all = [{type: 0, data: Buffer.alloc(0)}, ...sections, {name: '.shstrtab', type: 3, data: nameTable}];
  const chunks = [Buffer.alloc(headerSize)];
  let cursor = headerSize;
  const placed = all.map((section, index) => {
    const data = section.data || Buffer.alloc(0);
    const offset = section.offset ?? cursor;
    chunks.push(data);
    cursor += data.length;
    return {
      nameOffset: section.nameOffset ?? nameOffsets[index], type: section.type ?? 1, offset, size: section.size ?? data.length,
    };
  });
  const shoff = cursor;
  const table = Buffer.alloc(entrySize * placed.length);
  const w16 = (buffer, value, at) => (le ? buffer.writeUInt16LE(value, at) : buffer.writeUInt16BE(value, at));
  const w32 = (buffer, value, at) => (le ? buffer.writeUInt32LE(value, at) : buffer.writeUInt32BE(value, at));
  const w64 = (buffer, value, at) => (le ? buffer.writeBigUInt64LE(BigInt(value), at) : buffer.writeBigUInt64BE(BigInt(value), at));
  for (const [index, section] of placed.entries()) {
    const base = index * entrySize;
    w32(table, section.nameOffset, base);
    w32(table, section.type, base + 4);
    if (cls === 64) {
      w64(table, 0x10_00 + index, base + 0x10);
      w64(table, section.offset, base + 0x18);
      w64(table, section.size, base + 0x20);
    } else {
      w32(table, 0x10_00 + index, base + 0x0C);
      w32(table, Number(section.offset), base + 0x10);
      w32(table, section.size, base + 0x14);
    }
  }

  chunks.push(table);
  const buffer = Buffer.concat(chunks);
  Buffer.from([0x7F, 0x45, 0x4C, 0x46, cls === 64 ? 2 : 1, le ? 1 : 2, 1]).copy(buffer);
  if (ident) {
    ident.copy(buffer);
  }

  const values = {
    shoff, shentsize: entrySize, shnum: placed.length, shstrndx: placed.length - 1, ...header,
  };
  w16(buffer, 2, 0x10);
  w16(buffer, 62, 0x12);
  if (cls === 64) {
    w64(buffer, values.shoff, 0x28);
    w16(buffer, values.shentsize, 0x3A);
    w16(buffer, values.shnum, 0x3C);
    w16(buffer, values.shstrndx, 0x3E);
  } else {
    w32(buffer, values.shoff, 0x20);
    w16(buffer, values.shentsize, 0x2E);
    w16(buffer, values.shnum, 0x30);
    w16(buffer, values.shstrndx, 0x32);
  }

  return buffer;
}

module.exports = {
  hasGo, hasCargoAuditable, goProject, cargoProject, makeElf, GIT_ENV,
};

/**
 * Attestium - Rust crates, checked inside the binary
 *
 * A binary built with cargo-auditable records every crate compiled into it
 * (see ../elf cargoAuditable).  The verifier checks that list against
 * Cargo.lock at the deployed commit: each crate from a registry must be the
 * version the lockfile pins, from the same source, and the lockfile must pin
 * its checksum.
 *
 * As with Go, the list is written by the build; the binary's own hash is
 * what proves it.  This check shows the binary was built with the pinned
 * crates.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {parseToml} = require('../toml');
const {exists} = require('../util');
const {NoLockfileError, collect} = require('./common');

function readLock(repoDir, options = {}) {
  const file = options.lockfile || 'Cargo.lock';
  if (!exists(path.join(repoDir, file))) {
    throw new NoLockfileError('No Cargo.lock found');
  }

  const packages = new Map();
  for (const item of parseToml(fs.readFileSync(path.join(repoDir, file), 'utf8')).package || []) {
    packages.set(`${item.name} ${item.version}`, {
      name: item.name, version: item.version, source: item.source || null, checksum: item.checksum || null,
    });
  }

  return {format: 'cargo', file, packages};
}

/**
 * The kind of source cargo-auditable records for a Cargo.lock source.
 * @param {string|null} source
 * @returns {string}
 */
function sourceKind(source) {
  if (!source) {
    return 'local';
  }

  if (source === 'registry+https://github.com/rust-lang/crates.io-index' || source === 'sparse+https://index.crates.io/') {
    return 'crates.io';
  }

  if (source.startsWith('git+')) {
    return 'git';
  }

  return 'registry';
}

/**
 * @param {Object} input
 * @param {Array} input.packages - from elf.cargoAuditable()
 * @param {Object} input.lock - from readLock()
 * @returns {Object} comparison (see ./common)
 */
function compareAuditable({packages, lock}) {
  const results = packages.filter(crate => !crate.root).map(crate => {
    const item = {name: crate.name, version: crate.version, path: `${crate.name}@${crate.version}`};
    const locked = lock.packages.get(`${crate.name} ${crate.version}`);
    if (!locked) {
      return {status: 'failed', item, reason: 'not in Cargo.lock'};
    }

    const kind = sourceKind(locked.source);
    if (kind !== crate.source) {
      return {status: 'failed', item, reason: `built from ${crate.source}, Cargo.lock says ${kind}`};
    }

    if (kind === 'local') {
      return {status: 'verified', item};
    }

    if (kind === 'git') {
      return /#[\da-f]{40}$/.test(locked.source) ? {status: 'verified', item} : {status: 'unverifiable', item, reason: 'Cargo.lock pins no commit for this git source'};
    }

    return locked.checksum ? {status: 'verified', item} : {status: 'unverifiable', item, reason: 'Cargo.lock pins no checksum'};
  });
  return collect(results);
}

module.exports = {
  name: 'cargo',
  label: 'Cargo',
  lockfiles: ['Cargo.lock'],
  readLock,
  compareAuditable,
  sourceKind,
};

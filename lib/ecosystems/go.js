/**
 * Attestium - Go modules, checked inside the binary
 *
 * A Go binary records the module it was built from, every dependency with
 * its go.sum hash, and its build settings (see ../elf goBuildInfo).  The
 * verifier checks that record against go.sum at the deployed commit: each
 * dependency must be the one the repository pins, the binary must have been
 * built from that commit and from an unmodified tree.
 *
 * The record is written by the build, so a binary could claim anything; it
 * is the binary's own hash (a reproduced build, an attested artifact or a
 * published checksum) that proves what it is.  This check shows that the
 * binary was built with the pinned dependencies, and flags a build from
 * another commit or a modified tree.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {exists} = require('../util');
const {NoLockfileError, collect} = require('./common');

/**
 * Go.sum and go.mod of a module in a repository checkout.
 * @param {string} repoDir
 * @param {Object} [options]
 * @param {string} [options.dir='.'] - module directory
 * @returns {{module: string|null, sums: Map<string, string>}}
 */
function readLock(repoDir, options = {}) {
  const directory = path.join(repoDir, options.dir || '.');
  if (!exists(path.join(directory, 'go.mod'))) {
    throw new NoLockfileError(`No go.mod found in ${options.dir || 'the repository root'}`);
  }

  const module = (fs.readFileSync(path.join(directory, 'go.mod'), 'utf8').match(/^module\s+("?)(\S+)\1\s*$/m) || [])[2] || null;
  const sums = new Map();
  if (exists(path.join(directory, 'go.sum'))) {
    for (const line of fs.readFileSync(path.join(directory, 'go.sum'), 'utf8').split(/\r?\n/)) {
      const [modulePath, version, hash] = line.trim().split(/\s+/);
      if (modulePath && version && !version.endsWith('/go.mod') && (hash || '').startsWith('h1:')) {
        sums.set(`${modulePath} ${version}`, hash);
      }
    }
  }

  return {format: 'go.sum', module, sums};
}

/**
 * @param {Object} input
 * @param {Object} input.info - from elf.goBuildInfo()
 * @param {Object} input.lock - from readLock()
 * @param {string} [input.commit] - the deployed commit
 * @param {string} [input.label] - the binary, for messages
 * @returns {Object} comparison (see ./common)
 */
function compareBuildInfo({info, lock, commit, label = 'the binary'}) {
  const issues = [];
  if (info.unsupported) {
    issues.push({severity: 'warn', message: `${label} was built with ${info.unsupported}`, items: []});
    return collect([], issues);
  }

  if (lock.module && info.main && info.main.path !== lock.module) {
    issues.push({severity: 'fail', message: `${label} was built from module ${info.main.path}, not ${lock.module}`, items: []});
  }

  const settings = info.settings || {};
  if (settings['vcs.revision'] && commit && settings['vcs.revision'] !== commit) {
    issues.push({severity: 'fail', message: `${label} was built from commit ${settings['vcs.revision'].slice(0, 12)}, not the deployed ${commit.slice(0, 12)}`, items: []});
  }

  if (settings['vcs.modified'] === 'true') {
    issues.push({severity: 'fail', message: `${label} was built from a modified working tree`, items: []});
  }

  if (!settings['vcs.revision']) {
    issues.push({severity: 'info', message: `${label} records no commit (built with -buildvcs=false or outside a repository)`, items: []});
  }

  if (settings['-trimpath'] !== 'true') {
    issues.push({severity: 'info', message: `${label} was built without -trimpath; it will not reproduce byte for byte on another machine`, items: []});
  }

  const results = info.deps.map(dependency => {
    const item = {name: dependency.path, version: dependency.version, path: dependency.path};
    const effective = dependency.replace || dependency;
    // Go records a replacement by a local directory with the version "(devel)".
    if (dependency.replace && (!dependency.replace.version || dependency.replace.version === '(devel)')) {
      return {status: 'unverifiable', item, reason: `replaced by the local directory ${dependency.replace.path}`};
    }

    const pinned = lock.sums.get(`${effective.path} ${effective.version}`);
    if (!pinned) {
      return {status: 'failed', item, reason: `${effective.path} ${effective.version} is not in go.sum`};
    }

    if (pinned !== effective.sum) {
      return {status: 'failed', item, reason: `hash ${effective.sum} differs from go.sum (${pinned})`};
    }

    return {status: 'verified', item};
  });
  return collect(results, issues);
}

module.exports = {
  name: 'go',
  label: 'Go modules',
  lockfiles: ['go.sum'],
  readLock,
  compareBuildInfo,
};

/**
 * Attestium - shared parts of the package ecosystem plugins
 *
 * Each plugin in this directory has two halves:
 *
 *   attester  detect(root) finds where packages are installed and scan(dir)
 *             hashes what is there, reporting facts only
 *   verifier  readLock(repoDir) reads the lockfile at the public commit and
 *             compare({scan, lock, store}) fetches reference artifacts whose
 *             hashes the lockfile pins, and compares
 *
 * A comparison result has the same shape for every ecosystem:
 *
 *   summary   counts by status
 *   findings  one per package that did not verify: failed (differs from its
 *             reference), unverifiable (no reference can exist) or error (the
 *             reference could not be fetched)
 *   issues    other observations with a severity (fail, warn, info)
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {httpGet} = require('../http');
const {sha256, setOwn} = require('../util');

class NoLockfileError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NoLockfileError';
  }
}

const STATUSES = ['verified', 'bundled', 'patched', 'built', 'failed', 'unverifiable', 'error'];
const PASSING_SEVERITIES = new Set(['warn', 'info']);

/**
 * Downloads and cached reference manifests, shared by the plugins in a run.
 */
class ReferenceStore {
  /**
   * @param {Object} [options]
   * @param {string} [options.cacheDir] - persistent cache of reference manifests
   * @param {Object} [options.httpOptions] - passed to httpGet (timeout, retries, headers)
   * @param {Object<string, string>} [options.urls] - registry base URLs by name
   * @param {number} [options.concurrency=8]
   */
  constructor(options = {}) {
    this.cacheDir = options.cacheDir || null;
    this.httpOptions = options.httpOptions || {};
    this.urls = {
      pypi: 'https://pypi.org',
      pypiFiles: 'https://files.pythonhosted.org',
      rubygems: 'https://rubygems.org',
      hex: 'https://repo.hex.pm',
      nuget: 'https://api.nuget.org/v3-flatcontainer',
      maven: 'https://repo1.maven.org/maven2',
      packagist: 'https://repo.packagist.org',
      crates: 'https://static.crates.io/crates',
      goproxy: 'https://proxy.golang.org',
      ...options.urls,
    };
    this.concurrency = options.concurrency || 8;
    this._memory = new Map();
  }

  _cachePath(key) {
    return this.cacheDir ? path.join(this.cacheDir, `${sha256(key)}.json`) : null;
  }

  readCache(key) {
    const file = this._cachePath(key);
    if (!file) {
      return null;
    }

    try {
      const cached = JSON.parse(fs.readFileSync(file, 'utf8'));
      return cached.key === key ? cached.value : null;
    } catch {
      return null;
    }
  }

  writeCache(key, value) {
    const file = this._cachePath(key);
    if (!file) {
      return;
    }

    fs.mkdirSync(this.cacheDir, {recursive: true, mode: 0o700});
    const temporary = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(temporary, JSON.stringify({key, value}), {mode: 0o600});
    fs.renameSync(temporary, file);
  }

  /**
   * Compute a value once per run (and once ever, when `persist` is set and
   * a cache directory is configured).  Failures are not cached.
   *
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} compute
   * @param {Object} [options]
   * @param {boolean} [options.persist=true]
   * @returns {Promise<T>}
   */
  memo(key, compute, options = {}) {
    if (!this._memory.has(key)) {
      const promise = (async () => {
        if (options.persist !== false) {
          const cached = this.readCache(key);
          if (cached !== null) {
            return cached;
          }
        }

        const value = await compute();
        if (options.persist !== false) {
          this.writeCache(key, value);
        }

        return value;
      })();
      this._memory.set(key, promise);
      promise.catch(() => this._memory.delete(key));
    }

    return this._memory.get(key);
  }

  /**
   * @param {string} url
   * @param {Object} [options] - merged over the store's http options
   * @returns {Promise<Buffer>}
   */
  get(url, options = {}) {
    return httpGet(url, {...this.httpOptions, ...options, headers: {...this.httpOptions.headers, ...options.headers}});
  }

  async getJson(url, options = {}) {
    const body = await this.get(url, {...options, headers: {accept: 'application/json', ...options.headers}});
    return JSON.parse(body.toString('utf8'));
  }
}

/**
 * Hash a set of in-memory files: path -> sha256.
 * @param {Map<string, Buffer>} files
 * @returns {Object<string, string>}
 */
function hashFiles(files) {
  const result = {};
  for (const [file, content] of files) {
    setOwn(result, file, sha256(content));
  }

  return result;
}

/**
 * Compare installed files with expected ones.
 *
 * @param {Object<string, string>} installed - path -> sha256
 * @param {Object<string, string>} expected - path -> sha256
 * @param {Object} [options]
 * @param {(file: string, hash: string) => boolean} [options.allowExtra] - installed files a package may add
 * @param {(file: string) => boolean} [options.allowMissing] - expected files an install may leave out
 * @param {(file: string, installedHash: string, expectedHash: string) => boolean} [options.equivalent]
 * @returns {{modified: string[], missing: string[], added: string[]}}
 */
function compareFiles(installed, expected, options = {}) {
  const modified = [];
  const missing = [];
  const added = [];
  for (const [file, hash] of Object.entries(expected)) {
    if (!Object.hasOwn(installed, file)) {
      if (!options.allowMissing || !options.allowMissing(file)) {
        missing.push(file);
      }
    } else if (installed[file] !== hash && !(options.equivalent && options.equivalent(file, installed[file], hash))) {
      modified.push(file);
    }
  }

  for (const [file, hash] of Object.entries(installed)) {
    if (!Object.hasOwn(expected, file) && !(options.allowExtra && options.allowExtra(file, hash))) {
      added.push(file);
    }
  }

  return {modified: modified.sort(), missing: missing.sort(), added: added.sort()};
}

/**
 * Collect per-package results into the common comparison shape.
 *
 * @param {Array<{status: string, item: Object, reason?: string, modified?: string[], missing?: string[], added?: string[]}>} results
 * @param {Object[]} [issues]
 * @returns {{passed: boolean, summary: Object, findings: Object[], issues: Object[]}}
 */
function collect(results, issues = []) {
  const summary = {total: results.length};
  for (const status of STATUSES) {
    summary[status] = 0;
  }

  const findings = [];
  for (const result of results) {
    summary[result.status]++;
    if (result.status === 'failed' || result.status === 'unverifiable' || result.status === 'error') {
      const finding = {
        status: result.status,
        package: `${result.item.name}@${result.item.version}`,
        path: result.item.path,
        reason: result.reason,
      };
      for (const key of ['modified', 'missing', 'added']) {
        if (result[key] && result[key].length > 0) {
          finding[key] = result[key].slice(0, 50);
        }
      }

      findings.push(finding);
    }
  }

  findings.sort((a, b) => (a.path > b.path) - (a.path < b.path));
  return {
    // Only warnings and information leave a result passing; any other
    // severity (fail, or one this code does not know) does not.
    passed: summary.failed === 0 && summary.unverifiable === 0 && summary.error === 0 && issues.every(issue => PASSING_SEVERITIES.has(issue.severity)),
    summary,
    findings,
    issues,
  };
}

/**
 * Issues for what a scan could not read: a file left out of a scan is a
 * file nothing was compared with, so it fails.
 *
 * @param {{errors?: Array<{path: string, error: string}>}} scan
 * @returns {Object[]}
 */
function scanIssues(scan) {
  const errors = (scan && scan.errors) || [];
  return errors.length > 0
    ? [{severity: 'fail', message: 'Files or directories the scan could not read (not compared with anything)', items: errors.map(error => `${error.path}: ${error.error}`).sort()}]
    : [];
}

/**
 * Parse CSV as written by Python's csv module (a wheel's RECORD).
 * @param {string} text
 * @returns {string[][]}
 */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let started = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index++;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"' && field === '') {
      quoted = true;
      started = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
      started = true;
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[index + 1] === '\n') {
        index++;
      }

      if (started || field !== '') {
        row.push(field);
        rows.push(row);
      }

      row = [];
      field = '';
      started = false;
    } else {
      field += char;
      started = true;
    }
  }

  if (started || field !== '') {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

/**
 * Whether a path, resolved, stays inside a directory.
 * @param {string} directory
 * @param {string} target
 * @returns {boolean}
 */
function isInside(directory, target) {
  const relative = path.relative(directory, target);
  // "..data" is a name inside the directory; only ".." itself leaves it.
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

module.exports = {
  NoLockfileError,
  ReferenceStore,
  STATUSES,
  hashFiles,
  compareFiles,
  collect,
  scanIssues,
  parseCsv,
  isInside,
};

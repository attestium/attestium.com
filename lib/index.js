/**
 * Attestium - element of attestation
 *
 * File integrity manifests, signed verification reports, challenge-response
 * for remote verifiers, runtime module tracking, and optional TPM quotes.
 *
 * Submodules:
 *   attestium/process-integrity     running processes vs. their files, any language
 *   attestium/runtimes              language runtime profiles (injection vectors, debug ports)
 *   attestium/release-verification  Node.js, npm and packages vs. upstream releases
 *   attestium/ecosystems            installed packages of every ecosystem vs. their lockfiles
 *   attestium/elf                   Go and Rust build information inside binaries
 *   attestium/containers            containers: image, mounts, writable layer, root filesystem
 *   attestium/oci                   container images from registries, by digest
 *   attestium/distro                Debian and Ubuntu packages vs. the signed archive
 *   attestium/sigstore              Sigstore bundle verification
 *   attestium/tuf                   TUF client for Sigstore's trust roots
 *   attestium/attestations          GitHub artifact attestations and npm provenance
 *   attestium/checksums             published checksum lists (gpg, minisign, Sigstore)
 *   attestium/git-trees             git trees of pinned commits
 *   attestium/tpm                   TPM 2.0 quotes and verification
 *   attestium/tpm-identity          EK certificates and credential activation
 *   attestium/ima                   Linux IMA log replay
 *   attestium/confidential          AMD SEV-SNP and Intel TDX reports
 *   attestium/monitor               eBPF record of programs run between audits
 *   attestium/evidence              the evidence format (JSON Schema and validator)
 *   attestium/schema                the JSON Schema validator
 *   attestium/zip, attestium/toml   parsers
 *   attestium/signing               Ed25519 envelopes
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const {EventEmitter} = require('node:events');
const {cosmiconfigSync} = require('cosmiconfig');
const {version: VERSION} = require('../package.json');
const signing = require('./signing');
const Tpm = require('./tpm');
const {walkTree, createMatcher, globToRegExp, hashFile, manifestDigest} = require('./file-tree');
const {generateNonce, normalizeNonce, digestOf, sha256, safeEqual, exists} = require('./util');

/**
 * The digest of a verification report's file list: manifestDigest() over
 * its paths, hashes and types (a symbolic link has mode 120000).  The
 * attester and the verifier both use this, so they cannot disagree.
 *
 * @param {Array<{relativePath: string, checksum: string, mode: string}>} files
 * @returns {string}
 */
function reportDigest(files) {
  return manifestDigest(files.map(file => ({path: file.relativePath, sha256: file.checksum, type: file.mode === '120000' ? 'symlink' : 'file'})));
}

const DEFAULT_INCLUDE = [
  '**/*.js',
  '**/*.cjs',
  '**/*.mjs',
  '**/*.json',
  '**/*.ts',
  '**/*.node',
  '**/*.sh',
  '**/*.wasm',
  '**/*.css',
  '**/*.html',
  '**/*.pug',
  '**/*.md',
  '**/*.yml',
  '**/*.yaml',
  '**/*.txt',
  '**/*.xml',
  '**/*.svg',
  '**/*.png',
  '**/*.jpg',
  '**/*.jpeg',
  '**/*.gif',
  '**/*.ico',
  '**/*.woff',
  '**/*.woff2',
  '**/*.ttf',
  '**/*.eot',
  '**/Dockerfile*',
  '**/LICENSE*',
  '**/README*',
  '**/CHANGELOG*',
  '**/CONTRIBUTING*',
  '**/.dockerignore',
];

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/.svn/**',
  '**/.hg/**',
  '**/*.key',
  '**/*.pem',
  '**/*.p12',
  '**/*.pfx',
  '**/*.crt',
  '**/*.csr',
  '**/.env*',
  '**/.DS_Store',
  '**/Thumbs.db',
  '**/*.tmp',
  '**/*.temp',
  '**/*.swp',
  '**/*.swo',
  '**/~*',
  '**/.vscode/**',
  '**/.idea/**',
  '**/*.sublime-*',
];

// Config files are data only: executable formats (.js/.cjs/.ts) are not
// searched, because loading them would run code from the tree being verified.
const CONFIG_SEARCH_PLACES = [
  'package.json',
  '.attestiumrc',
  '.attestiumrc.json',
  '.attestiumrc.yaml',
  '.attestiumrc.yml',
  'attestium.config.json',
  'attestium.config.yaml',
  'attestium.config.yml',
];

// ─── runtime module tracking (process-wide) ─────────────────────────

const RUNTIME = {
  installed: false,
  modules: new Map(),
  listeners: new Set(),
};

/**
 * Record the SHA-256 of every CommonJS module's source exactly as it is
 * handed to the compiler.  This is the code that runs, even if the file on
 * disk is changed afterwards.  Installed once per process; ES modules are
 * not covered.
 */
function installRuntimeTracking() {
  if (RUNTIME.installed) {
    return;
  }

  const originalCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    const record = {filename, sha256: sha256(content), loadedAt: new Date().toISOString()};
    RUNTIME.modules.set(filename, record);
    for (const listener of RUNTIME.listeners) {
      listener(record);
    }

    return Reflect.apply(originalCompile, this, [content, filename]);
  };

  RUNTIME.installed = true;
}

class Attestium extends EventEmitter { // eslint-disable-line unicorn/prefer-event-target
  /**
   * @param {Object} [options]
   * @param {string} [options.projectRoot=process.cwd()]
   * @param {string[]} [options.includePatterns]
   * @param {string[]} [options.excludePatterns]
   * @param {boolean} [options.enableGitignoreInheritance=false] - also exclude root .gitignore patterns
   * @param {boolean} [options.enableRuntimeHooks=false] - record hashes of CommonJS modules as they are compiled
   * @param {string} [options.signingKey] - Ed25519 private key (PEM) used to sign exports and responses
   * @param {boolean} [options.continuousVerification=false]
   * @param {number|'random'} [options.verificationInterval=60000]
   * @param {Object<string, RegExp>} [options.customCategories]
   * @param {string} [options.gitCommit=process.env.GIT_COMMIT]
   * @param {string} [options.deployTime=process.env.DEPLOY_TIME]
   * @param {boolean} [options.enableTpm=true]
   * @param {Object} [options.tpm] - options for attestium/tpm
   * @param {Object} [options.logger=console] - object with a log(message) method
   */
  constructor(options = {}) {
    super();

    const projectRoot = path.resolve(options.projectRoot || process.cwd());
    if (!exists(projectRoot)) {
      throw new Error(`Project root does not exist: ${projectRoot}`);
    }

    const explorer = cosmiconfigSync('attestium', {searchPlaces: CONFIG_SEARCH_PLACES, stopDir: projectRoot});
    const found = explorer.search(projectRoot);
    const config = found && found.config && typeof found.config === 'object' ? found.config : {};
    const merged = {...config, ...options, projectRoot};

    this.version = VERSION;
    this.projectRoot = projectRoot;
    this.gitCommit = merged.gitCommit || process.env.GIT_COMMIT || null;
    this.deployTime = merged.deployTime || process.env.DEPLOY_TIME || null;
    this.logger = merged.logger || console;
    this.includePatterns = merged.includePatterns || [...DEFAULT_INCLUDE];
    this.excludePatterns = merged.excludePatterns || [...DEFAULT_EXCLUDE];
    this.customCategories = merged.customCategories || {};
    this.developmentMode = Boolean(merged.developmentMode);
    this.productionMode = Boolean(merged.productionMode);
    this.signingKey = merged.signingKey ? signing.toPrivateKey(merged.signingKey) : null;
    this.continuousVerification = Boolean(merged.continuousVerification);
    this.verificationInterval = merged.verificationInterval || 60_000;
    this.enableRuntimeHooks = merged.enableRuntimeHooks === true;
    this.tpmEnabled = merged.enableTpm !== false;
    this.tpm = new Tpm(merged.tpm || {});
    this.fileChecksums = new Map();
    this._verificationTimer = null;
    this._runtimeListener = null;

    if (merged.enableGitignoreInheritance) {
      this.loadGitignorePatterns();
    }

    this._compileMatchers();

    if (this.enableRuntimeHooks) {
      this.setupRuntimeHooks();
    }

    if (this.continuousVerification) {
      this.startContinuousVerification();
    }
  }

  _compileMatchers() {
    this._include = createMatcher(this.includePatterns);
    this._exclude = createMatcher(this.excludePatterns);
  }

  /**
   * @param {string} message
   * @param {string} [level='INFO']
   */
  log(message, level = 'INFO') {
    if (this.logger && typeof this.logger.log === 'function') {
      this.logger.log(`[${new Date().toISOString()}] [ATTESTIUM] [${level.toUpperCase()}] ${message}`);
    }
  }

  // ─── file selection ───────────────────────────────────────────────

  /**
   * Glob match (see attestium/file-tree globToRegExp).
   * @param {string} relativePath
   * @param {string} pattern
   * @returns {boolean}
   */
  matchesPattern(relativePath, pattern) {
    return globToRegExp(pattern).test(relativePath);
  }

  /**
   * @param {string} relativePath
   * @returns {boolean}
   */
  shouldExclude(relativePath) {
    const normalized = relativePath.replaceAll('\\', '/');
    return this._exclude(normalized);
  }

  /**
   * @param {string} relativePath
   * @returns {boolean}
   */
  shouldInclude(relativePath) {
    const normalized = relativePath.replaceAll('\\', '/');
    return this._include(normalized) && !this._exclude(normalized);
  }

  /**
   * @param {string} relativePath
   * @returns {string}
   */
  categorizeFile(relativePath) {
    const normalized = relativePath.replaceAll('\\', '/');
    for (const [category, pattern] of Object.entries(this.customCategories)) {
      if (pattern instanceof RegExp && pattern.test(normalized)) {
        return category;
      }
    }

    if (/(?:^|\/)node_modules\//.test(normalized)) {
      return 'dependency';
    }

    if (/\.(?:test|spec)\.[cm]?[jt]s$/.test(normalized) || /(?:^|\/)(?:test|tests|__tests__)\//.test(normalized)) {
      return 'test';
    }

    if (/^(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(normalized) || /(?:^|\/)config\//.test(normalized)) {
      return 'config';
    }

    if (/\.(?:md|txt|rst)$/i.test(normalized) || /(?:^|\/)(?:readme|changelog|license|contributing)[^/]*$/i.test(normalized)) {
      return 'documentation';
    }

    if (/\.(?:css|scss|sass|less|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp3|mp4|avi|mov|pdf)$/i.test(normalized)) {
      return 'static_asset';
    }

    return 'source';
  }

  /**
   * Convert .gitignore lines to glob patterns (negations are not supported
   * and are skipped).
   * @param {string} content
   * @returns {string[]}
   */
  parseGitignorePatterns(content) {
    const patterns = [];
    for (let line of content.split(/\r?\n/)) {
      line = line.trim();
      if (!line || line.startsWith('#') || line.startsWith('!')) {
        continue;
      }

      const anchored = line.startsWith('/') || line.slice(0, -1).includes('/');
      const body = line.replace(/^\//, '').replace(/\/$/, '');
      const base = anchored ? body : `**/${body}`;
      patterns.push(base, `${base}/**`);
    }

    return patterns;
  }

  /**
   * Add the project root's .gitignore patterns to the exclude list.
   */
  loadGitignorePatterns() {
    const file = path.join(this.projectRoot, '.gitignore');
    if (exists(file)) {
      const patterns = this.parseGitignorePatterns(fs.readFileSync(file, 'utf8'));
      this.excludePatterns = [...this.excludePatterns, ...patterns];
      this._compileMatchers();
      this.log(`Loaded ${patterns.length} patterns from .gitignore`);
    }
  }

  // ─── hashing and reports ──────────────────────────────────────────

  /**
   * Absolute paths of the files covered by the include/exclude patterns.
   * Symbolic links are never followed.
   * @returns {Promise<string[]>}
   */
  async scanProjectFiles() {
    const {entries} = await this._walk();
    return entries.map(entry => path.join(this.projectRoot, ...entry.path.split('/')));
  }

  _walk() {
    return walkTree(this.projectRoot, {
      exclude: (relativePath, isDirectory) => (isDirectory
        ? this._exclude(relativePath) || this._exclude(`${relativePath}/x`)
        : !this.shouldInclude(relativePath)),
    });
  }

  /**
   * SHA-256 of a file.
   * @param {string} filePath
   * @returns {Promise<string>}
   */
  async calculateFileChecksum(filePath) {
    return (await hashFile(filePath)).sha256;
  }

  /**
   * @param {string} filePath
   * @returns {Promise<string>}
   */
  async generateFileChecksum(filePath) {
    return this.calculateFileChecksum(filePath);
  }

  /**
   * @param {string} filePath
   * @returns {Promise<Object>}
   */
  async verifyFileIntegrity(filePath) {
    const relativePath = path.relative(this.projectRoot, filePath).split(path.sep).join('/');
    try {
      const {sha256: checksum, size} = await hashFile(filePath);
      return {
        checksum, verified: true, timestamp: new Date().toISOString(), category: this.categorizeFile(relativePath), size,
      };
    } catch (error) {
      return {
        checksum: null, verified: false, timestamp: new Date().toISOString(), error: error.code || error.message,
      };
    }
  }

  /**
   * Hash every covered file.
   *
   * `verifiedFiles` counts files that were read and hashed; comparing the
   * hashes with a trusted reference is a separate step (see
   * compareWithBaseline() or a remote verifier).
   *
   * @returns {Promise<Object>}
   */
  async generateVerificationReport() {
    const {entries, errors} = await this._walk();
    const files = entries.map(entry => ({
      relativePath: entry.path,
      checksum: entry.sha256,
      gitBlobId: entry.gitBlobId,
      mode: entry.mode,
      size: entry.size,
      category: this.categorizeFile(entry.path),
      verified: true,
    }));
    const categories = {};
    for (const file of files) {
      categories[file.category] = (categories[file.category] || 0) + 1;
    }

    return {
      timestamp: new Date().toISOString(),
      attestiumVersion: VERSION,
      projectRoot: this.projectRoot,
      gitCommit: this.gitCommit,
      deployTime: this.deployTime,
      files,
      errors,
      digest: reportDigest(files),
      summary: {
        totalFiles: files.length + errors.length,
        verifiedFiles: files.length,
        failedFiles: errors.length,
        categories,
      },
    };
  }

  /**
   * Export a baseline that can later be compared with compareWithBaseline().
   * Signed with `signingKey` when one is configured.
   *
   * @returns {Promise<Object>}
   */
  async exportVerificationData() {
    const report = await this.generateVerificationReport();
    const data = {
      type: 'attestium-baseline',
      metadata: {
        attestiumVersion: VERSION,
        timestamp: report.timestamp,
        gitCommit: this.gitCommit,
        deployTime: this.deployTime,
      },
      files: Object.fromEntries(report.files.map(file => [file.relativePath, {checksum: file.checksum, category: file.category, size: file.size}])),
      summary: report.summary,
      digest: report.digest,
    };
    if (this.signingKey) {
      const envelope = signing.sign(data, this.signingKey);
      return {
        ...data, signature: {
          alg: envelope.alg, keyId: envelope.keyId, publicKey: envelope.publicKey, value: envelope.signature,
        },
      };
    }

    return data;
  }

  /**
   * Compare the current tree with an exported baseline.
   *
   * @param {Object} baseline - from exportVerificationData()
   * @param {Object} [options]
   * @param {string} [options.publicKey] - trusted signer key; when set the baseline must be signed by it
   * @returns {Promise<{valid: boolean, signature: Object|null, added: string[], removed: string[], modified: string[], errors: Object[]}>}
   */
  async compareWithBaseline(baseline, options = {}) {
    const result = {
      valid: false, signature: null, added: [], removed: [], modified: [], errors: [],
    };
    if (!baseline || typeof baseline.files !== 'object' || baseline.files === null) {
      result.errors.push({error: 'Malformed baseline'});
      return result;
    }

    if (options.publicKey || baseline.signature) {
      const {signature, ...payload} = baseline;
      result.signature = signature
        ? signing.verify({
          alg: signature.alg, keyId: signature.keyId, publicKey: signature.publicKey, payload, signature: signature.value,
        }, options.publicKey)
        : {valid: false, trusted: false, error: 'Baseline is not signed'};
      if (!result.signature.valid) {
        result.errors.push({error: `Baseline signature: ${result.signature.error}`});
        return result;
      }

      // Signed by the right key, but it must also be a baseline (the key
      // may sign other kinds of statement).
      if (payload.type !== 'attestium-baseline') {
        result.errors.push({error: 'Not a baseline'});
        return result;
      }
    }

    const current = await this.generateVerificationReport();
    const seen = new Set();
    for (const file of current.files) {
      seen.add(file.relativePath);
      const expected = baseline.files[file.relativePath];
      if (!expected) {
        result.added.push(file.relativePath);
      } else if (expected.checksum !== file.checksum) {
        result.modified.push(file.relativePath);
      }
    }

    for (const relativePath of Object.keys(baseline.files)) {
      if (!seen.has(relativePath)) {
        result.removed.push(relativePath);
      }
    }

    result.errors.push(...current.errors);
    result.valid = result.added.length === 0 && result.removed.length === 0
      && result.modified.length === 0 && result.errors.length === 0;
    return result;
  }

  /**
   * @param {Object} baseline
   * @param {Object} [options]
   * @returns {Promise<boolean>} true when the tree matches the (signed, if required) baseline
   */
  async verifyImportedData(baseline, options = {}) {
    const result = await this.compareWithBaseline(baseline, options);
    if (!result.valid) {
      this.log(`Baseline mismatch: ${result.modified.length} modified, ${result.added.length} added, ${result.removed.length} removed`, 'WARN');
    }

    return result.valid;
  }

  // ─── challenge-response ───────────────────────────────────────────

  /**
   * A fresh challenge for a remote party to send back.
   * @param {number} [ttlMs=300000]
   * @returns {{nonce: string, timestamp: string, expiresAt: string}}
   */
  generateChallenge(ttlMs = 300_000) {
    const now = Date.now();
    return {nonce: generateNonce(32), timestamp: new Date(now).toISOString(), expiresAt: new Date(now + ttlMs).toISOString()};
  }

  /**
   * @param {{expiresAt: string}} challenge
   * @returns {boolean}
   */
  validateChallenge(challenge) {
    if (!challenge || !challenge.expiresAt) {
      return false;
    }

    const expiresAt = Date.parse(challenge.expiresAt);
    return Number.isFinite(expiresAt) && Date.now() < expiresAt;
  }

  /**
   * @param {Object|string} challenge
   * @param {string} nonce
   * @returns {Promise<boolean>}
   */
  async verifyChallenge(challenge, nonce) {
    let value = challenge;
    if (typeof value === 'string') {
      try {
        value = JSON.parse(value);
      } catch {
        return false;
      }
    }

    return Boolean(value) && typeof nonce === 'string' && safeEqual(value.nonce, nonce) && this.validateChallenge(value);
  }

  /**
   * Answer a verifier's challenge with a (signed) statement of the current
   * tree digest.
   *
   * @param {string} nonce - hex nonce chosen by the verifier
   * @returns {Promise<Object>} envelope from attestium/signing, or {payload, signature: null} without a key
   */
  async generateVerificationResponse(nonce) {
    const report = await this.generateVerificationReport();
    const payload = {
      type: 'attestium-verification-response',
      nonce: normalizeNonce(nonce),
      timestamp: report.timestamp,
      attestiumVersion: VERSION,
      gitCommit: this.gitCommit,
      digest: report.digest,
      summary: report.summary,
    };
    if (!this.signingKey) {
      return {payload, signature: null};
    }

    return signing.sign(payload, this.signingKey);
  }

  /**
   * Check a response produced by generateVerificationResponse().
   *
   * @param {Object} response
   * @param {Object} expected
   * @param {string} expected.nonce
   * @param {string} expected.publicKey - trusted signer
   * @param {string} [expected.digest] - required tree digest
   * @param {number} [expected.maxAgeMs=300000]
   * @returns {{valid: boolean, errors: string[]}}
   */
  static verifyVerificationResponse(response, expected) {
    const errors = [];
    const check = signing.verify(response, expected.publicKey);
    if (!check.valid || !check.trusted) {
      errors.push(`Signature: ${check.error || 'untrusted'}`);
      return {valid: false, errors};
    }

    const {payload} = response;
    // The same key may sign other kinds of statement (a baseline, an
    // application's own); only a verification response answers a challenge.
    if (!payload || typeof payload !== 'object' || payload.type !== 'attestium-verification-response') {
      errors.push('Not a verification response');
      return {valid: false, errors};
    }

    if (!safeEqual(payload.nonce, String(expected.nonce).toLowerCase())) {
      errors.push('Nonce mismatch');
    }

    const age = Date.now() - Date.parse(payload.timestamp);
    if (!(age >= -60_000 && age <= (expected.maxAgeMs ?? 300_000))) {
      errors.push('Response is too old or from the future');
    }

    if (expected.digest && payload.digest !== expected.digest) {
      errors.push('Tree digest differs from the expected digest');
    }

    return {valid: errors.length === 0, errors};
  }

  // ─── runtime tracking ─────────────────────────────────────────────

  /**
   * Start recording CommonJS modules as they are compiled.
   */
  setupRuntimeHooks() {
    installRuntimeTracking();
    if (!this._runtimeListener) {
      this._runtimeListener = record => {
        this.emit('moduleLoaded', record);
      };

      RUNTIME.listeners.add(this._runtimeListener);
    }
  }

  /**
   * Modules compiled since tracking started, with their source hash at
   * compile time and whether the file on disk still matches.
   *
   * @returns {Promise<{enabled: boolean, totalModules: number, changedOnDisk: number, modules: Object[]}>}
   */
  async getRuntimeVerificationStatus() {
    const modules = [];
    for (const record of RUNTIME.modules.values()) {
      let diskSha256 = null;
      try {
        diskSha256 = sha256(await fs.promises.readFile(record.filename, 'utf8'));
      } catch {}

      modules.push({...record, diskSha256, changedOnDisk: diskSha256 !== record.sha256});
    }

    return {
      enabled: RUNTIME.installed,
      totalModules: modules.length,
      changedOnDisk: modules.filter(module => module.changedOnDisk).length,
      modules,
    };
  }

  // ─── continuous verification ──────────────────────────────────────

  /**
   * Re-hash the tree periodically and emit `fileChanged`,
   * `integrityViolation` (for changed, added and removed files) and
   * `verificationError`.
   *
   * @param {number|'random'} [interval]
   */
  startContinuousVerification(interval) {
    if (interval) {
      this.verificationInterval = interval;
    }

    this.stopContinuousVerification();
    const nextDelay = () => (this.verificationInterval === 'random'
      ? 15_000 + crypto.randomInt(105_000)
      : (typeof this.verificationInterval === 'number' ? this.verificationInterval : 60_000));

    const schedule = () => {
      this._verificationTimer = setTimeout(run, nextDelay());
      this._verificationTimer.unref();
    };

    const run = async () => {
      try {
        await this.runVerificationCycle();
      } catch (error) {
        this.emit('verificationError', error);
      }

      if (this._verificationTimer) {
        schedule();
      }
    };

    schedule();
    this.log('Continuous verification started');
  }

  /**
   * One verification cycle (exposed for callers that schedule their own).
   * The first cycle records the baseline.
   *
   * @returns {Promise<Object[]>} violations found in this cycle
   */
  async runVerificationCycle() {
    const report = await this.generateVerificationReport();
    const violations = [];
    const first = this.fileChecksums.size === 0;
    const seen = new Set();
    for (const file of report.files) {
      seen.add(file.relativePath);
      const previous = this.fileChecksums.get(file.relativePath);
      if (!first && previous === undefined) {
        violations.push({type: 'fileAdded', file: file.relativePath, newChecksum: file.checksum});
      } else if (previous !== undefined && previous !== file.checksum) {
        violations.push({
          type: 'fileChanged', file: file.relativePath, previousChecksum: previous, newChecksum: file.checksum,
        });
        this.emit('fileChanged', file.relativePath, previous, file.checksum);
      }

      this.fileChecksums.set(file.relativePath, file.checksum);
    }

    for (const [relativePath, previous] of this.fileChecksums) {
      if (!seen.has(relativePath)) {
        violations.push({type: 'fileRemoved', file: relativePath, previousChecksum: previous});
        this.fileChecksums.delete(relativePath);
      }
    }

    for (const violation of violations) {
      this.emit('integrityViolation', {...violation, timestamp: report.timestamp});
    }

    return violations;
  }

  stopContinuousVerification() {
    if (this._verificationTimer) {
      clearTimeout(this._verificationTimer);
      this._verificationTimer = null;
      this.log('Continuous verification stopped');
    }
  }

  // ─── TPM ──────────────────────────────────────────────────────────

  /**
   * @returns {Promise<boolean>}
   */
  async isTpmAvailable() {
    return this.tpmEnabled && this.tpm.isAvailable();
  }

  /**
   * Make sure the persistent attestation key exists (creating it on first
   * use) and return its public part.
   * @returns {Promise<{handle: string, publicKey: string, keyId: string}>}
   */
  async initializeTpm() {
    if (!this.tpmEnabled) {
      throw new Error('TPM is disabled. Enable with { enableTpm: true }');
    }

    try {
      return await this.tpm.getAttestationKey();
    } catch {
      return this.tpm.createAttestationKey();
    }
  }

  /**
   * A verification report bound to a TPM quote.  The quote's qualifying
   * data is SHA-256(nonce || report digest), so the verifier can check both
   * freshness and that this exact report was produced on the quoting
   * machine at that time.
   *
   * @param {string} nonce - hex nonce chosen by the verifier
   * @param {Object} [options]
   * @param {number[]} [options.pcrList]
   * @returns {Promise<Object>}
   */
  async generateHardwareAttestation(nonce, options = {}) {
    nonce = normalizeNonce(nonce);
    if (!await this.isTpmAvailable()) {
      throw new Error('TPM not available for hardware attestation');
    }

    const report = await this.generateVerificationReport();
    const quote = await this.tpm.quote({
      nonce: sha256(Buffer.concat([Buffer.from(nonce, 'hex'), Buffer.from(report.digest, 'hex')])),
      pcrs: options.pcrList,
    });
    return {
      type: 'hardware-backed', nonce, reportDigest: report.digest, softwareVerification: report, hardwareAttestation: quote, timestamp: new Date().toISOString(),
    };
  }

  /**
   * Check generateHardwareAttestation() output.
   * @param {Object} attestation
   * @param {{nonce: string, publicKey: string, expectedPcrs?: Object}} expected
   * @returns {{valid: boolean, errors: string[]}}
   */
  static verifyHardwareAttestation(attestation, expected) {
    const errors = [];
    const digest = reportDigest(attestation.softwareVerification.files);
    if (digest !== attestation.reportDigest || digest !== attestation.softwareVerification.digest) {
      errors.push('Report digest does not match the file list');
    }

    let nonce;
    try {
      nonce = normalizeNonce(expected.nonce);
    } catch (error) {
      return {valid: false, errors: [error.message]};
    }

    if (attestation.nonce !== nonce) {
      errors.push('Attestation does not answer this nonce');
    }

    const qualifying = sha256(Buffer.concat([Buffer.from(nonce, 'hex'), Buffer.from(digest, 'hex')]));
    const quote = Tpm.verifyQuote({
      quote: attestation.hardwareAttestation, publicKey: expected.publicKey, nonce: qualifying, expectedPcrs: expected.expectedPcrs,
    });
    errors.push(...quote.errors);
    return {valid: errors.length === 0, errors};
  }

  /**
   * Random bytes from the TPM when available, otherwise from the OS CSPRNG.
   * @param {number} [length=32]
   * @returns {Promise<{bytes: Buffer, source: string}>}
   */
  async generateHardwareRandom(length = 32) {
    if (await this.isTpmAvailable()) {
      try {
        return {bytes: await this.tpm.getRandom(length), source: 'tpm'};
      } catch (error) {
        this.log(`TPM random failed: ${error.message}`, 'WARN');
      }
    }

    return {bytes: crypto.randomBytes(length), source: 'os'};
  }

  /**
   * @returns {string}
   */
  getTpmInstallationInstructions() {
    return [
      'Hardware attestation needs a TPM 2.0 and tpm2-tools:',
      '  Debian/Ubuntu: sudo apt-get install tpm2-tools',
      '  Fedora/RHEL:   sudo dnf install tpm2-tools',
      'The user running Attestium must be able to open /dev/tpmrm0 (usually the "tss" group).',
      'Check with: tpm2_getcap properties-fixed',
    ].join('\n');
  }

  /**
   * @returns {Promise<Object>}
   */
  async getSecurityStatus() {
    const tpmAvailable = await this.isTpmAvailable();
    return {
      success: true,
      security: {
        tpmAvailable,
        hardwareBacked: tpmAvailable,
        signingKeyConfigured: Boolean(this.signingKey),
        signingKeyId: this.signingKey ? signing.fingerprint(this.signingKey) : null,
        runtimeTracking: RUNTIME.installed,
      },
      system: {
        attestiumVersion: VERSION, nodeVersion: process.version, platform: process.platform, arch: process.arch,
      },
      project: {root: this.projectRoot, gitCommit: this.gitCommit, deployTime: this.deployTime},
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Stop timers and detach runtime listeners.
   */
  async cleanup() {
    this.stopContinuousVerification();
    if (this._runtimeListener) {
      RUNTIME.listeners.delete(this._runtimeListener);
      this._runtimeListener = null;
    }
  }
}

Attestium.VERSION = VERSION;
Attestium.DEFAULT_INCLUDE = DEFAULT_INCLUDE;
Attestium.DEFAULT_EXCLUDE = DEFAULT_EXCLUDE;
Attestium.digestOf = digestOf;

module.exports = Attestium;
module.exports.Attestium = Attestium;
module.exports.signing = signing;
module.exports.Tpm = Tpm;
module.exports.ProcessIntegrity = require('./process-integrity');
module.exports.ReleaseVerification = require('./release-verification');
module.exports.ima = require('./ima');
module.exports.fileTree = require('./file-tree');
module.exports.util = require('./util');
module.exports.http = require('./http');
module.exports.runtimes = require('./runtimes');
module.exports.ecosystems = require('./ecosystems');
module.exports.elf = require('./elf');
module.exports.zip = require('./zip');
module.exports.toml = require('./toml');
module.exports.asn1 = require('./asn1');
module.exports.sigstore = require('./sigstore');
module.exports.tuf = require('./tuf');
module.exports.attestations = require('./attestations');
module.exports.checksums = require('./checksums');
module.exports.distro = require('./distro');
module.exports.containers = require('./containers');
module.exports.oci = require('./oci');
module.exports.confidential = require('./confidential');
module.exports.tpmIdentity = require('./tpm-identity');
module.exports.monitor = require('./monitor');
module.exports.schema = require('./schema');
module.exports.gitTrees = require('./git-trees');
module.exports.evidence = require('./evidence');

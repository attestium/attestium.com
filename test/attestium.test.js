'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Attestium = require('../lib');
const {signing, Tpm} = require('../lib');
const {
  tempDir, writeFiles, windows, needsPosix, hasTpmSimulator, startSwtpm, sleep,
} = require('./helpers');

const quiet = {log() {}};

function project(t, files = {}) {
  const root = tempDir(t);
  writeFiles(root, {
    'package.json': '{"name":"app"}',
    'index.js': 'module.exports = 1;\n',
    'README.md': '# app\n',
    ...files,
  });
  return root;
}

test('exports every submodule', () => {
  for (const name of ['Attestium', 'signing', 'Tpm', 'ProcessIntegrity', 'ReleaseVerification', 'ima', 'fileTree', 'util', 'http']) {
    assert.ok(Attestium[name], name);
  }

  assert.equal(Attestium.VERSION, require('../package.json').version);
  assert.equal(require('../lib/process-integrity'), Attestium.ProcessIntegrity);
  assert.equal(typeof Attestium.digestOf, 'function');
});

test('submodules resolve as package subpaths, and docs/ is published', () => {
  const property = {
    './elf': 'elf', './tuf': 'tuf', './schema': 'schema', './git-trees': 'gitTrees', './zip': 'zip', './toml': 'toml', './evidence': 'evidence', './tpm-identity': 'tpmIdentity',
  };
  for (const [subpath, name] of Object.entries(property)) {
    // Resolved through the package's own "exports", as a consumer resolves it.
    assert.equal(require(`attestium${subpath.slice(1)}`), Attestium[name], subpath);
  }

  assert.ok(require('../package.json').files.includes('docs/'), 'README links to docs/');
});

test('file names cannot inject code (regression: vm string interpolation)', {skip: windows && 'Windows file names cannot hold quotes or line breaks'}, async t => {
  const marker = path.join(tempDir(t), 'pwned');
  const evil = [
    `a",this.constructor.constructor("return process")().mainModule.require("fs").writeFileSync(${JSON.stringify(marker).replaceAll('/', '∕')},"x"),"b.js`,
    String.raw`back\slash".js`,
    'new\nline.js',
    '${process.exit(1)}.js', // eslint-disable-line no-template-curly-in-string
  ];
  const root = project(t, Object.fromEntries(evil.map(name => [name, 'x'])));
  const attestium = new Attestium({projectRoot: root, logger: quiet});
  const report = await attestium.generateVerificationReport();
  assert.equal(fs.existsSync(marker), false);
  for (const name of evil) {
    assert.ok(report.files.some(file => file.relativePath === name), name);
  }
});

test('configuration: files, precedence, and executable config is never loaded', async t => {
  const executed = path.join(tempDir(t), 'executed');
  const root = project(t, {
    '.attestiumrc.json': JSON.stringify({includePatterns: ['**/*.md'], gitCommit: 'from-config'}),
    'attestium.config.js': `require('fs').writeFileSync(${JSON.stringify(executed)}, 'x'); module.exports = {};`,
  });
  const attestium = new Attestium({projectRoot: root, logger: quiet});
  assert.equal(fs.existsSync(executed), false);
  assert.deepEqual(attestium.includePatterns, ['**/*.md']);
  assert.equal(attestium.gitCommit, 'from-config');
  assert.equal(new Attestium({projectRoot: root, gitCommit: 'option', logger: quiet}).gitCommit, 'option');

  const viaPackage = project(t, {'package.json': JSON.stringify({attestium: {deployTime: 'd1'}})});
  assert.equal(new Attestium({projectRoot: viaPackage, logger: quiet}).deployTime, 'd1');
  const scalarConfig = project(t, {'.attestiumrc.yml': 'just a string\n'});
  assert.equal(new Attestium({projectRoot: scalarConfig, logger: quiet}).gitCommit, process.env.GIT_COMMIT || null);

  const originalCommit = process.env.GIT_COMMIT;
  const originalDeploy = process.env.DEPLOY_TIME;
  process.env.GIT_COMMIT = 'env-commit';
  process.env.DEPLOY_TIME = 'env-deploy';
  try {
    const fromEnvironment = new Attestium({projectRoot: viaPackage, logger: quiet});
    assert.equal(fromEnvironment.gitCommit, 'env-commit');
    assert.equal(fromEnvironment.deployTime, 'd1');
    assert.equal(new Attestium({projectRoot: scalarConfig, logger: quiet}).deployTime, 'env-deploy');
  } finally {
    if (originalCommit === undefined) {
      delete process.env.GIT_COMMIT;
    } else {
      process.env.GIT_COMMIT = originalCommit;
    }

    if (originalDeploy === undefined) {
      delete process.env.DEPLOY_TIME;
    } else {
      process.env.DEPLOY_TIME = originalDeploy;
    }
  }

  assert.throws(() => new Attestium({projectRoot: path.join(root, 'missing')}), /does not exist/);
  const cwdDefault = new Attestium({logger: quiet, enableTpm: false});
  assert.equal(cwdDefault.projectRoot, process.cwd());
  assert.equal(cwdDefault.logger, quiet);
  assert.equal(new Attestium({projectRoot: root}).logger, console);
});

test('file selection, categories and .gitignore inheritance', async t => {
  const root = project(t, {
    '.gitignore': '# build output\n/dist\nlogs/\n*.log\n!keep.log\ndocs/generated/\n\n',
    'dist/bundle.js': 'x',
    'logs/app.js': 'x',
    'server.log': 'x',
    'docs/generated/api.md': 'x',
    'docs/guide.md': 'x',
    'node_modules/dep/index.js': 'x',
    '.git/config': 'x',
    '.env': 'SECRET=1',
    'test/a.test.js': 'x',
    'lib/x.spec.ts': 'x',
    'config/app.json': '{}',
    'assets/logo.svg': '<svg/>',
    LICENSE: 'MIT',
    'src/app.js': 'x',
  });
  // A link back to the root is not followed (making one on Windows needs a privilege).
  if (!windows) {
    fs.symlinkSync(root, path.join(root, 'loop'));
  }

  const attestium = new Attestium({
    projectRoot: root,
    logger: quiet,
    enableGitignoreInheritance: true,
    customCategories: {generated: /^docs\/generated\//, invalid: 'not a regexp'},
  });
  assert.deepEqual(attestium.parseGitignorePatterns('/a\nb/\nc/d\n!e\n#f\n'), ['a', 'a/**', '**/b', '**/b/**', 'c/d', 'c/d/**']);
  const files = (await attestium.scanProjectFiles()).map(file => path.relative(root, file).split(path.sep).join('/')).sort();
  assert.deepEqual(files, ['LICENSE', 'README.md', 'assets/logo.svg', 'config/app.json', 'docs/guide.md', 'index.js', 'lib/x.spec.ts', 'package.json', 'src/app.js', 'test/a.test.js']);

  assert.equal(attestium.categorizeFile('docs/generated/x.md'), 'generated');
  assert.equal(attestium.categorizeFile(String.raw`node_modules\x\y.js`), 'dependency');
  assert.equal(attestium.categorizeFile('test/a.js'), 'test');
  assert.equal(attestium.categorizeFile('lib/x.spec.ts'), 'test');
  assert.equal(attestium.categorizeFile('package.json'), 'config');
  assert.equal(attestium.categorizeFile('config/app.json'), 'config');
  assert.equal(attestium.categorizeFile('docs/guide.md'), 'documentation');
  assert.equal(attestium.categorizeFile('CHANGELOG'), 'documentation');
  assert.equal(attestium.categorizeFile('assets/logo.svg'), 'static_asset');
  assert.equal(attestium.categorizeFile('src/app.js'), 'source');

  assert.equal(attestium.matchesPattern('a/b.js', '**/*.js'), true);
  assert.equal(attestium.shouldExclude('node_modules/'), true);
  assert.equal(attestium.shouldExclude(String.raw`src\app.js`), false);
  assert.equal(attestium.shouldInclude(String.raw`src\app.js`), true);
  assert.equal(attestium.shouldInclude('.env'), false);

  const noGitignore = new Attestium({projectRoot: project(t), logger: quiet, enableGitignoreInheritance: true});
  assert.deepEqual(noGitignore.excludePatterns, Attestium.DEFAULT_EXCLUDE);
});

test('reports, signed baselines and comparisons', async t => {
  const root = project(t, {'src/a.js': 'a', 'src/b.js': 'b'});
  const keys = signing.generateKeyPair();
  const other = signing.generateKeyPair();
  const signer = new Attestium({
    projectRoot: root, logger: quiet, signingKey: keys.privateKey, gitCommit: 'abc',
  });

  const report = await signer.generateVerificationReport();
  assert.equal(report.summary.totalFiles, 5);
  assert.equal(report.summary.verifiedFiles, 5);
  assert.equal(report.gitCommit, 'abc');
  assert.equal(report.files.find(file => file.relativePath === 'src/a.js').gitBlobId, '2e65efe2a145dda7ee51d1741299f848e5bf752e');
  assert.equal(await signer.calculateFileChecksum(path.join(root, 'src/a.js')), await signer.generateFileChecksum(path.join(root, 'src/a.js')));
  const integrity = await signer.verifyFileIntegrity(path.join(root, 'src/a.js'));
  assert.equal(integrity.verified, true);
  assert.equal(integrity.category, 'source');
  assert.deepEqual((await signer.verifyFileIntegrity(path.join(root, 'nope.js'))).error, 'ENOENT');

  const baseline = await signer.exportVerificationData();
  assert.equal(baseline.signature.keyId, signing.fingerprint(keys.publicKey));
  assert.equal((await signer.compareWithBaseline(baseline, {publicKey: keys.publicKey})).valid, true);
  assert.equal(await signer.verifyImportedData(baseline, {publicKey: keys.publicKey}), true);
  assert.equal((await signer.compareWithBaseline(baseline)).signature.trusted, false, 'self-consistent but not trusted');

  // Untrusted key, tampered baseline, missing signature.
  assert.match((await signer.compareWithBaseline(baseline, {publicKey: other.publicKey})).errors[0].error, /Key id does not match/);
  const tampered = structuredClone(baseline);
  tampered.files['src/a.js'].checksum = tampered.files['src/b.js'].checksum;
  assert.match((await signer.compareWithBaseline(tampered, {publicKey: keys.publicKey})).errors[0].error, /does not verify/);
  const {signature, ...unsigned} = baseline;
  assert.match((await signer.compareWithBaseline(unsigned, {publicKey: keys.publicKey})).errors[0].error, /not signed/);
  assert.equal(baseline.type, 'attestium-baseline');
  // Something else the same key signed, shaped like a baseline: not accepted as one.
  for (const type of [undefined, 'attestium-verification-response', 'deploy-approval']) {
    const {signature: _, ...data} = baseline;
    const envelope = signing.sign({...data, type}, keys.privateKey);
    const other = {
      ...envelope.payload, signature: {
        alg: envelope.alg, keyId: envelope.keyId, publicKey: envelope.publicKey, value: envelope.signature,
      },
    };
    assert.deepEqual((await signer.compareWithBaseline(other, {publicKey: keys.publicKey})).errors, [{error: 'Not a baseline'}], String(type));
  }

  assert.equal((await signer.compareWithBaseline(null)).errors[0].error, 'Malformed baseline');
  assert.equal((await signer.compareWithBaseline({files: null})).valid, false);

  // Changes on disk.
  const logs = [];
  const plain = new Attestium({projectRoot: root, logger: {log: message => logs.push(message)}});
  const plainBaseline = await plain.exportVerificationData();
  assert.equal(plainBaseline.signature, undefined);
  fs.writeFileSync(path.join(root, 'src/a.js'), 'changed');
  fs.rmSync(path.join(root, 'src/b.js'));
  fs.writeFileSync(path.join(root, 'src/c.js'), 'new');
  const diff = await plain.compareWithBaseline(plainBaseline);
  assert.deepEqual({added: diff.added, removed: diff.removed, modified: diff.modified}, {added: ['src/c.js'], removed: ['src/b.js'], modified: ['src/a.js']});
  assert.equal(await plain.verifyImportedData(plainBaseline), false);
  assert.ok(logs.some(line => /\[WARN] Baseline mismatch: 1 modified, 1 added, 1 removed/.test(line)));

  // Unreadable files are reported, not skipped silently (root reads every
  // file, and Windows has no unreadable mode).
  if (!windows && process.getuid() !== 0) {
    fs.chmodSync(path.join(root, 'src/c.js'), 0);
    const withError = await plain.generateVerificationReport();
    assert.equal(withError.summary.failedFiles, 1);
    fs.chmodSync(path.join(root, 'src/c.js'), 0o644);
  }
});

test('challenge-response with signed verification responses', async t => {
  const root = project(t);
  const keys = signing.generateKeyPair();
  const attestium = new Attestium({projectRoot: root, logger: quiet, signingKey: keys.privateKey});
  const challenge = attestium.generateChallenge();
  assert.equal(challenge.nonce.length, 64);
  assert.equal(attestium.validateChallenge(challenge), true);
  assert.equal(attestium.validateChallenge(attestium.generateChallenge(-1)), false);
  assert.equal(attestium.validateChallenge({expiresAt: 'not a date'}), false);
  assert.equal(attestium.validateChallenge(null), false);
  assert.equal(await attestium.verifyChallenge(challenge, challenge.nonce), true);
  assert.equal(await attestium.verifyChallenge(JSON.stringify(challenge), challenge.nonce), true);
  assert.equal(await attestium.verifyChallenge('{not json', challenge.nonce), false);
  assert.equal(await attestium.verifyChallenge(challenge, 'other'), false);
  assert.equal(await attestium.verifyChallenge(null, challenge.nonce), false);
  assert.equal(await attestium.verifyChallenge(challenge, 5), false);

  const response = await attestium.generateVerificationResponse(challenge.nonce.toUpperCase());
  const {digest} = await attestium.generateVerificationReport();
  assert.deepEqual(Attestium.verifyVerificationResponse(response, {nonce: challenge.nonce, publicKey: keys.publicKey, digest}), {valid: true, errors: []});
  assert.deepEqual(Attestium.verifyVerificationResponse(response, {
    nonce: 'ab'.repeat(32), publicKey: keys.publicKey, digest: 'x', maxAgeMs: -120_000,
  }).errors, [
    'Nonce mismatch',
    'Response is too old or from the future',
    'Tree digest differs from the expected digest',
  ]);
  assert.match(Attestium.verifyVerificationResponse(response, {nonce: challenge.nonce, publicKey: signing.generateKeyPair().publicKey}).errors[0], /^Signature:/);
  const untrusted = Attestium.verifyVerificationResponse({...response, signature: 'AAAA'}, {nonce: challenge.nonce, publicKey: keys.publicKey});
  assert.match(untrusted.errors[0], /does not verify/);

  // Another statement signed by the same key, with a matching nonce, time
  // and digest, is not a verification response.
  const {type, ...fields} = response.payload;
  for (const payload of [fields, {...fields, type: 'attestium-baseline'}, {...fields, type: 'deploy-approval'}, null, 'attestium-verification-response']) {
    assert.deepEqual(Attestium.verifyVerificationResponse(signing.sign(payload, keys.privateKey), {nonce: challenge.nonce, publicKey: keys.publicKey, digest}), {valid: false, errors: ['Not a verification response']}, JSON.stringify(payload));
  }

  const unsignedResponse = await new Attestium({projectRoot: root, logger: quiet}).generateVerificationResponse(challenge.nonce);
  assert.equal(unsignedResponse.signature, null);
  assert.equal(unsignedResponse.payload.digest, digest);
  await assert.rejects(attestium.generateVerificationResponse('short'), /16 to 64 bytes/);
});

test('runtime tracking records the source that was actually compiled', async t => {
  const root = project(t);
  const modulePath = path.join(root, 'tracked.js');
  fs.writeFileSync(modulePath, 'module.exports = "original";\n');
  const attestium = new Attestium({projectRoot: root, logger: quiet, enableRuntimeHooks: true});
  const loaded = [];
  attestium.on('moduleLoaded', record => loaded.push(record.filename));
  attestium.setupRuntimeHooks();
  assert.equal(require(modulePath), 'original');
  assert.deepEqual(loaded, [modulePath]);

  let status = await attestium.getRuntimeVerificationStatus();
  assert.equal(status.enabled, true);
  const record = status.modules.find(module => module.filename === modulePath);
  assert.equal(record.changedOnDisk, false);

  fs.writeFileSync(modulePath, 'module.exports = "swapped after load";\n');
  status = await attestium.getRuntimeVerificationStatus();
  assert.equal(status.modules.find(module => module.filename === modulePath).changedOnDisk, true);
  assert.ok(status.changedOnDisk >= 1);
  fs.rmSync(modulePath);
  status = await attestium.getRuntimeVerificationStatus();
  assert.equal(status.modules.find(module => module.filename === modulePath).diskSha256, null);

  // A second instance shares the process-wide hook without re-installing it.
  const second = new Attestium({projectRoot: root, logger: quiet, enableRuntimeHooks: true});
  await second.cleanup();
  await attestium.cleanup();
  await attestium.cleanup();
  const again = path.join(root, 'again.js');
  fs.writeFileSync(again, 'module.exports = 2;');
  require(again);
  assert.deepEqual(loaded, [modulePath], 'no events after cleanup');
  assert.equal((await attestium.getSecurityStatus()).security.runtimeTracking, true);
});

test('continuous verification reports changed, added and removed files', async t => {
  const root = project(t);
  const logs = [];
  const attestium = new Attestium({projectRoot: root, logger: {log: message => logs.push(message)}});
  const violations = [];
  const changed = [];
  attestium.on('integrityViolation', violation => violations.push(`${violation.type}:${violation.file}`));
  attestium.on('fileChanged', file => changed.push(file));
  assert.deepEqual(await attestium.runVerificationCycle(), []);

  attestium.startContinuousVerification(10);
  fs.writeFileSync(path.join(root, 'index.js'), 'changed');
  fs.writeFileSync(path.join(root, 'added.js'), 'new');
  fs.rmSync(path.join(root, 'README.md'));
  for (let i = 0; i < 100 && violations.length < 3; i++) {
    await sleep(10);
  }

  attestium.stopContinuousVerification();
  attestium.stopContinuousVerification();
  assert.deepEqual(violations.sort(), ['fileAdded:added.js', 'fileChanged:index.js', 'fileRemoved:README.md']);
  assert.deepEqual(changed, ['index.js']);
  assert.ok(logs.some(line => line.includes('Continuous verification started')));
  assert.ok(logs.some(line => line.includes('Continuous verification stopped')));

  // Errors are emitted and the loop keeps going.
  const errors = [];
  const failing = new Attestium({projectRoot: root, logger: quiet});
  failing.on('verificationError', error => errors.push(error.message));
  failing.generateVerificationReport = async () => {
    throw new Error('disk on fire');
  };

  failing.startContinuousVerification(5);
  for (let i = 0; i < 100 && errors.length < 2; i++) {
    await sleep(10);
  }

  await failing.cleanup();
  assert.ok(errors.length >= 2);

  // Random and non-numeric intervals schedule without running immediately.
  const random = new Attestium({
    projectRoot: root, logger: quiet, continuousVerification: true, verificationInterval: 'random',
  });
  assert.ok(random._verificationTimer);
  await random.cleanup();
  const odd = new Attestium({projectRoot: root, logger: quiet});
  odd.verificationInterval = {};
  odd.startContinuousVerification();
  assert.ok(odd._verificationTimer);
  await odd.cleanup();
});

test('a report with a symbolic link verifies (the verifier digests entry types as the attester does)', {skip: needsPosix}, async t => {
  const root = project(t);
  fs.symlinkSync('index.js', path.join(root, 'current.js'));
  const report = await new Attestium({projectRoot: root, logger: quiet}).generateVerificationReport();
  assert.equal(report.files.find(file => file.relativePath === 'current.js').mode, '120000');
  const attestation = {
    nonce: 'ab'.repeat(16), reportDigest: report.digest, softwareVerification: report, hardwareAttestation: {message: '', signature: ''},
  };
  const {errors} = Attestium.verifyHardwareAttestation(attestation, {nonce: 'ab'.repeat(16), publicKey: 'none'});
  assert.ok(!errors.includes('Report digest does not match the file list'), errors.join('; '));

  // A file whose content is the link's target is a different tree.
  const {manifestDigest} = Attestium.fileTree;
  assert.notEqual(report.digest, manifestDigest(report.files.map(file => ({path: file.relativePath, sha256: file.checksum}))));
});

test('TPM-bound hardware attestation', {skip: !hasTpmSimulator}, async t => {
  const {tcti} = await startSwtpm(t);
  const root = project(t);
  fs.symlinkSync('index.js', path.join(root, 'current.js'));
  const attestium = new Attestium({projectRoot: root, logger: quiet, tpm: {tcti}});
  assert.equal(await attestium.isTpmAvailable(), true);
  const key = await attestium.initializeTpm();
  assert.deepEqual(await attestium.initializeTpm(), key, 'existing key is reused');

  const {nonce} = attestium.generateChallenge();
  const attestation = await attestium.generateHardwareAttestation(nonce, {pcrList: [0, 7]});
  assert.equal(attestation.type, 'hardware-backed');
  assert.deepEqual(Attestium.verifyHardwareAttestation(attestation, {nonce, publicKey: key.publicKey}), {valid: true, errors: []});

  // Swapping the file list invalidates the binding to the quote.
  const tampered = structuredClone(attestation);
  tampered.softwareVerification.files[0].checksum = 'f'.repeat(64);
  assert.deepEqual(Attestium.verifyHardwareAttestation(tampered, {nonce, publicKey: key.publicKey}).errors, [
    'Report digest does not match the file list',
    'Quote nonce does not match (stale or replayed quote)',
  ]);

  // Consistent but different report: the quote was over another digest.
  const reDigested = structuredClone(tampered);
  const {manifestDigest} = Attestium.fileTree;
  reDigested.reportDigest = manifestDigest(reDigested.softwareVerification.files.map(file => ({path: file.relativePath, sha256: file.checksum, type: file.mode === '120000' ? 'symlink' : 'file'})));
  reDigested.softwareVerification.digest = reDigested.reportDigest;
  assert.deepEqual(Attestium.verifyHardwareAttestation(reDigested, {nonce, publicKey: key.publicKey}).errors, ['Quote nonce does not match (stale or replayed quote)']);
  // The expected nonce is required and must be the one the attestation answers.
  assert.deepEqual(Attestium.verifyHardwareAttestation(attestation, {nonce: undefined, publicKey: key.publicKey}), {valid: false, errors: ['Nonce must be 16 to 64 bytes of hex']});
  const {nonce: other} = attestium.generateChallenge();
  assert.deepEqual(Attestium.verifyHardwareAttestation(attestation, {nonce: other, publicKey: key.publicKey}).errors, [
    'Attestation does not answer this nonce',
    'Quote nonce does not match (stale or replayed quote)',
  ]);

  const random = await attestium.generateHardwareRandom(8);
  assert.equal(random.source, 'tpm');
  assert.equal(random.bytes.length, 8);
  const status = await attestium.getSecurityStatus();
  assert.equal(status.security.tpmAvailable, true);
  assert.equal(status.security.signingKeyConfigured, false);
  await assert.rejects(attestium.generateHardwareAttestation('short'), /16 to 64 bytes/);
});

test('TPM disabled or failing falls back explicitly', async t => {
  const root = project(t);
  const keys = signing.generateKeyPair();
  const disabled = new Attestium({
    projectRoot: root, logger: quiet, enableTpm: false, signingKey: keys.privateKey,
  });
  assert.equal(await disabled.isTpmAvailable(), false);
  await assert.rejects(disabled.initializeTpm(), /TPM is disabled/);
  await assert.rejects(disabled.generateHardwareAttestation('ab'.repeat(16)), /TPM not available/);
  assert.equal((await disabled.generateHardwareRandom()).source, 'os');
  const status = await disabled.getSecurityStatus();
  assert.equal(status.security.signingKeyId, signing.fingerprint(keys.publicKey));
  assert.equal(status.system.attestiumVersion, Attestium.VERSION);
  assert.match(disabled.getTpmInstallationInstructions(), /tpm2-tools/);

  const logs = [];
  const flaky = new Attestium({
    projectRoot: root,
    logger: {log: message => logs.push(message)},
    tpm: {
      tcti: 'fake',
      async run(file) {
        if (file === 'tpm2_getcap') {
          return 'TPM2_PT_FAMILY_INDICATOR:\n  raw: 0x322E3000\n  value: "2.0"\n';
        }

        throw new Error(`${file} exploded`);
      },
    },
  });
  const random = await flaky.generateHardwareRandom(4);
  assert.equal(random.source, 'os');
  assert.ok(logs.some(line => /\[WARN] TPM random failed: tpm2_getrandom exploded/.test(line)));
  await assert.rejects(flaky.initializeTpm(), /tpm2_readpublic exploded|tpm2_createek exploded/);
  assert.ok(flaky.tpm instanceof Tpm);

  // A logger without log() is tolerated.
  new Attestium({projectRoot: root, logger: {}}).log('ignored');
});

test('responses and file checks: untrusted signers and unstable files', async t => {
  const root = project(t);
  const keys = signing.generateKeyPair();
  const attestium = new Attestium({projectRoot: root, logger: quiet, signingKey: keys.privateKey});
  const {nonce} = attestium.generateChallenge();
  const response = await attestium.generateVerificationResponse(nonce);
  assert.deepEqual(Attestium.verifyVerificationResponse(response, {nonce}).errors, ['Signature: untrusted']);

  const file = path.join(root, 'big.bin');
  fs.writeFileSync(file, Buffer.alloc(2 * 1024 * 1024));
  const originalRead = fs.read;
  let appended = false;
  t.mock.method(fs, 'read', (...args) => {
    if (!appended) {
      appended = true;
      fs.appendFileSync(file, 'x');
    }

    return Reflect.apply(originalRead, fs, args);
  });
  const result = await attestium.verifyFileIntegrity(file);
  assert.equal(result.verified, false);
  assert.match(result.error, /changed while hashing/);
});

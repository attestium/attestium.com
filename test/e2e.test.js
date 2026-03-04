/**
 * End-to-end tests for Attestium
 *
 * These tests exercise the full Attestium workflow from initialization
 * through verification report generation, challenge-response protocol,
 * data export/import, and continuous verification lifecycle.
 */
const {test, describe} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const Attestium = require('../lib/index');

/**
 * Create a temporary project directory with realistic file structure.
 */
function createTestProject() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-e2e-'));

  fs.mkdirSync(path.join(tmpDir, 'lib'), {recursive: true});
  fs.mkdirSync(path.join(tmpDir, 'test'), {recursive: true});
  fs.mkdirSync(path.join(tmpDir, 'config'), {recursive: true});

  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
    name: 'test-project',
    version: '1.0.0',
    main: 'lib/index.js',
  }, null, 2));

  fs.writeFileSync(path.join(tmpDir, 'lib', 'index.js'),
    'const http = require("http");\nmodule.exports = { start() { return http.createServer(); } };\n');

  fs.writeFileSync(path.join(tmpDir, 'lib', 'utils.js'),
    'module.exports = { add(a, b) { return a + b; } };\n');

  fs.writeFileSync(path.join(tmpDir, 'test', 'index.test.js'),
    'const assert = require("assert");\nassert.strictEqual(1 + 1, 2);\n');

  fs.writeFileSync(path.join(tmpDir, 'config', 'default.json'),
    JSON.stringify({port: 3000, host: 'localhost'}, null, 2));

  fs.writeFileSync(path.join(tmpDir, '.gitignore'), 'node_modules\n.env\n');

  return tmpDir;
}

function cleanupProject(dir) {
  try {
    fs.rmSync(dir, {recursive: true, force: true});
  } catch {}
}

describe('E2E: Full Attestium Lifecycle', () => {
  let projectDir;
  let attestium;

  test('initializes with a real project directory', () => {
    projectDir = createTestProject();
    attestium = new Attestium({
      projectRoot: projectDir,
      enableTpm: false,
      fallbackMode: 'software',
      enableContinuousVerification: false,
    });

    assert.ok(attestium, 'Attestium instance created');
    assert.ok(attestium.tamperResistantStore, 'Has tamper-resistant store');
  });

  test('scans project files and produces checksums', async () => {
    const files = await attestium.scanProjectFiles();
    assert.ok(Array.isArray(files), 'Returns an array of files');
    assert.ok(files.length > 0, 'Finds files in the project');

    const fileNames = new Set(files.map(f => path.basename(f)));
    assert.ok(fileNames.has('index.js'), 'Finds lib/index.js');
    assert.ok(fileNames.has('package.json'), 'Finds package.json');
  });

  test('generates a full verification report', async () => {
    const report = await attestium.generateVerificationReport();
    assert.ok(report, 'Report generated');
    assert.ok(report.timestamp, 'Report has timestamp');
    assert.ok(report.projectRoot, 'Report has projectRoot');
    assert.ok(report.files, 'Report has files');
    assert.ok(report.summary, 'Report has summary');
    assert.ok(Array.isArray(report.files), 'Files is an array');
    assert.ok(report.files.length > 0, 'Has file entries');

    for (const file of report.files) {
      assert.ok(file.relativePath, 'File entry has relativePath');
      assert.ok(file.checksum, 'File entry has checksum');
      assert.ok(file.category, 'File entry has category');
      assert.ok(file.verified === true, 'File entry is verified');
    }
  });

  test('verifies individual file integrity', async () => {
    const filePath = path.join(projectDir, 'lib', 'index.js');
    const result = await attestium.verifyFileIntegrity(filePath);
    assert.ok(result, 'Integrity result exists');
    assert.strictEqual(result.verified, true, 'File passes integrity check');
    assert.ok(result.checksum, 'Has checksum');
    assert.ok(result.category, 'Has category');
  });

  test('detects file tampering via report comparison', async () => {
    const reportBefore = await attestium.generateVerificationReport();
    const checksumBefore = reportBefore.files.find(
      f => f.relativePath === path.join('lib', 'utils.js'),
    );

    // Tamper with a file
    const filePath = path.join(projectDir, 'lib', 'utils.js');
    fs.writeFileSync(filePath, 'module.exports = { add(a, b) { return a + b + 1; } };\n');

    const reportAfter = await attestium.generateVerificationReport();
    const checksumAfter = reportAfter.files.find(
      f => f.relativePath === path.join('lib', 'utils.js'),
    );

    assert.notStrictEqual(checksumBefore.checksum, checksumAfter.checksum, 'Checksum changes after tampering');

    // Restore
    fs.writeFileSync(filePath, 'module.exports = { add(a, b) { return a + b; } };\n');
  });

  test('challenge-response protocol works end-to-end', async () => {
    const challenge = attestium.generateChallenge();
    assert.ok(challenge, 'Challenge generated');
    assert.ok(challenge.nonce, 'Challenge has nonce');
    assert.ok(challenge.timestamp, 'Challenge has timestamp');
    assert.ok(challenge.expiresAt, 'Challenge has expiresAt');

    // GenerateVerificationResponse takes a nonce string
    const response = await attestium.generateVerificationResponse(challenge.nonce);
    assert.ok(response, 'Response generated');
    assert.strictEqual(response.success, true, 'Response is successful');
    assert.strictEqual(response.nonce, challenge.nonce, 'Nonce matches');
    assert.ok(response.verification, 'Response has verification data');
    assert.ok(response.verification.signature, 'Has signature');
    assert.ok(response.verification.checksum, 'Has checksum');
    assert.ok(response.verification.challengeResponse, 'Has challengeResponse');
  });

  test('data export and import roundtrip', async () => {
    const exported = await attestium.exportVerificationData();
    assert.ok(exported, 'Export produces data');
    assert.ok(exported.metadata, 'Export has metadata');
    assert.ok(exported.files, 'Export has files');
    assert.ok(exported.signature, 'Export has signature');
    assert.ok(exported.summary, 'Export has summary');

    // Import and verify - returns boolean
    const isValid = await attestium.verifyImportedData(exported);
    assert.strictEqual(isValid, true, 'Imported data is valid');
  });

  test('detects tampered export data', async () => {
    const exported = await attestium.exportVerificationData();

    // Tamper with the signature
    exported.signature = 'tampered_signature';

    const isValid = await attestium.verifyImportedData(exported);
    assert.strictEqual(isValid, false, 'Tampered data is rejected');
  });

  test('tamper-resistant store maintains integrity', () => {
    const store = attestium.tamperResistantStore;
    assert.ok(store.validateIntegrity(), 'Store validates integrity');
    assert.ok(typeof store.storeChecksum === 'function', 'Has storeChecksum');
    assert.ok(typeof store.verifyChecksum === 'function', 'Has verifyChecksum');
    assert.ok(typeof store.generateSecureNonce === 'function', 'Has generateSecureNonce');

    const nonce = store.generateSecureNonce();
    assert.ok(nonce, 'Generates secure nonce');
    assert.ok(typeof nonce === 'string', 'Nonce is a string');
  });

  test('runtime verification status is available', () => {
    const status = attestium.getRuntimeVerificationStatus();
    assert.ok(status, 'Status available');
  });

  test('security status provides comprehensive info', async () => {
    const status = await attestium.getSecurityStatus();
    assert.ok(status, 'Security status available');
    assert.strictEqual(status.success, true, 'Status reports success');
    assert.ok(status.security, 'Has security section');
    assert.ok(status.system, 'Has system section');
    assert.ok(status.project, 'Has project section');
    assert.strictEqual(status.security.tpmEnabled, false, 'TPM is disabled');
    assert.strictEqual(status.security.tamperResistant, true, 'Tamper resistant is enabled');
  });

  test('file categorization works correctly', () => {
    assert.ok(attestium.categorizeFile('lib/index.js'), 'Categorizes .js files');
    assert.ok(attestium.categorizeFile('package.json'), 'Categorizes .json files');
    assert.ok(attestium.categorizeFile('test/index.test.js'), 'Categorizes test files');
  });

  test('include/exclude patterns work', () => {
    assert.ok(attestium.shouldInclude('lib/index.js'), 'Includes source files');
    assert.ok(attestium.shouldExclude('node_modules/foo/bar.js'), 'Excludes node_modules');
  });

  test('continuous verification lifecycle', () => {
    attestium.startContinuousVerification({interval: 60_000});
    attestium.stopContinuousVerification();
  });

  test('cleanup releases resources', async () => {
    await attestium.cleanup();
    cleanupProject(projectDir);
  });
});

describe('E2E: Multiple Attestium Instances', () => {
  test('different projects produce different checksums', async () => {
    const dir1 = createTestProject();
    const dir2 = createTestProject();

    // Make dir2 different
    fs.writeFileSync(path.join(dir2, 'lib', 'extra.js'), 'module.exports = "extra";\n');

    const a1 = new Attestium({
      projectRoot: dir1, enableTpm: false, fallbackMode: 'software', enableContinuousVerification: false,
    });
    const a2 = new Attestium({
      projectRoot: dir2, enableTpm: false, fallbackMode: 'software', enableContinuousVerification: false,
    });

    const r1 = await a1.generateVerificationReport();
    const r2 = await a2.generateVerificationReport();

    // Different file counts at minimum
    assert.notStrictEqual(r1.files.length, r2.files.length, 'Different projects have different file counts');

    await a1.cleanup();
    await a2.cleanup();
    cleanupProject(dir1);
    cleanupProject(dir2);
  });
});

describe('E2E: Verification Report with Challenge', () => {
  test('generates report with embedded challenge', async () => {
    const dir = createTestProject();
    const a = new Attestium({
      projectRoot: dir, enableTpm: false, fallbackMode: 'software', enableContinuousVerification: false,
    });

    const challenge = a.generateChallenge();
    const report = await a.generateVerificationReportWithChallenge(challenge.nonce);

    assert.ok(report, 'Report with challenge generated');
    assert.ok(report.files, 'Has files');
    assert.ok(report.challengeResponse, 'Has challengeResponse');
    assert.ok(report.challengeResponse.signature, 'ChallengeResponse has signature');

    await a.cleanup();
    cleanupProject(dir);
  });
});

describe('E2E: Sign and Verify', () => {
  test('sign and verify workflow', async () => {
    const dir = createTestProject();
    const a = new Attestium({
      projectRoot: dir, enableTpm: false, fallbackMode: 'software', enableContinuousVerification: false,
    });

    const nonce = crypto.randomBytes(16).toString('hex');
    const checksum = crypto.randomBytes(32).toString('hex');
    const signature = a.signResponse(nonce, checksum);

    assert.ok(signature, 'Signature generated');
    assert.ok(typeof signature === 'string', 'Signature is a string');

    await a.cleanup();
    cleanupProject(dir);
  });
});

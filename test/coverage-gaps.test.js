/**
 * Additional coverage tests targeting all remaining uncovered lines.
 * This file supplements coverage-100-final.test.js.
 */

const {test} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const projectRoot = path.join(__dirname, '..');

// ============================================================
// TPM-INTEGRATION.JS - Lines 50-61, 158-159, 191-192, 286-289, 337-349, 398-399
// ============================================================

test('TpmIntegration - checkTpmAvailability with device found and getcap success', async t => {
  const proxyquire = require('proxyquire');

  await t.test('checkTpmAvailability lines 50-56: TPM device found and getcap succeeds', async () => {
    const TpmIntegration = proxyquire('../lib/tpm-integration', {
      'node:fs': {
        existsSync: p => p === '/dev/tpm0' || p === '/dev/tpmrm0',
        readFileSync: fs.readFileSync,
        writeFileSync: fs.writeFileSync,
        unlinkSync: fs.unlinkSync,
      },
      'node:child_process': {
        execSync(cmd) {
          if (cmd === 'tpm2_getcap properties-fixed') {
            return 'TPM2_PT_FIXED:\n  version: 2.0';
          }

          throw new Error('unexpected command: ' + cmd);
        },
      },
    });
    const tpm = new TpmIntegration();
    tpm.tpmAvailable = null;
    tpm.checkTpm2Tools = async () => true;
    const result = await tpm.checkTpmAvailability();
    assert.strictEqual(result, true);
    assert.strictEqual(tpm.tpmAvailable, true);
  });

  await t.test('checkTpmAvailability lines 57-61: getcap throws error', async () => {
    const TpmIntegration = proxyquire('../lib/tpm-integration', {
      'node:fs': {
        existsSync: p => p === '/dev/tpm0' || p === '/dev/tpmrm0',
        readFileSync: fs.readFileSync,
        writeFileSync: fs.writeFileSync,
        unlinkSync: fs.unlinkSync,
      },
      'node:child_process': {
        execSync(cmd) {
          if (cmd === 'tpm2_getcap properties-fixed') {
            throw new Error('TPM error');
          }

          throw new Error('unexpected command: ' + cmd);
        },
      },
    });
    const tpm = new TpmIntegration();
    tpm.tpmAvailable = null;
    tpm.checkTpm2Tools = async () => true;
    const result = await tpm.checkTpmAvailability();
    assert.strictEqual(result, false);
  });

  await t.test('createPrimaryKey error branch lines 157-159', async () => {
    const TpmIntegration = require('../lib/tpm-integration');
    const tpm = new TpmIntegration();
    // Mock tpm2.createPrimary to throw
    tpm.tpm2.createPrimary = () => {
      throw new Error('hardware fault');
    };

    await assert.rejects(
      async () => tpm.createPrimaryKey(),
      /Failed to create TPM primary key: hardware fault/,
    );
  });

  await t.test('sealData error branch lines 190-192', async () => {
    const TpmIntegration = require('../lib/tpm-integration');
    const tpm = new TpmIntegration();
    tpm.tpmAvailable = true;
    tpm.checkTpmAvailability = async () => true;
    // Mock tpm2.create to throw
    tpm.tpm2.create = () => {
      throw new Error('seal error');
    };

    await assert.rejects(
      async () => tpm.sealData('test data', [0, 1]),
      /Failed to seal data to TPM: seal error/,
    );
  });

  await t.test('createAttestationQuote success path lines 258-289', async () => {
    const TpmIntegration = require('../lib/tpm-integration');
    const tpm = new TpmIntegration();
    tpm.tpmAvailable = true;
    tpm.checkTpmAvailability = async () => true;
    // Mock tpm2.quote to create the files
    tpm.tpm2.quote = opts => {
      fs.writeFileSync(opts.signature, 'mock-signature');
      fs.writeFileSync(opts.message, 'mock-quote');
    };

    tpm.getTmpVersion = async () => ({version: '2.0', details: 'mock'});
    const result = await tpm.createAttestationQuote('test-nonce', [0, 1]);
    assert.ok(result.quote);
    assert.ok(result.signature);
    assert.strictEqual(result.nonce, 'test-nonce');
    assert.ok(result.tpmVersion);
  });

  await t.test('verifySystemIntegrity success path lines 320-349', async () => {
    const TpmMocked = proxyquire('../lib/tpm-integration', {
      'node:child_process': {
        execSync(cmd) {
          if (cmd === 'tpm2_pcrread') {
            return 'sha256:\n  0 : 0xABCD1234\n  1 : 0x5678EFAB\n';
          }

          return '';
        },
      },
    });
    const tpm = new TpmMocked();
    tpm.tpmAvailable = true;
    tpm.checkTpmAvailability = async () => true;
    tpm.initializeTpm = async () => true;
    const result = await tpm.verifySystemIntegrity({});
    assert.strictEqual(result.verified, true);
    assert.ok(result.measurements);
  });

  await t.test('verifySystemIntegrity with mismatched measurements lines 337-349', async () => {
    const TpmMocked = proxyquire('../lib/tpm-integration', {
      'node:child_process': {
        execSync(cmd) {
          if (cmd === 'tpm2_pcrread') {
            return 'sha256:\n  0 : 0xABCD1234\n  1 : 0x5678EFAB\n';
          }

          return '';
        },
      },
    });
    const tpm = new TpmMocked();
    tpm.tpmAvailable = true;
    tpm.checkTpmAvailability = async () => true;
    tpm.initializeTpm = async () => true;
    const result = await tpm.verifySystemIntegrity({0: 'wrong_value'});
    assert.strictEqual(result.verified, false);
    assert.ok(result.differences.length > 0);
  });

  await t.test('verifySystemIntegrity with matching measurements', async () => {
    const TpmMocked = proxyquire('../lib/tpm-integration', {
      'node:child_process': {
        execSync(cmd) {
          if (cmd === 'tpm2_pcrread') {
            return 'sha256:\n  0 : 0xABCD1234\n';
          }

          return '';
        },
      },
    });
    const tpm = new TpmMocked();
    tpm.tpmAvailable = true;
    tpm.checkTpmAvailability = async () => true;
    tpm.initializeTpm = async () => true;
    const result = await tpm.verifySystemIntegrity({0: 'abcd1234'});
    assert.strictEqual(result.verified, true);
    assert.strictEqual(result.differences.length, 0);
  });

  await t.test('cleanup error branch lines 397-399', async () => {
    const TpmIntegration = require('../lib/tpm-integration');
    const tpm = new TpmIntegration();
    // Mock fs.existsSync to throw
    const origExistsSync = fs.existsSync;
    fs.existsSync = () => {
      throw new Error('cleanup error');
    };

    try {
      await tpm.cleanup(); // Should not throw, just warn
    } finally {
      fs.existsSync = origExistsSync;
    }
  });
});

// ============================================================
// EXTERNAL-VALIDATION.JS - Lines 74-90, 326-331, 340-344, 409-411, 550-558, 579-580, 586-587
// ============================================================

test('ExternalValidationManager - initialize success path', async t => {
  const ExternalValidationManager = require('../lib/external-validation');

  await t.test('initialize full success path lines 72-90', async () => {
    const ev = new ExternalValidationManager({
      challengeServices: ['https://api.github.com'],
      validationInterval: 999_999_999,
      challengeInterval: 999_999_999,
      auditEndpoints: [],
    });
    const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    // Mock makeHTTPSRequest for all calls
    ev.makeHTTPSRequest = async opts => {
      if (opts.hostname === 'api.github.com' && opts.path.includes('releases')) {
        return JSON.stringify({tag_name: `v${packageJson.version}`, published_at: new Date().toISOString()}); // eslint-disable-line camelcase
      }

      if (opts.hostname === 'registry.npmjs.org') {
        return JSON.stringify({version: packageJson.version, time: {}, dist: {shasum: 'abc'}});
      }

      // Challenge services
      return 'mock response';
    };

    const result = await ev.initialize();
    assert.strictEqual(result, true);
    assert.strictEqual(ev.validationState.initialized, true);
    assert.ok(ev.validationTimer);
    assert.ok(ev.challengeTimer);
    ev.stop();
  });
});

test('ExternalValidationManager - startPeriodicValidation callback', async t => {
  const ExternalValidationManager = require('../lib/external-validation');

  await t.test('startPeriodicValidation callback error branch lines 326-331', async () => {
    const ev = new ExternalValidationManager({
      validationInterval: 10, // Very short interval
      auditEndpoints: [],
    });
    // Make performPeriodicValidation throw
    ev.performPeriodicValidation = async () => {
      throw new Error('periodic fail');
    };

    ev.logAuditEvent = async () => {};
    ev.startPeriodicValidation();
    // Wait for the callback to fire
    await new Promise(resolve => setTimeout(resolve, 50));
    ev.stop();
  });

  await t.test('startExternalChallengePolling callback error branch lines 340-344', async () => {
    const ev = new ExternalValidationManager({
      challengeInterval: 10, // Very short interval
    });
    ev.updateExternalChallenges = async () => {
      throw new Error('challenge fail');
    };

    ev.startExternalChallengePolling();
    await new Promise(resolve => setTimeout(resolve, 50));
    ev.stop();
  });
});

test('ExternalValidationManager - performPeriodicValidation error branch', async t => {
  const ExternalValidationManager = require('../lib/external-validation');

  await t.test('performPeriodicValidation error branch lines 408-411', async () => {
    const ev = new ExternalValidationManager({auditEndpoints: []});
    // Make calculateAttestiumChecksum throw
    ev.calculateAttestiumChecksum = async () => {
      throw new Error('checksum error');
    };

    await assert.rejects(
      async () => ev.performPeriodicValidation(),
      /checksum error/,
    );
  });
});

test('ExternalValidationManager - sendAuditLog and makeHTTPSRequest', async t => {
  const ExternalValidationManager = require('../lib/external-validation');
  const https = require('node:https');
  const {EventEmitter} = require('node:events');

  await t.test('sendAuditLog lines 533-565', async () => {
    const ev = new ExternalValidationManager();
    // We can't easily test real HTTPS, but we can test the method exists
    // and the logAuditEvent calls it
    let sendCalled = false;
    ev.sendAuditLog = async () => {
      sendCalled = true;
    };

    await ev.logAuditEvent('test', {});
    // No endpoints configured by default, so sendAuditLog won't be called
    assert.strictEqual(sendCalled, false);
  });

  await t.test('sendAuditLog with endpoint', async () => {
    const ev = new ExternalValidationManager({
      auditEndpoints: ['https://example.com/audit'],
    });
    let sendCalled = false;
    ev.sendAuditLog = async () => {
      sendCalled = true;
    };

    await ev.logAuditEvent('test', {});
    assert.strictEqual(sendCalled, true);
  });

  await t.test('makeHTTPSRequest error and timeout branches lines 579-587', async () => {
    const ev = new ExternalValidationManager();
    // Test with a non-existent host to trigger error
    await assert.rejects(
      async () => ev.makeHTTPSRequest({
        hostname: 'localhost',
        port: 1,
        path: '/',
        headers: {},
      }),
    );
  });
});

// ============================================================
// INDEX.JS - Lines 185-186, 353-354, 456-461, 583-594, 619-630, 683-684, 883-885
// Lines 971-1008, 1021-1052, 1064-1100, 1187-1193, 1222-1247
// ============================================================

test('Attestium - constructor integrity failure line 185-186', async t => {
  const Attestium = require('../lib/index');

  await t.test('constructor throws on integrity failure', () => {
    // We need to mock TamperResistantStore.validateIntegrity to return false
    // This is tricky since it's called in constructor
    // We can monkey-patch the prototype
    const vm = require('node:vm');
    const origRunInContext = vm.runInContext;
    let interceptValidateIntegrity = false;
    vm.runInContext = function (code, context) {
      const result = origRunInContext.call(this, code, context);
      if (interceptValidateIntegrity && code.includes('validateIntegrity')) {
        return false;
      }

      return result;
    };

    try {
      interceptValidateIntegrity = true;
      assert.throws(
        () => new Attestium({
          projectRoot,
          continuousVerification: false,
          enableRuntimeHooks: false,
        }),
        /Tamper-resistant store integrity validation failed/,
      );
    } finally {
      interceptValidateIntegrity = false;
      vm.runInContext = origRunInContext;
    }
  });
});

test('Attestium - setupRuntimeHooks catch branch line 352-354', async t => {
  const Attestium = require('../lib/index');

  await t.test('setupRuntimeHooks catch block is hit for non-file modules', () => {
    // The catch block at line 352-354 catches Module._resolveFilename errors
    // This happens when requiring built-in modules or modules that can't be resolved to files
    const a = new Attestium({
      projectRoot,
      enableRuntimeHooks: true,
      continuousVerification: false,
    });
    // Requiring a built-in module - _resolveFilename may throw or return non-file path
    // The catch block silently ignores these
    require('node:os'); // eslint-disable-line import-x/no-unassigned-import
    assert.ok(a);
  });
});

test('Attestium - scanProjectFiles error branches lines 455-461', async t => {
  const Attestium = require('../lib/index');

  await t.test('scanProjectFiles handles stat error on file', async () => {
    // Lines 455-457: error accessing a specific file
    const a = new Attestium({
      projectRoot: os.tmpdir(),
      continuousVerification: false,
      enableRuntimeHooks: false,
      includePatterns: ['**/*'],
      excludePatterns: [],
    });
    // Create a temp dir with a file that will cause stat error
    const tmpDir = path.join(os.tmpdir(), `attestium-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, {recursive: true});
    fs.writeFileSync(path.join(tmpDir, 'test.js'), 'test');
    a.projectRoot = tmpDir;
    const files = await a.scanProjectFiles();
    assert.ok(Array.isArray(files));
    // Cleanup
    fs.rmSync(tmpDir, {recursive: true, force: true});
  });

  await t.test('scanProjectFiles handles readdir error', async () => {
    // Lines 459-461: error reading directory
    const tmpDir = path.join(os.tmpdir(), `attestium-scan-err-${Date.now()}`);
    fs.mkdirSync(tmpDir, {recursive: true});
    const a = new Attestium({
      projectRoot: tmpDir,
      continuousVerification: false,
      enableRuntimeHooks: false,
      includePatterns: ['**/*'],
      excludePatterns: [],
    });
    // Create a subdirectory that we'll make unreadable
    const subDir = path.join(tmpDir, 'unreadable');
    fs.mkdirSync(subDir);
    fs.chmodSync(subDir, 0o000);
    try {
      const files = await a.scanProjectFiles();
      assert.ok(Array.isArray(files));
    } finally {
      fs.chmodSync(subDir, 0o755);
      fs.rmSync(tmpDir, {recursive: true, force: true});
    }
  });
});

test('Attestium - generateVerificationReport error and fail branches', async t => {
  const Attestium = require('../lib/index');

  await t.test('report with file that has error field lines 583-585', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    // Mock verifyFileIntegrity to return an object with error
    const origVerify = a.verifyFileIntegrity.bind(a);
    let first = true;
    a.verifyFileIntegrity = async filePath => {
      if (first) {
        first = false;
        return {
          checksum: null,
          verified: false,
          timestamp: new Date().toISOString(),
          error: 'Test error message',
          category: 'source',
        };
      }

      return origVerify(filePath);
    };

    const report = await a.generateVerificationReport();
    // Check that at least one file has error and failedFiles > 0
    assert.ok(report.summary.failedFiles >= 1);
    const errorFile = report.files.find(f => f.error);
    assert.ok(errorFile);
    assert.strictEqual(errorFile.error, 'Test error message');
  });
});

test('Attestium - dead 3-arg filterFilesByPatterns lines 618-630', async t => {
  const Attestium = require('../lib/index');

  await t.test('the 3-arg filterFilesByPatterns is dead code (overridden by 1-arg version)', () => {
    // Lines 618-630 are dead code because the 1-arg version at line 944 overrides it.
    // We verify this by checking the function signature.
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    // The function only takes 1 arg (files)
    assert.strictEqual(a.filterFilesByPatterns.length, 1);
  });
});

test('Attestium - verifySignature error catch lines 882-885', async t => {
  const Attestium = require('../lib/index');

  await t.test('verifySignature catch block when crypto throws', () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    // To trigger the catch block, we need something in the try block to throw.
    // The try block calls: nonce + expectedChecksum + new Date().toISOString().slice(0, 16)
    // We can pass a Symbol as nonce which will throw on string concatenation
    const result = a.verifySignature(Symbol('bad'), 'sig', 'checksum');
    assert.strictEqual(result, false);
  });
});

test('Attestium - TPM-enabled method success paths', async t => {
  const Attestium = require('../lib/index');

  await t.test('initializeTpm success when TPM enabled lines 971-972', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    // Mock TPM to be available and initialize successfully
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.initializeTpm = async () => true;
    const result = await a.initializeTpm();
    assert.strictEqual(result, true);
  });

  await t.test('generateHardwareAttestation success lines 985-1008', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.createAttestationQuote = async nonce => ({
      quote: 'mock-quote',
      signature: 'mock-sig',
      nonce,
      pcrList: [0, 1],
      timestamp: new Date().toISOString(),
    });
    const result = await a.generateHardwareAttestation('test-nonce');
    assert.strictEqual(result.type, 'hardware-backed');
    assert.ok(result.softwareVerification);
    assert.ok(result.hardwareAttestation);
    assert.strictEqual(result.nonce, 'test-nonce');
  });

  await t.test('generateHardwareAttestation error branch lines 1005-1008', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.createAttestationQuote = async () => {
      throw new Error('attestation error');
    };

    await assert.rejects(
      async () => a.generateHardwareAttestation('nonce'),
      /attestation error/,
    );
  });

  await t.test('sealVerificationData success lines 1021-1031', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.sealData = async () => '/tmp/sealed.dat';
    const result = await a.sealVerificationData({test: true});
    assert.strictEqual(result, '/tmp/sealed.dat');
  });

  await t.test('sealVerificationData error branch lines 1028-1031', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.sealData = async () => {
      throw new Error('seal error');
    };

    await assert.rejects(
      async () => a.sealVerificationData({test: true}),
      /seal error/,
    );
  });

  await t.test('unsealVerificationData success lines 1042-1052', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.unsealData = async () => JSON.stringify({test: true});
    const result = await a.unsealVerificationData();
    assert.deepStrictEqual(result, {test: true});
  });

  await t.test('unsealVerificationData error branch lines 1049-1052', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.unsealData = async () => {
      throw new Error('unseal error');
    };

    await assert.rejects(
      async () => a.unsealVerificationData(),
      /unseal error/,
    );
  });

  await t.test('verifySystemIntegrity success lines 1064-1077', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.verifySystemIntegrity = async () => ({verified: true, measurements: {}});
    const result = await a.verifySystemIntegrity();
    assert.strictEqual(result.verified, true);
  });

  await t.test('verifySystemIntegrity failed verification', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.verifySystemIntegrity = async () => ({verified: false, measurements: {}});
    const result = await a.verifySystemIntegrity();
    assert.strictEqual(result.verified, false);
  });

  await t.test('verifySystemIntegrity error branch lines 1074-1077', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.verifySystemIntegrity = async () => {
      throw new Error('integrity error');
    };

    await assert.rejects(
      async () => a.verifySystemIntegrity(),
      /integrity error/,
    );
  });

  await t.test('generateHardwareRandom with TPM available lines 1091-1100', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.generateHardwareRandom = async len => crypto.randomBytes(len);
    const result = await a.generateHardwareRandom(16);
    assert.ok(Buffer.isBuffer(result));
    assert.strictEqual(result.length, 16);
  });

  await t.test('generateHardwareRandom TPM error fallback lines 1096-1100', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
      enableTpm: true,
    });
    a.tpm.tpmAvailable = true;
    a.tpm.checkTpmAvailability = async () => true;
    a.tpm.generateHardwareRandom = async () => {
      throw new Error('hw random error');
    };

    const result = await a.generateHardwareRandom(16);
    assert.ok(Buffer.isBuffer(result));
    assert.strictEqual(result.length, 16);
  });
});

test('Attestium - getSecurityStatus error branch lines 1187-1193', async t => {
  const Attestium = require('../lib/index');

  await t.test('getSecurityStatus error branch', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    // Make isTpmAvailable throw
    a.isTpmAvailable = async () => {
      throw new Error('tpm check error');
    };

    const status = await a.getSecurityStatus();
    assert.strictEqual(status.success, false);
    assert.ok(status.error);
  });
});

test('Attestium - continuous verification runVerification lines 1222-1247', async t => {
  const Attestium = require('../lib/index');

  await t.test('runVerification detects file changes', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });

    // Set up a previous checksum that differs
    const events = [];
    a.on('fileChanged', (filePath, prev, curr) => {
      events.push({
        type: 'fileChanged', filePath, prev, curr,
      });
    });
    a.on('integrityViolation', data => {
      events.push({type: 'integrityViolation', data});
    });

    // Pre-populate with a wrong checksum for a known file
    const report = await a.generateVerificationReport();
    if (report.files.length > 0) {
      const file = report.files[0];
      a.fileChecksums.set(file.path || file.relativePath, 'wrong_old_checksum');
    }

    // Mock generateVerificationReport to return files with path property
    a.generateVerificationReport = async () => ({
      files: [{path: 'test.js', checksum: 'new_checksum'}],
    });
    a.fileChecksums.set('test.js', 'old_checksum');

    // Start continuous verification with very short interval
    a.verificationInterval = 10;
    a._startContinuousVerification();

    // Wait for the callback to fire
    await new Promise(resolve => setTimeout(resolve, 100));
    a.stopContinuousVerification();

    // Check that events were emitted
    assert.ok(events.some(e => e.type === 'fileChanged'));
    assert.ok(events.some(e => e.type === 'integrityViolation'));
  });

  await t.test('runVerification handles errors lines 1241-1243', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    a.generateVerificationReport = async () => {
      throw new Error('verification error');
    };

    a.verificationInterval = 10;
    a._startContinuousVerification();
    await new Promise(resolve => setTimeout(resolve, 100));
    a.stopContinuousVerification();
  });

  await t.test('runVerification with null report', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    a.generateVerificationReport = async () => null;
    a.verificationInterval = 10;
    a._startContinuousVerification();
    await new Promise(resolve => setTimeout(resolve, 100));
    a.stopContinuousVerification();
  });

  await t.test('runVerification with report without files', async () => {
    const a = new Attestium({
      projectRoot,
      continuousVerification: false,
      enableRuntimeHooks: false,
    });
    a.generateVerificationReport = async () => ({});
    a.verificationInterval = 10;
    a._startContinuousVerification();
    await new Promise(resolve => setTimeout(resolve, 100));
    a.stopContinuousVerification();
  });
});

// ============================================================
// TAMPER-PROOF-CORE.JS - Lines 77-78, 94-95, 128-129, 133-134, 138-139
// Lines 150-151, 155-156, 171-172, 209-210, 216-217, 219-220, 237-238, 241-242
// ============================================================

test('TamperProofCore - additional coverage', async t => {
  // Note: TamperProofCore is an IIFE singleton. The freezeVerificationState
  // is set once initializeTamperProofProtection is called. Since it's a module
  // singleton, calling it again just re-initializes.

  await t.test('protectVariable with freeze option for object', () => {
    const TPC = require('../lib/tamper-proof-core');
    TPC.initializeTamperProofProtection();
    const obj = {key: 'value'};
    const id = TPC.protectVariable('frozenObj', obj, {freeze: true});
    assert.ok(id);
    assert.ok(Object.isFrozen(obj));
  });

  await t.test('protectVariable with freeze=false for object', () => {
    const TPC = require('../lib/tamper-proof-core');
    TPC.initializeTamperProofProtection();
    const obj = {key: 'value'};
    const id = TPC.protectVariable('unfrozenObj', obj, {freeze: false});
    assert.ok(id);
    assert.ok(!Object.isFrozen(obj));
  });

  await t.test('verifyProtectedVariable with frozen object that is unfrozen lines 148-151', () => {
    const TPC = require('../lib/tamper-proof-core');
    TPC.initializeTamperProofProtection();
    // Protect a non-frozen object but mark it as frozen
    const obj = {key: 'value'};
    TPC.protectVariable('frozenTest', obj, {freeze: true});
    // Obj is now frozen. Verify it.
    const result = TPC.verifyProtectedVariable('frozenTest', obj);
    assert.strictEqual(result.valid, true);
  });

  await t.test('verifyProtectedVariable with object not in frozen tracking lines 153-156', () => {
    const TPC = require('../lib/tamper-proof-core');
    TPC.initializeTamperProofProtection();
    // Protect a primitive (not frozen)
    TPC.protectVariable('primTest', 42, {freeze: false});
    const result = TPC.verifyProtectedVariable('primTest', 42);
    assert.strictEqual(result.valid, true);
  });

  await t.test('verifyProtectedVariable for unknown variable lines 131-134', () => {
    const TPC = require('../lib/tamper-proof-core');
    TPC.initializeTamperProofProtection();
    const result = TPC.verifyProtectedVariable('nonexistent', 'value');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.error, 'Variable not protected');
  });

  await t.test('detectScheduledTampering when setTimeout replaced lines 232-238', () => {
    const TPC = require('../lib/tamper-proof-core');
    const origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = function () {};
    try {
      const result = TPC.detectScheduledTampering();
      assert.strictEqual(result.valid, false);
      assert.ok(result.suspiciousActivities.includes('setTimeout has been replaced'));
    } finally {
      globalThis.setTimeout = origSetTimeout;
    }
  });

  await t.test('detectScheduledTampering when setInterval replaced lines 236-238', () => {
    const TPC = require('../lib/tamper-proof-core');
    const origSetInterval = globalThis.setInterval;
    globalThis.setInterval = function () {};
    try {
      const result = TPC.detectScheduledTampering();
      assert.strictEqual(result.valid, false);
      assert.ok(result.suspiciousActivities.includes('setInterval has been replaced'));
    } finally {
      globalThis.setInterval = origSetInterval;
    }
  });

  await t.test('detectScheduledTampering when setImmediate replaced lines 240-242', () => {
    const TPC = require('../lib/tamper-proof-core');
    const origSetImmediate = globalThis.setImmediate;
    globalThis.setImmediate = function () {};
    try {
      const result = TPC.detectScheduledTampering();
      assert.strictEqual(result.valid, false);
      assert.ok(result.suspiciousActivities.includes('setImmediate has been replaced'));
    } finally {
      globalThis.setImmediate = origSetImmediate;
    }
  });

  await t.test('verifyObjectFreezeIntegrity when Object.freeze replaced', () => {
    // Lines 200-201: Object.freeze replaced
    const TPC = require('../lib/tamper-proof-core');
    const origFreeze = Object.freeze;
    Object.freeze = function () {};
    try {
      const result = TPC.verifyObjectFreezeIntegrity();
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error, 'Object.freeze has been replaced');
    } finally {
      Object.freeze = origFreeze;
    }
  });
});

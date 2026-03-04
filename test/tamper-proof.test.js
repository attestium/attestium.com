/**
 * Comprehensive tests for tamper-proof functionality
 */

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const TamperProofCore = require('../lib/tamper-proof-core');

test('Tamper-Proof Core Tests', async t => {
  await t.test('should initialize tamper-proof protection', () => {
    const verificationState = TamperProofCore.initializeTamperProofProtection();

    assert.ok(verificationState);
    assert.ok(typeof verificationState.bootTime === 'number');
    assert.ok(typeof verificationState.bootSignature === 'string');
    assert.ok(verificationState.bootSignature.length === 64); // SHA-256 hex
  });

  await t.test('should protect variables with tamper-proof storage', () => {
    const testValue = {secret: 'test-secret', key: 'test-key'};
    const protectionId = TamperProofCore.protectVariable('testVar', testValue);

    assert.ok(typeof protectionId === 'string');
    assert.ok(protectionId.length === 32); // 16 bytes hex
    assert.ok(Object.isFrozen(testValue));
  });

  await t.test('should verify protected variables correctly', () => {
    const testValue = {data: 'protected-data'};
    TamperProofCore.protectVariable('verifyTest', testValue);

    const verification = TamperProofCore.verifyProtectedVariable('verifyTest', testValue);

    assert.strictEqual(verification.valid, true);
    assert.ok(typeof verification.protectionId === 'string');
    assert.ok(typeof verification.timestamp === 'number');
  });

  await t.test('should detect variable tampering', () => {
    const originalValue = {count: 42};
    const tamperedValue = {count: 99};

    TamperProofCore.protectVariable('tamperTest', originalValue);

    const verification = TamperProofCore.verifyProtectedVariable('tamperTest', tamperedValue);

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('checksum mismatch'));
  });

  await t.test('should verify Object.freeze integrity', () => {
    const freezeCheck = TamperProofCore.verifyObjectFreezeIntegrity();

    assert.strictEqual(freezeCheck.valid, true);
  });

  await t.test('should detect if Object.freeze is replaced', () => {
    // Save original
    const originalFreeze = Object.freeze;

    // Replace with fake function
    Object.freeze = () => {};

    const freezeCheck = TamperProofCore.verifyObjectFreezeIntegrity();

    // Restore original
    Object.freeze = originalFreeze;

    assert.strictEqual(freezeCheck.valid, false);
    assert.ok(freezeCheck.error.includes('replaced'));
  });

  await t.test('should detect scheduled tampering attempts', () => {
    const tamperingCheck = TamperProofCore.detectScheduledTampering();

    assert.strictEqual(tamperingCheck.valid, true);
    assert.strictEqual(tamperingCheck.suspiciousActivities.length, 0);
  });

  await t.test('should detect if setTimeout is replaced', () => {
    // Save original
    const originalSetTimeout = globalThis.setTimeout;

    // Replace with fake function
    globalThis.setTimeout = () => {};

    const tamperingCheck = TamperProofCore.detectScheduledTampering();

    // Restore original
    globalThis.setTimeout = originalSetTimeout;

    assert.strictEqual(tamperingCheck.valid, false);
    assert.ok(tamperingCheck.suspiciousActivities.includes('setTimeout has been replaced'));
  });

  await t.test('should perform comprehensive tamper check', () => {
    const comprehensiveCheck = TamperProofCore.performComprehensiveTamperCheck();

    assert.strictEqual(comprehensiveCheck.valid, true);
    assert.ok(typeof comprehensiveCheck.timestamp === 'number');
    assert.ok(typeof comprehensiveCheck.bootTime === 'number');
    assert.ok(comprehensiveCheck.checks.objectFreezeIntegrity);
    assert.ok(comprehensiveCheck.checks.scheduledTampering);
    assert.ok(comprehensiveCheck.checks.verificationState);
  });

  await t.test('should generate tamper-proof proof with nonce', () => {
    const nonce = 'test-nonce-12345';
    const proof = TamperProofCore.generateTamperProofProof(nonce);

    assert.strictEqual(proof.nonce, nonce);
    assert.ok(typeof proof.bootTime === 'number');
    assert.ok(typeof proof.bootSignature === 'string');
    assert.ok(typeof proof.signature === 'string');
    assert.ok(typeof proof.proof === 'string');
    assert.ok(proof.signature.length === 64); // SHA-256 hex
  });

  await t.test('should create verification challenge', () => {
    const challenge = TamperProofCore.createVerificationChallenge();

    assert.ok(typeof challenge.nonce === 'string');
    assert.ok(challenge.nonce.length === 64); // 32 bytes hex
    assert.ok(typeof challenge.timestamp === 'number');
    assert.ok(typeof challenge.bootTime === 'number');
    assert.ok(typeof challenge.bootSignature === 'string');
    assert.ok(challenge.tamperProof);
    assert.ok(challenge.tamperCheck);
    assert.ok(typeof challenge.signature === 'string');
    assert.ok(challenge.expiresAt > challenge.timestamp);
  });

  await t.test('should verify challenge correctly', () => {
    const challenge = TamperProofCore.createVerificationChallenge();
    const verification = TamperProofCore.verifyChallenge(challenge, challenge.nonce);

    assert.strictEqual(verification.valid, true);
    assert.ok(verification.challenge);
  });

  await t.test('should reject challenge with wrong nonce', () => {
    const challenge = TamperProofCore.createVerificationChallenge();
    const verification = TamperProofCore.verifyChallenge(challenge, 'wrong-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('Invalid nonce'));
  });

  await t.test('should reject expired challenge', () => {
    const challenge = TamperProofCore.createVerificationChallenge();
    // Manually expire the challenge
    challenge.expiresAt = Date.now() - 1000;

    const verification = TamperProofCore.verifyChallenge(challenge, challenge.nonce);

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('expired'));
  });

  await t.test('should prevent modification of frozen objects', () => {
    const testObject = {value: 'original'};
    TamperProofCore.enhancedFreeze(testObject);

    // Try to modify
    try {
      testObject.value = 'modified';
    } catch {
      // Expected in strict mode
    }

    assert.strictEqual(testObject.value, 'original');
    assert.ok(Object.isFrozen(testObject));
  });

  await t.test('should maintain boot signature consistency', () => {
    const bootSig1 = TamperProofCore.bootSignature;
    const bootSig2 = TamperProofCore.bootSignature;

    assert.strictEqual(bootSig1, bootSig2);
    assert.ok(typeof bootSig1 === 'string');
    assert.ok(bootSig1.length === 64); // SHA-256 hex
  });

  await t.test('should maintain boot time consistency', () => {
    const bootTime1 = TamperProofCore.bootTime;
    const bootTime2 = TamperProofCore.bootTime;

    assert.strictEqual(bootTime1, bootTime2);
    assert.ok(typeof bootTime1 === 'number');
    assert.ok(bootTime1 > 0);
  });

  await t.test('should handle setTimeout tampering simulation', (t, done) => {
    const testValue = {critical: 'data'};
    TamperProofCore.protectVariable('timeoutTest', testValue);

    // Verify initial state
    const initialVerification = TamperProofCore.verifyProtectedVariable('timeoutTest', testValue);
    assert.strictEqual(initialVerification.valid, true);

    // Schedule tampering attempt
    setTimeout(() => {
      try {
        testValue.critical = 'hacked';
      } catch {
        // Expected - modification should be blocked
      }

      // Verify protection is still intact
      const postTamperVerification = TamperProofCore.verifyProtectedVariable('timeoutTest', testValue);
      assert.strictEqual(postTamperVerification.valid, true);
      assert.strictEqual(testValue.critical, 'data'); // Should be unchanged

      done();
    }, 10);
  });

  await t.test('should generate unique nonces for each challenge', async () => {
    const challenge1 = TamperProofCore.createVerificationChallenge();

    // Add small delay to ensure different timestamps
    await new Promise(resolve => setTimeout(resolve, 1));

    const challenge2 = TamperProofCore.createVerificationChallenge();

    assert.notStrictEqual(challenge1.nonce, challenge2.nonce);
    // Timestamps might be the same due to high resolution, so we'll just check nonces are different
  });

  await t.test('should maintain API immutability', () => {
    // Try to modify the TamperProofCore API
    try {
      TamperProofCore.newMethod = () => 'hacked';
    } catch {
      // Expected - API should be frozen
    }

    assert.strictEqual(TamperProofCore.newMethod, undefined);
    assert.ok(Object.isFrozen(TamperProofCore));
  });
});


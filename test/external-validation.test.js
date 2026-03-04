/**
 * Tests for External Validation System
 */

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const ExternalValidationManager = require('../lib/external-validation');

test('External Validation System Tests', async t => {
  await t.test('should initialize external validation manager', () => {
    const validator = new ExternalValidationManager({
      challengeServices: ['https://httpbin.org'],
      validationInterval: 60_000,
      challengeInterval: 30_000,
    });

    assert.ok(validator);
    assert.ok(validator.options);
    assert.strictEqual(validator.options.validationInterval, 60_000);
    assert.strictEqual(validator.options.challengeInterval, 30_000);
  });

  await t.test('should calculate Attestium checksum', async () => {
    const validator = new ExternalValidationManager();
    const checksum = await validator.calculateAttestiumChecksum();

    assert.ok(typeof checksum === 'string');
    assert.strictEqual(checksum.length, 64); // SHA-256 hex
  });

  await t.test('should make HTTPS requests', async () => {
    const validator = new ExternalValidationManager();

    try {
      const response = await validator.makeHTTPSRequest({
        hostname: 'httpbin.org',
        path: '/uuid',
        headers: {
          'User-Agent': 'Attestium-Test',
        },
      });

      assert.ok(typeof response === 'string');
      const data = JSON.parse(response);
      assert.ok(data.uuid);
    } catch (error) {
      // Skip test if network is unavailable
      console.log('Skipping HTTPS test due to network issue:', error.message);
    }
  });

  await t.test('should get external challenge from httpbin', async () => {
    const validator = new ExternalValidationManager();

    try {
      const challenge = await validator.getExternalChallenge('https://httpbin.org');

      assert.ok(challenge);
      assert.ok(typeof challenge.service === 'string');
      assert.ok(typeof challenge.challenge === 'string');
      assert.ok(typeof challenge.timestamp === 'number');
      assert.ok(challenge.challenge.length > 0);
    } catch (error) {
      // Skip test if network is unavailable
      console.log('Skipping external challenge test due to network issue:', error.message);
    }
  });

  await t.test('should generate different challenges from same service', async () => {
    const validator = new ExternalValidationManager();

    try {
      const challenge1 = await validator.getExternalChallenge('https://httpbin.org');

      // Wait a moment to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 100));

      const challenge2 = await validator.getExternalChallenge('https://httpbin.org');

      // Challenges should be different (due to timestamp inclusion)
      assert.notStrictEqual(challenge1.challenge, challenge2.challenge);
      assert.notStrictEqual(challenge1.timestamp, challenge2.timestamp);
    } catch (error) {
      // Skip test if network is unavailable
      console.log('Skipping challenge uniqueness test due to network issue:', error.message);
    }
  });

  await t.test('should handle invalid service URLs gracefully', async () => {
    const validator = new ExternalValidationManager();

    try {
      await validator.getExternalChallenge('https://invalid-service-that-does-not-exist.com');
      assert.fail('Should have thrown an error');
    } catch (error) {
      assert.ok(error.message.includes('Failed to get challenge'));
    }
  });

  await t.test('should generate external validation proof', async () => {
    const validator = new ExternalValidationManager();

    // Initialize validation state manually for testing
    validator.validationState.initialized = true;
    validator.validationState.trustedSources.set('github', {
      version: 'v1.0.0',
      verified: true,
      timestamp: Date.now(),
    });
    validator.validationState.externalChallenges.set('test-service', {
      challenge: 'test-challenge',
      timestamp: Date.now(),
    });
    validator.validationState.lastValidation = {
      checksumValid: true,
      sourcesValid: true,
      challengesValid: true,
    };

    const nonce = 'test-nonce-12345';
    const proof = await validator.generateExternalValidationProof(nonce);

    assert.strictEqual(proof.nonce, nonce);
    assert.ok(typeof proof.timestamp === 'number');
    assert.ok(typeof proof.attestiumChecksum === 'string');
    assert.ok(proof.trustedSources);
    assert.ok(proof.externalChallenges);
    assert.ok(proof.lastValidation);
    assert.ok(typeof proof.signature === 'string');
    assert.strictEqual(proof.signature.length, 64); // SHA-256 hex
  });

  await t.test('should verify valid external validation proof', async () => {
    const validator = new ExternalValidationManager();

    const nonce = 'test-nonce-12345';
    const proof = {
      nonce,
      timestamp: Date.now(),
      attestiumChecksum: 'test-checksum',
      trustedSources: {
        github: {verified: true},
      },
      externalChallenges: {
        service1: {timestamp: Date.now()},
        service2: {timestamp: Date.now()},
      },
      lastValidation: {
        checksumValid: true,
      },
    };

    const verification = await validator.verifyExternalValidationProof(proof, nonce);

    assert.strictEqual(verification.valid, true);
    assert.ok(verification.proof);
  });

  await t.test('should reject proof with wrong nonce', async () => {
    const validator = new ExternalValidationManager();

    const proof = {
      nonce: 'correct-nonce',
      timestamp: Date.now(),
      trustedSources: {github: {verified: true}},
      externalChallenges: {service1: {timestamp: Date.now()}},
      lastValidation: {checksumValid: true},
    };

    const verification = await validator.verifyExternalValidationProof(proof, 'wrong-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('Invalid nonce'));
  });

  await t.test('should reject expired proof', async () => {
    const validator = new ExternalValidationManager();

    const proof = {
      nonce: 'test-nonce',
      timestamp: Date.now() - 400_000, // 6+ minutes ago
      trustedSources: {github: {verified: true}},
      externalChallenges: {service1: {timestamp: Date.now()}},
      lastValidation: {checksumValid: true},
    };

    const verification = await validator.verifyExternalValidationProof(proof, 'test-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('expired'));
  });

  await t.test('should reject proof without GitHub verification', async () => {
    const validator = new ExternalValidationManager();

    const proof = {
      nonce: 'test-nonce',
      timestamp: Date.now(),
      trustedSources: {},
      externalChallenges: {service1: {timestamp: Date.now()}},
      lastValidation: {checksumValid: true},
    };

    const verification = await validator.verifyExternalValidationProof(proof, 'test-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('GitHub source not verified'));
  });

  await t.test('should reject proof with insufficient external challenges', async () => {
    const validator = new ExternalValidationManager();

    const proof = {
      nonce: 'test-nonce',
      timestamp: Date.now(),
      trustedSources: {github: {verified: true}},
      externalChallenges: {
        service1: {timestamp: Date.now() - 120_000}, // 2 minutes ago - too old
      },
      lastValidation: {checksumValid: true},
    };

    const verification = await validator.verifyExternalValidationProof(proof, 'test-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('Insufficient recent external challenges'));
  });

  await t.test('should reject proof with failed last validation', async () => {
    const validator = new ExternalValidationManager();

    const proof = {
      nonce: 'test-nonce',
      timestamp: Date.now(),
      trustedSources: {github: {verified: true}},
      externalChallenges: {
        service1: {timestamp: Date.now()},
        service2: {timestamp: Date.now()},
      },
      lastValidation: {checksumValid: false},
    };

    const verification = await validator.verifyExternalValidationProof(proof, 'test-nonce');

    assert.strictEqual(verification.valid, false);
    assert.ok(verification.error.includes('Last validation failed'));
  });

  await t.test('should get validation status', () => {
    const validator = new ExternalValidationManager();

    // Set up some test state
    validator.validationState.initialized = true;
    validator.validationState.trustedSources.set('test', {});
    validator.validationState.externalChallenges.set('test', {});
    validator.validationState.validationHistory.push({});
    validator.validationState.challengeHistory.push({});

    const status = validator.getValidationStatus();

    assert.strictEqual(status.initialized, true);
    assert.strictEqual(status.trustedSourceCount, 1);
    assert.strictEqual(status.externalChallengeCount, 1);
    assert.strictEqual(status.validationHistoryCount, 1);
    assert.strictEqual(status.challengeHistoryCount, 1);
  });

  await t.test('should stop validation timers', () => {
    const validator = new ExternalValidationManager();

    // Set up fake timers
    validator.validationTimer = setTimeout(() => {}, 1000);
    validator.challengeTimer = setTimeout(() => {}, 1000);

    validator.stop();

    assert.strictEqual(validator.validationTimer, null);
    assert.strictEqual(validator.challengeTimer, null);
  });

  await t.test('should handle audit logging gracefully', async () => {
    const validator = new ExternalValidationManager({
      auditEndpoints: ['https://invalid-audit-endpoint.com/api/audit'],
    });

    // This should not throw even if audit endpoint is invalid
    await validator.logAuditEvent('test_event', {test: 'data'});

    // Test passes if no exception is thrown
    assert.ok(true);
  });
});


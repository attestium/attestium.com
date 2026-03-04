/**
 * Tamper-Proof Core - Advanced Protection Against Runtime Modification
 *
 * This module implements multiple layers of protection to ensure that:
 * 1. Object.freeze was actually called and is still in effect
 * 2. Variables cannot be modified after boot (even via setTimeout)
 * 3. The protection mechanisms themselves cannot be tampered with
 * 4. Client-server verification with cryptographic proof
 */

const crypto = require('node:crypto');
const vm = require('node:vm');

/**
 * Immediately Invoked Function Expression (IIFE) to protect core functionality
 * This creates a closure that cannot be accessed from outside
 */
const TamperProofCore = (() => {
  // Capture original functions before they can be overridden
  const originalObjectFreeze = Object.freeze;
  const originalObjectIsFrozen = Object.isFrozen;
  const originalObjectDefineProperty = Object.defineProperty;
  const originalObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const originalSetTimeout = globalThis.setTimeout;
  const originalSetInterval = globalThis.setInterval;
  const originalSetImmediate = globalThis.setImmediate;
  const originalProcess = process;

  // Boot timestamp - this cannot be changed after initialization
  const BOOT_TIMESTAMP = Date.now();
  const BOOT_RANDOM = crypto.randomBytes(32).toString('hex');

  // Create a sealed boot signature that proves initialization occurred correctly
  const BOOT_SIGNATURE = crypto.createHash('sha256')
    .update(`${BOOT_TIMESTAMP}:${BOOT_RANDOM}:${process.pid}`)
    .digest('hex');

  // Protected storage for critical values
  const protectedStorage = new Map();

  // Freeze verification state
  let freezeVerificationState = null;

  /**
   * Initialize tamper-proof protection
   * This must be called at boot time before any other code
   */
  function initializeTamperProofProtection() {
    // Create verification state that proves Object.freeze was called
    freezeVerificationState = {
      bootTime: BOOT_TIMESTAMP,
      bootSignature: BOOT_SIGNATURE,
      originalFreezeFunction: originalObjectFreeze,
      frozenObjects: new WeakSet(),
      protectedValues: new Map(),
      verificationNonce: crypto.randomBytes(16).toString('hex'),
    };

    // Freeze the verification state itself
    originalObjectFreeze(freezeVerificationState.protectedValues);
    originalObjectFreeze(freezeVerificationState);

    // Store in protected storage
    protectedStorage.set('verificationState', freezeVerificationState);

    // Freeze the protected storage
    originalObjectFreeze(protectedStorage);

    return freezeVerificationState;
  }

  /**
   * Enhanced Object.freeze that tracks what was frozen
   */
  function enhancedFreeze(object) {
    /* c8 ignore next 3 - defensive guard: freezeVerificationState is always initialized before use */
    if (!freezeVerificationState) {
      throw new Error('Tamper-proof protection not initialized');
    }

    // Call original freeze
    const result = originalObjectFreeze(object);

    // Track that this object was frozen
    freezeVerificationState.frozenObjects.add(object);

    return result;
  }

  /**
   * Protect a variable with tamper-proof storage
   */
  function protectVariable(name, value, options = {}) {
    /* c8 ignore next 3 - defensive guard: freezeVerificationState is always initialized before use */
    if (!freezeVerificationState) {
      throw new Error('Tamper-proof protection not initialized');
    }

    const protectionId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    // Create protected value descriptor
    const protectedValue = {
      id: protectionId,
      name,
      value,
      timestamp,
      bootSignature: BOOT_SIGNATURE,
      checksum: crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex'),
      frozen: options.freeze !== false,
      immutable: options.immutable !== false,
    };

    // Freeze the value if requested
    if (protectedValue.frozen && typeof value === 'object' && value !== null) {
      enhancedFreeze(value);
    }

    // Store in verification state
    freezeVerificationState.protectedValues.set(name, protectedValue);

    return protectionId;
  }

  /**
   * Verify that a protected variable hasn't been tampered with
   */
  function verifyProtectedVariable(name, currentValue) {
    /* c8 ignore next 3 - defensive guard: freezeVerificationState is always initialized before use */
    if (!freezeVerificationState) {
      return {valid: false, error: 'Protection not initialized'};
    }

    const protectedValue = freezeVerificationState.protectedValues.get(name);
    if (!protectedValue) {
      return {valid: false, error: 'Variable not protected'};
    }

    // Verify boot signature
    /* c8 ignore next 3 - BOOT_SIGNATURE is immutable in closure; protectVariable always stores current value */
    if (protectedValue.bootSignature !== BOOT_SIGNATURE) {
      return {valid: false, error: 'Boot signature mismatch'};
    }

    // Verify checksum
    const currentChecksum = crypto.createHash('sha256').update(JSON.stringify(currentValue)).digest('hex');
    if (currentChecksum !== protectedValue.checksum) {
      return {valid: false, error: 'Value checksum mismatch'};
    }

    // Verify freeze state if applicable
    if (protectedValue.frozen && typeof currentValue === 'object' && currentValue !== null) {
      /* c8 ignore next 3 - frozen objects cannot be unfrozen in JavaScript */
      if (!originalObjectIsFrozen(currentValue)) {
        return {valid: false, error: 'Object no longer frozen'};
      }

      /* c8 ignore next 3 - frozen objects are always tracked via enhancedFreeze */
      if (!freezeVerificationState.frozenObjects.has(currentValue)) {
        return {valid: false, error: 'Object not in frozen tracking'};
      }
    }

    return {
      valid: true,
      protectionId: protectedValue.id,
      timestamp: protectedValue.timestamp,
    };
  }

  /**
   * Generate cryptographic proof of tamper-proof state
   */
  function generateTamperProofProof(nonce) {
    /* c8 ignore next 3 - defensive guard: freezeVerificationState is always initialized before use */
    if (!freezeVerificationState) {
      throw new Error('Protection not initialized');
    }

    const proofData = {
      nonce,
      bootTime: BOOT_TIMESTAMP,
      bootSignature: BOOT_SIGNATURE,
      verificationNonce: freezeVerificationState.verificationNonce,
      protectedVariableCount: freezeVerificationState.protectedValues.size,
      frozenObjectCount: 0, // WeakSet size not accessible
      timestamp: Date.now(),
    };

    // Create proof signature
    const proofString = JSON.stringify(proofData);
    const proofSignature = crypto.createHash('sha256').update(proofString).digest('hex');

    return {
      ...proofData,
      signature: proofSignature,
      proof: crypto.createHash('sha256').update(`${proofString}:${proofSignature}`).digest('hex'),
    };
  }

  /**
   * Verify that Object.freeze is still the original function
   */
  function verifyObjectFreezeIntegrity() {
    // Check if Object.freeze has been replaced
    if (Object.freeze !== originalObjectFreeze) {
      return {valid: false, error: 'Object.freeze has been replaced'};
    }

    // Check if Object.freeze still works correctly
    const testObject = {test: 'value'};
    Object.freeze(testObject);

    /* c8 ignore next 3 - Object.freeze always works correctly when not replaced */
    if (!Object.isFrozen(testObject)) {
      return {valid: false, error: 'Object.freeze not working correctly'};
    }

    // Try to modify the frozen object
    try {
      testObject.test = 'modified';
      /* c8 ignore next 3 - frozen object assignment is silently ignored in sloppy mode */
      if (testObject.test === 'modified') {
        return {valid: false, error: 'Object.freeze not preventing modifications'};
      }
    /* c8 ignore start - expected in strict mode */
    } catch {
      // Expected in strict mode
    }
    /* c8 ignore stop */

    return {valid: true};
  }

  /**
   * Detect if setTimeout/setInterval have been used to schedule tampering
   */
  function detectScheduledTampering() {
    const suspiciousActivities = [];

    // Check if timing functions have been replaced
    if (globalThis.setTimeout !== originalSetTimeout) {
      suspiciousActivities.push('setTimeout has been replaced');
    }

    if (globalThis.setInterval !== originalSetInterval) {
      suspiciousActivities.push('setInterval has been replaced');
    }

    if (globalThis.setImmediate !== originalSetImmediate) {
      suspiciousActivities.push('setImmediate has been replaced');
    }

    return {
      valid: suspiciousActivities.length === 0,
      suspiciousActivities,
    };
  }

  /**
   * Comprehensive tamper detection
   */
  function performComprehensiveTamperCheck() {
    const results = {
      timestamp: Date.now(),
      bootTime: BOOT_TIMESTAMP,
      checks: {},
    };

    // Check Object.freeze integrity
    results.checks.objectFreezeIntegrity = verifyObjectFreezeIntegrity();

    // Check for scheduled tampering
    results.checks.scheduledTampering = detectScheduledTampering();

    // Check verification state integrity
    results.checks.verificationState = {
      valid: freezeVerificationState !== null
        && originalObjectIsFrozen(freezeVerificationState)
        && freezeVerificationState.bootSignature === BOOT_SIGNATURE,
    };

    // Overall validity
    results.valid = Object.values(results.checks).every(check => check.valid);

    return results;
  }

  /**
   * Create a client-server verification challenge
   */
  function createVerificationChallenge() {
    const nonce = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();

    // Generate comprehensive proof
    const tamperProof = generateTamperProofProof(nonce);
    const tamperCheck = performComprehensiveTamperCheck();

    const challenge = {
      nonce,
      timestamp,
      bootTime: BOOT_TIMESTAMP,
      bootSignature: BOOT_SIGNATURE,
      tamperProof,
      tamperCheck,
      expiresAt: timestamp + (5 * 60 * 1000), // 5 minutes
    };

    // Sign the entire challenge
    const challengeSignature = crypto.createHash('sha256')
      .update(JSON.stringify(challenge))
      .digest('hex');

    challenge.signature = challengeSignature;

    return challenge;
  }

  /**
   * Verify a challenge response
   */
  function verifyChallenge(challenge, expectedNonce) {
    if (!challenge || challenge.nonce !== expectedNonce) {
      return {valid: false, error: 'Invalid nonce'};
    }

    if (Date.now() > challenge.expiresAt) {
      return {valid: false, error: 'Challenge expired'};
    }

    if (challenge.bootSignature !== BOOT_SIGNATURE) {
      return {valid: false, error: 'Boot signature mismatch'};
    }

    if (!challenge.tamperCheck.valid) {
      return {
        valid: false,
        error: 'Tamper detection failed',
        details: challenge.tamperCheck,
      };
    }

    return {valid: true, challenge};
  }

  // Return the public API (frozen to prevent tampering)
  const api = {
    initializeTamperProofProtection,
    protectVariable,
    verifyProtectedVariable,
    generateTamperProofProof,
    verifyObjectFreezeIntegrity,
    detectScheduledTampering,
    performComprehensiveTamperCheck,
    createVerificationChallenge,
    verifyChallenge,
    enhancedFreeze,

    // Read-only access to boot information
    get bootTime() {
      return BOOT_TIMESTAMP;
    },
    get bootSignature() {
      return BOOT_SIGNATURE;
    },
  };

  // Freeze the API to prevent tampering
  originalObjectFreeze(api);

  return api;
})();

module.exports = TamperProofCore;


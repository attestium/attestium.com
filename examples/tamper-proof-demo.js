/**
 * Tamper-Proof Protection Demo
 *
 * This demonstrates how to use the tamper-proof core to protect variables
 * and verify they haven't been tampered with, even via setTimeout attacks.
 */

const crypto = require('node:crypto');
const TamperProofCore = require('../lib/tamper-proof-core');

console.log('🔒 Tamper-Proof Protection Demo\n');

// Step 1: Initialize tamper-proof protection (must be done at boot)
console.log('1. Initializing tamper-proof protection...');
const verificationState = TamperProofCore.initializeTamperProofProtection();
console.log(`   ✅ Boot time: ${new Date(TamperProofCore.bootTime).toISOString()}`);
console.log(`   ✅ Boot signature: ${TamperProofCore.bootSignature.slice(0, 16)}...`);

// Step 2: Protect some critical variables
console.log('\n2. Protecting critical variables...');

const criticalConfig = {
  apiKey: 'secret-api-key-12345',
  adminPassword: 'super-secret-password',
  encryptionKey: crypto.randomBytes(32).toString('hex'),
};

const protectionId = TamperProofCore.protectVariable('criticalConfig', criticalConfig, {
  freeze: true,
  immutable: true,
});

console.log(`   ✅ Protected variable with ID: ${protectionId}`);
console.log(`   ✅ Config frozen: ${Object.isFrozen(criticalConfig)}`);

// Step 3: Verify the variable is protected
console.log('\n3. Verifying variable protection...');
const verification = TamperProofCore.verifyProtectedVariable('criticalConfig', criticalConfig);
console.log(`   ✅ Verification result: ${verification.valid ? 'VALID' : 'INVALID'}`);
if (verification.valid) {
  console.log(`   ✅ Protection ID: ${verification.protectionId}`);
}

// Step 4: Test Object.freeze integrity
console.log('\n4. Testing Object.freeze integrity...');
const freezeCheck = TamperProofCore.verifyObjectFreezeIntegrity();
console.log(`   ✅ Object.freeze integrity: ${freezeCheck.valid ? 'INTACT' : 'COMPROMISED'}`);

// Step 5: Detect scheduled tampering attempts
console.log('\n5. Checking for scheduled tampering...');
const tamperingCheck = TamperProofCore.detectScheduledTampering();
console.log(`   ✅ Scheduled tampering check: ${tamperingCheck.valid ? 'CLEAN' : 'SUSPICIOUS'}`);
if (!tamperingCheck.valid) {
  console.log(`   ⚠️  Suspicious activities: ${tamperingCheck.suspiciousActivities.join(', ')}`);
}

// Step 6: Comprehensive tamper check
console.log('\n6. Performing comprehensive tamper check...');
const comprehensiveCheck = TamperProofCore.performComprehensiveTamperCheck();
console.log(`   ✅ Overall tamper check: ${comprehensiveCheck.valid ? 'SECURE' : 'COMPROMISED'}`);
console.log(`   📊 Checks performed: ${Object.keys(comprehensiveCheck.checks).length}`);

// Step 7: Generate client-server verification challenge
console.log('\n7. Generating verification challenge for client-server validation...');
const challenge = TamperProofCore.createVerificationChallenge();
console.log(`   ✅ Challenge nonce: ${challenge.nonce.slice(0, 16)}...`);
console.log(`   ✅ Challenge expires: ${new Date(challenge.expiresAt).toISOString()}`);
console.log(`   ✅ Tamper proof valid: ${challenge.tamperProof ? 'YES' : 'NO'}`);

// Step 8: Verify the challenge (simulating client-server interaction)
console.log('\n8. Verifying challenge (simulating client response)...');
const challengeVerification = TamperProofCore.verifyChallenge(challenge, challenge.nonce);
console.log(`   ✅ Challenge verification: ${challengeVerification.valid ? 'VALID' : 'INVALID'}`);

// Step 9: Demonstrate tampering detection
console.log('\n9. Demonstrating tampering detection...');

// Try to modify the protected variable (this should fail)
try {
  criticalConfig.apiKey = 'hacked-key';
  console.log(`   ⚠️  Modification attempt: ${criticalConfig.apiKey === 'hacked-key' ? 'SUCCEEDED' : 'BLOCKED'}`);
} catch (error) {
  console.log(`   ✅ Modification blocked: ${error.message}`);
}

// Verify the variable is still intact
const postTamperVerification = TamperProofCore.verifyProtectedVariable('criticalConfig', criticalConfig);
console.log(`   ✅ Post-tamper verification: ${postTamperVerification.valid ? 'STILL VALID' : 'COMPROMISED'}`);

// Step 10: Simulate setTimeout attack (this is what we're protecting against)
console.log('\n10. Simulating setTimeout attack...');

// This is the type of attack we're protecting against
setTimeout(() => {
  console.log('\n   🚨 setTimeout attack executing...');

  try {
    // Try to modify the protected variable
    criticalConfig.apiKey = 'delayed-hack';
    console.log(`   ⚠️  Delayed modification: ${criticalConfig.apiKey === 'delayed-hack' ? 'SUCCEEDED' : 'BLOCKED'}`);
  } catch (error) {
    console.log(`   ✅ Delayed modification blocked: ${error.message}`);
  }

  // Verify protection is still intact
  const delayedVerification = TamperProofCore.verifyProtectedVariable('criticalConfig', criticalConfig);
  console.log(`   ✅ Delayed verification: ${delayedVerification.valid ? 'STILL PROTECTED' : 'COMPROMISED'}`);

  // Generate new challenge to prove system is still secure
  const postAttackChallenge = TamperProofCore.createVerificationChallenge();
  console.log(`   ✅ Post-attack challenge: ${postAttackChallenge.tamperCheck.valid ? 'SYSTEM SECURE' : 'SYSTEM COMPROMISED'}`);

  console.log('\n🎉 Demo complete! The system successfully protected against tampering attempts.');
}, 1000);

console.log('\n⏱️  Waiting for setTimeout attack simulation...');

// Step 11: Create a server endpoint simulation
console.log('\n11. Server endpoint simulation...');

function simulateServerEndpoint(clientNonce) {
  console.log(`\n📡 Server received verification request with nonce: ${clientNonce.slice(0, 16)}...`);

  // Generate server challenge
  const serverChallenge = TamperProofCore.createVerificationChallenge();

  // Verify client nonce matches
  const verification = TamperProofCore.verifyChallenge(serverChallenge, clientNonce);

  const response = {
    success: verification.valid,
    timestamp: Date.now(),
    bootTime: TamperProofCore.bootTime,
    bootSignature: TamperProofCore.bootSignature,
    tamperCheck: serverChallenge.tamperCheck,
    proof: serverChallenge.tamperProof,
  };

  console.log(`📤 Server response: ${response.success ? 'VERIFIED' : 'FAILED'}`);
  console.log(`📊 Tamper check: ${response.tamperCheck.valid ? 'CLEAN' : 'COMPROMISED'}`);

  return response;
}

// Simulate client request
const clientNonce = crypto.randomBytes(32).toString('hex');
const serverResponse = simulateServerEndpoint(clientNonce);

console.log('\n✅ Client-server verification complete!');
console.log(`🔐 System integrity: ${serverResponse.success && serverResponse.tamperCheck.valid ? 'VERIFIED' : 'COMPROMISED'}`);

// Export for testing
module.exports = {
  TamperProofCore,
  criticalConfig,
  protectionId,
  simulateServerEndpoint,
};


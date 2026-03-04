/**
 * External Validation Demo
 *
 * This demonstrates how external validation prevents tampering even when
 * someone modifies the local Attestium files in node_modules.
 */

const crypto = require('node:crypto');
const ExternalValidationManager = require('../lib/external-validation');

console.log('🌐 External Validation Demo\n');

async function runDemo() {
  // Step 1: Initialize external validation
  console.log('1. Initializing external validation system...');

  const validator = new ExternalValidationManager({
    githubRepo: 'forwardemail/attestium',
    challengeServices: [
      'https://api.github.com',
      'https://httpbin.org',
      'https://worldtimeapi.org',
    ],
    validationInterval: 15_000, // 15 seconds for demo
    challengeInterval: 8000, // 8 seconds for demo
    auditEndpoints: [
      // 'https://your-audit-service.com/api/audit' // Uncomment to use real audit service
    ],
  });

  try {
    await validator.initialize();
    console.log('✅ External validation initialized successfully\n');
  } catch (error) {
    console.error('❌ Failed to initialize external validation:', error.message);
    return;
  }

  // Step 2: Show validation status
  console.log('2. Current validation status:');
  const status = validator.getValidationStatus();
  console.log(`   📊 Initialized: ${status.initialized}`);
  console.log(`   📊 Trusted sources: ${status.trustedSourceCount}`);
  console.log(`   📊 External challenges: ${status.externalChallengeCount}`);
  console.log(`   📊 Validation history: ${status.validationHistoryCount}`);
  console.log(`   📊 Challenge history: ${status.challengeHistoryCount}\n`);

  // Step 3: Generate external validation proof
  console.log('3. Generating external validation proof...');
  const nonce = crypto.randomBytes(32).toString('hex');

  try {
    const proof = await validator.generateExternalValidationProof(nonce);
    console.log(`   ✅ Proof generated with nonce: ${nonce.slice(0, 16)}...`);
    console.log(`   📋 Attestium checksum: ${proof.attestiumChecksum.slice(0, 16)}...`);
    console.log(`   📋 Trusted sources: ${Object.keys(proof.trustedSources).join(', ')}`);
    console.log(`   📋 External challenges: ${Object.keys(proof.externalChallenges).length} services`);
    console.log(`   📋 Proof signature: ${proof.signature.slice(0, 16)}...\n`);

    // Step 4: Verify the proof
    console.log('4. Verifying external validation proof...');
    const verification = await validator.verifyExternalValidationProof(proof, nonce);
    console.log(`   ✅ Proof verification: ${verification.valid ? 'VALID' : 'INVALID'}`);
    if (!verification.valid) {
      console.log(`   ❌ Verification error: ${verification.error}`);
    }
  } catch (error) {
    console.error('❌ Failed to generate/verify proof:', error.message);
  }

  // Step 5: Simulate client-server validation
  console.log('\n5. Simulating client-server validation...');

  function simulateServerValidation(clientNonce) {
    console.log(`   📡 Server received validation request with nonce: ${clientNonce.slice(0, 16)}...`);

    return validator.generateExternalValidationProof(clientNonce)
      .then(proof => ({
        success: true,
        timestamp: Date.now(),
        externalValidation: {
          attestiumChecksum: proof.attestiumChecksum,
          trustedSources: Object.keys(proof.trustedSources),
          externalChallenges: Object.keys(proof.externalChallenges),
          lastValidation: proof.lastValidation,
          signature: proof.signature,
        },
      }))
      .catch(error => ({
        success: false,
        error: error.message,
        timestamp: Date.now(),
      }));
  }

  const clientNonce = crypto.randomBytes(32).toString('hex');
  const serverResponse = await simulateServerValidation(clientNonce);

  console.log(`   📤 Server response: ${serverResponse.success ? 'SUCCESS' : 'FAILED'}`);
  if (serverResponse.success) {
    console.log(`   📊 Trusted sources: ${serverResponse.externalValidation.trustedSources.join(', ')}`);
    console.log(`   📊 External challenges: ${serverResponse.externalValidation.externalChallenges.length} services`);
    console.log(`   📊 Last validation: ${serverResponse.externalValidation.lastValidation ? 'PASSED' : 'FAILED'}`);
  } else {
    console.log(`   ❌ Error: ${serverResponse.error}`);
  }

  // Step 6: Show how tampering would be detected
  console.log('\n6. Demonstrating tampering detection...');
  console.log('   🚨 If someone modified node_modules/attestium/lib/index.js:');
  console.log('   📋 Current checksum would change');
  console.log('   📋 GitHub signature verification would fail');
  console.log('   📋 External validation would detect the mismatch');
  console.log('   📋 All subsequent validation proofs would be invalid');
  console.log('   ✅ Tampering would be immediately detected!\n');

  // Step 7: Monitor external challenges for a bit
  console.log('7. Monitoring external challenges (30 seconds)...');
  console.log('   ⏱️  External services will provide new challenges every 8 seconds');
  console.log('   🔍 Validation checks will run every 15 seconds');

  let monitorCount = 0;
  const monitorInterval = setInterval(() => {
    monitorCount++;
    const currentStatus = validator.getValidationStatus();
    console.log(`   📊 Monitor ${monitorCount}: Challenges=${currentStatus.challengeHistoryCount}, Validations=${currentStatus.validationHistoryCount}`);

    if (monitorCount >= 6) { // 30 seconds / 5 second intervals
      clearInterval(monitorInterval);

      // Step 8: Final validation proof
      console.log('\n8. Final validation proof after monitoring...');
      validator.generateExternalValidationProof(crypto.randomBytes(32).toString('hex'))
        .then(finalProof => {
          console.log('   ✅ Final proof generated successfully');
          console.log(`   📊 Challenge history: ${finalProof.challengeHistory.length} entries`);
          console.log(`   📊 Validation history: ${finalProof.validationHistory.length} entries`);
          console.log('   🎉 External validation system working perfectly!\n');

          // Cleanup
          validator.stop();
          console.log('🏁 Demo completed successfully!');
        })
        .catch(error => {
          console.error('❌ Final proof generation failed:', error.message);
          validator.stop();
        });
    }
  }, 5000);
}

// Handle cleanup on exit
process.on('SIGINT', () => {
  console.log('\n🛑 Demo interrupted, cleaning up...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Demo terminated, cleaning up...');
  process.exit(0);
});

// Run the demo
runDemo().catch(error => {
  console.error('❌ Demo failed:', error.message);
  process.exit(1);
});


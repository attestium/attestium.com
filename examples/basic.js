const Attestium = require('../lib/index.js');

async function basicExample() {
  console.log('🧪 Attestium - Element of Attestation\n');
  console.log('   Runtime Code Verification and Integrity Monitoring');
  console.log('   Inspired by Forward Email and Mullvad research\n');

  // Initialize Attestium with default options
  const attestium = new Attestium({
    projectRoot: process.cwd(),
    gitCommit: process.env.GIT_COMMIT || 'unknown',
  });

  console.log('📊 Generating comprehensive checksums...');
  const checksums = await attestium.generateComprehensiveChecksums();

  console.log(`✅ Generated checksums for ${checksums.files.length} files`);
  console.log(`📅 Timestamp: ${checksums.timestamp}`);
  console.log(`🔗 Git Commit: ${checksums.gitCommit || 'Not specified'}\n`);

  // Show file categories
  const categories = checksums.files.reduce((acc, file) => {
    acc[file.category] = (acc[file.category] || 0) + 1;
    return acc;
  }, {});

  console.log('📂 File Categories:');
  for (const [category, count] of Object.entries(categories)) {
    console.log(`   ${category}: ${count} files`);
  }

  console.log('\n🔍 Verifying integrity...');
  const results = await attestium.verifyIntegrity(checksums);

  if (results.status === 'success') {
    console.log('✅ All files verified successfully!');
    console.log('🧪 Element of attestation: STABLE');
  } else {
    console.log(`❌ Verification ${results.status}: ${results.discrepancies.length} discrepancies found`);
    console.log('🧪 Element of attestation: UNSTABLE');
  }

  // Generate human-readable report
  const report = attestium.generateVerificationReport(results);
  console.log('\n📋 Verification Summary:');
  console.log(`   Total Files: ${report.summary.totalFiles}`);
  console.log(`   Verified: ${report.verified ? 'Yes' : 'No'}`);
  console.log(`   Discrepancies: ${report.summary.discrepancies}`);
  console.log(`   Element State: ${report.verified ? 'STABLE' : 'UNSTABLE'}`);

  console.log('\n🔬 Research References:');
  console.log('   • Forward Email Technical Whitepaper: https://forwardemail.net/technical-whitepaper.pdf');
  console.log('   • Mullvad System Transparency: https://mullvad.net/media/system-transparency-rev4.pdf');
}

basicExample().catch(console.error);


/**
 * Baseline and compare: record a signed manifest at deploy time, then check
 * the tree against it later.
 *
 *   node examples/basic.js [projectRoot]
 */

'use strict';

const Attestium = require('../lib/index.js');

async function main(projectRoot = process.cwd()) {
  // In production, generate the key once and keep the private key off the
  // machine being verified (sign the baseline in CI, publish the public key).
  const keys = Attestium.signing.generateKeyPair();

  const attestium = new Attestium({projectRoot, signingKey: keys.privateKey, logger: {log() {}}});
  const report = await attestium.generateVerificationReport();
  console.log(`Hashed ${report.summary.verifiedFiles} files, tree digest ${report.digest.slice(0, 16)}...`);
  for (const [category, count] of Object.entries(report.summary.categories)) {
    console.log(`  ${category}: ${count}`);
  }

  const baseline = await attestium.exportVerificationData();
  console.log(`Baseline signed by key ${baseline.signature.keyId.slice(0, 16)}...`);

  const result = await attestium.compareWithBaseline(baseline, {publicKey: keys.publicKey});
  console.log(result.valid
    ? 'Tree matches the signed baseline.'
    : `Mismatch: ${result.modified.length} modified, ${result.added.length} added, ${result.removed.length} removed`);
  return result;
}

module.exports = main;

if (require.main === module) {
  main(process.argv[2]).catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

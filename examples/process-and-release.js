/**
 * Inspect running Node.js processes and verify the Node.js release and
 * installed packages against upstream sources.
 *
 *   node examples/process-and-release.js [pid]
 *
 * Needs network access to nodejs.org and registry.npmjs.org.  Reading
 * another process's memory needs ptrace access to it.
 */

'use strict';

const {ProcessIntegrity, ReleaseVerification} = require('../lib/index.js');

async function main(pid = process.pid, options = {}) {
  const report = new ProcessIntegrity().checkAll(pid);
  console.log(`Process ${pid}: ${report.passed ? 'no findings' : `${report.findings.length} finding(s)`}`);
  for (const finding of report.findings) {
    console.log(`  [${finding.severity}] ${finding.type}: ${finding.detail}`);
  }

  if (report.executablePages.supported) {
    console.log(`  ${report.executablePages.regions.length} executable mappings compared with disk`);
  }

  const release = await new ReleaseVerification(options).verifyNodeRelease();
  console.log(release.passed
    ? `Node.js ${release.details.version} matches the official release`
    : `Node.js ${release.details.version}: ${release.details.error}`);
  return {report, release};
}

module.exports = main;

if (require.main === module) {
  main(process.argv[2]).catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

'use strict';

// Regressions found by fuzzing Audit Status's verifier with mutated evidence.

const test = require('node:test');
const assert = require('node:assert/strict');
const ReleaseVerification = require('../lib/release-verification');
const {sha256} = require('../lib/util');

test('comparePackages: a package matched by digest must carry the file list the digest was computed from', async () => {
  const rv = new ReleaseVerification({retryDelay: 1});
  const tarball = new Map([
    ['package.json', Buffer.from(JSON.stringify({name: 'parent', version: '1.0.0'}))],
    ['index.js', Buffer.from('module.exports = 1;\n')],
    ['node_modules/child/package.json', Buffer.from(JSON.stringify({name: 'child', version: '2.0.0'}))],
    ['node_modules/child/index.js', Buffer.from('module.exports = 2;\n')],
  ]);
  const manifest = ReleaseVerification.packageManifestFromFiles(tarball);
  const child = ReleaseVerification.packageManifestFromFiles(new Map([...tarball].filter(([file]) => file.startsWith('node_modules/child/')).map(([file, content]) => [file.slice('node_modules/child/'.length), content])));
  const [bundled] = manifest.bundled;
  assert.equal(bundled.digest, child.digest);
  const compare = installed => rv.comparePackages({installed, manifestProvider: async () => manifest});

  const parent = {
    name: 'parent', version: '1.0.0', path: 'parent', digest: manifest.digest,
  };
  const inside = {
    name: 'child', version: '2.0.0', path: 'parent/node_modules/child', digest: child.digest,
  };
  // The honest file lists (and none at all) verify.
  const honest = await compare([{...parent, files: manifest.files}, {...inside, files: child.files}]);
  assert.equal(honest.passed, true);
  assert.deepEqual(honest.summary.bundled, 1);
  // Without a file list, the reference's file hashes are returned for the
  // package that matched by digest; a bundled one carries none.
  const digestOnly = await compare([parent, inside]);
  assert.equal(digestOnly.passed, true);
  assert.deepEqual([...digestOnly.files], [['parent', manifest.files]]);
  assert.deepEqual([...honest.files], [['parent', manifest.files]]);

  // A file list that adds a native module, or changes a file, while the
  // digest still matches: those files would be explained as verified.
  const evil = sha256('evil');
  for (const files of [{...manifest.files, 'build/Release/evil.node': evil}, {...manifest.files, 'index.js': evil}]) {
    const result = await compare([{...parent, files}]);
    assert.equal(result.passed, false);
    assert.deepEqual(result.findings.map(finding => finding.reason), ['the file list does not match the package digest']);
  }

  // The same for a dependency bundled in it.
  const tampered = await compare([parent, {...inside, files: {...child.files, 'evil.node': evil}}]);
  assert.deepEqual(tampered.findings.map(finding => `${finding.package}: ${finding.reason}`), ['child@2.0.0: the file list does not match the package digest']);
});

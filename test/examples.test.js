'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const basic = require('../examples/basic');
const sshVerification = require('../examples/ssh-verification');
const processAndRelease = require('../examples/process-and-release');
const {tempDir, writeFiles, startServer} = require('./helpers');

// The examples are documentation; running them keeps them honest.

function silence(t) {
  const {log} = console;
  console.log = () => {};
  t.after(() => {
    console.log = log;
  });
}

test('examples/basic.js', async t => {
  silence(t);
  const root = tempDir(t);
  writeFiles(root, {'index.js': 'x', 'README.md': 'y'});
  assert.equal((await basic(root)).valid, true);
});

test('examples/ssh-verification.js', {skip: process.platform === 'win32'}, async t => {
  silence(t);
  const fs = require('node:fs');
  const path = require('node:path');
  const {signing} = require('../lib');
  const root = tempDir(t);
  const project = path.join(root, 'app');
  writeFiles(project, {'index.js': 'x'});
  assert.equal((await sshVerification.main(project)).valid, true);

  // The forced command: SSH_ORIGINAL_COMMAND is the request.
  const keys = signing.generateKeyPair();
  const keyFile = path.join(root, 'signing-key.pem');
  fs.writeFileSync(keyFile, keys.privateKey);
  await assert.rejects(sshVerification.forcedCommand([project, keyFile], {}), /Expected "attest <nonce>"/);
  await assert.rejects(sshVerification.forcedCommand([project, keyFile], {SSH_ORIGINAL_COMMAND: 'sh -c id'}), /Expected "attest <nonce>"/);
  await assert.rejects(sshVerification.forcedCommand([project, keyFile], {SSH_ORIGINAL_COMMAND: 'attest abc'}), /16 to 64 bytes/);

  // A stand-in for ssh that checks the options, then runs the example as
  // sshd runs a forced command: the request in SSH_ORIGINAL_COMMAND.
  const example = path.join(__dirname, '..', 'examples', 'ssh-verification.js');
  const ssh = path.join(root, 'ssh');
  fs.writeFileSync(ssh, `#!/bin/sh
case " $* " in *" -o StrictHostKeyChecking=yes "*) ;; *) echo "host key not pinned" >&2; exit 255 ;; esac
for last; do :; done
SSH_ORIGINAL_COMMAND="$last" exec "${process.execPath}" "${example}" "${project}" "${keyFile}"
`, {mode: 0o755});
  const {digest} = await new (require('../lib'))({projectRoot: project, logger: {log() {}}}).generateVerificationReport();
  const input = {
    ssh, destination: 'attester@server.example', identity: path.join(root, 'id'), knownHosts: path.join(root, 'known_hosts'),
  };
  assert.deepEqual(await sshVerification.verify({...input, publicKey: keys.publicKey, expectedDigest: digest}), {valid: true, errors: []});
  // Another key, another tree, an attester that fails, and output that is not JSON.
  assert.equal((await sshVerification.verify({...input, publicKey: signing.generateKeyPair().publicKey})).valid, false);
  assert.equal((await sshVerification.verify({...input, publicKey: keys.publicKey, expectedDigest: 'f'.repeat(64)})).valid, false);
  const failing = await sshVerification.verify({...input, ssh: path.join(root, 'missing-ssh'), publicKey: keys.publicKey});
  assert.match(failing.errors[0], /^ssh failed: /);
  assert.deepEqual(sshVerification.check({statement: 'not json', nonce: 'a'.repeat(32), publicKey: keys.publicKey}), {valid: false, errors: ['The answer is not JSON']});
  assert.deepEqual(sshVerification.sshArguments({
    destination: 'a@b', identity: 'id', knownHosts: 'kh', nonce: 'n',
  }).slice(-3), ['--', 'a@b', 'attest n']);
});

test('examples/process-and-release.js', async t => {
  silence(t);
  const upstream = await startServer(t, {});
  const {report, release} = await processAndRelease(process.pid, {nodeDistUrl: upstream.url, maxRetries: 0});
  assert.equal(typeof report.passed, 'boolean');
  assert.equal(release.passed, false);
  assert.match(release.details.error, /HTTP 404/);
});

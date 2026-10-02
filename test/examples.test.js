'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const basic = require('../examples/basic');
const httpVerification = require('../examples/http-verification');
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

test('examples/http-verification.js', async t => {
  silence(t);
  const root = tempDir(t);
  writeFiles(root, {'index.js': 'x'});
  assert.equal((await httpVerification.main(root)).valid, true);

  const keys = require('../lib').signing.generateKeyPair();
  const server = await httpVerification.startServer({projectRoot: root, privateKey: keys.privateKey});
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${url}/other`)).status, 404);
  const bad = await fetch(`${url}/attestation?nonce=short`);
  assert.equal(bad.status, 400);
  assert.match((await bad.json()).error, /16 to 64 bytes/);
  assert.equal((await fetch(`${url}/attestation`)).status, 400);
  const wrongKey = await httpVerification.verify({url, publicKey: require('../lib').signing.generateKeyPair().publicKey});
  assert.equal(wrongKey.valid, false);
});

test('examples/process-and-release.js', async t => {
  silence(t);
  const upstream = await startServer(t, {});
  const {report, release} = await processAndRelease(process.pid, {nodeDistUrl: upstream.url, maxRetries: 0});
  assert.equal(typeof report.passed, 'boolean');
  assert.equal(release.passed, false);
  assert.match(release.details.error, /HTTP 404/);
});

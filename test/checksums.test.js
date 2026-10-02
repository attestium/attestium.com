'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {
  parseChecksums, verifyMinisign, fetchChecksums, toIdentity, gpgStatusProblem,
} = require('../lib/checksums');
const {ReferenceStore} = require('../lib/ecosystems/common');
const {tempDir, startServer, which} = require('./helpers');
const fixture = require('./fixtures/sigstore');

const MINISIGN = path.join(__dirname, 'fixtures/minisign');
const hasMinisign = which('minisign');
const hasGpg = which('gpg') && which('gpgv');
const sha = text => crypto.createHash('sha256').update(text).digest('hex');

const LIST = Buffer.from([
  `${sha('app-linux')}  app-linux-amd64.tar.gz`,
  `${sha('app-mac').toUpperCase()} *app-darwin-arm64.tar.gz`,
  '',
].join('\n'));

test('parseChecksums reads GNU and BSD lines', () => {
  const text = [
    `${sha('a')}  a.tar.gz`,
    `${sha('b')} *b.zip`,
    `${sha('c').toUpperCase()}  ./dir/c file.bin  `,
    `SHA256 (./d.deb) = ${sha('d')}`,
    `SHA256(e.rpm)=${sha('e').toUpperCase()}`,
    `SHA512 (f.tar) = ${sha('f')}`,
    `${sha('g').slice(1)}  short.txt`,
    '# comment',
    '',
  ].join('\r\n');
  assert.deepStrictEqual(parseChecksums(text), new Map([
    ['a.tar.gz', sha('a')],
    ['b.zip', sha('b')],
    ['dir/c file.bin', sha('c')],
    ['d.deb', sha('d')],
    ['e.rpm', sha('e')],
  ]));
  assert.strictEqual(parseChecksums('').size, 0);
});

test('verifyMinisign checks real minisign signatures', () => {
  const data = fs.readFileSync(path.join(MINISIGN, 'sums.txt'));
  const publicKey = fs.readFileSync(path.join(MINISIGN, 'mk.pub'), 'utf8').split('\n')[1];
  const prehashed = fs.readFileSync(path.join(MINISIGN, 'sums.txt.minisig'), 'utf8');
  const legacy = fs.readFileSync(path.join(MINISIGN, 'sums.legacy.minisig'), 'utf8');
  assert.strictEqual(verifyMinisign(data, prehashed, publicKey), true);
  assert.strictEqual(verifyMinisign(data, legacy, `${publicKey}\n`), true);
  assert.strictEqual(verifyMinisign(data, prehashed.replaceAll('\n', '\r\n'), publicKey), true);

  assert.strictEqual(verifyMinisign(Buffer.from('abc124  file\n'), prehashed, publicKey), false);
  assert.strictEqual(verifyMinisign(Buffer.from('abc124  file\n'), legacy, publicKey), false);
  // The trusted comment is signed, too.
  assert.strictEqual(verifyMinisign(data, prehashed.replace('release 1.0', 'release 2.0'), publicKey), false);

  const lines = prehashed.split('\n');
  const key = Buffer.from(publicKey, 'base64');
  const signature = Buffer.from(lines[1], 'base64');
  const withLine = (index, value) => lines.map((line, position) => (position === index ? value : line)).join('\n');
  const otherKeyId = Buffer.from(key);
  otherKeyId[2] ^= 1;
  const notEd = Buffer.from(key);
  notEd.write('XX', 0, 'latin1');
  const otherAlgorithm = Buffer.from(signature);
  otherAlgorithm.write('EX', 0, 'latin1');
  const cases = [
    [prehashed, 'AAAA'],
    [prehashed, otherKeyId.toString('base64')],
    [prehashed, notEd.toString('base64')],
    [withLine(1, otherAlgorithm.toString('base64')), publicKey],
    [withLine(1, 'AAAA'), publicKey],
    [withLine(2, 'untrusted: release 1.0'), publicKey],
    [withLine(3, 'AAAA'), publicKey],
    [lines[0], publicKey],
    ['', publicKey],
  ];
  for (const [signatureText, keyText] of cases) {
    assert.strictEqual(verifyMinisign(data, signatureText, keyText), false);
  }
});

test('toIdentity turns /regex/ strings into patterns', () => {
  const identity = toIdentity({issuer: 'https://accounts.example.com', subjectAlternativeName: String.raw`/^https://github\.com/octo//`, ref: '/'});
  assert.strictEqual(identity.issuer, 'https://accounts.example.com');
  assert.ok(identity.subjectAlternativeName instanceof RegExp);
  assert.ok(identity.subjectAlternativeName.test('https://github.com/octo/app'));
  assert.strictEqual(identity.ref, '/');
  assert.deepStrictEqual(toIdentity(), {});
});

test('fetchChecksums without a signature, cached per run', async t => {
  const {url, requests} = await startServer(t, {'/SHA256SUMS': {body: LIST}});
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const result = await fetchChecksums({url: `${url}/SHA256SUMS`}, {store});
  assert.strictEqual(result.signed, false);
  assert.strictEqual(result.checksums.get('app-linux-amd64.tar.gz'), sha('app-linux'));
  assert.strictEqual(result.checksums.get('app-darwin-arm64.tar.gz'), sha('app-mac'));
  await fetchChecksums({url: `${url}/SHA256SUMS`}, {store});
  assert.strictEqual(requests.length, 1);
  await assert.rejects(fetchChecksums({url: `${url}/missing`}, {store}), /HTTP 404/);
  await assert.rejects(fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'pgp'}}, {store}), /unknown signature type pgp/);
});

test('fetchChecksums with a minisign signature', {skip: !hasMinisign && 'minisign is not installed'}, async t => {
  const directory = tempDir(t);
  const list = path.join(directory, 'SHA256SUMS');
  fs.writeFileSync(list, LIST);
  execFileSync('minisign', ['-G', '-W', '-p', 'key.pub', '-s', 'key.sec'], {cwd: directory, stdio: 'ignore'});
  execFileSync('minisign', ['-S', '-s', 'key.sec', '-m', 'SHA256SUMS', '-t', 'app 1.0'], {cwd: directory, stdio: 'ignore'});
  execFileSync('minisign', ['-S', '-l', '-s', 'key.sec', '-m', 'SHA256SUMS', '-x', 'legacy.minisig'], {cwd: directory, stdio: 'ignore'});
  const publicKey = fs.readFileSync(path.join(directory, 'key.pub'), 'utf8').split('\n')[1];
  const {url} = await startServer(t, {
    '/SHA256SUMS': {body: LIST},
    '/SHA256SUMS.minisig': {body: fs.readFileSync(`${list}.minisig`)},
    '/legacy.minisig': {body: fs.readFileSync(path.join(directory, 'legacy.minisig'))},
    '/other.minisig': {body: fs.readFileSync(path.join(MINISIGN, 'sums.txt.minisig'))},
  });
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const source = {url: `${url}/SHA256SUMS`, signature: {type: 'minisign', publicKey}};
  const result = await fetchChecksums(source, {store});
  assert.strictEqual(result.signed, true);
  assert.strictEqual(result.checksums.size, 2);
  const legacy = await fetchChecksums({...source, signature: {...source.signature, url: `${url}/legacy.minisig`}}, {store});
  assert.strictEqual(legacy.checksums.size, 2);
  await assert.rejects(fetchChecksums({...source, signature: {...source.signature, url: `${url}/other.minisig`}}, {store}), /does not verify \(minisign\)/);
});

test('fetchChecksums with a gpg signature', {skip: !hasGpg && 'gpg is not installed'}, async t => {
  const home = tempDir(t, 'gpg-');
  const env = {...process.env, GNUPGHOME: home};
  const gpg = args => execFileSync('gpg', ['--batch', '--pinentry-mode', 'loopback', '--passphrase', '', ...args], {cwd: home, env, stdio: ['ignore', 'pipe', 'ignore']});
  try {
    gpg(['--quick-gen-key', 'Release <release@example.com>', 'ed25519', 'sign', 'never']);
    fs.writeFileSync(path.join(home, 'keyring.gpg'), gpg(['--export']));
    fs.writeFileSync(path.join(home, 'SHA256SUMS'), LIST);
    gpg(['--detach-sign', '-o', 'SHA256SUMS.sig', 'SHA256SUMS']);
  } finally {
    try {
      execFileSync('gpgconf', ['--kill', 'gpg-agent'], {env, stdio: 'ignore'});
    } catch {}
  }

  const {url} = await startServer(t, {
    '/SHA256SUMS': {body: LIST},
    '/SHA256SUMS.sig': {body: fs.readFileSync(path.join(home, 'SHA256SUMS.sig'))},
    '/tampered': {body: Buffer.concat([LIST, Buffer.from('\n')])},
  });
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const signature = {type: 'gpg', keyring: path.join(home, 'keyring.gpg')};
  const result = await fetchChecksums({url: `${url}/SHA256SUMS`, signature}, {store});
  assert.strictEqual(result.signed, true);
  assert.strictEqual(result.checksums.get('app-linux-amd64.tar.gz'), sha('app-linux'));
  await assert.rejects(fetchChecksums({url: `${url}/tampered`, signature: {...signature, url: `${url}/SHA256SUMS.sig`}}, {store}), /does not verify \(gpgv\): /);
});

test('fetchChecksums refuses gpg signatures by revoked or expired keys, and signed messages', {skip: !hasGpg && 'gpg is not installed'}, async t => {
  const home = tempDir(t, 'gpg-');
  const env = {...process.env, GNUPGHOME: home};
  const gpg = (args, time) => execFileSync('gpg', ['--batch', '--pinentry-mode', 'loopback', '--passphrase', '', ...(time ? ['--faked-system-time', time] : []), ...args], {
    cwd: home, env, stdio: ['ignore', 'pipe', 'ignore'],
  });
  const fingerprint = email => gpg(['--list-keys', '--with-colons', email]).toString().match(/^fpr:+([\dA-F]{40}):/m)[1];
  fs.writeFileSync(path.join(home, 'SHA256SUMS'), LIST);
  try {
    // Revoked: the publisher revoked the key (for example after a compromise).
    gpg(['--quick-gen-key', 'Revoked <revoked@example.com>', 'ed25519', 'sign', 'never']);
    gpg(['-u', 'revoked@example.com', '--detach-sign', '-o', 'revoked.sig', 'SHA256SUMS']);
    const revocation = fs.readFileSync(path.join(home, 'openpgp-revocs.d', `${fingerprint('revoked@example.com')}.rev`), 'utf8');
    fs.writeFileSync(path.join(home, 'revocation.asc'), revocation.replace(/^:-{5}BEGIN/m, '-----BEGIN'));
    gpg(['--import', 'revocation.asc']);
    fs.writeFileSync(path.join(home, 'revoked.gpg'), gpg(['--export', 'revoked@example.com']));
    // Expired: a key that expired a day after it was made.
    gpg(['--quick-gen-key', 'Expired <expired@example.com>', 'ed25519', 'sign', '1d'], '20200101T000000');
    gpg(['-u', 'expired@example.com', '--detach-sign', '-o', 'expired.sig', 'SHA256SUMS'], '20200101T010000');
    fs.writeFileSync(path.join(home, 'expired.gpg'), gpg(['--export', 'expired@example.com']));
    // A signed message (not a detached signature) carrying other contents.
    gpg(['--quick-gen-key', 'Good <good@example.com>', 'ed25519', 'sign', 'never']);
    fs.writeFileSync(path.join(home, 'OTHER'), 'other contents\n');
    gpg(['-u', 'good@example.com', '--sign', '-o', 'message.gpg', 'OTHER']);
    fs.writeFileSync(path.join(home, 'good.gpg'), gpg(['--export', 'good@example.com']));
  } finally {
    try {
      execFileSync('gpgconf', ['--kill', 'gpg-agent'], {env, stdio: 'ignore'});
    } catch {}
  }

  const {url} = await startServer(t, {
    '/SHA256SUMS': {body: LIST},
    '/revoked.sig': {body: fs.readFileSync(path.join(home, 'revoked.sig'))},
    '/expired.sig': {body: fs.readFileSync(path.join(home, 'expired.sig'))},
    '/message.gpg': {body: fs.readFileSync(path.join(home, 'message.gpg'))},
  });
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  const check = (name, keyring) => fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'gpg', url: `${url}/${name}`, keyring: path.join(home, keyring)}}, {store});
  await assert.rejects(check('revoked.sig', 'revoked.gpg'), /does not verify \(gpgv\): the signing key is revoked/);
  await assert.rejects(check('expired.sig', 'expired.gpg'), /does not verify \(gpgv\): the signing key has expired/);
  await assert.rejects(check('message.gpg', 'good.gpg'), /does not verify \(gpgv\): /);
});

test('gpgStatusProblem accepts only good signatures by valid keys', () => {
  const good = ['NEWSIG', 'KEY_CONSIDERED ABCD 0', 'GOODSIG ABCD Name', 'VALIDSIG ABCD 2026-01-01'].map(line => `[GNUPG:] ${line}`).join('\n');
  assert.strictEqual(gpgStatusProblem(`gpgv: noise\n${good}\n`), null);
  assert.strictEqual(gpgStatusProblem(`${good}\n${good}`), null);
  assert.strictEqual(gpgStatusProblem(''), 'no good signature');
  // Two signatures, one of them not good.
  assert.strictEqual(gpgStatusProblem(`${good}\n[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG ABCD Name`), 'no good signature');
  assert.strictEqual(gpgStatusProblem(`${good}\n[GNUPG:] NEWSIG\n[GNUPG:] BADSIG ABCD Name`), 'a signature is bad');
  assert.strictEqual(gpgStatusProblem('[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG ABCD 22 10 00 1 9'), 'a signature could not be checked');
  assert.strictEqual(gpgStatusProblem(`${good}\n[GNUPG:] EXPSIG ABCD Name`), 'the signature has expired');
});

test('fetchChecksums with a Sigstore bundle', async t => {
  const {trustedRoot} = fixture.getAuthority();
  const blob = fixture.makeBundle({artifact: LIST, certificate: {repository: 'octo/app'}});
  const statement = fixture.makeBundle({
    statement: {_type: 'https://in-toto.io/Statement/v1', subject: [{name: 'SHA256SUMS', digest: {sha256: sha(LIST)}}], predicateType: 'https://slsa.dev/provenance/v1'},
    certificate: {repository: 'octo/app'},
  });
  const {url} = await startServer(t, {
    '/SHA256SUMS': {body: LIST},
    '/SHA256SUMS.sigstore.json': {body: JSON.stringify(blob.bundle)},
    '/statement.json': {body: JSON.stringify(statement.bundle)},
  });
  const store = new ReferenceStore({httpOptions: {maxRetries: 0}});
  let loads = 0;
  const context = {
    store,
    async trustedRoot() {
      loads++;
      return trustedRoot;
    },
  };
  const identity = {issuer: fixture.GITHUB_ISSUER, subjectAlternativeName: String.raw`/^https://github\.com/octo/app//`};
  const result = await fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'sigstore', identity}}, context);
  assert.strictEqual(result.signed, true);
  assert.strictEqual(result.checksums.size, 2);
  const viaStatement = await fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'sigstore', url: `${url}/statement.json`, identity}}, context);
  assert.strictEqual(viaStatement.checksums.size, 2);
  assert.strictEqual(loads, 2);
  await assert.rejects(fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'sigstore', identity: {subjectAlternativeName: '/evil/'}}}, context), /certificate subjectAlternativeName/);

  // Without an identity, any signer the CA certified would be accepted: refused.
  const before = loads;
  for (const identity of [undefined, {}]) {
    await assert.rejects(fetchChecksums({url: `${url}/SHA256SUMS`, signature: {type: 'sigstore', identity}}, context), /a Sigstore signature needs an identity/);
  }

  assert.strictEqual(loads, before, 'refused before anything is fetched or verified');
});

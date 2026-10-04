'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const evidence = require('../lib/evidence');
const {digestOf} = require('../lib/util');
const {
  tempDir, writeFiles, needsPosix, PATH_MAX,
} = require('./helpers');

const sha = text => crypto.createHash('sha256').update(text).digest('hex');
const COMMIT = 'c'.repeat(40);
const TIME = '2026-09-30T12:00:00.000Z';

const processEntry = {
  pid: 4242,
  ppid: 1,
  uid: 1000,
  cwd: '/srv/app',
  exe: '/usr/bin/node',
  exeDeleted: false,
  cmdline: ['node', 'server.js'],
  startTime: TIME,
  runtime: {
    name: 'node', label: 'Node.js', version: 'v22.0.0', by: 'exe',
  },
  integrity: {
    passed: false,
    findings: [{
      type: 'unexpected-module', severity: 'warning', check: 'memoryMaps', path: '/tmp/x.js',
    }],
    incomplete: [{check: 'maps', error: 'EACCES'}],
    libraries: ['/usr/lib/libc.so.6'],
  },
  changedAfterStart: ['server.js'],
  metadataChangedAfterStart: [],
  changedAfterStartTruncated: false,
  metadataChangedAfterStartTruncated: false,
};

const owner = {
  name: 'nodejs', version: '22.0.0-1', arch: 'amd64', listedAs: 'nodejs:amd64', source: 'nodejs', installedAt: null,
};

/**
 * Evidence using every part of the format.
 */
function fullEvidence() {
  const value = {
    type: evidence.TYPE,
    version: evidence.VERSION,
    nonce: 'ab'.repeat(16),
    collectedAt: TIME,
    attester: {
      name: 'attestium', version: '0.1.0', platform: 'linux', arch: 'x64', node: 'v22.0.0', executable: {path: '/usr/bin/node', sha256: sha('node')},
    },
    host: {
      hostname: 'web-1', kernel: '6.8.0', bootId: null, os: {id: 'debian', versionId: '12', codename: 'bookworm'},
    },
    distro: {format: 'dpkg', arch: 'amd64'},
    services: [
      {
        name: 'app',
        kind: 'directory',
        root: '/srv/app',
        realRoot: '/srv/app',
        git: {commit: COMMIT, ref: 'refs/heads/main'},
        files: {'server.js': [sha('server'), '100644'], 'bin/start': ['symlink:../server.js', '120000']},
        fileCount: 2,
        errors: [{path: 'secret', error: 'EACCES'}],
        manifest: Buffer.from('{}').toString('base64'),
        truncated: false,
        installs: [{
          ecosystem: 'npm',
          dir: '/srv/app/node_modules',
          packages: [{
            name: 'express', version: '5.0.0', path: 'node_modules/express', files: {'index.js': sha('express')}, digest: sha('express files'), fileCount: 1, invalid: false, meta: {},
          }],
          unaccounted: [],
          links: [{path: 'node_modules/.bin/x', problem: 'outside'}],
          caches: [{path: 'node_modules/.cache', files: ['a']}],
          errors: [],
          meta: {lockfile: 'package-lock.json'},
        }],
        processes: [structuredClone(processEntry)],
        userProcesses: [{pid: 99}, {
          pid: 100, exe: '/usr/bin/pm2', name: 'pm2', cwd: null,
        }],
      },
      {
        name: 'db',
        kind: 'container',
        containers: [{
          id: 'f'.repeat(64),
          runtime: 'docker',
          name: 'db',
          image: {
            reference: 'postgres:16', id: null, manifestDigest: `sha256:${sha('manifest')}`, repoDigests: [],
          },
          platform: {os: 'linux', architecture: 'amd64'},
          mounts: [{
            destination: '/var/lib/postgresql/data', source: '/srv/db', root: '/', fsType: 'ext4', readOnly: false,
          }],
          upper: {files: {'etc/passwd': [sha('passwd'), '100644']}, deleted: ['tmp/x'], errors: []},
          rootfs: {
            files: {}, fileCount: 0, errors: [], truncated: false,
          },
          processes: [{...structuredClone(processEntry), runtime: null, startTime: null}],
        }],
      },
    ],
    executables: [{
      path: '/usr/bin/node', container: null, deleted: false, platform: 'linux', arch: 'x64', sha256: sha('node'), size: 1024, nodeVersion: 'v22.0.0', go: {}, cargo: {}, package: owner,
    }],
    libraries: [{
      path: '/usr/lib/libc.so.6', container: 'f'.repeat(64), sha256: sha('libc'), package: null,
    }],
    globalPackages: {
      dir: '/usr/lib/node_modules',
      node: {version: 'v22.0.0', platform: 'linux', arch: 'x64'},
      packages: [],
      links: [],
      caches: [],
      errors: [],
    },
    monitor: {
      since: TIME,
      until: null,
      execs: [{
        path: '/usr/bin/node', count: 3, uids: [0, 1000], firstSeen: TIME, lastSeen: TIME, sha256: sha('node'), package: owner,
      }],
      maps: [],
      truncated: false,
      malformed: 0,
    },
    tpm: {
      enabled: true,
      available: true,
      required: false,
      quote: {
        message: 'AA==', signature: 'AA==', pcrs: {sha256: {}}, keyId: 'ak', handle: '0x81010002', hashAlg: 'sha256',
      },
    },
    confidential: {
      enabled: true, available: true, required: false, provider: 'sev-snp', report: 'AAAA', auxblob: null,
    },
    ima: {log: 'AAAA'},
  };
  value.evidenceDigest = evidence.evidenceDigest(value);
  return value;
}

test('constants', () => {
  assert.strictEqual(evidence.TYPE, 'attestium-evidence');
  assert.strictEqual(evidence.VERSION, 2);
  assert.strictEqual(evidence.MANIFEST_TYPE, 'attestium-manifest');
  assert.strictEqual(evidence.MANIFEST_NAME, '.attestium-manifest.json');
});

test('validateEvidence accepts evidence using every part of the format', () => {
  const result = evidence.validateEvidence(fullEvidence());
  assert.deepStrictEqual(result, {valid: true, errors: []});

  // The smallest evidence, and optional parts in their other forms.
  const minimal = {
    type: 'attestium-evidence',
    version: 2,
    nonce: '00'.repeat(32),
    collectedAt: '2026-09-30T12:00:00Z',
    attester: {name: 'attestium', version: '0.1.0'},
    host: {hostname: 'h', kernel: 'k', os: null},
    distro: null,
    services: [],
    executables: [],
    libraries: [],
    monitor: {error: 'no permission'},
    tpm: {enabled: false, reason: 'disabled'},
    confidential: {enabled: true, error: 'no device'},
    ima: {error: 'not mounted'},
    evidenceDigest: sha('x'),
  };
  assert.deepStrictEqual(evidence.validateEvidence(minimal).errors, []);
});

test('validateEvidence reports what is wrong', () => {
  const cases = [
    [value => delete value.nonce, ['$.nonce is required']],
    [value => value.nonce = 'abc', ['$.nonce does not match ^(?:[0-9a-f]{2}){16,64}$']],
    [value => value.version = 1, ['$.version must be 2']],
    [value => value.extra = true, ['$.extra is not allowed']],
    [value => value.collectedAt = 'yesterday', [String.raw`$.collectedAt does not match ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$`]],
    [value => value.attester.name = 'a b', [String.raw`$.attester.name does not match ^[\w.-]{1,64}$`]],
    [value => value.host.os = 'debian', ['$.host.os does not match any allowed form']],
    [value => value.services[0].git.commit = 'main', ['$.services[0].git.commit does not match any allowed form']],
    [value => value.services[0].files['server.js'] = [sha('server')], ['$.services[0].files.server.js has fewer than 2 items']],
    [value => value.services[1].containers[0].id = 'short', ['$.services[1].containers[0].id does not match ^[0-9a-f]{12,64}$']],
    [value => value.services[1].kind = 'vm', ['$.services[1].kind must be "container"']],
    [value => value.executables[0].size = -1, ['$.executables[0].size is below 0']],
    [value => value.monitor.malformed = 1.5, ['$.monitor does not match any allowed form']],
    [value => value.confidential.provider = 'sev snp', [String.raw`$.confidential.provider does not match ^[\w-]{1,32}$`]],
    [value => value.ima.log = 'not base64!', ['$.ima.log does not match ^[A-Za-z0-9+/]*(?:[AQgw]==|[AEIMQUYcgkosw048]=)?$', '$.ima.log is not padded base64']],
    [value => value.evidenceDigest = sha('x').toUpperCase(), ['$.evidenceDigest does not match ^[0-9a-f]{64}$']],
    // What a verifier judges processes and packages by.
    [value => value.services[0].installs[0].packages[0].digest = 'x', ['$.services[0].installs[0].packages[0].digest does not match ^[0-9a-f]{64}$']],
    [value => value.tpm.quote.hashAlg = 'sha1', ['$.tpm.quote.hashAlg must be one of "sha256", "sha384", "sha512"']],
  ];
  for (const [change, errors] of cases) {
    const value = fullEvidence();
    change(value);
    assert.deepStrictEqual(evidence.validateEvidence(value).errors, errors);
  }

  assert.deepStrictEqual(evidence.validateEvidence(null).errors, ['$ must be object']);
  assert.strictEqual(evidence.validateEvidence({}).errors.length, 10);
});

test('validateEvidence accepts only canonical base64 in every base64 field', () => {
  const pattern = '^[A-Za-z0-9+/]*(?:[AQgw]==|[AEIMQUYcgkosw048]=)?$';
  const fields = [
    ['tpm.quote.message', value => value.tpm.quote],
    ['tpm.quote.signature', value => value.tpm.quote],
    ['confidential.report', value => value.confidential],
    ['confidential.auxblob', value => value.confidential],
    ['ima.log', value => value.ima],
    ['services[0].manifest', value => value.services[0]],
  ];
  // Each encodes bytes Buffer.from() would decode, but not as the one
  // canonical text: a verifier and a digest could disagree on what was signed.
  const nonCanonical = [
    ['QR==', 'does not match'], // Unused bits set: decodes as "A".
    ['QUF=', 'does not match'],
    ['QQ', 'is not padded base64'], // Missing padding.
    ['QUJD\nREVG', 'does not match'], // A line break.
    ['QQ==QQ==', 'does not match'], // Padding inside.
    ['Q===', 'does not match'],
    ['QUJD-_==', 'does not match'], // The URL-safe alphabet.
  ];
  for (const [name, holder] of fields) {
    const key = name.split('.').pop();
    for (const valid of ['', 'AA==', 'QUI=', 'QUJD', Buffer.from('any bytes \u0000ÿ').toString('base64')]) {
      const value = fullEvidence();
      holder(value)[key] = valid;
      assert.deepStrictEqual(evidence.validateEvidence(value).errors, [], `${name}: ${valid}`);
    }

    for (const [invalid, problem] of nonCanonical) {
      const value = fullEvidence();
      holder(value)[key] = invalid;
      const {errors} = evidence.validateEvidence(value);
      const at = name === 'confidential.auxblob' ? '$.confidential.auxblob does not match any allowed form' : `$.${name} ${problem === 'does not match' ? `does not match ${pattern}` : problem}`;
      assert.ok(errors.includes(at), `${name}: ${JSON.stringify(invalid)}: ${errors.join('; ')}`);
    }
  }
});

test('base64 fields are checked in linear time, however large', () => {
  // A pattern that backtracks on every group of 4 characters exhausts the
  // regular expression engine's stack on a few megabytes; this one does not.
  const script = `
    const evidence = require(${JSON.stringify(require.resolve('../lib/evidence'))});
    const value = JSON.parse(process.argv[1]);
    const check = log => {
      value.ima.log = log;
      const started = Date.now();
      const {errors} = evidence.validateEvidence(value);
      return {errors, ms: Date.now() - started};
    };
    const good = 'QUJD'.repeat(16 * 1024 * 1024);
    const results = [check(good), check(good + 'QQ=='), check(good + '!'), check(good + 'QR=='), check(good.slice(1)), check('A'.repeat(64 * 1024 * 1024 - 2) + 'B=')];
    process.stdout.write(JSON.stringify(results.map(result => [result.errors.length, result.ms])));
  `;
  const value = fullEvidence();
  const {status, stdout, stderr} = require('node:child_process').spawnSync(process.execPath, ['-e', script, JSON.stringify(value)], {encoding: 'utf8'});
  assert.equal(status, 0, stderr.slice(-500));
  const results = JSON.parse(stdout);
  assert.deepStrictEqual(results.map(([errors]) => errors), [0, 0, 2, 1, 1, 1], stdout);
  for (const [, ms] of results) {
    assert.ok(ms < 5000, `64 MiB checked in ${ms} ms`);
  }
});

test('evidenceDigest covers everything but what is added after it', () => {
  const value = fullEvidence();
  const {
    evidenceDigest: _digest, tpm, ima, confidential, ...rest
  } = value;
  assert.strictEqual(evidence.evidenceDigest(value), digestOf(rest));
  assert.strictEqual(value.evidenceDigest, digestOf(rest));
  assert.strictEqual(evidence.evidenceDigest({
    ...value, tpm: {enabled: false}, ima: undefined, confidential: null,
  }), value.evidenceDigest);
  assert.notStrictEqual(evidence.evidenceDigest({...value, nonce: 'cd'.repeat(16)}), value.evidenceDigest);
});

test('the digest\'s canonical JSON: SPEC.md edge cases', () => {
  const {canonicalize} = require('../lib/util');
  // Numbers and strings as JSON.stringify writes them: -0 is 0, lone
  // surrogates are escaped, keys sort by UTF-16 code units.
  assert.strictEqual(canonicalize([-0, 1e21, 0.1, '\uD800', 'é']), String.raw`[0,1e+21,0.1,"\ud800","é"]`);
  assert.strictEqual(canonicalize(JSON.parse('{"b":1,"a":2,"b":3,"__proto__":4}')), '{"__proto__":4,"a":2,"b":3}');
  // A hole is an undefined item, not an empty one ("[,1]" is not JSON).
  // eslint-disable-next-line no-sparse-arrays
  assert.throws(() => canonicalize([, 1]), /undefined inside an array/);
  assert.throws(() => evidence.evidenceDigest({type: 'attestium-evidence', executables: Array.from({length: 2})}), /undefined inside an array/);
  const holes = [];
  holes[2] = 'x';
  assert.throws(() => digestOf({holes}), /undefined inside an array/);
});

test('createManifest lists files, modes and symbolic links', {skip: needsPosix}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {
    'server.js': 'console.log(1)\n',
    'lib/util.js': 'module.exports = {}\n',
    'logs/today.log': 'noise',
    '.git/HEAD': 'ref: refs/heads/main\n',
    '.attestium-manifest.json': '{}',
    'bin/start': '#!/bin/sh\n',
  });
  fs.chmodSync(path.join(directory, 'bin/start'), 0o755);
  fs.symlinkSync('../server.js', path.join(directory, 'bin/server'));
  const manifest = await evidence.createManifest(directory, {repository: 'octo/app', commit: COMMIT, exclude: ['logs/**']});
  assert.deepStrictEqual(manifest, {
    type: 'attestium-manifest',
    version: 1,
    repository: 'octo/app',
    commit: COMMIT,
    files: {
      'bin/server': ['symlink:../server.js', '120000'],
      'bin/start': [sha('#!/bin/sh\n'), '100755'],
      'lib/util.js': [sha('module.exports = {}\n'), '100644'],
      'server.js': [sha('console.log(1)\n'), '100644'],
    },
  });
  assert.deepStrictEqual(evidence.parseManifest(JSON.stringify(manifest)), manifest);
  const all = await evidence.createManifest(directory, {repository: 'octo/app', commit: COMMIT});
  assert.ok(all.files['logs/today.log']);
});

test('createManifest requires a repository and full commit', async () => {
  for (const input of [{commit: COMMIT}, {repository: 'octo', commit: COMMIT}, {repository: 'octo/app'}, {repository: 'octo/app', commit: 'abc123'}]) {
    await assert.rejects(evidence.createManifest('.', input), /needs repository \(owner\/name\) and a full commit id/);
  }
});

test('createManifest fails when files cannot be read', {skip: !PATH_MAX && 'paths have no length limit here'}, async t => {
  // A directory nested deeper than the system's path limit cannot be
  // listed, even by root.
  const directory = tempDir(t);
  writeFiles(directory, {'ok.txt': 'ok'});
  const cwd = process.cwd();
  const name = 'd'.repeat(200);
  let depth = 0;
  try {
    process.chdir(directory);
    for (; depth < 24; depth++) {
      fs.mkdirSync(name);
      process.chdir(name);
    }
  } finally {
    process.chdir(cwd);
  }

  try {
    await assert.rejects(evidence.createManifest(directory, {repository: 'octo/app', commit: COMMIT}), /Could not read 1 file\(s\): d+(\/d+)* \(ENAMETOOLONG\)/);
  } finally {
    // Remove the chain from the inside out with relative paths.
    try {
      process.chdir(directory);
      for (let level = 0; level < depth - 1; level++) {
        process.chdir(name);
      }

      for (let level = 0; level < depth; level++) {
        fs.rmdirSync(name);
        process.chdir('..');
      }
    } finally {
      process.chdir(cwd);
    }
  }
});

test('parseManifest rejects what is not a manifest', () => {
  const good = {
    type: 'attestium-manifest', version: 1, repository: 'octo/app', commit: COMMIT, files: {'a.txt': [sha('a'), '100644']},
  };
  assert.deepStrictEqual(evidence.parseManifest(Buffer.from(JSON.stringify(good))), good);
  const bad = [
    null,
    [],
    {...good, type: 'attestium-evidence'},
    {...good, version: 2},
    {...good, repository: undefined},
    {...good, repository: 'octo'},
    {...good, commit: undefined},
    {...good, commit: 'C'.repeat(40)},
    {...good, files: null},
    {...good, files: []},
    {...good, files: 'a.txt'},
    {...good, files: {'a.txt': sha('a')}},
    {...good, files: {'a.txt': [sha('a')]}},
    {...good, files: {'a.txt': [sha('a'), 100_644]}},
  ];
  for (const value of bad) {
    assert.throws(() => evidence.parseManifest(JSON.stringify(value)), /Not an Attestium manifest/, JSON.stringify(value));
  }

  assert.throws(() => evidence.parseManifest('{'), SyntaxError);
});

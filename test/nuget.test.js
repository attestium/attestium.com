'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {promisify} = require('node:util');
const {execFile, execFileSync} = require('node:child_process');
const nuget = require('../lib/ecosystems/nuget');
const {NoLockfileError, ReferenceStore} = require('../lib/ecosystems/common');
const {tempDir, writeFiles, startServer, which} = require('./helpers');

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const sha512 = data => crypto.createHash('sha512').update(data).digest('base64');

const CRC_TABLE = Array.from({length: 256}, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xED_B8_83_20 ^ (c >>> 1) : c >>> 1;
  }

  return c >>> 0;
});

function crc32(data) {
  let crc = 0xFF_FF_FF_FF;
  for (const byte of data) {
    crc = CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
  }

  return (crc ^ 0xFF_FF_FF_FF) >>> 0;
}

/**
 * A stored (uncompressed) zip.  An entry's `descriptor` ('signed' or
 * 'unsigned') writes its sizes and CRC in a data descriptor after the data,
 * with or without the descriptor's optional signature.
 * @param {Array<{name: string, data: string|Buffer, descriptor?: string}>} entries
 * @param {string} [comment]
 * @returns {Buffer}
 */
function makeZip(entries, comment = '') {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const {name, data: raw, descriptor} of entries) {
    const data = Buffer.from(raw);
    const nameBytes = Buffer.from(name);
    const crc = crc32(data);
    const flags = descriptor ? 0x08 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04_03_4B_50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(descriptor ? 0 : crc, 14);
    local.writeUInt32LE(descriptor ? 0 : data.length, 18);
    local.writeUInt32LE(descriptor ? 0 : data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const parts = [local, nameBytes, data];
    if (descriptor) {
      const trailer = Buffer.alloc(12);
      trailer.writeUInt32LE(crc, 0);
      trailer.writeUInt32LE(data.length, 4);
      trailer.writeUInt32LE(data.length, 8);
      if (descriptor === 'signed') {
        parts.push(Buffer.from([0x50, 0x4B, 0x07, 0x08]));
      }

      parts.push(trailer);
    }

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02_01_4B_50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);
    const entry = Buffer.concat(parts);
    locals.push(entry);
    offset += entry.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06_05_4B_50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(Buffer.byteLength(comment), 20);
  return Buffer.concat([...locals, directory, end, Buffer.from(comment)]);
}

function nupkg(id, files) {
  return makeZip([
    {name: '_rels/.rels', data: '<Relationships/>'},
    {name: `${id}.nuspec`, data: `<package><metadata><id>${id}</id></metadata></package>`},
    ...Object.entries(files).map(([name, data]) => ({name, data})),
    {name: '[Content_Types].xml', data: '<Types/>'},
  ]);
}

function project(properties, items = '') {
  return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>${properties}</PropertyGroup><ItemGroup>${items}</ItemGroup></Project>\n`;
}

const SIGNATURE = {name: '.signature.p7s', data: Buffer.alloc(300, 7)};

test('detect finds published application directories', t => {
  const root = tempDir(t);
  const app = {'App.runtimeconfig.json': '{}', 'App.deps.json': '{}'};
  const at = directory => Object.fromEntries(Object.entries(app).map(([file, content]) => [`${directory}/${file}`, content]));
  writeFiles(root, {
    ...app,
    ...at('src/App/bin/Release/net8.0'),
    ...at('src/App/bin/Release/net8.0/publish'),
    ...at('src/Api/bin/Release/net8.0/linux-x64/publish'),
    ...at('out'),
    ...at('node_modules/tool/publish'),
    ...at('src/App/obj/publish'),
    ...at('.git/publish'),
    'half/publish/App.runtimeconfig.json': '{}',
    ...at('a/b/c/d/e/f/g/publish'),
    ...at('a/b/c/d/e/f/g/h/publish'),
  });
  // A root that is itself an application is not searched further.
  assert.deepEqual(nuget.detect(root), []);
  fs.rmSync(path.join(root, 'App.deps.json'));
  assert.deepEqual(nuget.detect(root).sort(), [
    path.join(root, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'publish'),
    path.join(root, 'out'),
    path.join(root, 'src', 'Api', 'bin', 'Release', 'net8.0', 'linux-x64', 'publish'),
    path.join(root, 'src', 'App', 'bin', 'Release', 'net8.0', 'publish'),
  ].sort());
  assert.deepEqual(nuget.detect(path.join(root, 'missing')), []);
  assert.equal(nuget.installRoot('/srv/publish'), '/srv/publish');
  assert.deepEqual(nuget.lockfiles, ['packages.lock.json']);
});

test('scan lists assemblies and native libraries as packages', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {
    'App.dll': 'app',
    App: 'apphost',
    'App.deps.json': '{}',
    'App.pdb': 'pdb',
    'Acme.Lib.dll': 'lib',
    'tool.exe': 'exe',
    'runtimes/linux-x64/native/libacme.so': 'so',
    'runtimes/linux-x64/native/libz.so.1': 'z',
    'runtimes/osx/native/libacme.dylib': 'dylib',
    'static.a': 'a',
  });
  fs.symlinkSync('libz.so.1', path.join(directory, 'runtimes', 'linux-x64', 'native', 'libz.so'));
  const result = await nuget.scan(directory);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.packages.map(item => item.path).sort(), [
    'Acme.Lib.dll',
    'App.dll',
    'runtimes/linux-x64/native/libacme.so',
    'runtimes/linux-x64/native/libz.so',
    'runtimes/linux-x64/native/libz.so.1',
    'runtimes/osx/native/libacme.dylib',
    'static.a',
    'tool.exe',
  ]);
  const libacme = result.packages.find(item => item.path.endsWith('libacme.so'));
  assert.deepEqual(libacme, {
    name: 'libacme.so', version: null, path: 'runtimes/linux-x64/native/libacme.so', files: {'runtimes/linux-x64/native/libacme.so': sha256('so')},
  });
  assert.equal(result.packages.find(item => item.path.endsWith('libz.so')).files['runtimes/linux-x64/native/libz.so'], 'symlink:libz.so.1');
  assert.deepEqual(Object.keys(result.meta.other).sort(), ['App', 'App.deps.json', 'App.pdb']);
});

test('readLock merges every project lock file', t => {
  const repo = tempDir(t);
  assert.throws(() => nuget.readLock(repo), NoLockfileError);
  assert.throws(() => nuget.readLock(path.join(repo, 'missing')), /RestorePackagesWithLockFile/);
  const hash = sha512('x');
  writeFiles(repo, {
    'src/App/packages.lock.json': JSON.stringify({
      version: 1,
      dependencies: {
        'net8.0': {
          'Acme.Lib': {
            type: 'Direct', requested: '[1.0.0, )', resolved: '1.0.0', contentHash: hash,
          },
          'Acme.Shared': {type: 'Project', resolved: '1.0.0', contentHash: hash},
          'Acme.NoHash': {type: 'Transitive', resolved: '1.0.0'},
          'Acme.Null': null,
        },
        'net8.0/linux-x64': null,
      },
    }),
    'tests/App.Tests/packages.lock.json': JSON.stringify({
      version: 1,
      dependencies: {'net8.0': {'XUnit.Core': {type: 'Direct', resolved: '2.9.0-Beta', contentHash: hash}}},
    }),
    'src/App/bin/packages.lock.json': '{',
    'src/App/obj/packages.lock.json': '{',
    'a/b/c/d/packages.lock.json': JSON.stringify({}),
    'a/b/c/d/e/packages.lock.json': '{',
  });
  const lock = nuget.readLock(repo);
  assert.equal(lock.format, 'nuget');
  assert.deepEqual(lock.file.split(', ').sort(), ['a/b/c/d/packages.lock.json', 'src/App/packages.lock.json', 'tests/App.Tests/packages.lock.json']);
  assert.deepEqual([...lock.packages.keys()].sort(), ['acme.lib/1.0.0', 'xunit.core/2.9.0-beta']);
  assert.deepEqual(lock.packages.get('xunit.core/2.9.0-beta'), {id: 'XUnit.Core', version: '2.9.0-Beta', contentHash: hash});

  const one = nuget.readLock(repo, {lockfile: 'tests/App.Tests/packages.lock.json'});
  assert.deepEqual([...one.packages.keys()], ['xunit.core/2.9.0-beta']);
  assert.throws(() => nuget.readLock(repo, {lockfile: 'nope/packages.lock.json'}), NoLockfileError);
});

test('contentHash of an unsigned package is the SHA-512 of the file', () => {
  const buffer = nupkg('Acme.Lib', {'lib/net8.0/Acme.Lib.dll': 'assembly'});
  assert.equal(nuget.contentHash(buffer), sha512(buffer));
});

test('contentHash of a signed package leaves the signature out', () => {
  const files = [
    {name: 'Acme.Lib.nuspec', data: '<package/>'},
    {name: 'lib/net8.0/Acme.Lib.dll', data: 'assembly', descriptor: 'signed'},
    {name: 'lib/net6.0/Acme.Lib.dll', data: 'older assembly', descriptor: 'unsigned'},
    {name: '[Content_Types].xml', data: '<Types/>'},
  ];
  // NuGet appends the signature as the last entry; the hash is the one the
  // package had before it was signed.
  const unsigned = makeZip(files, 'comment');
  const signed = makeZip([...files, SIGNATURE], 'comment');
  assert.notEqual(sha512(signed), sha512(unsigned));
  assert.equal(nuget.contentHash(signed), sha512(unsigned));
  // Entries after the signature have their offsets adjusted.
  const middle = makeZip([files[0], files[1], {...SIGNATURE, descriptor: 'signed'}, files[2], files[3]]);
  assert.equal(nuget.contentHash(middle), sha512(makeZip(files)));
});

test('packageFiles indexes the code under lib/ and runtimes/ by file name', () => {
  const buffer = nupkg('Acme.Lib', {
    'lib/net8.0/Acme.Lib.dll': 'net8',
    'lib/net8.0/Acme.Lib.xml': '<doc/>',
    'Lib/net6.0/Acme.Lib.dll': 'net6',
    'runtimes/linux-x64/native/libacme.so': 'so',
    'lib/net8.0/constructor': 'not code',
    'lib/net8.0/__proto__': 'not code',
    'content/Acme.Lib.dll': 'not a runtime file',
  });
  assert.deepEqual(nuget.packageFiles(buffer), {
    'Acme.Lib.dll': [sha256('net8'), sha256('net6')],
    'libacme.so': [sha256('so')],
  });
});

test('compare checks each published library against the locked packages', async t => {
  const lib = nupkg('Acme.Lib', {'lib/net8.0/Acme.Lib.dll': 'acme lib'});
  const signed = makeZip([
    {name: 'Acme.Native.nuspec', data: '<package/>'},
    {name: 'runtimes/linux-x64/native/libacme.so', data: 'native'},
    SIGNATURE,
  ]);
  const tampered = nupkg('Acme.Tampered', {'lib/net8.0/Acme.Tampered.dll': 'x'});
  const server = await startServer(t, {
    '/acme.lib/1.0.0/acme.lib.1.0.0.nupkg': {body: lib},
    '/acme.native/2.0.0-rc.1/acme.native.2.0.0-rc.1.nupkg': {body: signed},
    '/acme.tampered/1.0.0/acme.tampered.1.0.0.nupkg': {body: tampered},
  });
  const lock = {
    packages: new Map([
      ['acme.lib/1.0.0', {id: 'Acme.Lib', version: '1.0.0', contentHash: nuget.contentHash(lib)}],
      ['acme.native/2.0.0-rc.1', {id: 'Acme.Native', version: '2.0.0-RC.1', contentHash: nuget.contentHash(signed)}],
      ['acme.tampered/1.0.0', {id: 'Acme.Tampered', version: '1.0.0', contentHash: sha512('other')}],
      ['acme.gone/1.0.0', {id: 'Acme.Gone', version: '1.0.0', contentHash: sha512('gone')}],
    ]),
  };
  const directory = tempDir(t);
  writeFiles(directory, {
    'Acme.Lib.dll': 'acme lib',
    'runtimes/linux-x64/native/libacme.so': 'native',
    'runtimes/win-x64/lib/net8.0/Acme.Lib.dll': 'patched',
    'App.dll': 'app',
    'Plugin.dll': 'plugin',
    'App.deps.json': '{}',
    'App.runtimeconfig.json': '{}',
    'App.pdb': 'pdb',
    'App.xml': '<doc/>',
  });
  const store = new ReferenceStore({urls: {nuget: server.url}, httpOptions: {maxRetries: 0}});
  const covered = file => file === 'App.dll' || file === 'App.runtimeconfig.json';
  const result = await nuget.compare({
    scan: await nuget.scan(directory), lock, store, covered,
  });

  assert.deepEqual(result.summary, {
    total: 4, verified: 2, bundled: 0, patched: 0, built: 0, failed: 2, unverifiable: 0, error: 0,
  });
  assert.deepEqual(result.findings, [
    {
      status: 'failed', package: 'Plugin.dll@null', path: 'Plugin.dll', reason: 'no locked package ships this file, and no build reproduces it',
    },
    {
      status: 'failed', package: 'Acme.Lib.dll@null', path: 'runtimes/win-x64/lib/net8.0/Acme.Lib.dll', reason: 'differs from the file of the same name in the locked packages',
    },
  ]);
  assert.equal(result.issues[0].severity, 'fail');
  assert.equal(result.issues[0].items.length, 2);
  assert.equal(result.issues[0].items[0], 'Acme.Tampered@1.0.0: Downloaded Acme.Tampered 1.0.0 does not match its content hash');
  assert.match(result.issues[0].items[1], /^Acme\.Gone@1\.0\.0: .*404/);
  assert.deepEqual(result.issues[1], {severity: 'warn', message: result.issues[1].message, items: ['App.deps.json']});
  assert.equal(result.passed, false);

  // A download that failed, with nothing that differs, is an error.
  const gone = await nuget.compare({
    scan: {packages: [], meta: {}}, lock: {packages: new Map([['acme.gone/1.0.0', lock.packages.get('acme.gone/1.0.0')]])}, store,
  });
  assert.equal(gone.issues[0].severity, 'error');
  assert.deepEqual(gone.issues.length, 1);
});

test('compare without packages.lock.json fails every library', async () => {
  const scan = {
    packages: [
      {
        name: 'App.dll', version: null, path: 'App.dll', files: {'App.dll': 'x'},
      },
      {
        name: 'Acme.dll', version: null, path: 'Acme.dll', files: {'Acme.dll': 'y'},
      },
    ],
    meta: {other: {}},
  };
  const result = await nuget.compare({scan, lock: null, store: new ReferenceStore()});
  assert.deepEqual(result.findings.map(finding => finding.path), ['Acme.dll', 'App.dll']);
  assert.equal(result.findings[0].reason, 'no packages.lock.json pins the application\'s packages');
  const covered = await nuget.compare({
    scan, lock: null, store: new ReferenceStore(), covered: file => file === 'App.dll',
  });
  assert.deepEqual(covered.findings.map(finding => finding.path), ['Acme.dll']);
});

test('a published .NET application with a signed package verifies', {skip: !(which('dotnet') && which('openssl')) && 'dotnet or openssl is not installed', timeout: 300_000}, async t => {
  const work = tempDir(t);
  const feed = path.join(work, 'feed');
  const environment = {
    ...process.env,
    DOTNET_CLI_TELEMETRY_OPTOUT: '1',
    DOTNET_NOLOGO: '1',
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1',
    DOTNET_CLI_HOME: work,
    NUGET_PACKAGES: path.join(work, 'packages'),
    // The test certificate is self-signed.
    DOTNET_NUGET_SIGNATURE_VERIFICATION: 'false',
  };
  writeFiles(work, {
    'nuget.config': `<?xml version="1.0" encoding="utf-8"?>\n<configuration><packageSources><clear /><add key="local" value="${feed}" /></packageSources></configuration>\n`,
    'lib/Acme.Lib.csproj': project('<TargetFramework>net8.0</TargetFramework><PackageId>Acme.Lib</PackageId><Version>1.0.0</Version>'),
    'lib/Greeter.cs': 'namespace Acme; public static class Greeter { public static string Hello() => "hi"; }\n',
    'app/App.csproj': project(
      '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>',
      '<PackageReference Include="Acme.Lib" Version="1.0.0" />',
    ),
    'app/Program.cs': 'System.Console.WriteLine(Acme.Greeter.Hello());\n',
  });
  const run = (command, args) => promisify(execFile)(command, args, {cwd: work, env: environment, maxBuffer: 64 * 1024 * 1024});
  try {
    await run('dotnet', ['pack', 'lib', '-o', feed, '--configfile', 'nuget.config']);
  } catch (error) {
    t.skip(`dotnet cannot build here: ${String(error.stdout || error.message).trim().split('\n').pop()}`);
    return;
  }

  const certificate = ['-days', '2', '-nodes', '-subj', '/CN=Attestium Test', '-addext', 'extendedKeyUsage=codeSigning'];
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', 'key.pem', '-out', 'cert.pem', ...certificate], {cwd: work, stdio: 'ignore'});
  execFileSync('openssl', ['pkcs12', '-export', '-out', 'cert.pfx', '-inkey', 'key.pem', '-in', 'cert.pem', '-passout', 'pass:test'], {cwd: work, stdio: 'ignore'});
  const packageFile = path.join(feed, 'Acme.Lib.1.0.0.nupkg');
  const unsigned = fs.readFileSync(packageFile);
  await run('dotnet', ['nuget', 'sign', packageFile, '--certificate-path', 'cert.pfx', '--certificate-password', 'test']);
  const signed = fs.readFileSync(packageFile);
  assert.ok(nuget.contentHash(signed) !== sha512(signed), 'the package is signed');
  await run('dotnet', ['publish', 'app', '-c', 'Release', '-o', path.join(work, 'app', 'publish'), '--configfile', 'nuget.config']);

  const lock = nuget.readLock(path.join(work, 'app'));
  // NuGet's own content hash of the signed package is that of the unsigned one.
  assert.equal(lock.packages.get('acme.lib/1.0.0').contentHash, nuget.contentHash(signed));
  assert.equal(nuget.contentHash(signed), sha512(unsigned));

  const publish = path.join(work, 'app', 'publish');
  assert.deepEqual(nuget.detect(path.join(work, 'app')), [publish]);
  const server = await startServer(t, {'/acme.lib/1.0.0/acme.lib.1.0.0.nupkg': {body: signed}});
  const store = new ReferenceStore({urls: {nuget: server.url}});
  // The application's own files are build output, verified by reproducing the build.
  const covered = file => /^App(?:\.dll|\.deps\.json|\.runtimeconfig\.json)?$/.test(file);
  const result = await nuget.compare({
    scan: await nuget.scan(publish), lock, store, covered,
  });
  assert.equal(result.passed, true, JSON.stringify(result));
  assert.deepEqual(result.summary.verified, 1);
  assert.deepEqual(result.issues, []);
});

test('code whose extension is upper case is checked like any other', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'App.deps.json': '{}', 'Evil.DLL': 'injected', 'libevil.SO': 'injected'});
  const scan = await nuget.scan(directory);
  assert.deepEqual(scan.packages.map(item => item.path).sort(), ['Evil.DLL', 'libevil.SO']);
  const result = await nuget.compare({
    scan, lock: {packages: new Map()}, store: new ReferenceStore(), covered: file => file === 'App.deps.json',
  });
  assert.equal(result.passed, false);
  assert.equal(result.summary.failed, 2);
});

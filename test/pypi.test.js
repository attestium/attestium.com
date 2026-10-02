'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const pypi = require('../lib/ecosystems/pypi');
const {ReferenceStore, NoLockfileError} = require('../lib/ecosystems/common');
const {crc32} = require('../lib/zip');
const {tempDir, writeFiles, startServer, which} = require('./helpers');

const hex = content => crypto.createHash('sha256').update(content).digest('hex');
const recordHash = content => crypto.createHash('sha256').update(content).digest('base64url');

// ─── fixtures ──────────────────────────────────────────────────────────

/**
 * A zip archive with stored (uncompressed) members.
 */
function makeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const nameBuffer = Buffer.from(name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04_03_4B_50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02_01_4B_50, 0);
    central.writeUInt16LE(0x03_14, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE(((name.includes('scripts/') ? 0o10_0755 : 0o10_0644) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuffer, data);
    centrals.push(central, nameBuffer);
    offset += 30 + nameBuffer.length + data.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06_05_4B_50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/**
 * A wheel with a valid RECORD.  `tag` is the file name's (possibly
 * compressed) tag; `tags` the WHEEL file's expanded ones.
 */
function makeWheel({name, version, tag = 'py3-none-any', tags, files = {}, entryPoints}) {
  const distInfo = `${name}-${version}.dist-info`;
  const all = {
    ...files,
    [`${distInfo}/METADATA`]: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`,
    [`${distInfo}/WHEEL`]: `Wheel-Version: 1.0\nGenerator: attestium-test\nRoot-Is-Purelib: true\n${(tags || [tag]).map(item => `Tag: ${item}\n`).join('')}`,
  };
  if (entryPoints) {
    all[`${distInfo}/entry_points.txt`] = entryPoints;
  }

  all[`${distInfo}/RECORD`] = Object.entries(all).map(([file, content]) => `${file},sha256=${recordHash(content)},${Buffer.byteLength(content)}\n`).join('') + `${distInfo}/RECORD,,\n`;
  const buffer = makeZip(all);
  return {
    name, version, filename: `${name}-${version}-${tag}.whl`, buffer, sha256: hex(buffer),
  };
}

/**
 * A local server imitating PyPI's JSON API and file host.
 */
async function startRegistry(t) {
  const server = await startServer(t);
  const registry = {
    server,
    store: options => new ReferenceStore({urls: {pypi: server.url, uvSource: `${server.url}/uv`}, httpOptions: {maxRetries: 0}, ...options}),
    url: filename => `${server.url}/files/${filename}`,
    add(...distributions) {
      for (const distribution of distributions) {
        const route = `/pypi/${distribution.name}/${distribution.version}/json`;
        const json = server.routes[route] ? JSON.parse(server.routes[route].body) : {urls: []};
        json.urls.push({
          filename: distribution.filename, url: registry.url(distribution.filename), digests: {sha256: distribution.sha256}, packagetype: distribution.sdist ? 'sdist' : 'bdist_wheel',
        });
        server.routes[route] = {body: JSON.stringify(json), headers: {'content-type': 'application/json'}};
        server.routes[`/files/${distribution.filename}`] = {body: distribution.buffer};
      }
    },
  };
  return registry;
}

const demoWheel = (version = '1.0') => makeWheel({
  name: 'demo',
  version,
  files: {
    'demo/__init__.py': 'VALUE = 1\n',
    'demo/cli.py': 'def main():\n    print("demo")\n',
    [`demo-${version}.data/scripts/demo-tool`]: '#!python\nprint("tool")\n',
    [`demo-${version}.data/purelib/demo_extra.py`]: 'EXTRA = True\n',
    [`demo-${version}.data/data/share/demo/notes.txt`]: 'notes\n',
    [`demo-${version}.data/headers/demo.h`]: '#define DEMO 1\n',
  },
  entryPoints: '[console_scripts]\ndemo = demo.cli:main\n\n[gui_scripts]\ndemo-gui = demo.cli:main [gui]\n',
});

const statusOf = (result, name) => result.findings.find(finding => finding.package.startsWith(`${name}@`));
const issue = (result, pattern) => result.issues.find(item => pattern.test(item.message));

// Python's own generated entry-point scripts, per installer.
const PIP_SCRIPT = '#!/venv/bin/python\n# -*- coding: utf-8 -*-\nimport re\nimport sys\nfrom demo.cli import main\nif __name__ == \'__main__\':\n    sys.argv[0] = re.sub(r\'(-script\\.pyw|\\.exe)?$\', \'\', sys.argv[0])\n    sys.exit(main())\n';
const UV_SCRIPT = '#!/venv/bin/python3\n# -*- coding: utf-8 -*-\nimport sys\nfrom demo.cli import main\nif __name__ == "__main__":\n    if sys.argv[0].endswith("-script.pyw"):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith(".exe"):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n';
const INSTALLER_SCRIPT = '#!python\n# -*- coding: utf-8 -*-\nimport re\nimport sys\nfrom demo.cli import main\nif __name__ == "__main__":\n    sys.argv[0] = re.sub(r"(-script\\.pyw|\\.exe)?$", "", sys.argv[0])\n    sys.exit(main())\n';

// ─── names, tags, entry points ─────────────────────────────────────────

test('names and versions are normalized for comparison', () => {
  assert.equal(pypi.normalizeName('Zope.Interface__x'), 'zope-interface-x');
  assert.equal(pypi.normalizeVersion(' V01.002.0rc1 '), '1.2.0rc1');
  assert.equal(pypi.normalizeVersion('2024.01.05'), '2024.1.5');
});

test('wheelTags expands compressed tag sets and rejects other names', () => {
  assert.deepEqual(pypi.wheelTags('demo-1.0-py2.py3-none-any.whl'), ['py2-none-any', 'py3-none-any']);
  assert.deepEqual(pypi.wheelTags('demo-1.0-1build-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'), ['cp311-cp311-manylinux2014_x86_64', 'cp311-cp311-manylinux_2_17_x86_64']);
  assert.equal(pypi.wheelTags('demo-1.0.tar.gz'), null);
  assert.equal(pypi.wheelTags(undefined), null);
});

test('scriptEntryPoints reads console and GUI scripts only', () => {
  const points = pypi.scriptEntryPoints('[console_scripts]\ndemo = demo.cli:main\n[ gui_scripts ]\ngui = demo.gui:run [extra]\n[other]\nplugin = demo.plugin:x\nno equals sign\n');
  assert.deepEqual([...points], [['demo', 'demo.cli:main'], ['gui', 'demo.gui:run']]);
  assert.equal(pypi.scriptEntryPoints(null).size, 0);
});

test('isGeneratedScript accepts the scripts pip, uv and installer write, and nothing else', () => {
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT, 'demo.cli:main'), true);
  assert.equal(pypi.isGeneratedScript(UV_SCRIPT, 'demo.cli:main'), true);
  assert.equal(pypi.isGeneratedScript(INSTALLER_SCRIPT, 'demo.cli:main'), true);
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT.replace('/venv/bin/python', '/venv/bin/python3.11w'), 'demo.cli:main'), true);
  const attribute = PIP_SCRIPT.replace('import main', 'import App').replace('exit(main())', 'exit(App.run())');
  assert.equal(pypi.isGeneratedScript(attribute, 'demo.cli:App.run'), true);
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT, 'demo.cli:other'), false);
  assert.equal(pypi.isGeneratedScript(`${PIP_SCRIPT}import os\n`, 'demo.cli:main'), false);
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT.replace('#!/venv/bin/python', '#!/bin/sh'), 'demo.cli:main'), false);
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT, 'demo.cli'), false);
  assert.equal(pypi.isGeneratedScript(PIP_SCRIPT, 'os;x:main'), false);
});

test('installLayout maps .data directories to install locations', () => {
  const files = new Map([
    ['demo/__init__.py', Buffer.from('x')],
    ['demo-1.0.dist-info/RECORD', Buffer.from('')],
    ['demo-1.0.dist-info/entry_points.txt', Buffer.from('[console_scripts]\ndemo = demo:main\n')],
    ['demo-1.0.data/purelib/pure.py', Buffer.from('p')],
    ['demo-1.0.data/platlib/plat.so', Buffer.from('s')],
    ['demo-1.0.data/scripts/tool', Buffer.from('#!python\nprint(1)\n')],
    ['demo-1.0.data/scripts/tool3', Buffer.from('#!python3.11\r\nprint(3)\n')],
    ['demo-1.0.data/scripts/shell', Buffer.from('#!/bin/sh\necho\n')],
    ['demo-1.0.data/data/share/x.txt', Buffer.from('d')],
    ['demo-1.0.data/headers/demo.h', Buffer.from('h')],
  ]);
  const layout = pypi.installLayout(files);
  assert.equal(layout.distInfo, 'demo-1.0.dist-info');
  assert.match(layout.entryPoints, /console_scripts/);
  assert.deepEqual(Object.keys(layout.expected).sort(), [
    '../../../bin/shell', '../../../bin/tool', '../../../bin/tool3', '../../../share/x.txt', 'demo-1.0.dist-info/entry_points.txt', 'demo/__init__.py', 'plat.so', 'pure.py',
  ]);
  assert.deepEqual(Object.keys(layout.scripts).sort(), ['../../../bin/tool', '../../../bin/tool3']);
  assert.equal(Buffer.from(layout.scripts['../../../bin/tool'].rest, 'base64').toString(), 'print(1)\n');
  assert.deepEqual(layout.headers, {'demo.h': hex('h')});
  const empty = pypi.installLayout(new Map());
  assert.equal(empty.distInfo, null);
  assert.equal(empty.entryPoints, null);
});

// ─── lockfiles ─────────────────────────────────────────────────────────

test('readLock reads uv.lock', t => {
  const dir = tempDir(t);
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  writeFiles(dir, {
    'uv.lock': `version = 1

[[package]]
name = "Demo_Pkg"
version = "1.0"
wheels = [
  { url = "https://files.example/demo_pkg-1.0-py3-none-any.whl", hash = "sha256:${a.toUpperCase()}", size = 1 },
  { url = "https://files.example/demo_pkg-1.0-py2-none-any.whl", hash = "md5:0123" },
  { url = "not a url", hash = "sha256:${b}" },
  { url = "https://files.example/unhashed.whl" },
]
sdist = { url = "https://files.example/demo_pkg-1.0.tar.gz", hash = "sha256:${b}" }

[[package]]
name = "editable"
version = "0.1"
source = { editable = "." }
`,
  });
  const lock = pypi.readLock(dir);
  assert.equal(lock.format, 'uv');
  assert.equal(lock.file, 'uv.lock');
  assert.deepEqual(lock.packages.get('demo-pkg'), [{
    name: 'Demo_Pkg',
    version: '1.0',
    files: [
      {
        name: 'demo_pkg-1.0-py3-none-any.whl', url: 'https://files.example/demo_pkg-1.0-py3-none-any.whl', sha256: a, sdist: false,
      },
      {
        name: null, url: 'not a url', sha256: b, sdist: false,
      },
      {
        name: 'demo_pkg-1.0.tar.gz', url: 'https://files.example/demo_pkg-1.0.tar.gz', sha256: b, sdist: true,
      },
    ],
  }]);
  assert.deepEqual(lock.packages.get('editable')[0].files, []);

  writeFiles(dir, {'uv.lock': 'version = 1\n'});
  assert.equal(pypi.readLock(dir).packages.size, 0);
});

test('readLock reads pylock.toml', t => {
  const dir = tempDir(t);
  const a = 'a'.repeat(64);
  writeFiles(dir, {
    'pylock.toml': `lock-version = "1.0"

[[packages]]
name = "demo"
version = "2.0"
sdist = { url = "https://files.example/demo-2.0.tar.gz", hashes = { sha256 = "${a}" } }

[[packages.wheels]]
name = "demo-2.0-py3-none-any.whl"
url = "https://files.example/wheels/demo-2.0-py3-none-any.whl"
hashes = { sha256 = "${a.toUpperCase()}" }

[[packages.wheels]]
url = "https://files.example/wheels/demo-2.0-py2-none-any.whl"
hashes = { sha256 = "${a}" }

[[packages.wheels]]
url = "https://files.example/wheels/unhashed.whl"

[[packages]]
name = "sdist-only"
version = "1"
sdist = { name = "sdist_only-1.tar.gz", hashes = { sha256 = "${a}" } }

[[packages]]
name = "vcs"
version = "1"
vcs = { type = "git", url = "https://example/repo.git" }
`,
  });
  const lock = pypi.readLock(dir);
  assert.equal(lock.format, 'pylock');
  assert.deepEqual(lock.packages.get('demo')[0].files.map(file => [file.name, file.sha256, file.sdist]), [
    ['demo-2.0-py3-none-any.whl', a, false],
    ['demo-2.0-py2-none-any.whl', a, false],
    ['demo-2.0.tar.gz', a, true],
  ]);

  assert.deepEqual(lock.packages.get('sdist-only')[0].files, [{
    name: 'sdist_only-1.tar.gz', url: undefined, sha256: a, sdist: true,
  }]);
  assert.deepEqual(lock.packages.get('vcs')[0].files, []);
  writeFiles(dir, {'pylock.toml': 'lock-version = "1.0"\n'});
  assert.equal(pypi.readLock(dir).packages.size, 0);
});

test('readLock reads poetry.lock', t => {
  const dir = tempDir(t);
  const a = 'a'.repeat(64);
  writeFiles(dir, {
    'poetry.lock': `[[package]]
name = "demo"
version = "3.0"
files = [
  {file = "demo-3.0-py3-none-any.whl", hash = "sha256:${a}"},
  {file = "demo-3.0.tar.gz", hash = "sha256:${a}"},
  {file = "demo-3.0.zip", hash = "sha512:00"},
]

[[package]]
name = "nofiles"
version = "1"
`,
  });
  const lock = pypi.readLock(dir);
  assert.equal(lock.format, 'poetry');
  assert.deepEqual(lock.packages.get('demo')[0].files, [
    {name: 'demo-3.0-py3-none-any.whl', sha256: a, sdist: false},
    {name: 'demo-3.0.tar.gz', sha256: a, sdist: true},
  ]);
  assert.deepEqual(lock.packages.get('nofiles')[0].files, []);

  writeFiles(dir, {'poetry.lock': '[metadata]\nlock-version = "2.0"\n'});
  assert.equal(pypi.readLock(dir).packages.size, 0);
});

test('readLock reads Pipfile.lock', t => {
  const dir = tempDir(t);
  const a = 'a'.repeat(64);
  writeFiles(dir, {
    'Pipfile.lock': JSON.stringify({
      _meta: {},
      default: {
        demo: {version: '==1.0', hashes: [`sha256:${a}`, 'md5:00']},
        nohashes: {version: '==2.0'},
        vcs: {git: 'https://example/repo.git'},
        broken: null,
      },
      develop: {tool: {version: '3.0', hashes: [`sha256:${a}`]}},
    }),
  });
  const lock = pypi.readLock(dir);
  assert.equal(lock.format, 'pipfile');
  assert.deepEqual(lock.packages.get('demo'), [{name: 'demo', version: '1.0', files: [{sha256: a}]}]);
  assert.deepEqual(lock.packages.get('nohashes')[0].files, []);
  assert.equal(lock.packages.get('tool')[0].version, '3.0');
  assert.equal(lock.packages.has('vcs'), false);

  writeFiles(dir, {'Pipfile.lock': '{}'});
  assert.equal(pypi.readLock(dir).packages.size, 0);
});

test('readLock reads requirements files with hashes', t => {
  const dir = tempDir(t);
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64);
  writeFiles(dir, {
    'requirements.txt': [
      '# comment',
      '--index-url https://pypi.org/simple',
      'demo[extra]==1.0 \\',
      `    --hash=sha256:${a} \\`,
      `    --hash sha256:${b}`,
      'exact===2.0 ; python_version >= "3.8"  # trailing comment',
      'loose>=1.0',
      '',
    ].join('\n'),
    'locks/other.txt': 'demo==9\n',
  });
  const lock = pypi.readLock(dir);
  assert.equal(lock.format, 'requirements');
  assert.deepEqual(lock.packages.get('demo')[0].files, [{sha256: a}, {sha256: b.toLowerCase()}]);
  assert.equal(lock.packages.get('exact')[0].version, '2.0');
  assert.equal(lock.packages.has('loose'), false);
  assert.equal(pypi.readLock(dir, {lockfile: 'locks/other.txt'}).packages.get('demo')[0].version, '9');
  assert.deepEqual([...pypi.parseRequirements('a==1\r\nb==2\n')].map(([name]) => name), ['a', 'b']);
});

test('readLock prefers uv.lock and reports a missing lockfile', t => {
  const dir = tempDir(t);
  assert.throws(() => pypi.readLock(dir), error => error instanceof NoLockfileError && /uv\.lock, pylock\.toml/.test(error.message));
  assert.throws(() => pypi.readLock(dir, {lockfile: 'deps.lock'}), /No Python lockfile found \(deps\.lock\)/);
  writeFiles(dir, {'requirements.txt': 'x==1\n', 'uv.lock': 'version = 1\n'});
  assert.equal(pypi.readLock(dir).format, 'uv');
});

// ─── attester ──────────────────────────────────────────────────────────

test('detect finds virtual environments and installRoot names them', t => {
  const root = tempDir(t);
  writeFiles(root, {
    '.venv/pyvenv.cfg': 'home = /usr/bin\n',
    '.venv/lib/python3.12/site-packages/.keep': '',
    '.venv/lib/python3.13t/site-packages/.keep': '',
    '.venv/lib/python3.11/.keep': '',
    '.venv/lib/site-python/.keep': '',
    'venv/pyvenv.cfg': '',
    'env/pyvenv.cfg': '',
    'env/lib/pypy3.10/site-packages/.keep': '',
    'virtualenv/lib/python3.12/site-packages/.keep': '',
  });
  assert.deepEqual(pypi.detect(root), [
    path.join(root, '.venv/lib/python3.12/site-packages'),
    path.join(root, '.venv/lib/python3.13t/site-packages'),
    path.join(root, 'env/lib/pypy3.10/site-packages'),
  ]);
  assert.equal(pypi.installRoot(path.join(root, '.venv/lib/python3.12/site-packages')), path.join(root, '.venv'));
  const system = path.join(root, 'virtualenv/lib/python3.12/site-packages');
  assert.equal(pypi.installRoot(system), system);
  assert.equal(pypi.name, 'pypi');
  assert.ok(pypi.lockfiles.includes('poetry.lock'));
});

/**
 * Write an installed distribution: its files, and a RECORD listing them
 * (plus `extraRecord` rows).
 */
function installDistribution(site, {name, version, files = {}, record = [], metadata, wheel = 'Tag: py3-none-any\n', installer = 'pip\n'}) {
  const distInfo = `${name}-${version}.dist-info`;
  const all = {...files};
  if (metadata !== null) {
    all[`${distInfo}/METADATA`] = metadata || `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`;
  }

  if (wheel !== null) {
    all[`${distInfo}/WHEEL`] = wheel;
  }

  if (installer !== null) {
    all[`${distInfo}/INSTALLER`] = installer;
  }

  fs.mkdirSync(path.join(site, distInfo), {recursive: true});
  writeFiles(site, all);
  const rows = [...Object.entries(all).map(([file, content]) => `${file},sha256=${recordHash(content)},${Buffer.byteLength(content)}`), ...record, `${distInfo}/RECORD,,`];
  fs.writeFileSync(path.join(site, distInfo, 'RECORD'), `${rows.join('\n')}\n`);
}

test('scan hashes each distribution\'s RECORD and reports what no RECORD claims', async t => {
  const venv = tempDir(t);
  const site = path.join(venv, 'lib/python3.12/site-packages');
  writeFiles(venv, {
    'pyvenv.cfg': 'home = /usr/bin\nuv = 0.8.0\n# comment\n',
    'bin/python': '',
    'bin/activate': 'deactivate () {}\n',
  });
  fs.rmSync(path.join(venv, 'bin/python'));
  fs.symlinkSync('/usr/bin/python3', path.join(venv, 'bin/python'));
  fs.symlinkSync('/usr/bin/python3', path.join(venv, 'bin/linked-tool'));
  const bigScript = `#!/venv/bin/python\n${'#'.repeat(20_000)}\n`;
  installDistribution(site, {
    name: 'demo',
    version: '1.0',
    files: {
      'demo/__init__.py': 'VALUE = 1\n',
      'demo/__pycache__/__init__.cpython-312.pyc': 'bytecode',
      '../../../bin/demo': PIP_SCRIPT,
      '../../../bin/plain': 'no interpreter line',
      '../../../bin/oneline': '#!/venv/bin/python',
      '../../../bin/big': bigScript,
    },
    record: [
      '../../../bin/linked-tool,,',
      'demo/gone.py,sha256=x,1',
      'demo/sub,,',
      '../../../../outside.txt,,',
      ',,',
      '"quoted,name.txt",,',
    ],
  });
  writeFiles(site, {
    'quoted,name.txt': 'q',
    'demo/sub/.keep': '',
    'demo/stray.py': 'import os\n',
    'demo/__pycache__/stray.cpython-312.pyc': 'cache',
    'other/__pycache__/x.cpython-312.pyc': 'cache',
    'other/__pycache__/y.cpython-312.pyc': 'cache',
    'sitecustomize.py': 'import os\n',
    '_virtualenv.py': 'hook',
    '_virtualenv.pth': 'import _virtualenv',
    // No METADATA, no WHEEL, no INSTALLER.
  });
  installDistribution(site, {
    name: 'nometa', version: '1', metadata: null, wheel: null, installer: null,
  });
  installDistribution(site, {name: 'noversion', version: '1', metadata: 'Name: noversion\nName: second\n\nVersion: 1\n'});
  installDistribution(site, {name: 'noname', version: '1', metadata: 'Metadata-Version: 2.1\r\nVersion: 1\r\n'});
  writeFiles(site, {
    'norecord-1.dist-info/METADATA': 'Name: norecord\nVersion: 1\n',
    'dirmeta-1.dist-info/METADATA/.keep': '',
    'dirmeta-1.dist-info/RECORD': '',
    'legacy-1.0-py3.12.egg-info/PKG-INFO': 'Name: legacy\n',
    'legacy-1.0-py3.12.egg-info/SOURCES.txt': '',
    'develop.egg-link': '/src/develop\n',
    'old-2.0-py3.12.egg/old/__init__.py': 'x',
    'stray.dist-info': 'a file, not a directory',
  });

  const result = await pypi.scan(site);
  const byPath = Object.fromEntries(result.packages.map(item => [item.path, item]));
  assert.deepEqual(result.packages.map(item => item.path), [
    'demo-1.0.dist-info', 'develop.egg-link', 'dirmeta-1.dist-info', 'legacy-1.0-py3.12.egg-info', 'nometa-1.dist-info', 'noname-1.dist-info', 'norecord-1.dist-info', 'noversion-1.dist-info', 'old-2.0-py3.12.egg',
  ]);
  const demo = byPath['demo-1.0.dist-info'];
  assert.equal(demo.name, 'demo');
  assert.equal(demo.version, '1.0');
  assert.equal(demo.invalid, undefined);
  assert.deepEqual(demo.meta.tags, ['py3-none-any']);
  assert.equal(demo.meta.installer, 'pip');
  assert.equal(demo.files['demo/__init__.py'], hex('VALUE = 1\n'));
  assert.equal(demo.files['../../../bin/linked-tool'], 'symlink:/usr/bin/python3');
  assert.equal(demo.files['quoted,name.txt'], hex('q'));
  assert.deepEqual(demo.meta.missing, ['demo/gone.py']);
  assert.equal(demo.meta.shebangs['../../../bin/demo'], '#!/venv/bin/python');
  assert.equal(demo.meta.shebangs['../../../bin/oneline'], '#!/venv/bin/python');
  assert.equal(demo.meta.shebangs['../../../bin/big'], '#!/venv/bin/python');
  assert.equal(demo.meta.shebangs['../../../bin/plain'], undefined);
  assert.equal(demo.meta.generated['../../../bin/demo'], PIP_SCRIPT);
  assert.equal(demo.meta.generated['../../../bin/big'], undefined);
  assert.equal(demo.meta.generated['../../../bin/linked-tool'], undefined);

  assert.deepEqual(byPath['nometa-1.dist-info'].meta.tags, []);
  assert.equal(byPath['nometa-1.dist-info'].invalid, true);
  assert.equal(byPath['noversion-1.dist-info'].name, 'noversion');
  assert.equal(byPath['noversion-1.dist-info'].invalid, true);
  assert.equal(byPath['noname-1.dist-info'].name, null);
  assert.equal(byPath['noname-1.dist-info'].version, '1');
  assert.equal(byPath['noname-1.dist-info'].invalid, true);
  assert.equal(byPath['norecord-1.dist-info'].invalid, true);
  assert.equal(byPath['legacy-1.0-py3.12.egg-info'].name, 'legacy');
  assert.equal(byPath['develop.egg-link'].name, 'develop');
  assert.equal(byPath['old-2.0-py3.12.egg'].name, 'old');
  assert.match(byPath['old-2.0-py3.12.egg'].meta.reason, /egg/);

  assert.deepEqual(result.errors.map(error => [error.path, String(error.error)]).sort(), [
    ['demo-1.0.dist-info/RECORD', 'path outside the environment: ../../../../outside.txt'],
    ['demo/sub', 'ENOTFILE'],
    ['dirmeta-1.dist-info/METADATA', 'EISDIR'],
    ['nometa-1.dist-info/METADATA', 'ENOENT'],
    ['norecord-1.dist-info/RECORD', 'ENOENT'],
  ]);
  assert.deepEqual(result.unaccounted, [
    '_virtualenv.pth', '_virtualenv.py', 'demo/stray.py', 'demo/sub/.keep', 'dirmeta-1.dist-info/METADATA/.keep', 'dirmeta-1.dist-info/RECORD', 'norecord-1.dist-info/METADATA', 'sitecustomize.py', 'stray.dist-info',
  ]);
  assert.deepEqual(result.caches, [
    {path: 'demo/__pycache__', files: ['stray.cpython-312.pyc']},
    {path: 'other/__pycache__', files: ['x.cpython-312.pyc', 'y.cpython-312.pyc']},
  ]);
  const {venv: meta} = result.meta;
  assert.deepEqual(meta.cfg, {home: '/usr/bin', uv: '0.8.0'});
  assert.equal(Buffer.from(meta['_virtualenv.py'], 'base64').toString(), 'hook');
  assert.equal(meta.bin.python, 'symlink:/usr/bin/python3');
  assert.equal(meta.bin.activate, hex('deactivate () {}\n'));
});

test('scan reports a bin entry it cannot hash, a missing site-packages and unreadable directories', async t => {
  const venv = tempDir(t);
  const site = path.join(venv, 'lib/python3.12/site-packages');
  writeFiles(venv, {'pyvenv.cfg': 'home = /usr/bin\n', 'bin/subdir/x': '', 'lib/python3.12/site-packages/.keep': ''});
  // A directory deeper than PATH_MAX cannot be listed by its absolute path.
  const deep = path.join(site, 'deep');
  fs.mkdirSync(deep);
  execFileSync('bash', ['-c', 'cd "$1" && for i in $(seq 20); do d=$(printf "%0250d" "$i"); mkdir "$d" && cd "$d"; done', 'bash', deep]);
  let result;
  try {
    result = await pypi.scan(site);
  } finally {
    execFileSync('rm', ['-rf', deep]);
  }

  assert.deepEqual(result.errors.find(error => error.path === 'bin/subdir'), {path: 'bin/subdir', error: 'ENOTFILE'});
  assert.ok(result.errors.some(error => error.error === 'ENAMETOOLONG'), JSON.stringify(result.errors));

  const missing = await pypi.scan(path.join(venv, 'nowhere/lib/python3/site-packages'));
  assert.deepEqual(missing.errors, [{path: '.', error: 'ENOENT'}, {path: '.', error: 'ENOENT'}]);
  assert.deepEqual(missing.meta, {});
});

test('scan reports a file that changes while it is hashed', async t => {
  const fileTree = require('../lib/file-tree');
  const site = path.join(tempDir(t), 'lib/python3.12/site-packages');
  installDistribution(site, {name: 'demo', version: '1.0', files: {'demo/__init__.py': ''}});
  const {hashFile} = fileTree;
  fileTree.hashFile = async file => {
    throw new Error(`File changed while hashing: ${file}`);
  };

  t.after(() => {
    fileTree.hashFile = hashFile;
  });
  const result = await pypi.scan(site);
  assert.match(result.errors.find(error => error.path === 'demo/__init__.py').error, /^File changed while hashing/);
});

test('scan outside a virtual environment has no environment metadata', async t => {
  const prefix = tempDir(t);
  const site = path.join(prefix, 'lib/python3.12/site-packages');
  installDistribution(site, {name: 'demo', version: '1.0', files: {'demo/__init__.py': ''}});
  const result = await pypi.scan(site);
  assert.deepEqual(result.meta, {});
  assert.equal(result.packages[0].name, 'demo');
  // Without bin/ in a virtual environment.
  writeFiles(prefix, {'pyvenv.cfg': ''});
  const bare = await pypi.scan(site);
  assert.deepEqual(bare.meta.venv, {cfg: {}, bin: {}});
});

// ─── verifier ──────────────────────────────────────────────────────────

/**
 * An installed distribution scanned exactly as an installer lays out the
 * wheel (for compare tests that do not need a real installer).
 */
function installedItem(wheel, overrides = {}) {
  const {readZipFiles} = require('../lib/zip');
  const layout = pypi.installLayout(readZipFiles(wheel.buffer));
  const files = {...layout.expected};
  for (const [file, script] of Object.entries(layout.scripts)) {
    files[file] = hex(Buffer.concat([Buffer.from('#!/venv/bin/python\n'), Buffer.from(script.rest, 'base64')]));
  }

  const distInfo = `${wheel.name}-${wheel.version}.dist-info`;
  files[`${distInfo}/RECORD`] = hex('');
  files[`${distInfo}/INSTALLER`] = hex('pip\n');
  return {
    name: wheel.name,
    version: wheel.version,
    path: distInfo,
    files,
    meta: {
      missing: [],
      shebangs: Object.fromEntries(Object.keys(layout.scripts).map(file => [file, '#!/venv/bin/python'])),
      generated: {},
      tags: wheel.filename.replace(/\.whl$/, '').split('-').slice(-3).join('-').split(' '),
    },
    ...overrides,
  };
}

const scanOf = (...packages) => ({
  packages, unaccounted: [], links: [], caches: [], errors: [], meta: {},
});

test('compareDistribution applies the wheel install rules', () => {
  const wheel = demoWheel();
  const {readZipFiles} = require('../lib/zip');
  const layout = pypi.installLayout(readZipFiles(wheel.buffer));
  const item = installedItem(wheel);
  item.files['../../../bin/demo'] = hex(PIP_SCRIPT);
  item.meta.generated['../../../bin/demo'] = PIP_SCRIPT;
  item.files['demo/__pycache__/cli.cpython-312.pyc'] = hex('pyc');
  item.files['../../../include/site/python3.12/demo/demo.h'] = hex('#define DEMO 1\n');
  let result = pypi.compareDistribution(item, layout);
  assert.deepEqual(result, {
    modified: [], missing: [], added: [], bytecode: ['demo/__pycache__/cli.cpython-312.pyc'], generated: ['../../../bin/demo'],
  });

  // A header with other content, a rewritten script with another
  // interpreter, a script without a recorded interpreter line, an extra
  // file in bin/, a generated script for an unknown entry point.
  item.files['../../../include/site/python3.12/demo/demo.h'] = hex('#define DEMO 2\n');
  item.files['../../../include/other.h'] = hex('#define DEMO 1\n');
  item.meta.shebangs['../../../bin/demo-tool'] = '#!/bin/sh';
  item.files['../../../bin/demo-gui'] = hex('x');
  item.meta.generated['../../../bin/demo-gui'] = 'not generated';
  item.files['../../../bin/other'] = hex(PIP_SCRIPT);
  item.meta.generated['../../../bin/other'] = PIP_SCRIPT;
  item.files['../../../bin/sub/demo'] = hex('x');
  item.files['demo-1.0.dist-info/sub/RECORD'] = hex('');
  item.files['other.dist-info/INSTALLER'] = hex('');
  delete item.files['demo/cli.py'];
  item.meta.missing.push('demo/removed.py');
  result = pypi.compareDistribution(item, layout);
  assert.deepEqual(result.modified, ['../../../bin/demo-tool']);
  assert.deepEqual(result.missing, ['demo/cli.py', 'demo/removed.py']);
  assert.deepEqual(result.added, [
    '../../../bin/demo-gui', '../../../bin/other', '../../../bin/sub/demo', '../../../include/other.h', '../../../include/site/python3.12/demo/demo.h', 'demo-1.0.dist-info/sub/RECORD', 'other.dist-info/INSTALLER',
  ]);
  delete item.meta.shebangs['../../../bin/demo-tool'];
  assert.deepEqual(pypi.compareDistribution(item, layout).modified, ['../../../bin/demo-tool']);
});

test('compare verifies distributions against wheels the lockfile pins', async t => {
  const registry = await startRegistry(t);
  const wheel = demoWheel();
  const sdist = {
    name: 'demo', version: '1.0', filename: 'demo-1.0.tar.gz', buffer: Buffer.from('sdist'), sha256: hex('sdist'), sdist: true,
  };
  registry.add(wheel, sdist);
  const store = registry.store();
  const lock = {
    packages: new Map([
      ['demo', [{name: 'demo', version: '1.0', files: [{sha256: wheel.sha256}, {sha256: sdist.sha256}]}]],
    ]),
  };
  let result = await pypi.compare({scan: scanOf(installedItem(wheel)), lock, store});
  assert.equal(result.passed, true);
  assert.equal(result.summary.verified, 1);
  assert.deepEqual(result.issues, []);

  // With the lockfile's own URLs, the registry is not asked.
  const requests = registry.server.requests.length;
  const urlLock = {packages: new Map([['demo', [{name: 'demo', version: 'v1.00', files: [{name: wheel.filename, url: registry.url(wheel.filename), sha256: wheel.sha256}]}]]])};
  result = await pypi.compare({scan: scanOf(installedItem(wheel)), lock: urlLock, store: registry.store()});
  assert.equal(result.summary.verified, 1);
  assert.deepEqual(registry.server.requests.slice(requests).map(request => request.url), [`/files/${wheel.filename}`]);

  // A modified file.
  const modified = installedItem(wheel);
  modified.files['demo/cli.py'] = hex('import os\n');
  result = await pypi.compare({scan: scanOf(modified), lock, store});
  assert.equal(result.passed, false);
  assert.deepEqual(result.findings, [{
    status: 'failed', package: 'demo@1.0', path: 'demo-1.0.dist-info', reason: 'files differ from the pinned wheel', modified: ['demo/cli.py'],
  }]);
});

test('compare matches wheels by tags', async t => {
  const registry = await startRegistry(t);
  const universal = makeWheel({
    name: 'multi', version: '1', tag: 'py2.py3-none-any', tags: ['py2-none-any', 'py3-none-any'], files: {'multi.py': ''},
  });
  const native = makeWheel({
    name: 'multi', version: '1', tag: 'cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64', files: {'multi.py': ''},
  });
  const other = makeWheel({
    name: 'multi', version: '1', tag: 'cp312-cp312-musllinux_1_1_x86_64', files: {'multi.py': ''},
  });
  registry.add(universal, native, other);
  const lock = {packages: new Map([['multi', [{name: 'multi', version: '1', files: [universal, native, other].map(wheel => ({sha256: wheel.sha256}))}]]])};
  const store = registry.store();

  // WHEEL's tags equal a wheel's expanded tags.
  const item = installedItem(universal);
  item.meta.tags = ['py2-none-any', 'py3-none-any'];
  assert.equal((await pypi.compare({scan: scanOf(item), lock, store})).summary.verified, 1);

  // WHEEL names one of a wheel's tags: the only overlapping wheel.
  const nativeItem = installedItem(native);
  nativeItem.meta.tags = ['cp312-cp312-manylinux_2_17_x86_64'];
  let result = await pypi.compare({scan: scanOf(nativeItem), lock, store});
  assert.equal(result.summary.verified, 1);

  // No wheel matches, and no source distribution is pinned.
  item.meta.tags = ['cp313-cp313-win_amd64'];
  result = await pypi.compare({scan: scanOf(item), lock, store});
  assert.deepEqual(result.findings.map(finding => finding.reason), ['no pinned wheel matches the installed tags cp313-cp313-win_amd64']);
});

test('compare reports what it cannot verify', async t => {
  const registry = await startRegistry(t);
  const wheel = demoWheel();
  const sdistOnly = {
    name: 'built', version: '1', filename: 'built-1.tar.gz', buffer: Buffer.from('s'), sha256: hex('s'), sdist: true,
  };
  registry.add(wheel, sdistOnly);
  registry.server.routes['/pypi/nourls/1/json'] = {body: '{}'};
  registry.server.routes['/pypi/nourl/1/json'] = {body: JSON.stringify({urls: [{filename: 'nourl-1-py3-none-any.whl', digests: {sha256: 'e'.repeat(64)}}]})};
  registry.server.routes['/pypi/nodigests/1/json'] = {body: JSON.stringify({urls: [{filename: 'nodigests-1-py3-none-any.whl', url: registry.url('x')}]})};
  const store = registry.store();
  const item = (name, version = '1', extra = {}) => ({
    name, version, path: `${name}-${version}.dist-info`, files: {}, meta: {
      missing: [], shebangs: {}, generated: {}, tags: ['py3-none-any'],
    }, ...extra,
  });
  const lock = {
    packages: new Map([
      ['nohash', [{name: 'nohash', version: '1', files: []}]],
      ['built', [{name: 'built', version: '1', files: [{sha256: sdistOnly.sha256}]}]],
      ['nourls', [{name: 'nourls', version: '1', files: [{sha256: 'a'.repeat(64)}]}]],
      ['nodigests', [{name: 'nodigests', version: '1', files: [{sha256: 'a'.repeat(64)}]}]],
      ['missing', [{name: 'missing', version: '1', files: [{sha256: 'a'.repeat(64)}]}]],
      ['otherversion', [{name: 'otherversion', version: '2', files: [{sha256: 'a'.repeat(64)}]}]],
      ['nourl', [{name: 'nourl', version: '1', files: [{name: 'nourl-1-py3-none-any.whl', sha256: 'e'.repeat(64)}]}]],
      ['ftp', [{name: 'ftp', version: '1', files: [{name: 'ftp-1-py3-none-any.whl', url: 'ftp://example/ftp-1-py3-none-any.whl', sha256: 'b'.repeat(64)}]}]],
      ['tampered', [{name: 'tampered', version: '1', files: [{name: 'tampered-1-py3-none-any.whl', url: registry.url(wheel.filename), sha256: 'c'.repeat(64)}]}]],
      ['gone', [{name: 'gone', version: '1', files: [{name: 'gone-1-py3-none-any.whl', url: registry.url('gone.whl'), sha256: 'd'.repeat(64)}]}]],
    ]),
  };
  const result = await pypi.compare({
    scan: scanOf(
      item('egg', null, {invalid: true, meta: {reason: 'installed as an egg'}}),
      item('broken', '1', {invalid: true}),
      item('nometa', '1', {invalid: true, meta: undefined}),
      item('nohash'),
      item('built'),
      item('nourls'),
      item('nodigests'),
      item('missing'),
      item('otherversion'),
      item('unlocked'),
      item('nourl'),
      item('ftp'),
      item('tampered'),
      item('gone'),
    ),
    lock,
    store,
  });
  const reasons = Object.fromEntries(result.findings.map(finding => [finding.package, `${finding.status}: ${finding.reason}`]));
  assert.deepEqual(reasons, {
    'egg@null': 'failed: installed as an egg',
    'broken@1': 'failed: missing or unreadable METADATA or RECORD',
    'nometa@1': 'failed: missing or unreadable METADATA or RECORD',
    'nohash@1': 'unverifiable: the lockfile pins no hashes for this package',
    'built@1': 'unverifiable: built on the server from a source distribution (no pinned wheel matches the installed tags)',
    'nourls@1': 'failed: no pinned wheel matches the installed tags py3-none-any',
    'nodigests@1': 'failed: no pinned wheel matches the installed tags py3-none-any',
    'missing@1': `error: could not list its files: HTTP 404 fetching ${registry.server.url}/pypi/missing/1/json`,
    'otherversion@1': 'failed: installed package is not pinned by the lockfile',
    'unlocked@1': 'failed: installed package is not pinned by the lockfile',
    'nourl@1': 'error: No download URL for nourl-1-py3-none-any.whl',
    // A URL on another host is not used; the registry is asked instead.
    'ftp@1': `error: could not list its files: HTTP 404 fetching ${registry.server.url}/pypi/ftp/1/json`,
    'tampered@1': 'failed: Downloaded tampered-1-py3-none-any.whl does not match its pinned hash',
    'gone@1': `error: HTTP 404 fetching ${registry.server.url}/files/gone.whl`,
  });
  assert.equal(result.passed, false);

  const unlocked = await pypi.compare({scan: scanOf(item('demo', '1.0')), lock: null, store});
  assert.equal(unlocked.findings[0].reason, 'no lockfile pins this package');
});

test('compare looks up seed packages the lockfile leaves out in the registry', async t => {
  const registry = await startRegistry(t);
  const pip = makeWheel({
    name: 'pip',
    version: '24.0',
    files: {'pip/__init__.py': ''},
    entryPoints: '[console_scripts]\npip = pip._internal.cli.main:main\npip3 = pip._internal.cli.main:main\npip3.12 = pip._internal.cli.main:main\n',
  });
  registry.add(pip);
  const item = installedItem(pip);
  for (const name of ['pip', 'pip3', 'pip3.12', 'pip3.11', 'pip-3.11']) {
    const script = PIP_SCRIPT.replace('from demo.cli import main', 'from pip._internal.cli.main import main');
    item.files[`../../../bin/${name}`] = hex(script);
    item.meta.generated[`../../../bin/${name}`] = script;
  }

  const lock = {packages: new Map()};
  let result = await pypi.compare({scan: scanOf(item), lock, store: registry.store()});
  assert.equal(result.passed, true);
  assert.deepEqual(result.issues, [{severity: 'info', message: 'Packages the environment tool installed (not in the lockfile) match their registry release', items: ['pip==24.0']}]);

  // A seed package whose wheel is not in the registry.
  const setuptools = {...installedItem(makeWheel({name: 'setuptools', version: '1', files: {}})), meta: {...item.meta, tags: ['py3-none-any']}};
  registry.server.routes['/pypi/setuptools/1/json'] = {
    body: JSON.stringify({
      urls: [{
        filename: 'setuptools-1.tar.gz', url: registry.url('s'), digests: {sha256: 'a'.repeat(64)}, packagetype: 'sdist',
      }],
    }),
  };
  registry.server.routes['/pypi/wheel/1/json'] = {body: JSON.stringify({urls: []})};
  result = await pypi.compare({scan: scanOf(setuptools, {...setuptools, name: 'wheel', path: 'wheel-1.dist-info'}), lock: null, store: registry.store()});
  assert.deepEqual(result.findings.map(finding => finding.reason), [
    'built on the server from a source distribution (no pinned wheel matches the installed tags)',
    'no pinned wheel matches the installed tags py3-none-any',
  ]);
});

test('compare matches seed packages with the distribution\'s patched wheels (python3 -m venv on Debian and Ubuntu)', async t => {
  const registry = await startRegistry(t);
  // The registry's pip, and the one Ubuntu patched and ships in python3-pip-whl.
  const upstream = makeWheel({name: 'pip', version: '24.0', files: {'pip/__init__.py': '', 'pip/py.typed': ''}});
  const patched = makeWheel({name: 'pip', version: '24.0', files: {'pip/__init__.py': '# patched\n'}});
  registry.add(upstream);
  const item = installedItem(patched);
  item.files['pip/__pycache__/__init__.cpython-312.pyc'] = hex('bytecode');
  const calls = [];
  const archive = {
    cacheKey: () => 'test-archive',
    async versions(name, arch) {
      calls.push(['versions', name, arch]);
      return ['24.0+dfsg-1ubuntu1.3', '24.0.1-1', '1:23.0-1', '24.0'];
    },
    async contents(name, version, arch, wanted) {
      calls.push(['contents', name, version, arch]);
      const files = {
        '/usr/share/python-wheels/pip-24.0-py3-none-any.whl': patched.buffer,
        '/usr/share/python-wheels/setuptools-68.1.2-py3-none-any.whl': Buffer.from('other'),
        '/usr/share/doc/python3-pip-whl/copyright': Buffer.from('text'),
      };
      return new Map(Object.entries(files).filter(([file]) => wanted(file)));
    },
  };
  const store = registry.store();
  const lock = {packages: new Map()};
  let result = await pypi.compare({
    scan: scanOf(item), lock, store, distro: {archive, arch: 'amd64'},
  });
  assert.equal(result.passed, true, JSON.stringify(result));
  assert.deepEqual(issue(result, /distribution's patched wheels/).items, ['pip==24.0 (python3-pip-whl 24.0+dfsg-1ubuntu1.3)']);
  assert.equal(issue(result, /registry release/), undefined);
  assert.deepEqual(issue(result, /bytecode/).items, ['pip-24.0.dist-info: pip/__pycache__/__init__.cpython-312.pyc']);
  // Only versions of the installed upstream version are fetched (with or without an epoch).
  assert.deepEqual(calls, [['versions', 'python3-pip-whl', 'amd64'], ['contents', 'python3-pip-whl', '24.0+dfsg-1ubuntu1.3', 'amd64']]);
  // The wheel's layout is kept.
  calls.length = 0;
  await pypi.compare({
    scan: scanOf(item), lock, store, distro: {archive, arch: 'amd64'},
  });
  assert.deepEqual(calls, [['versions', 'python3-pip-whl', 'amd64']]);

  // Without the distribution's archive, or when its wheel differs, the registry's verdict stands.
  result = await pypi.compare({scan: scanOf(item), lock, store});
  assert.equal(statusOf(result, 'pip').reason, 'files differ from the pinned wheel');
  const changed = {...item, files: {...item.files, 'pip/__init__.py': hex('# changed\n')}};
  result = await pypi.compare({
    scan: scanOf(changed), lock, store, distro: {archive, arch: 'amd64'},
  });
  assert.equal(statusOf(result, 'pip').reason, 'files differ from the pinned wheel');
  // A package with no wheel of that version, or more than one.
  const noWheel = {...archive, contents: async () => new Map()};
  result = await pypi.compare({
    scan: scanOf(item), lock, store: registry.store(), distro: {archive: noWheel, arch: 'amd64'},
  });
  assert.equal(statusOf(result, 'pip').reason, 'files differ from the pinned wheel');
  const twoWheels = {...archive, contents: async () => new Map([['/a', patched.buffer], ['/b', patched.buffer]])};
  result = await pypi.compare({
    scan: scanOf(item), lock, store: registry.store(), distro: {archive: twoWheels, arch: 'amd64'},
  });
  assert.equal(statusOf(result, 'pip').reason, 'files differ from the pinned wheel');

  // An archive that cannot be read leaves the package unchecked, not failed.
  const unreachable = {
    ...archive, async versions() {
      throw new Error('archive.ubuntu.com: ECONNRESET');
    },
  };
  result = await pypi.compare({
    scan: scanOf(item), lock, store, distro: {archive: unreachable, arch: 'amd64'},
  });
  assert.deepEqual(result.findings.map(finding => [finding.status, finding.reason]), [['error', 'could not compare it with the distribution\'s wheel: archive.ubuntu.com: ECONNRESET']]);

  // A seed package the registry verifies, and a pinned package, are not looked up in the archive.
  const refusing = {...archive, versions: async () => assert.fail('not consulted')};
  result = await pypi.compare({
    scan: scanOf(installedItem(upstream)), lock, store, distro: {archive: refusing, arch: 'amd64'},
  });
  assert.equal(result.passed, true);
  const demo = demoWheel();
  registry.add(demo);
  const changedDemo = {...installedItem(demo), files: {...installedItem(demo).files, 'demo/__init__.py': hex('changed')}};
  result = await pypi.compare({
    scan: scanOf(changedDemo), lock: {packages: new Map([['demo', [{version: '1.0', files: [{sha256: demo.sha256}]}]]])}, store, distro: {archive: refusing, arch: 'amd64'},
  });
  assert.equal(statusOf(result, 'demo').reason, 'files differ from the pinned wheel');
});

test('compare appraises bytecode caches, strays and the environment\'s bin directory', async t => {
  const registry = await startRegistry(t);
  const wheel = demoWheel();
  registry.add(wheel);
  const item = installedItem(wheel);
  item.files['demo/__pycache__/cli.cpython-312.pyc'] = hex('pyc');
  item.files['../../../bin/demo'] = hex(UV_SCRIPT);
  item.meta.generated['../../../bin/demo'] = UV_SCRIPT;
  const egg = {
    name: 'legacy', version: null, path: 'legacy.egg-info', invalid: true, meta: {reason: 'egg'},
  };
  const installed = {
    ...scanOf(item, egg),
    unaccounted: ['sitecustomize.py', '_virtualenv.py', '_virtualenv.pth'],
    caches: [{path: 'demo/__pycache__', files: ['x.cpython-312.pyc', 'payload.txt']}],
    meta: {
      venv: {
        cfg: {virtualenv: '20.0.0'},
        bin: {
          python: 'symlink:/usr/bin/python3', python3: hex('copied interpreter'), activate: hex('a'), 'Activate.ps1': hex('a'), demo: hex(UV_SCRIPT), 'demo-tool': hex('t'), evil: hex('e'),
        },
      },
    },
  };
  const lock = {packages: new Map([['demo', [{name: 'demo', version: '1.0', files: [{sha256: wheel.sha256}]}]]])};
  const result = await pypi.compare({scan: installed, lock, store: registry.store()});
  assert.equal(result.passed, false);
  assert.deepEqual(result.issues.map(item_ => [item_.severity, item_.items]), [
    ['fail', ['demo/__pycache__/payload.txt']],
    ['warn', ['demo-1.0.dist-info: demo/__pycache__/cli.cpython-312.pyc', 'demo/__pycache__/x.cpython-312.pyc']],
    ['fail', ['bin/evil', 'bin/python3']],
    ['info', ['Activate.ps1', 'activate', 'python']],
    ['fail', ['sitecustomize.py']],
  ]);

  // Bytecode only in caches; no scan metadata at all.
  const bare = await pypi.compare({scan: {...scanOf(), caches: [{path: 'x/__pycache__', files: ['a.pyc']}], meta: undefined}, lock, store: registry.store()});
  assert.deepEqual(bare.issues.map(item_ => item_.severity), ['warn']);
  assert.equal(bare.passed, true);
});

test('compare checks uv\'s _virtualenv start-up hook against uv\'s source', async t => {
  const registry = await startRegistry(t);
  const hook = 'import sys\n# _virtualenv\n';
  registry.server.routes['/uv/0.8.17/crates/uv-virtualenv/src/_virtualenv.py'] = {body: hook};
  const venv = (cfg, files) => ({...scanOf(), meta: {venv: {cfg, bin: {}, ...files}}});
  const encode = text => Buffer.from(text).toString('base64');
  const store = registry.store();
  let result = await pypi.compare({scan: venv({uv: '0.8.17'}, {'_virtualenv.py': encode(hook), '_virtualenv.pth': encode('import _virtualenv\n')}), lock: null, store});
  assert.deepEqual(result.issues, [{severity: 'info', message: 'The environment\'s start-up hook (_virtualenv) matches its creator\'s release', items: ['uv 0.8.17']}]);
  assert.equal(result.passed, true);

  result = await pypi.compare({scan: venv({uv: '0.8.17'}, {'_virtualenv.py': encode(`${hook}import os\n`), '_virtualenv.pth': encode('import _virtualenv')}), lock: null, store});
  assert.equal(result.issues[0].severity, 'fail');
  assert.equal(result.passed, false);
  result = await pypi.compare({scan: venv({uv: '0.8.17'}, {'_virtualenv.pth': encode('import os')}), lock: null, store});
  assert.equal(result.issues[0].severity, 'fail');
  result = await pypi.compare({scan: venv({uv: '0.8.17'}, {'_virtualenv.py': encode(hook)}), lock: null, store});
  assert.equal(result.issues[0].severity, 'fail');

  // A hook that cannot be checked (a version its creator never released,
  // or pyvenv.cfg rewritten to name none) runs in every Python process:
  // it fails, whatever its content.
  const evil = {'_virtualenv.py': encode(`${hook}import os; os.system("id")\n`), '_virtualenv.pth': encode('import _virtualenv')};
  result = await pypi.compare({scan: venv({uv: '9.9.9'}, evil), lock: null, store});
  assert.match(result.issues[0].message, /Could not check the environment's start-up hook against its creator's release: HTTP 404/);
  assert.equal(result.issues[0].severity, 'fail');
  assert.equal(result.passed, false);
  result = await pypi.compare({scan: venv({uv: 'main; rm'}, evil), lock: null, store});
  assert.equal(result.issues[0].message, 'Could not check the environment\'s start-up hook against its creator\'s release: pyvenv.cfg names no uv or virtualenv version');
  assert.equal(result.passed, false);
  result = await pypi.compare({scan: venv({}, evil), lock: null, store});
  assert.equal(result.passed, false);

  // Without a configured source, uv's repository on GitHub.
  const offline = new ReferenceStore();
  const fetched = [];
  offline.get = async url => {
    fetched.push(url);
    return Buffer.from(hook);
  };

  result = await pypi.compare({scan: venv({uv: '0.8.17'}, {'_virtualenv.py': encode(hook), '_virtualenv.pth': encode('import _virtualenv')}), lock: null, store: offline});
  assert.equal(result.issues[0].severity, 'info');
  assert.deepEqual(fetched, ['https://raw.githubusercontent.com/astral-sh/uv/0.8.17/crates/uv-virtualenv/src/_virtualenv.py']);
});

test('compare checks virtualenv\'s start-up hook against the virtualenv wheel', async t => {
  const registry = await startRegistry(t);
  const hook = 'import sys\n# virtualenv hook\n';
  const good = makeWheel({name: 'virtualenv', version: '20.1.0', files: {'virtualenv/create/via_global_ref/_virtualenv.py': hook}});
  const empty = makeWheel({name: 'virtualenv', version: '20.2.0', files: {'virtualenv/__init__.py': ''}});
  const platform = makeWheel({
    name: 'virtualenv', version: '20.3.0', tag: 'cp312-cp312-win_amd64', files: {},
  });
  registry.add(good, empty, platform);
  registry.server.routes['/pypi/virtualenv/20.4.0/json'] = {body: JSON.stringify({urls: [{filename: good.filename, url: registry.url(good.filename), digests: {sha256: 'a'.repeat(64)}}]})};
  const encode = text => Buffer.from(text).toString('base64');
  const check = async version => {
    const result = await pypi.compare({
      scan: {
        ...scanOf(), meta: {
          venv: {
            cfg: {virtualenv: version}, bin: {}, '_virtualenv.py': encode(hook), '_virtualenv.pth': encode('import _virtualenv'),
          },
        },
      },
      lock: null,
      store: registry.store(),
    });
    return result.issues[0];
  };

  assert.deepEqual(await check('20.1.0'), {severity: 'info', message: 'The environment\'s start-up hook (_virtualenv) matches its creator\'s release', items: ['virtualenv 20.1.0']});
  assert.match((await check('20.2.0')).message, /_virtualenv\.py not found in the virtualenv wheel/);
  assert.match((await check('20.3.0')).message, /no virtualenv 20\.3\.0 wheel/);
  assert.match((await check('20.4.0')).message, /virtualenv wheel does not match the registry's hash/);
  assert.match((await check('nightly')).message, /names no uv or virtualenv version/);
});

// ─── real environments ─────────────────────────────────────────────────

const python = which('python3') ? 'python3' : null;

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    stdio: 'pipe', encoding: 'utf8', ...options, env: {
      ...process.env, PIP_DISABLE_PIP_VERSION_CHECK: '1', PIP_NO_INPUT: '1', ...options.env,
    },
  });
}

/**
 * The pip and setuptools wheels ensurepip seeds environments from, when
 * the interpreter has them.
 */
function seedWheels() {
  try {
    const directory = run(python, ['-c', 'import ensurepip, os; print(os.path.join(os.path.dirname(ensurepip.__file__), "_bundled"))']).trim();
    return fs.readdirSync(directory).filter(name => name.endsWith('.whl')).map(filename => {
      const buffer = fs.readFileSync(path.join(directory, filename));
      const [name, version] = filename.split('-');
      return {
        name, version, filename, buffer, sha256: hex(buffer),
      };
    });
  } catch {
    return [];
  }
}

const seeds = python ? seedWheels() : [];

test('a pip-installed virtual environment verifies against its requirements file', {skip: seeds.length === 0 && 'python3 with ensurepip is not installed'}, async t => {
  const project = tempDir(t);
  const dist = path.join(project, 'dist');
  const wheel = demoWheel();
  writeFiles(dist, {[wheel.filename]: wheel.buffer});
  writeFiles(project, {'requirements.txt': `demo==1.0 \\\n    --hash=sha256:${wheel.sha256}\n`});
  run(python, ['-m', 'venv', path.join(project, '.venv')]);
  run(path.join(project, '.venv/bin/python'), ['-m', 'pip', 'install', '--no-index', '--find-links', dist, '--require-hashes', '-r', path.join(project, 'requirements.txt')]);

  const registry = await startRegistry(t);
  registry.add(wheel, ...seeds);
  const [site] = pypi.detect(project);
  assert.ok(site, 'site-packages found');
  assert.equal(pypi.installRoot(site), path.join(project, '.venv'));
  const installed = await pypi.scan(site);
  assert.deepEqual(installed.errors, []);
  const lock = pypi.readLock(project);
  let result = await pypi.compare({scan: installed, lock, store: registry.store()});
  assert.deepEqual(result.findings, []);
  assert.equal(result.passed, true, JSON.stringify(result.issues));
  assert.equal(result.summary.verified, installed.packages.length);
  assert.deepEqual(issue(result, /not in the lockfile/).items.sort(), seeds.map(seed => `${seed.name}==${seed.version}`).sort());
  assert.ok(issue(result, /bytecode/).items.some(file => file.startsWith('demo-1.0.dist-info: demo/__pycache__/')));
  assert.ok(issue(result, /activation scripts/).items.includes('activate'));

  // Tampering with a module, bin/ and site-packages.
  fs.appendFileSync(path.join(site, 'demo/cli.py'), 'import os\n');
  fs.writeFileSync(path.join(site, 'evil.pth'), 'import os\n');
  fs.writeFileSync(path.join(project, '.venv/bin/evil'), '#!/bin/sh\n');
  fs.writeFileSync(path.join(site, 'demo/__pycache__/payload.txt'), 'x');
  result = await pypi.compare({scan: await pypi.scan(site), lock, store: registry.store()});
  assert.equal(result.passed, false);
  assert.deepEqual(statusOf(result, 'demo').modified, ['demo/cli.py']);
  assert.deepEqual(issue(result, /belong to no installed package/).items, ['demo/__pycache__/payload.txt', 'evil.pth']);
  assert.deepEqual(issue(result, /bin directory/).items, ['bin/evil']);
});

test('a uv-installed virtual environment verifies against uv.lock and uv\'s start-up hook', {skip: !(python && which('uv')) && 'uv is not installed'}, async t => {
  const project = tempDir(t);
  const dist = path.join(project, 'dist');
  const wheel = demoWheel();
  writeFiles(dist, {[wheel.filename]: wheel.buffer});
  const env = {
    UV_CACHE_DIR: path.join(project, '.uv-cache'), UV_OFFLINE: '1', UV_NO_CONFIG: '1', UV_PYTHON_DOWNLOADS: 'never',
  };
  run('uv', ['venv', '--quiet', '--python', python, path.join(project, '.venv')], {env});
  run('uv', ['pip', 'install', '--quiet', '--python', path.join(project, '.venv/bin/python'), '--no-index', '--find-links', dist, 'demo==1.0'], {env});

  const registry = await startRegistry(t);
  writeFiles(project, {
    'uv.lock': `version = 1\n\n[[package]]\nname = "demo"\nversion = "1.0"\nwheels = [{ url = "${registry.url(wheel.filename)}", hash = "sha256:${wheel.sha256}" }]\n`,
  });
  registry.server.routes[`/files/${wheel.filename}`] = {body: wheel.buffer};
  const [site] = pypi.detect(project);
  const installed = await pypi.scan(site);
  const {cfg} = installed.meta.venv;
  assert.match(cfg.uv, /^[\d.]+$/);
  registry.server.routes[`/uv/${cfg.uv}/crates/uv-virtualenv/src/_virtualenv.py`] = {body: fs.readFileSync(path.join(site, '_virtualenv.py'))};
  const lock = pypi.readLock(project);
  let result = await pypi.compare({scan: installed, lock, store: registry.store()});
  assert.deepEqual(result.findings, []);
  assert.equal(result.passed, true, JSON.stringify(result.issues));
  assert.deepEqual(issue(result, /start-up hook/).items, [`uv ${cfg.uv}`]);
  assert.equal(issue(result, /bytecode/), undefined);
  assert.equal(installed.packages[0].meta.installer, 'uv');

  // A changed hook, and bytecode written by importing a module.
  fs.appendFileSync(path.join(site, '_virtualenv.py'), '\nimport os\n');
  run(path.join(project, '.venv/bin/python'), ['-c', 'import demo.cli'], {env: {PYTHONDONTWRITEBYTECODE: ''}});
  result = await pypi.compare({scan: await pypi.scan(site), lock, store: registry.store()});
  assert.equal(result.passed, false);
  assert.equal(issue(result, /start-up hook/).severity, 'fail');
  assert.ok(issue(result, /bytecode/).items.some(file => file.startsWith('demo/__pycache__/cli.')));
});

test('a RECORD line naming a directory, and a FIFO .pth file, do not hide code from the check', {skip: !which('mkfifo') && 'mkfifo is not installed'}, async t => {
  const registry = await startRegistry(t);
  const wheel = makeWheel({name: 'tiny', version: '1', files: {'tiny.py': 'X = 1\n'}});
  registry.add(wheel);
  const lock = {packages: new Map([['tiny', [{name: 'tiny', version: '1', files: [{sha256: wheel.sha256}]}]]])};
  const site = path.join(tempDir(t), 'lib/python3.12/site-packages');
  const install = record => installDistribution(site, {
    name: 'tiny', version: '1', files: {'tiny.py': 'X = 1\n'}, wheel: 'Wheel-Version: 1.0\nGenerator: attestium-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n', record,
  });
  install([]);
  let result = await pypi.compare({scan: await pypi.scan(site), lock, store: registry.store()});
  assert.equal(result.passed, true, JSON.stringify(result));

  // Python imports a sitecustomize package at start-up.  Claiming its
  // directory in any RECORD must not account for what is in it.
  writeFiles(site, {'sitecustomize/__init__.py': 'import os\nos.system("id")\n'});
  install(['sitecustomize,,']);
  let scan = await pypi.scan(site);
  assert.deepEqual(scan.unaccounted, ['sitecustomize/__init__.py']);
  assert.deepEqual(scan.errors, [{path: 'sitecustomize', error: 'ENOTFILE'}]);
  result = await pypi.compare({scan, lock, store: registry.store()});
  assert.equal(result.passed, false);
  assert.ok(result.issues.some(item => item.severity === 'fail' && item.items.includes('sitecustomize/__init__.py')));
  assert.ok(result.issues.some(item => item.severity === 'fail' && item.items.includes('sitecustomize: ENOTFILE')));
  fs.rmSync(path.join(site, 'sitecustomize'), {recursive: true});
  install([]);

  // Python reads a .pth that is a FIFO from whatever process writes to it.
  execFileSync('mkfifo', [path.join(site, 'evil.pth')]);
  scan = await pypi.scan(site);
  assert.deepEqual(scan.errors, [{path: 'evil.pth', error: 'ENOTFILE'}]);
  result = await pypi.compare({scan, lock, store: registry.store()});
  assert.equal(result.passed, false);
});

test('lockfile download URLs on other hosts are not fetched', async t => {
  const registry = await startRegistry(t);
  const wheel = demoWheel();
  registry.add(wheel);
  const elsewhere = await startServer(t, {[`/${wheel.filename}`]: {body: wheel.buffer}});
  const store = registry.store({httpOptions: {maxRetries: 0, headers: {authorization: 'Bearer mirror-token'}}});
  const lock = {packages: new Map([['demo', [{name: 'demo', version: '1.0', files: [{name: wheel.filename, url: `http://localhost:${new URL(elsewhere.url).port}/${wheel.filename}`, sha256: wheel.sha256}]}]]])};
  const result = await pypi.compare({scan: scanOf(installedItem(wheel)), lock, store});
  assert.equal(result.passed, true);
  // Found through the configured registry by its pinned hash instead.
  assert.deepEqual(elsewhere.requests, []);
  assert.ok(registry.server.requests.some(request => request.url === `/files/${wheel.filename}`));
  assert.equal(new ReferenceStore().urls.pypiFiles, 'https://files.pythonhosted.org');
  const invalid = {packages: new Map([['demo', [{name: 'demo', version: '1.0', files: [{name: wheel.filename, url: 'not a URL', sha256: wheel.sha256}]}]]])};
  assert.equal((await pypi.compare({scan: scanOf(installedItem(wheel)), lock: invalid, store})).passed, true);
});

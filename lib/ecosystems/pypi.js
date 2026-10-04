/**
 * Attestium - Python packages (PyPI)
 *
 * Attester: each installed distribution in a site-packages directory is
 * found through its .dist-info directory, and every file its RECORD lists is
 * hashed where it is installed (including console scripts outside
 * site-packages).  Files in site-packages that no RECORD claims are listed:
 * Python runs .pth files and sitecustomize.py at start-up, so a stray file
 * there is code.
 *
 * Verifier: the lockfile at the public commit (uv.lock, pylock.toml,
 * poetry.lock, Pipfile.lock, or a requirements file with --hash) pins the
 * SHA-256 of every distribution file.  The wheel whose tags match the
 * installed WHEEL file is downloaded, checked against that hash, and its
 * contents compared with what is installed, following the wheel install
 * rules (.data directories, rewritten script interpreters, generated
 * entry-point scripts).
 *
 * Bytecode (.pyc) cannot be compared with anything and is reported as such;
 * running with PYTHONDONTWRITEBYTECODE=1 and installing without compiling
 * (uv's default, `pip install --no-compile`) avoids it.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {walkTree} = require('../file-tree');
const {readZipFiles} = require('../zip');
const {parseToml} = require('../toml');
const {
  sha256, parallelMap, exists, setOwn,
} = require('../util');
const {
  NoLockfileError, compareFiles, collect, scanIssues, parseCsv, isInside,
} = require('./common');

const VENV_NAMES = ['.venv', 'venv', 'env', '.virtualenv', 'virtualenv'];
// Installers seed these into environments (python -m venv, virtualenv);
// they are looked up in the registry when the lockfile does not pin them.
const SEED_PACKAGES = new Set(['pip', 'setuptools', 'wheel']);
// Files installers write into a .dist-info directory: metadata, not code.
const INSTALLER_FILES = new Set(['RECORD', 'INSTALLER', 'REQUESTED', 'direct_url.json', 'uv_cache.json', 'uv_build.json']);
const ACTIVATION = /^(?:activate(?:\.(?:csh|fish|nu|ps1|bat|xsh))?|Activate\.ps1|activate_this\.py|deactivate\.(?:bat|csh)|pydoc\.bat)$/;
// Interpreter links in an environment's bin directory (Python 3.14's venv
// adds 𝜋thon).
const INTERPRETER = /^(?:(?:python|pypy)[\d.]*w?|\u{1D70B}thon)$/u;
const BYTECODE = /(?:^|\/)__pycache__\/[^/]+\.pyc$/;
const SCRIPT_LIMIT = 16 * 1024;

/**
 * PEP 503 normalized project name.
 * @param {string} name
 * @returns {string}
 */
function normalizeName(name) {
  return String(name).toLowerCase().replaceAll(/[-_.]+/g, '-');
}

/**
 * A version string in a comparable form (case, a leading "v", and leading
 * zeros in release numbers do not matter).
 * @param {string} version
 * @returns {string}
 */
function normalizeVersion(version) {
  return String(version).trim().toLowerCase().replace(/^v/, '').replaceAll(/(^|\.)0+(\d)/g, '$1$2');
}

// ─── attester ──────────────────────────────────────────────────────────

/**
 * Virtual environments in a project root, and their site-packages.
 * @param {string} root
 * @returns {string[]} absolute site-packages directories
 */
function detect(root) {
  const found = [];
  for (const name of VENV_NAMES) {
    const venv = path.join(root, name);
    if (!exists(path.join(venv, 'pyvenv.cfg'))) {
      continue;
    }

    let versions = [];
    try {
      versions = fs.readdirSync(path.join(venv, 'lib')).filter(entry => /^(?:python\d+\.\d+t?|pypy\d+\.\d+)$/.test(entry)).sort();
    } catch {}

    for (const version of versions) {
      const site = path.join(venv, 'lib', version, 'site-packages');
      if (exists(site)) {
        found.push(site);
      }
    }
  }

  return found;
}

/**
 * The directories a detected install occupies in the project, which the
 * project's own file list leaves out (the ecosystem accounts for them).
 * @param {string} site - site-packages directory
 * @returns {string} the virtual environment's root, or site-packages
 */
function installRoot(site) {
  const prefix = path.resolve(site, '..', '..', '..');
  return exists(path.join(prefix, 'pyvenv.cfg')) ? prefix : site;
}

function parseMetadata(text) {
  const headers = {};
  for (const line of text.split(/\r?\n/)) {
    if (line === '') {
      break;
    }

    const match = line.match(/^([\w-]+):\s*(.*)$/);
    if (match && headers[match[1].toLowerCase()] === undefined) {
      headers[match[1].toLowerCase()] = match[2].trim();
    }
  }

  return headers;
}

function parseKeyValue(text) {
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([^=#]+?)\s*=\s*(.*?)\s*$/);
    if (match) {
      values[match[1]] = match[2];
    }
  }

  return values;
}

async function hashEntry(file) {
  const stats = await fs.promises.lstat(file);
  if (stats.isSymbolicLink()) {
    return `symlink:${await fs.promises.readlink(file)}`;
  }

  if (!stats.isFile()) {
    throw Object.assign(new Error('not a regular file'), {code: 'ENOTFILE'});
  }

  const {hashFile} = require('../file-tree');
  return (await hashFile(file)).sha256;
}

/**
 * Hash the distributions installed in a site-packages directory.
 *
 * @param {string} site
 * @returns {Promise<Object>} scan result (see ./common)
 */
async function scan(site) {
  site = path.resolve(site);
  // Scripts and data are installed relative to the scheme's prefix: the
  // virtual environment, or /usr/local for lib/pythonX.Y/site-packages.
  const prefix = path.resolve(site, '..', '..', '..');
  const packages = [];
  const errors = [];
  const claimed = new Set();
  let dirents = [];
  try {
    dirents = await fs.promises.readdir(site, {withFileTypes: true});
  } catch (error) {
    errors.push({path: '.', error: error.code});
  }

  // Eggs are reported as packages (which fail), so what is in them is not
  // listed again.
  const eggs = new Set();
  for (const dirent of dirents.filter(entry => /\.(?:egg-info|egg-link|egg)$/.test(entry.name))) {
    packages.push({
      name: dirent.name.replace(/[-.](?:\d.*)?(?:egg-info|egg-link|egg)$/, ''), version: null, path: dirent.name, invalid: true, meta: {reason: 'installed as an egg (setup.py develop or easy_install), which records no file hashes'},
    });
    eggs.add(dirent.name);
  }

  const distributions = dirents.filter(entry => entry.isDirectory() && entry.name.endsWith('.dist-info'));
  const scanned = await parallelMap(distributions.map(dirent => async () => {
    const distInfo = path.join(site, dirent.name);
    const item = {
      name: null, version: null, path: dirent.name, files: {}, meta: {missing: [], shebangs: {}, generated: {}},
    };
    try {
      const headers = parseMetadata(await fs.promises.readFile(path.join(distInfo, 'METADATA'), 'utf8'));
      item.name = headers.name || null;
      item.version = headers.version || null;
    } catch (error) {
      errors.push({path: `${dirent.name}/METADATA`, error: error.code});
    }

    try {
      item.meta.tags = (await fs.promises.readFile(path.join(distInfo, 'WHEEL'), 'utf8')).split(/\r?\n/).map(line => line.match(/^Tag:\s*(\S+)/)).filter(Boolean).map(match => match[1]).sort();
    } catch {
      item.meta.tags = [];
    }

    try {
      item.meta.installer = (await fs.promises.readFile(path.join(distInfo, 'INSTALLER'), 'utf8')).trim().slice(0, 64);
    } catch {}

    let rows = [];
    try {
      rows = parseCsv(await fs.promises.readFile(path.join(distInfo, 'RECORD'), 'utf8'));
    } catch (error) {
      errors.push({path: `${dirent.name}/RECORD`, error: error.code});
      item.invalid = true;
    }

    for (const [recordPath] of rows) {
      if (!recordPath) {
        continue;
      }

      const posix = recordPath.replaceAll('\\', '/');
      const absolute = path.resolve(site, ...posix.split('/'));
      if (!isInside(prefix, absolute)) {
        errors.push({path: `${dirent.name}/RECORD`, error: `path outside the environment: ${posix.slice(0, 200)}`});
        continue;
      }

      try {
        setOwn(item.files, posix, await hashEntry(absolute));
      } catch (error) {
        if (error.code === 'ENOENT') {
          item.meta.missing.push(posix);
        } else {
          errors.push({path: posix, error: error.code || error.message});
        }

        continue;
      }

      // Only a file that was hashed is accounted for: a RECORD line naming a
      // directory must not hide what is in it.
      claimed.add(absolute);

      // Scripts outside site-packages: the interpreter line an installer
      // wrote, and small scripts in full (entry points are generated).
      if (!isInside(site, absolute) && !item.files[posix].startsWith('symlink:')) {
        const content = await fs.promises.readFile(absolute);
        if (content.subarray(0, 2).toString() === '#!') {
          const end = content.indexOf(0x0A);
          setOwn(item.meta.shebangs, posix, content.subarray(0, end === -1 ? content.length : end).toString('utf8').slice(0, 512));
        }

        if (content.length <= SCRIPT_LIMIT) {
          setOwn(item.meta.generated, posix, content.toString('utf8'));
        }
      }
    }

    if (!item.name || !item.version) {
      item.invalid = true;
    }

    return item;
  }), 8);
  packages.push(...scanned);

  // Everything else in site-packages.  Bytecode caches no RECORD lists are
  // reported apart (Python writes them when it imports a module).  The walk
  // reports anything that is not a file, a directory or a link as an error:
  // Python reads .pth files at start-up whatever kind of file they are (a
  // FIFO is read from whoever writes to it).
  const caches = new Map();
  const walk = await walkTree(site, {
    exclude(relativePath, isDirectory) {
      return isDirectory && eggs.has(relativePath) && relativePath.endsWith('.egg-info');
    },
  });
  for (const walkError of walk.errors) {
    errors.push(walkError);
  }

  const unaccounted = [];
  for (const entry of walk.entries) {
    if (claimed.has(path.join(site, ...entry.path.split('/')))) {
      continue;
    }

    if (BYTECODE.test(entry.path)) {
      const directory = entry.path.slice(0, entry.path.lastIndexOf('/'));
      if (!caches.has(directory)) {
        caches.set(directory, []);
      }

      caches.get(directory).push(entry.path.slice(directory.length + 1));
    } else if (!eggs.has(entry.path.split('/')[0])) {
      unaccounted.push(entry.path);
    }
  }

  const result = {
    packages: packages.sort((a, b) => (a.path > b.path) - (a.path < b.path)),
    unaccounted: unaccounted.sort(),
    links: [],
    caches: [...caches].map(([directory, files]) => ({path: directory, files: files.sort()})).sort((a, b) => (a.path > b.path) - (a.path < b.path)),
    errors,
    meta: {},
  };

  // Files a virtual environment's creator wrote: its configuration, and
  // what is in bin/ (scripts, interpreter links).
  if (exists(path.join(prefix, 'pyvenv.cfg'))) {
    const venv = {cfg: parseKeyValue(await fs.promises.readFile(path.join(prefix, 'pyvenv.cfg'), 'utf8')), bin: {}};
    for (const name of ['_virtualenv.py', '_virtualenv.pth']) {
      try {
        setOwn(venv, name, (await fs.promises.readFile(path.join(site, name))).toString('base64'));
      } catch {}
    }

    let bin = [];
    try {
      bin = await fs.promises.readdir(path.join(prefix, 'bin'));
    } catch {}

    for (const name of bin) {
      try {
        setOwn(venv.bin, name, await hashEntry(path.join(prefix, 'bin', name)));
      } catch (error) {
        errors.push({path: `bin/${name}`, error: error.code});
      }
    }

    result.meta.venv = venv;
  }

  return result;
}

// ─── lockfiles ─────────────────────────────────────────────────────────

const LOCKFILES = ['uv.lock', 'pylock.toml', 'poetry.lock', 'Pipfile.lock', 'requirements.lock', 'requirements.txt'];

/**
 * Add a pinned distribution to a lock map.
 */
function pin(packages, name, version, files) {
  const key = normalizeName(name);
  if (!packages.has(key)) {
    packages.set(key, []);
  }

  packages.get(key).push({name, version: String(version), files});
}

const hashValue = hash => {
  const match = String(hash || '').match(/^sha256[:=]([\da-f]{64})$/i);
  return match ? match[1].toLowerCase() : null;
};

function fileName(url) {
  try {
    return decodeURIComponent(new URL(url).pathname.split('/').pop());
  } catch {
    return null;
  }
}

/**
 * Parse a requirements file with hashes (pip-compile, uv export).
 * @param {string} text
 * @returns {Map}
 */
function parseRequirements(text) {
  const packages = new Map();
  const logical = text.replaceAll(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of logical) {
    const line = raw.replace(/(?:^|\s)#.*$/, '').trim();
    const match = line.match(/^([A-Za-z\d][\w.-]*)(?:\[[^\]]*])?\s*===?\s*([^\s;]+)/);
    if (!match) {
      continue;
    }

    const hashes = [...line.matchAll(/--hash[=\s]+sha256:([\da-fA-F]{64})/g)].map(item => ({sha256: item[1].toLowerCase()}));
    pin(packages, match[1], match[2], hashes);
  }

  return packages;
}

/**
 * Read the lockfile at a repository checkout.
 *
 * @param {string} repoDir
 * @param {Object} [options]
 * @param {string} [options.lockfile] - path relative to repoDir (default: the first of LOCKFILES found)
 * @returns {{format: string, file: string, packages: Map<string, Array<{name: string, version: string, files: Array<{name?: string, url?: string, sha256: string}>}>>}}
 */
function readLock(repoDir, options = {}) {
  const candidates = options.lockfile ? [options.lockfile] : LOCKFILES;
  const file = candidates.find(name => exists(path.join(repoDir, name)));
  if (!file) {
    throw new NoLockfileError(`No Python lockfile found (${candidates.join(', ')})`);
  }

  const text = fs.readFileSync(path.join(repoDir, file), 'utf8');
  const packages = new Map();
  const base = path.basename(file);
  if (base === 'uv.lock') {
    for (const item of parseToml(text).package || []) {
      const files = [...(item.wheels || []), ...(item.sdist ? [{...item.sdist, sdist: true}] : [])]
        .filter(entry => hashValue(entry.hash))
        .map(entry => ({
          name: fileName(entry.url), url: entry.url, sha256: hashValue(entry.hash), sdist: Boolean(entry.sdist),
        }));
      pin(packages, item.name, item.version, files);
    }

    return {format: 'uv', file, packages};
  }

  if (base === 'pylock.toml') {
    for (const item of parseToml(text).packages || []) {
      const files = [...(item.wheels || []), ...(item.sdist ? [{...item.sdist, sdist: true}] : [])]
        .filter(entry => entry.hashes && entry.hashes.sha256)
        .map(entry => ({
          name: entry.name || fileName(entry.url), url: entry.url, sha256: String(entry.hashes.sha256).toLowerCase(), sdist: Boolean(entry.sdist),
        }));
      pin(packages, item.name, item.version, files);
    }

    return {format: 'pylock', file, packages};
  }

  if (base === 'poetry.lock') {
    for (const item of parseToml(text).package || []) {
      const files = (item.files || []).filter(entry => hashValue(entry.hash)).map(entry => ({name: entry.file, sha256: hashValue(entry.hash), sdist: !String(entry.file).endsWith('.whl')}));
      pin(packages, item.name, item.version, files);
    }

    return {format: 'poetry', file, packages};
  }

  if (base === 'Pipfile.lock') {
    const lock = JSON.parse(text);
    for (const section of ['default', 'develop']) {
      for (const [name, entry] of Object.entries(lock[section] || {})) {
        if (entry && typeof entry.version === 'string') {
          pin(packages, name, entry.version.replace(/^==/, ''), (entry.hashes || []).map(hash => ({sha256: hashValue(hash)})).filter(entry_ => entry_.sha256));
        }
      }
    }

    return {format: 'pipfile', file, packages};
  }

  return {format: 'requirements', file, packages: parseRequirements(text)};
}

// ─── wheels ────────────────────────────────────────────────────────────

/**
 * The tags a wheel's file name declares (compressed tag sets expanded).
 * @param {string} name
 * @returns {string[]|null}
 */
function wheelTags(name) {
  const match = String(name).match(/^(.+?)-([^-]+)(?:-(\d[^-]*))?-([^-]+)-([^-]+)-([^-]+)\.whl$/);
  if (!match) {
    return null;
  }

  const tags = [];
  for (const python of match[4].split('.')) {
    for (const abi of match[5].split('.')) {
      for (const platform of match[6].split('.')) {
        tags.push(`${python}-${abi}-${platform}`);
      }
    }
  }

  return tags.sort();
}

/**
 * Where a wheel's files end up, as paths relative to site-packages (the
 * form RECORD uses).
 *
 * @param {Map<string, Buffer>} files - wheel contents
 * @returns {{expected: Object<string, string>, scripts: Object<string, {rest: string}>, headers: Object<string, string>, distInfo: string|null, entryPoints: string|null}}
 */
function installLayout(files) {
  const expected = {};
  const scripts = {};
  const headers = {};
  let distInfo = null;
  let entryPoints = null;
  for (const [file, content] of files) {
    const top = file.split('/')[0];
    if (top.endsWith('.dist-info') && file === `${top}/RECORD`) {
      distInfo = top;
      continue;
    }

    if (top.endsWith('.dist-info') && file === `${top}/entry_points.txt`) {
      entryPoints = content.toString('utf8');
    }

    if (top.endsWith('.data')) {
      const [, scheme, ...rest] = file.split('/');
      const relative = rest.join('/');
      switch (scheme) {
        case 'purelib':
        case 'platlib': {
          setOwn(expected, relative, sha256(content));

          break;
        }

        case 'scripts': {
          const target = `../../../bin/${relative}`;
          setOwn(expected, target, sha256(content));
          // Installers replace "#!python" with the environment's interpreter.
          if (/^#!python[w\d.]*\r?\n/.test(content.subarray(0, 64).toString('latin1'))) {
            const newline = content.indexOf(0x0A);
            setOwn(scripts, target, {rest: content.subarray(newline + 1).toString('base64')});
          }

          break;
        }

        case 'data': {
          expected[`../../../${relative}`] = sha256(content);

          break;
        }

        default: {
        // Headers go to include/site/pythonX.Y/<name>/, which differs by
        // installer; they are not code Python runs.
          setOwn(headers, relative, sha256(content));
        }
      }

      continue;
    }

    setOwn(expected, file, sha256(content));
  }

  return {
    expected, scripts, headers, distInfo, entryPoints,
  };
}

/**
 * Entry points declared as console or GUI scripts.
 * @param {string|null} text - entry_points.txt
 * @returns {Map<string, string>} script name -> "module:attr"
 */
function scriptEntryPoints(text) {
  const result = new Map();
  let section = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    const header = line.match(/^\[(.+)]$/);
    if (header) {
      section = header[1].trim();
    } else if ((section === 'console_scripts' || section === 'gui_scripts') && line.includes('=')) {
      const [name, value] = line.split('=');
      result.set(name.trim(), value.trim().replace(/\s*\[.*]$/, ''));
    }
  }

  return result;
}

/**
 * Whether a file is exactly what an installer generates for an entry point
 * (pip, distlib, uv or installer), so it runs only that entry point.
 *
 * @param {string} content
 * @param {string} entryPoint - "module.path:object.attr"
 * @returns {boolean}
 */
function isGeneratedScript(content, entryPoint) {
  const match = entryPoint.match(/^([\w.]+):([\w.]+)$/);
  if (!match) {
    return false;
  }

  const [, module, call] = match;
  const from = `from ${module} import ${call.split('.')[0]}`;
  const exit = `    sys.exit(${call}())`;
  const reSub = quote => String.raw`    sys.argv[0] = re.sub(r${quote}(-script\.pyw|\.exe)?$${quote}, ${quote}${quote}, sys.argv[0])`;
  const templates = [
    // Pip 25.1 and earlier (distlib 0.3).
    ['# -*- coding: utf-8 -*-', 'import re', 'import sys', from, 'if __name__ == \'__main__\':', reSub('\''), exit],
    // Pip 25.2 and 25.3.
    ['import sys', from, 'if __name__ == \'__main__\':', '    if sys.argv[0].endswith(\'.exe\'):', '        sys.argv[0] = sys.argv[0][:-4]', exit],
    // Pip 26 and later.
    ['import sys', from, 'if __name__ == \'__main__\':', '    sys.argv[0] = sys.argv[0].removesuffix(\'.exe\')', exit],
    // Distlib 0.4 and later (virtualenv seeds pip with it).
    ['# -*- coding: utf-8 -*-', 'import re', 'import sys', 'if __name__ == \'__main__\':', `    ${from}`, reSub('\''), exit],
    // Uv.
    ['# -*- coding: utf-8 -*-', 'import sys', from, 'if __name__ == "__main__":', '    if sys.argv[0].endswith("-script.pyw"):', '        sys.argv[0] = sys.argv[0][:-11]', '    elif sys.argv[0].endswith(".exe"):', '        sys.argv[0] = sys.argv[0][:-4]', exit],
    // Installer (pypa/installer).
    ['# -*- coding: utf-8 -*-', 'import re', 'import sys', from, 'if __name__ == "__main__":', reSub('"'), exit],
  ];
  const interpreter = content.match(/^#!(?:\/[^\n]*\/)?python[\d.]*w?\n/);
  return interpreter !== null && templates.some(lines => content.slice(interpreter[0].length) === `${lines.join('\n')}\n`);
}

// ─── verifier ──────────────────────────────────────────────────────────

/**
 * Whether a lockfile's download URL is on the configured registry or file
 * host.  The content is checked by its hash either way; other hosts are not
 * contacted, so a lockfile cannot point the verifier (and the headers it is
 * configured with) at a host of its choosing.
 * @param {import('./common').ReferenceStore} store
 * @param {string} url
 * @returns {boolean}
 */
function onConfiguredHost(store, url) {
  const origin = value => {
    try {
      return new URL(value).origin;
    } catch {
      return null;
    }
  };

  const target = origin(url);
  return target !== null && [store.urls.pypi, store.urls.pypiFiles].some(base => origin(base) === target);
}

/**
 * Candidate distribution files for name==version: the lockfile's own URLs
 * when they are on the configured hosts, or the registry's file list
 * filtered to the hashes the lockfile pins.
 */
async function candidates(store, name, version, pinned) {
  if (pinned && pinned.length > 0 && pinned.every(file => file.url && file.name && onConfiguredHost(store, file.url))) {
    return pinned;
  }

  const listing = await store.memo(`pypi-files:v1:${normalizeName(name)}==${version}`, async () => {
    const json = await store.getJson(`${store.urls.pypi}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`, {maxBytes: 16 * 1024 * 1024});
    return (json.urls || []).map(file => ({
      name: file.filename, url: file.url, sha256: file.digests && file.digests.sha256, sdist: file.packagetype === 'sdist',
    }));
  });
  if (pinned === null) {
    return listing;
  }

  const hashes = new Set(pinned.map(file => file.sha256));
  return listing.filter(file => hashes.has(file.sha256));
}

async function wheelManifest(store, file) {
  return store.memo(`pypi-wheel:v2:${file.sha256}`, async () => {
    if (!/^https:\/\/|^http:\/\/(?:127\.0\.0\.1|localhost)[:/]/.test(file.url || '')) {
      throw new Error(`No download URL for ${file.name}`);
    }

    const buffer = await store.get(file.url, {maxBytes: 512 * 1024 * 1024});
    if (sha256(buffer) !== file.sha256) {
      throw new Error(`Downloaded ${file.name} does not match its pinned hash`);
    }

    return installLayout(readZipFiles(buffer));
  });
}

/**
 * Compare one installed distribution with its wheel.
 */
function compareDistribution(item, layout) {
  const entryPoints = scriptEntryPoints(layout.entryPoints);
  const bytecode = [];
  const generated = [];
  const result = compareFiles(item.files, layout.expected, {
    equivalent(file, installedHash) {
      const script = layout.scripts[file];
      const shebang = item.meta.shebangs[file];
      if (!script || !shebang || !/^#!\/\S*python[\d.]*w?$/.test(shebang)) {
        return false;
      }

      return sha256(Buffer.concat([Buffer.from(`${shebang}\n`), Buffer.from(script.rest, 'base64')])) === installedHash;
    },
    allowExtra(file, hash) {
      const [top, base] = file.split('/');
      if (top === layout.distInfo && INSTALLER_FILES.has(base) && file.split('/').length === 2) {
        return true;
      }

      if (BYTECODE.test(file)) {
        bytecode.push(file);
        return true;
      }

      // A header, wherever the installer put it under include/.
      if (file.startsWith('../../../include/') && Object.entries(layout.headers).some(([header, expected]) => file.endsWith(`/${header}`) && hash === expected)) {
        return true;
      }

      const script = file.match(/^(?:\.{2}\/){3}bin\/([^/]+)$/);
      // Pip also writes versioned copies of its own scripts (pip3.12).
      const name = script && !entryPoints.has(script[1]) ? script[1].replace(/^(pip|easy_install)(?:\d+(?:\.\d+)?|-\d+\.\d+)$/, '$1') : script && script[1];
      if (script && entryPoints.has(name) && typeof item.meta.generated[file] === 'string' && isGeneratedScript(item.meta.generated[file], entryPoints.get(name))) {
        generated.push(file);
        return true;
      }

      return false;
    },
  });
  const missing = [...result.missing, ...item.meta.missing];
  return {
    ...result, missing, bytecode, generated,
  };
}

/**
 * Debian and Ubuntu patch pip and setuptools (python3-<name>-whl), and their
 * `python3 -m venv` seeds environments from those wheels, which differ from
 * the registry's.  The installed distribution is compared with each wheel
 * of its version in the distribution's signed archive.
 *
 * @param {{archive: Object, arch: string}} distro - an ArchiveReference, and the host's dpkg architecture
 * @returns {Promise<{label: string, comparison: Object}|null>} the matching wheel, or null
 */
async function distroWheel(distro, store, item) {
  const project = normalizeName(item.name);
  const debName = `python3-${project}-whl`;
  const wheelPrefix = `${project.replaceAll('-', '_')}-${item.version}-`.toLowerCase();
  const versions = (await distro.archive.versions(debName, distro.arch))
    .filter(version => version.replace(/^\d+:/, '').startsWith(item.version) && /^[+~-]/.test(version.replace(/^\d+:/, '').slice(item.version.length)));
  for (const version of versions) {
    const layout = await store.memo(`pypi-distro-wheel:v1:${distro.archive.cacheKey()}:${debName}_${version}:${wheelPrefix}`, async () => {
      const wheels = await distro.archive.contents(debName, version, distro.arch, file => file.startsWith('/usr/share/python-wheels/') && path.posix.basename(file).toLowerCase().startsWith(wheelPrefix) && file.endsWith('.whl'));
      return wheels.size === 1 ? installLayout(readZipFiles([...wheels.values()][0])) : null;
    });
    const comparison = layout && compareDistribution(item, layout);
    if (comparison && comparison.modified.length === 0 && comparison.missing.length === 0 && comparison.added.length === 0) {
      return {label: `${debName} ${version}`, comparison};
    }
  }

  return null;
}

/**
 * Compare one installed distribution with the wheel the lockfile pins (or,
 * for a seed package it leaves out, the registry's).
 * @returns {Promise<{result: Object, bytecode: string[]}>}
 */
async function appraiseDistribution(item, entry, store) {
  const none = result => ({result: {...result, item}, bytecode: []});
  const pinned = entry ? entry.files : null;
  if (entry && pinned.length === 0) {
    return none({status: 'unverifiable', reason: 'the lockfile pins no hashes for this package'});
  }

  let files;
  try {
    files = await candidates(store, item.name, item.version, pinned);
  } catch (error) {
    return none({status: 'error', reason: `could not list its files: ${error.message}`});
  }

  // The installed WHEEL file is the wheel's own, so its tags name the
  // file that was installed; wheels whose file names abbreviate the tags
  // differently are matched by overlap when only one overlaps.
  const tags = item.meta.tags.join(' ');
  const wheels = files.filter(file => !file.sdist && wheelTags(file.name));
  const overlapping = wheels.filter(file => wheelTags(file.name).some(tag => item.meta.tags.includes(tag)));
  const wheel = wheels.find(file => wheelTags(file.name).join(' ') === tags) || (overlapping.length === 1 ? overlapping[0] : null);
  if (!wheel) {
    // The candidates, not the lockfile's entries: hash-only pins
    // (requirements files, Pipfile.lock) do not say which is a source
    // distribution, the registry's listing does.
    return files.some(file => file.sdist)
      ? none({status: 'unverifiable', reason: 'built on the server from a source distribution (no pinned wheel matches the installed tags)'})
      : none({status: 'failed', reason: `no pinned wheel matches the installed tags ${tags}`});
  }

  let layout;
  try {
    layout = await wheelManifest(store, wheel);
  } catch (error) {
    return none({status: /does not match/.test(error.message) ? 'failed' : 'error', reason: error.message});
  }

  const comparison = compareDistribution(item, layout);
  const bytecode = comparison.bytecode.map(file => `${item.path}: ${file}`);
  if (comparison.modified.length > 0 || comparison.missing.length > 0 || comparison.added.length > 0) {
    return {
      result: {
        status: 'failed', item, reason: 'files differ from the pinned wheel', modified: comparison.modified, missing: comparison.missing, added: comparison.added,
      },
      bytecode,
    };
  }

  return {result: {status: 'verified', item, note: entry ? undefined : 'registry'}, bytecode};
}

/**
 * Compare a site-packages scan with the lockfile.
 *
 * @param {Object} input
 * @param {Object} input.scan - from scan()
 * @param {Object|null} input.lock - from readLock(), or null when there is none
 * @param {import('./common').ReferenceStore} input.store
 * @param {{archive: Object, arch: string}} [input.distro] - the host's Debian or Ubuntu archive (an ArchiveReference) and dpkg architecture, for the pip and setuptools its `python3 -m venv` seeds
 * @returns {Promise<Object>} comparison (see ./common)
 */
async function compare({scan: installed, lock, store, distro}) {
  const issues = [];
  const bytecode = [];
  const results = await parallelMap(installed.packages.map(item => async () => {
    if (item.invalid) {
      return {status: 'failed', item, reason: (item.meta && item.meta.reason) || 'missing or unreadable METADATA or RECORD'};
    }

    const entries = lock ? lock.packages.get(normalizeName(item.name)) || [] : [];
    const entry = entries.find(candidate => normalizeVersion(candidate.version) === normalizeVersion(item.version));
    const seed = !entry && SEED_PACKAGES.has(normalizeName(item.name));
    if (!entry && !seed) {
      return {status: 'failed', item, reason: lock ? 'installed package is not pinned by the lockfile' : 'no lockfile pins this package'};
    }

    const appraised = await appraiseDistribution(item, entry, store);
    if (seed && distro && appraised.result.status !== 'verified') {
      let matched;
      try {
        matched = await distroWheel(distro, store, item);
      } catch (error) {
        return {status: 'error', item, reason: `could not compare it with the distribution's wheel: ${error.message}`};
      }

      if (matched) {
        bytecode.push(...matched.comparison.bytecode.map(file => `${item.path}: ${file}`));
        return {status: 'verified', item, note: matched.label};
      }
    }

    bytecode.push(...appraised.bytecode);
    return appraised.result;
  }), store.concurrency);

  const distribution = results.filter(result => result.status === 'verified' && result.note && result.note !== 'registry').map(result => `${result.item.name}==${result.item.version} (${result.note})`);
  if (distribution.length > 0) {
    issues.push({severity: 'info', message: 'Packages the environment tool installed (not in the lockfile) match the distribution\'s patched wheels in its signed archive', items: distribution});
  }

  const unpinned = results.filter(result => result.status === 'verified' && result.note === 'registry').map(result => `${result.item.name}==${result.item.version}`);
  if (unpinned.length > 0) {
    issues.push({severity: 'info', message: 'Packages the environment tool installed (not in the lockfile) match their registry release', items: unpinned});
  }

  const cacheFiles = installed.caches.flatMap(cache => cache.files.map(file => `${cache.path}/${file}`));
  const foreign = cacheFiles.filter(file => !file.endsWith('.pyc'));
  if (foreign.length > 0) {
    issues.push({severity: 'fail', message: 'Files in bytecode cache directories that are not bytecode', items: foreign});
  }

  if (bytecode.length > 0 || cacheFiles.length > foreign.length) {
    issues.push({severity: 'warn', message: 'Python bytecode (.pyc) cannot be verified; install without compiling and run with PYTHONDONTWRITEBYTECODE=1 to avoid it', items: [...bytecode, ...cacheFiles.filter(file => file.endsWith('.pyc'))]});
  }

  await appraiseEnvironment(installed, issues, store);
  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

/**
 * Files outside any distribution: site-packages strays, the environment
 * creator's start-up hook, and bin/.
 */
async function appraiseEnvironment(installed, issues, store) {
  const claimedBin = new Set();
  for (const item of installed.packages) {
    for (const file of Object.keys(item.files || {})) {
      const match = file.match(/^(?:\.{2}\/){3}bin\/([^/]+)$/);
      if (match) {
        claimedBin.add(match[1]);
      }
    }
  }

  const venv = installed.meta && installed.meta.venv;
  let strays = installed.unaccounted;
  if (venv) {
    strays = strays.filter(file => file !== '_virtualenv.py' && file !== '_virtualenv.pth');
    if (venv['_virtualenv.py'] !== undefined || venv['_virtualenv.pth'] !== undefined) {
      try {
        const expected = await virtualenvHook(store, venv.cfg);
        const pth = Buffer.from(venv['_virtualenv.pth'] || '', 'base64').toString('utf8').trim();
        const module = sha256(Buffer.from(venv['_virtualenv.py'] || '', 'base64'));
        if (pth === 'import _virtualenv' && module === expected) {
          issues.push({severity: 'info', message: 'The environment\'s start-up hook (_virtualenv) matches its creator\'s release', items: [venv.cfg.uv ? `uv ${venv.cfg.uv}` : `virtualenv ${venv.cfg.virtualenv}`]});
        } else {
          issues.push({severity: 'fail', message: 'The environment\'s start-up hook (_virtualenv.pth, _virtualenv.py) differs from its creator\'s release', items: ['_virtualenv.pth', '_virtualenv.py']});
        }
      } catch (error) {
        // The hook runs in every Python process: unchecked is not a pass.
        issues.push({severity: 'fail', message: `Could not check the environment's start-up hook against its creator's release: ${error.message}`, items: ['_virtualenv.py']});
      }
    }

    const unexplained = [];
    const informational = [];
    for (const [name, hash] of Object.entries(venv.bin)) {
      if (claimedBin.has(name)) {
        continue;
      }

      if (ACTIVATION.test(name) || (INTERPRETER.test(name) && hash.startsWith('symlink:'))) {
        informational.push(name);
      } else {
        unexplained.push(`bin/${name}`);
      }
    }

    if (unexplained.length > 0) {
      issues.push({severity: 'fail', message: 'Files in the environment\'s bin directory that no installed package created', items: unexplained.sort()});
    }

    if (informational.length > 0) {
      issues.push({severity: 'info', message: 'Interpreter links and activation scripts in the environment (not run by the application)', items: informational.sort()});
    }
  }

  if (strays.length > 0) {
    issues.push({severity: 'fail', message: 'Files in site-packages that belong to no installed package (Python runs .pth files and sitecustomize at start-up)', items: strays});
  }
}

/**
 * SHA-256 of the _virtualenv.py the environment's creator writes, from its
 * published source at the version pyvenv.cfg names.
 */
function virtualenvHook(store, cfg) {
  if (cfg.uv && /^[\d.]+$/.test(cfg.uv)) {
    return store.memo(`pypi-virtualenv-hook:uv:${cfg.uv}`, async () => sha256(await store.get(`${store.urls.uvSource || 'https://raw.githubusercontent.com/astral-sh/uv'}/${cfg.uv}/crates/uv-virtualenv/src/_virtualenv.py`, {maxBytes: 1024 * 1024})));
  }

  if (cfg.virtualenv && /^[\d.]+$/.test(cfg.virtualenv)) {
    return store.memo(`pypi-virtualenv-hook:virtualenv:${cfg.virtualenv}`, async () => {
      const files = await candidates(store, 'virtualenv', cfg.virtualenv, null);
      const wheel = files.find(file => /-py3-none-any\.whl$/.test(file.name));
      if (!wheel) {
        throw new Error(`no virtualenv ${cfg.virtualenv} wheel`);
      }

      const buffer = await store.get(wheel.url, {maxBytes: 64 * 1024 * 1024});
      if (sha256(buffer) !== wheel.sha256) {
        throw new Error('virtualenv wheel does not match the registry\'s hash');
      }

      const content = readZipFiles(buffer, {filter: name => name.endsWith('/_virtualenv.py')});
      if (content.size !== 1) {
        throw new Error('_virtualenv.py not found in the virtualenv wheel');
      }

      return sha256([...content.values()][0]);
    });
  }

  return Promise.reject(new Error('pyvenv.cfg names no uv or virtualenv version'));
}

module.exports = {
  name: 'pypi',
  label: 'PyPI',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  // Exposed for tests and other tools.
  normalizeName,
  normalizeVersion,
  parseRequirements,
  wheelTags,
  installLayout,
  scriptEntryPoints,
  isGeneratedScript,
  compareDistribution,
};

/**
 * Attestium - operating system packages (Debian, Ubuntu)
 *
 * The runtime and the shared libraries a process maps usually come from
 * the distribution.  Their reference is the distribution's signed archive:
 *
 *   attester  finds which installed package owns each file (the dpkg
 *             database), and reports the owner with the file's hash
 *   verifier  checks the archive's InRelease signature with the
 *             distribution's keyring (gpgv), follows the hash chain to the
 *             Packages index and to the .deb, and compares the file with the
 *             one in the package
 *
 * The dpkg database is the server's claim; the package it names must hold
 * the file with the same contents, so a false claim fails.  Files owned by
 * no package are reported as such.
 *
 * Archive indexes may be fetched over plain HTTP: their contents are
 * authenticated by the signature and hashes, not by the transport.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const {execFile, spawn} = require('node:child_process');
const {httpGet} = require('./http');
const {gpgStatusProblem} = require('./checksums');
const {readTar} = require('./tar');
const {sha256, setOwn} = require('./util');

// Maintainer scripts dpkg keeps for installed packages, which it runs when
// they are upgraded or removed.
const SCRIPTS = ['preinst', 'postinst', 'prerm', 'postrm', 'config'];
const MAINTAINER_SCRIPT = new RegExp(`^/var/lib/dpkg/info/([^/]+)\\.(${SCRIPTS.join('|')})$`);

// Top-level directories that are links into /usr on merged-/usr systems.
const MERGED = ['bin', 'sbin', 'lib', 'lib32', 'lib64', 'libx32'];

/**
 * The paths dpkg may have recorded for a file (with and without /usr).
 * @param {string} file
 * @returns {string[]}
 */
function aliases(file) {
  const result = [file];
  for (const directory of MERGED) {
    if (file.startsWith(`/usr/${directory}/`)) {
      result.push(file.slice(4));
    } else if (file.startsWith(`/${directory}/`)) {
      result.push(`/usr${file}`);
    }
  }

  return result;
}

/**
 * Parse Debian control stanzas (dpkg status, Packages indexes).
 * @param {string} text
 * @returns {Object<string, string>[]}
 */
function parseStanzas(text) {
  const stanzas = [];
  let current = {};
  let last = null;
  for (const line of text.split('\n')) {
    if (line === '') {
      if (Object.keys(current).length > 0) {
        stanzas.push(current);
      }

      current = {};
      last = null;
    } else if (/^\s/.test(line) && last) {
      current[last] += `\n${line.trim()}`;
    } else {
      const colon = line.indexOf(':');
      if (colon > 0) {
        last = line.slice(0, colon);
        current[last] = line.slice(colon + 1).trim();
      }
    }
  }

  if (Object.keys(current).length > 0) {
    stanzas.push(current);
  }

  return stanzas;
}

/**
 * The dpkg database: installed packages and which one owns each file.
 */
class DpkgDatabase {
  /**
   * @param {Object} [options]
   * @param {string} [options.root='/'] - the filesystem root (a container's, through /proc/<pid>/root)
   */
  constructor(options = {}) {
    this.root = options.root || '/';
    this._owners = null;
    this._packages = null;
  }

  available() {
    try {
      fs.statSync(path.join(this.root, 'var/lib/dpkg/status'));
      return true;
    } catch {
      return false;
    }
  }

  packages() {
    if (!this._packages) {
      this._packages = new Map();
      for (const stanza of parseStanzas(fs.readFileSync(path.join(this.root, 'var/lib/dpkg/status'), 'utf8'))) {
        if (/\binstalled$/.test(stanza.Status || '') && stanza.Package) {
          const key = stanza['Multi-Arch'] === 'same' ? `${stanza.Package}:${stanza.Architecture}` : stanza.Package;
          this._packages.set(key, {
            name: stanza.Package, version: stanza.Version, arch: stanza.Architecture, source: stanza.Source ? stanza.Source.split(' ')[0] : null,
          });
        }
      }
    }

    return this._packages;
  }

  owners() {
    if (!this._owners) {
      this._owners = new Map();
      const info = path.join(this.root, 'var/lib/dpkg/info');
      let names = [];
      try {
        names = fs.readdirSync(info).filter(name => name.endsWith('.list'));
      } catch {}

      for (const name of names) {
        const key = name.slice(0, -5);
        for (const line of fs.readFileSync(path.join(info, name), 'utf8').split('\n')) {
          if (line.startsWith('/') && !this._owners.has(line)) {
            this._owners.set(line, key);
          }
        }
      }
    }

    return this._owners;
  }

  /**
   * The installed package that owns a file.
   * @param {string} file - absolute path (as the process sees it)
   * @returns {{name: string, version: string, arch: string, source: string|null, listedAs: string}|null}
   */
  ownerOf(file) {
    // A maintainer script dpkg keeps (and runs) for an installed package:
    // named in the package's control archive, as dpkg-deb unpacks it.
    const script = MAINTAINER_SCRIPT.exec(file);
    const candidates = script ? [[script[1], `/DEBIAN/${script[2]}`]] : aliases(file).map(candidate => [this.owners().get(candidate), candidate]);
    for (const [key, candidate] of candidates) {
      const installed = key && (this.packages().get(key) || this.packages().get(key.split(':')[0]));
      if (installed) {
        // When it was installed: the archive's snapshot from then holds
        // a version that has since been superseded.
        let installedAt = null;
        try {
          installedAt = fs.statSync(path.join(this.root, 'var/lib/dpkg/info', `${key}.list`)).mtime.toISOString();
        } catch {}

        return {...installed, listedAs: candidate, installedAt};
      }
    }

    return null;
  }
}

/**
 * The /etc/os-release of a root.
 * @param {string} [root='/']
 * @returns {{id: string|null, versionId: string|null, codename: string|null}|null}
 */
function osRelease(root = '/') {
  for (const file of ['etc/os-release', 'usr/lib/os-release']) {
    try {
      const values = {};
      for (const line of fs.readFileSync(path.join(root, file), 'utf8').split('\n')) {
        const match = line.match(/^([A-Z_]+)=(?:"([^"]*)"|(.*))$/);
        if (match) {
          values[match[1]] = match[2] ?? match[3];
        }
      }

      return {id: values.ID || null, versionId: values.VERSION_ID || null, codename: values.VERSION_CODENAME || null};
    } catch {}
  }

  return null;
}

// ─── verifier ──────────────────────────────────────────────────────────

/**
 * The archives a distribution release installs from, by default.
 * @param {{id: string, codename: string}} release
 * @param {string} arch - dpkg architecture
 * @returns {Array<{url: string, suites: string[], components: string[], keyring: string}>}
 */
function defaultArchives(release, arch) {
  if (release.id === 'ubuntu') {
    const url = arch === 'amd64' || arch === 'i386' ? 'http://archive.ubuntu.com/ubuntu' : 'http://ports.ubuntu.com/ubuntu-ports';
    return [{
      url,
      suites: [release.codename, `${release.codename}-updates`, `${release.codename}-security`],
      components: ['main', 'restricted', 'universe', 'multiverse'],
      keyring: '/usr/share/keyrings/ubuntu-archive-keyring.gpg',
      snapshot: url.includes('ports') ? 'https://snapshot.ubuntu.com/ubuntu-ports' : 'https://snapshot.ubuntu.com/ubuntu',
    }];
  }

  if (release.id === 'debian') {
    return [
      {
        url: 'http://deb.debian.org/debian', suites: [release.codename, `${release.codename}-updates`], components: ['main', 'contrib', 'non-free', 'non-free-firmware'], keyring: '/usr/share/keyrings/debian-archive-keyring.gpg', snapshot: 'https://snapshot.debian.org/archive/debian',
      },
      {
        url: 'http://deb.debian.org/debian-security', suites: [`${release.codename}-security`], components: ['main', 'contrib', 'non-free', 'non-free-firmware'], keyring: '/usr/share/keyrings/debian-archive-keyring.gpg', snapshot: 'https://snapshot.debian.org/archive/debian-security',
      },
    ];
  }

  return [];
}

/**
 * @param {string} command
 * @param {string[]} args
 * @returns {Promise<{stdout: Buffer, stderr: Buffer}>}
 */
function run(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, {encoding: 'buffer', maxBuffer: 2 * 1024 * 1024 * 1024, timeout: 300_000}, (error, stdout, stderr) => {
      if (error) {
        // Stderr is a Buffer, truthy even when empty.
        const detail = stderr.length > 0 ? stderr.toString('utf8') : error.message;
        error.message = `${command} failed: ${detail.trim().split('\n').pop()}`;
        reject(error);
        return;
      }

      resolve({stdout, stderr});
    });
  });
}

/**
 * Run gpgv with its status lines on a descriptor of their own (3): stdout
 * carries the signed text, and stderr carries messages that may quote what
 * was signed, so neither can pass for a status line.
 *
 * @param {string} command
 * @param {string[]} args - without --status-fd
 * @returns {Promise<{stdout: Buffer, status: string}>}
 */
function runGpgv(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, ['--status-fd', '3', ...args], {stdio: ['ignore', 'pipe', 'pipe', 'pipe']});
    // Not spawn's timeout option: Node 18 keeps its timer after a failed spawn.
    /* c8 ignore next - five minutes */
    const timer = setTimeout(() => child.kill('SIGKILL'), 300_000);
    const output = [[], [], []];
    for (const [index, stream] of [child.stdout, child.stderr, child.stdio[3]].entries()) {
      stream.on('data', chunk => output[index].push(chunk));
    }

    child.on('error', error => {
      error.message = `${command} failed: ${error.message}`;
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const [stdout, stderr, status] = output.map(chunks => Buffer.concat(chunks));
      if (code === 0) {
        resolve({stdout, status: status.toString('utf8')});
        return;
      }

      const lines = stderr.toString('utf8').split('\n').map(line => line.trim()).filter(Boolean);
      reject(new Error(`${command} failed: ${lines.length > 0 ? lines.pop() : (signal ? `killed by ${signal}` : `exit code ${code}`)}`));
    });
  });
}

class ArchiveReference {
  /**
   * @param {Object} options
   * @param {Array<{url: string, suites: string[], components: string[], keyring: string}>} options.archives
   * @param {Object} options.store - ReferenceStore (cache and HTTP options)
   * @param {string} [options.gpgv='gpgv']
   * @param {string} [options.dpkgDeb='dpkg-deb']
   */
  constructor({archives, store, gpgv = 'gpgv', dpkgDeb = 'dpkg-deb'}) {
    this.archives = archives;
    this.store = store;
    this.gpgv = gpgv;
    this.dpkgDeb = dpkgDeb;
    this._indexes = new Map();
  }

  _get(url, maxBytes) {
    return httpGet(url, {...this.store.httpOptions, maxBytes, allowHttp: true});
  }

  /**
   * The signed release file of a suite: {hashes: Map<path, {sha256, size}>}.
   */
  async _release(archive, suite) {
    const text = await this._get(`${archive.url}/dists/${suite}/InRelease`, 64 * 1024 * 1024);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-apt-'));
    let signed;
    try {
      const file = path.join(directory, 'InRelease');
      fs.writeFileSync(file, text);
      // Its own home directory (only the archive's keyring, no user
      // configuration), and its status lines read: gpgv exits with 0 for a
      // signature by a revoked or expired key, so its exit status alone is
      // not enough.
      const {stdout, status} = await runGpgv(this.gpgv, ['--homedir', directory, '--quiet', '--keyring', path.resolve(archive.keyring), '--output', '-', file]);
      const problem = gpgStatusProblem(status);
      if (problem) {
        throw new Error(`${archive.url}/dists/${suite}/InRelease does not verify (gpgv): ${problem}`);
      }

      signed = stdout.toString('utf8');
    } finally {
      fs.rmSync(directory, {recursive: true, force: true});
    }

    const hashes = new Map();
    const release = parseStanzas(signed)[0] || {};
    for (const line of String(release.SHA256 || '').split('\n')) {
      const match = line.trim().match(/^([\da-f]{64})\s+(\d+)\s+(\S+)$/);
      if (match) {
        hashes.set(match[3], {sha256: match[1], size: Number(match[2])});
      }
    }

    return {hashes, date: release.Date || null};
  }

  /**
   * Every package in one suite/component/architecture, name -> versions.
   */
  _index(archive, suite, component, arch) {
    const key = `${archive.url}|${suite}|${component}|${arch}`;
    if (!this._indexes.has(key)) {
      this._indexes.set(key, (async () => {
        const release = await this.store.memo(`apt-release:v1:${archive.url}/${suite}`, () => this._release(archive, suite).then(result => ({hashes: [...result.hashes], date: result.date})), {persist: false});
        const hashes = new Map(release.hashes);
        const name = `${component}/binary-${arch}/Packages.gz`;
        const expected = hashes.get(name);
        if (!expected) {
          return new Map();
        }

        const compressed = await this._get(`${archive.url}/dists/${suite}/${name}`, 512 * 1024 * 1024);
        if (sha256(compressed) !== expected.sha256) {
          throw new Error(`${suite}/${name} does not match the signed release file`);
        }

        const packages = new Map();
        for (const stanza of parseStanzas(zlib.gunzipSync(compressed).toString('utf8'))) {
          const list = packages.get(stanza.Package) || [];
          list.push({
            version: stanza.Version, arch: stanza.Architecture, filename: stanza.Filename, sha256: stanza.SHA256,
          });
          packages.set(stanza.Package, list);
        }

        return packages;
      })());
      this._indexes.get(key).catch(() => this._indexes.delete(key));
    }

    return this._indexes.get(key);
  }

  /**
   * Where a package version is published: the archive and its pool entry.
   * A version no longer in the archives is looked up in their snapshots
   * from the time it was installed.
   *
   * @param {string} name
   * @param {string} version
   * @param {string} arch
   * @param {string|null} [installedAt] - ISO time
   * @returns {Promise<{url: string, filename: string, sha256: string}|null>}
   */
  async locate(name, version, arch, installedAt = null) {
    const current = await this._locateIn(this.archives, name, version, arch);
    if (current || !installedAt) {
      return current;
    }

    // The next whole hour, so packages installed together share snapshots
    // (and their indexes are fetched once).
    const time = Math.ceil(Date.parse(installedAt) / 3_600_000) * 3_600_000;
    for (const offset of [0, 86_400_000]) {
      const stamp = new Date(time + offset).toISOString().replaceAll(/[-:]|\.\d+/g, '');
      const snapshots = this.archives.filter(archive => archive.snapshot).map(archive => ({...archive, url: `${archive.snapshot}/${stamp}`}));
      const found = await this._locateIn(snapshots, name, version, arch);
      if (found) {
        return found;
      }
    }

    return null;
  }

  /**
   * Each package index of the archives that lists an architecture's
   * packages (architecture-independent ones are in every index).
   */
  async * _eachIndex(archives, arch) {
    for (const archive of archives) {
      for (const suite of archive.suites) {
        for (const component of archive.components) {
          for (const indexArch of arch === 'all' ? ['amd64', 'arm64'] : [arch]) {
            let index;
            try {
              index = await this._index(archive, suite, component, indexArch);
            } catch (error) {
              if (error.statusCode === 404) {
                continue;
              }

              throw error;
            }

            yield {archive, index};
          }
        }
      }
    }
  }

  async _locateIn(archives, name, version, arch) {
    for await (const {archive, index} of this._eachIndex(archives, arch)) {
      const entry = (index.get(name) || []).find(item => item.version === version && (item.arch === arch || item.arch === 'all'));
      if (entry) {
        return {url: `${archive.url}/${entry.filename}`, filename: entry.filename, sha256: entry.sha256};
      }
    }

    return null;
  }

  /**
   * The versions of a package the archives publish for an architecture
   * (not their snapshots).
   * @param {string} name
   * @param {string} arch
   * @returns {Promise<string[]>}
   */
  async versions(name, arch) {
    const versions = new Set();
    for await (const {index} of this._eachIndex(this.archives, arch)) {
      for (const entry of index.get(name) || []) {
        if (entry.arch === arch || entry.arch === 'all') {
          versions.add(entry.version);
        }
      }
    }

    return [...versions];
  }

  /**
   * A key naming the archives, for caches: distributions publish different
   * builds under one name and version (Ubuntu rebuilds packages it takes
   * from Debian).
   * @returns {string}
   */
  cacheKey() {
    return this.archives.map(archive => `${archive.url} ${archive.keyring}`).join(' ');
  }

  /**
   * A published package's data and control archives (tar), checked against
   * the signed index.
   */
  async _unpack(name, version, arch, installedAt) {
    const location = await this.locate(name, version, arch, installedAt);
    if (!location) {
      throw Object.assign(new Error(`${name} ${version} (${arch}) is not in the configured archives (a superseded version: upgrade, or add an archive snapshot)`), {code: 'ENOTINARCHIVE'});
    }

    const deb = await this._get(location.url, 2 * 1024 * 1024 * 1024);
    if (sha256(deb) !== location.sha256) {
      throw new Error(`${location.filename} does not match the archive's index`);
    }

    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-deb-'));
    try {
      const file = path.join(directory, 'package.deb');
      fs.writeFileSync(file, deb);
      const {stdout: data} = await run(this.dpkgDeb, ['--fsys-tarfile', file]);
      const {stdout: control} = await run(this.dpkgDeb, ['--ctrl-tarfile', file]);
      return {data, control};
    } finally {
      fs.rmSync(directory, {recursive: true, force: true});
    }
  }

  /**
   * The contents of a published package's regular files that a filter
   * selects, path -> Buffer (paths absolute).
   * @param {string} name
   * @param {string} version
   * @param {string} arch
   * @param {(file: string) => boolean} wanted
   * @returns {Promise<Map<string, Buffer>>}
   */
  async contents(name, version, arch, wanted) {
    const {data} = await this._unpack(name, version, arch, null);
    const contents = new Map();
    for (const entry of readTar(data)) {
      const member = `/${entry.name.replace(/^\.?\//, '')}`;
      if (entry.type === '0' && wanted(member)) {
        contents.set(member, entry.data);
      }
    }

    return contents;
  }

  /**
   * File hashes of a published package, path -> sha256 (paths absolute).
   * @param {string} name
   * @param {string} version
   * @param {string} arch
   * @param {string|null} [installedAt]
   * @returns {Promise<Object<string, string>>}
   */
  async files(name, version, arch, installedAt = null) {
    return this.store.memo(`apt-deb:v3:${this.cacheKey()}:${name}_${version}_${arch}`, async () => {
      const {data, control} = await this._unpack(name, version, arch, installedAt);
      const files = {};
      for (const entry of readTar(data)) {
        const member = `/${entry.name.replace(/^\.?\//, '')}`;
        switch (entry.type) {
          case '0': {
            setOwn(files, member, sha256(entry.data));
            break;
          }

          case '1': {
            // A hard link to an earlier member (Debian packages have them).
            const target = `/${entry.linkName.replace(/^\.?\//, '')}`;
            if (Object.hasOwn(files, target)) {
              setOwn(files, member, files[target]);
            }

            break;
          }

          case '2': {
            setOwn(files, member, `symlink:${entry.linkName}`);
            break;
          }

          // No default
        }
      }

      // Maintainer scripts, as /DEBIAN/<name> (the owner's listedAs).
      for (const entry of readTar(control)) {
        const name = entry.name.replace(/^\.?\//, '');
        if (entry.type === '0' && SCRIPTS.includes(name)) {
          setOwn(files, `/DEBIAN/${name}`, sha256(entry.data));
        }
      }

      return files;
    });
  }
}

module.exports = {
  DpkgDatabase,
  ArchiveReference,
  parseStanzas,
  aliases,
  osRelease,
  defaultArchives,
};

'use strict';

/**
 * Fixtures backed by real system tools: GnuPG-signed Debian archives built
 * with dpkg-deb, dpkg databases, Docker containers, a local OCI registry
 * serving an image from `docker save`, and a software TPM with an EK
 * certificate from swtpm's local CA.
 */

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const {execFileSync, spawn} = require('node:child_process');
const {
  tempDir, writeFiles, which, freePort, sleep,
} = require('./helpers');

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');

const hasDebianTools = process.platform === 'linux' && which('gpg') && which('gpgv') && which('dpkg-deb');

/**
 * Whether a Docker daemon answers (asked once, when a test file needs it).
 */
let dockerAnswers;
function hasDocker() {
  if (dockerAnswers === undefined) {
    dockerAnswers = process.platform === 'linux' && which('docker') && (() => {
      try {
        execFileSync('docker', ['info'], {stdio: 'ignore', timeout: 20_000});
        return true;
      } catch {
        return false;
      }
    })();
  }

  return dockerAnswers;
}

const hasTpmCertificates = process.platform === 'linux' && which('swtpm') && which('swtpm_setup') && which('tpm2_createek') && which('tpm2_nvread');

/**
 * Run a command without blocking the event loop (a server in this process
 * may have to answer it).
 * @returns {Promise<string>} stdout
 */
function runAsync(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {stdio: ['ignore', 'pipe', 'pipe'], ...options});
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => {
      stdout += chunk;
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', code => (code === 0 ? resolve(stdout) : reject(new Error(`${command} exited with ${code}: ${stderr.trim()}`))));
  });
}

// ─── Debian archives ────────────────────────────────────────────────────

/**
 * A throwaway GnuPG signing key.
 * @returns {{home: string, keyring: string, clearsign(file: string, output: string): void}}
 */
function makeGpgKey(t, options = {}) {
  const home = tempDir(t, 'attestium-gpg-');
  fs.chmodSync(home, 0o700);
  // An expiring key is made, and signs, at a faked time in the past.
  const time = options.expired ? ['--faked-system-time', '20200101T000000'] : [];
  const gpg = args => execFileSync('gpg', ['--homedir', home, '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '', ...time, ...args], {stdio: ['ignore', 'pipe', 'pipe']});
  gpg(['--quick-gen-key', 'Test Signer <signer@example.com>', 'ed25519', 'sign', options.expired ? '1d' : 'never']);
  const keyring = path.join(home, 'signer.gpg');
  fs.writeFileSync(keyring, gpg(['--export']));
  t.after(() => {
    try {
      execFileSync('gpgconf', ['--homedir', home, '--kill', 'all'], {stdio: 'ignore'});
    } catch {}
  });
  return {
    home,
    keyring,
    clearsign(file, output) {
      gpg(['--clearsign', '--output', output, file]);
    },
    // Revoke the key (with the certificate gpg made with it) and export it again.
    revoke() {
      const fingerprint = gpg(['--list-keys', '--with-colons']).toString().match(/^fpr:+([\dA-F]{40}):/m)[1];
      const certificate = fs.readFileSync(path.join(home, 'openpgp-revocs.d', `${fingerprint}.rev`), 'utf8').replace(/^:-{5}BEGIN/m, '-----BEGIN');
      fs.writeFileSync(path.join(home, 'revocation.asc'), certificate);
      gpg(['--import', path.join(home, 'revocation.asc')]);
      fs.writeFileSync(keyring, gpg(['--export']));
    },
  };
}

/**
 * Build a .deb with dpkg-deb.
 * @param {Object} item - {name, version, arch, files: {path: content}, symlinks: {path: target}}
 * @returns {Buffer}
 */
function buildDeb(t, item) {
  const staging = tempDir(t, 'attestium-deb-');
  writeFiles(staging, {'DEBIAN/control': `Package: ${item.name}\nVersion: ${item.version}\nArchitecture: ${item.arch}\nMaintainer: Test <test@example.com>\nDescription: test\n`});
  for (const [file, content] of Object.entries(item.files || {})) {
    writeFiles(staging, {[file.replace(/^\//, '')]: content});
  }

  // Maintainer scripts (postinst, ...), which dpkg-deb requires to be executable.
  for (const [name, content] of Object.entries(item.scripts || {})) {
    writeFiles(staging, {[`DEBIAN/${name}`]: content});
    fs.chmodSync(path.join(staging, 'DEBIAN', name), 0o755);
  }

  for (const [link, target] of Object.entries(item.symlinks || {})) {
    const full = path.join(staging, link.replace(/^\//, ''));
    fs.mkdirSync(path.dirname(full), {recursive: true});
    fs.symlinkSync(target, full);
  }

  const output = path.join(tempDir(t, 'attestium-deb-out-'), 'package.deb');
  execFileSync('dpkg-deb', ['--build', '--root-owner-group', staging, output], {stdio: 'ignore'});
  return fs.readFileSync(output);
}

/**
 * Write a signed suite of a Debian archive under `root`: pool entries,
 * dists/<suite>/<component>/binary-<arch>/Packages.gz and a clearsigned
 * dists/<suite>/InRelease listing them.
 *
 * @param {import('node:test').TestContext} t
 * @param {Object} input
 * @param {string} input.root
 * @param {Object} input.key - from makeGpgKey
 * @param {string} [input.suite='test']
 * @param {string} [input.component='main']
 * @param {Array<Object>} input.packages - for buildDeb; each may set indexArch (default: its arch)
 * @param {string} [input.release] - the Release text to sign instead of the generated one
 */
function writeAptSuite(t, {root, key, suite = 'test', component = 'main', packages, release}) {
  const byArch = new Map();
  for (const item of packages) {
    const deb = item.deb || buildDeb(t, item);
    const filename = `pool/${component}/${item.name}_${item.version}_${item.arch}.deb`;
    writeFiles(root, {[filename]: deb});
    const indexArch = item.indexArch || item.arch;
    const stanzas = byArch.get(indexArch) || [];
    stanzas.push(`Package: ${item.name}\nVersion: ${item.version}\nArchitecture: ${item.arch}\nFilename: ${filename}\nSize: ${deb.length}\nSHA256: ${item.indexSha256 || sha256(deb)}\n`);
    byArch.set(indexArch, stanzas);
  }

  const lines = [];
  for (const [arch, stanzas] of byArch) {
    const gz = zlib.gzipSync(stanzas.join('\n'));
    const indexPath = `${component}/binary-${arch}/Packages.gz`;
    writeFiles(root, {[`dists/${suite}/${indexPath}`]: gz});
    lines.push(` ${sha256(gz)} ${gz.length} ${indexPath}`);
  }

  const releaseFile = path.join(root, 'dists', suite, 'Release');
  fs.mkdirSync(path.dirname(releaseFile), {recursive: true});
  fs.writeFileSync(releaseFile, release ?? `Suite: ${suite}\nDate: ${new Date().toUTCString()}\nSHA256:\n${lines.join('\n')}\n`);
  key.clearsign(releaseFile, path.join(root, 'dists', suite, 'InRelease'));
}

/**
 * Serve a directory over HTTP (404 for anything missing).
 * @returns {Promise<{url: string, requests: string[]}>}
 */
async function serveDirectory(t, root) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    const file = path.join(root, decodeURIComponent(request.url.split('?')[0]));
    let body;
    try {
      body = file.startsWith(`${root}/`) ? fs.readFileSync(file) : null;
    } catch {}

    if (!body) {
      response.writeHead(404);
      response.end();
      return;
    }

    response.writeHead(200, {'content-length': body.length});
    response.end(body);
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  return {url: `http://127.0.0.1:${server.address().port}`, requests};
}

/**
 * A dpkg database root saying which package owns which files.
 * @param {Array<{name: string, version: string, arch: string, files: string[], multiArch?: string, source?: string, status?: string}>} packages
 * @returns {string} the root
 */
function makeDpkgRoot(t, packages) {
  const root = tempDir(t, 'attestium-dpkg-');
  const status = packages.map(item => [
    `Package: ${item.name}`,
    `Status: ${item.status || 'install ok installed'}`,
    `Architecture: ${item.arch}`,
    item.multiArch ? `Multi-Arch: ${item.multiArch}` : null,
    item.source ? `Source: ${item.source}` : null,
    `Version: ${item.version}`,
    'Description: test package',
    ' with a continuation line',
  ].filter(Boolean).join('\n')).join('\n\n');
  writeFiles(root, {'var/lib/dpkg/status': `${status}\n`});
  for (const item of packages) {
    const list = item.multiArch === 'same' ? `${item.name}:${item.arch}` : item.name;
    writeFiles(root, {[`var/lib/dpkg/info/${list}.list`]: `/.\n${item.files.join('\n')}\n`});
  }

  return root;
}

// ─── Docker and OCI ─────────────────────────────────────────────────────

/**
 * Start a container for a test and remove it afterwards.
 * @returns {Promise<{id: string, name: string, pid: number}>}
 */
async function startContainer(t, args) {
  const name = `attestium-test-${crypto.randomBytes(4).toString('hex')}`;
  t.after(() => {
    try {
      execFileSync('docker', ['rm', '-f', name], {stdio: 'ignore'});
    } catch {}
  });
  const id = (await runAsync('docker', ['run', '-d', '--name', name, ...args])).trim();
  let pid = 0;
  for (let attempt = 0; attempt < 100 && !pid; attempt++) {
    pid = Number((await runAsync('docker', ['inspect', '-f', '{{.State.Pid}}', name])).trim());
    if (!pid) {
      await sleep(50);
    }
  }

  return {id, name, pid};
}

/**
 * A local OCI registry serving one image (from `docker save`), with
 * referrers that tests can add.
 *
 * @param {import('node:test').TestContext} t
 * @param {string} image - a local image, such as alpine:3.20
 * @param {Object} [options]
 * @param {Object<string, Buffer>} [options.replace] - blob digest -> other content (a tampered registry)
 * @param {boolean} [options.bearer] - require a bearer token from /token
 * @param {{username: string, password: string}} [options.basic] - credentials /token requires
 * @param {(host: string) => string} [options.challenge] - WWW-Authenticate value to send instead of the default
 * @param {'token'|'access_token'|'none'} [options.tokenField='token']
 * @param {boolean} [options.noReferrers] - answer 404 for the referrers API
 */
async function startRegistry(t, image, options = {}) {
  const directory = tempDir(t, 'attestium-registry-');
  execFileSync('docker', ['save', image, '-o', path.join(directory, 'image.tar')]);
  execFileSync('tar', ['-xf', 'image.tar'], {cwd: directory});
  const blobs = new Map();
  for (const name of fs.readdirSync(path.join(directory, 'blobs', 'sha256'))) {
    blobs.set(`sha256:${name}`, fs.readFileSync(path.join(directory, 'blobs', 'sha256', name)));
  }

  const top = JSON.parse(fs.readFileSync(path.join(directory, 'index.json'), 'utf8')).manifests[0].digest;
  const referrers = new Map();
  const requests = [];
  let issued = 'token-1';
  const server = http.createServer((request, response) => {
    requests.push({url: request.url, authorization: request.headers.authorization || null});
    if (request.url.startsWith('/token')) {
      const expected = options.basic && `Basic ${Buffer.from(`${options.basic.username}:${options.basic.password}`).toString('base64')}`;
      if (expected && request.headers.authorization !== expected) {
        response.writeHead(401);
        response.end();
        return;
      }

      const field = options.tokenField || 'token';
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(field === 'none' ? {} : {[field]: issued}));
      return;
    }

    const authorized = !options.bearer || request.headers.authorization === `Bearer ${issued}`;
    if (!authorized) {
      const challenge = options.challenge ? options.challenge(request.headers.host) : `Bearer realm="http://${request.headers.host}/token",service="test-registry"`;
      response.writeHead(401, challenge ? {'www-authenticate': challenge} : {});
      response.end();
      return;
    }

    if (request.url === '/v2/') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{}');
      return;
    }

    const match = request.url.match(/^\/v2\/(.+?)\/(manifests|blobs|referrers)\/([^/?]+)/);
    if (match && match[2] === 'referrers') {
      if (options.noReferrers) {
        response.writeHead(404);
        response.end();
        return;
      }

      const body = JSON.stringify({schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: referrers.get(match[3]) || []});
      response.writeHead(200, {'content-type': 'application/vnd.oci.image.index.v1+json'});
      response.end(body);
      return;
    }

    const digest = match && match[3];
    const blob = digest && blobs.get(digest);
    if (!blob) {
      response.writeHead(404);
      response.end();
      return;
    }

    const content = (options.replace && options.replace[digest]) || blob;
    response.writeHead(200, {'content-length': content.length, 'docker-content-digest': digest});
    response.end(content);
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  const host = `127.0.0.1:${server.address().port}`;
  const add = content => {
    const digest = `sha256:${sha256(content)}`;
    blobs.set(digest, content);
    return digest;
  };

  return {
    host,
    url: `http://${host}`,
    repository: 'test/app',
    digest: top,
    blobs,
    requests,
    add,
    get token() {
      return issued;
    },
    /** Expire the issued token: requests with it are refused. */
    rotateToken() {
      issued = `token-${Number(issued.slice(6)) + 1}`;
    },
    /** Attach an artifact manifest to a subject as an OCI referrer. */
    addReferrer(subject, {artifactType, layers, descriptorType = artifactType}) {
      const config = Buffer.from('{}');
      const manifest = Buffer.from(JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        artifactType,
        config: {mediaType: 'application/vnd.oci.empty.v1+json', digest: add(config), size: config.length},
        layers: layers && layers.map(layer => ({mediaType: layer.mediaType, digest: add(layer.content), size: layer.content.length})),
      }));
      const digest = add(manifest);
      const list = referrers.get(subject) || [];
      list.push({
        mediaType: 'application/vnd.oci.image.manifest.v1+json', digest, size: manifest.length, artifactType: descriptorType,
      });
      referrers.set(subject, list);
      return digest;
    },
  };
}

// ─── TPM ────────────────────────────────────────────────────────────────

async function portIsFree(port) {
  const net = require('node:net');
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
    return true;
  } catch {
    return false;
  } finally {
    server.close();
  }
}

async function waitForPort(port) {
  const net = require('node:net');
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
          socket.destroy();
          resolve();
        });
        socket.on('error', reject);
      });
      return true;
    } catch {
      await sleep(50);
    }
  }

  return false;
}

/**
 * A software TPM.  With {ekCertificate: true}, swtpm_setup creates the EKs
 * and has swtpm's local CA (a manufacturer stand-in) sign EK certificates,
 * stored in the TPM's NV indexes as a vendor does.
 *
 * @returns {Promise<{tcti: string, ca: {issuer: string, root: string}|null}>}
 */
async function startSwtpm(t, options = {}) {
  const state = tempDir(t, 'attestium-swtpm-');
  let ca = null;
  if (options.ekCertificate) {
    const localca = tempDir(t, 'attestium-localca-');
    const write = (name, text) => {
      fs.writeFileSync(path.join(localca, name), text);
      return path.join(localca, name);
    };

    const caConfig = write('localca.conf', `statedir = ${localca}\nsigningkey = ${localca}/signkey.pem\nissuercert = ${localca}/issuercert.pem\ncertserial = ${localca}/certserial\n`);
    const caOptions = write('localca.options', '--platform-manufacturer Test\n--platform-version 2.1\n--platform-model Test\n');
    const setupConfig = write('setup.conf', `create_certs_tool = ${which('swtpm_localca') ? 'swtpm_localca' : '/usr/share/swtpm/swtpm-localca'}\ncreate_certs_tool_config = ${caConfig}\ncreate_certs_tool_options = ${caOptions}\nactive_pcr_banks = sha256\n`);
    execFileSync('swtpm_setup', ['--tpm2', '--tpmstate', state, '--create-ek-cert', '--config', setupConfig, '--overwrite'], {stdio: 'ignore'});
    ca = {issuer: path.join(localca, 'issuercert.pem'), root: path.join(localca, 'swtpm-localca-rootca-cert.pem')};
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const port = await freePort();
    if (!(await portIsFree(port + 1))) {
      continue;
    }

    const child = spawn('swtpm', ['socket', '--tpm2', '--tpmstate', `dir=${state}`, '--server', `type=tcp,port=${port},bindaddr=127.0.0.1`, '--ctrl', `type=tcp,port=${port + 1},bindaddr=127.0.0.1`, '--flags', 'not-need-init,startup-clear'], {stdio: 'ignore'});
    let exited = false;
    child.once('exit', () => {
      exited = true;
    });
    t.after(() => {
      child.kill('SIGKILL');
    });
    if (await waitForPort(port)) {
      // A simulator that lost a port race exits right away.
      await sleep(100);
      if (!exited) {
        return {tcti: `swtpm:host=127.0.0.1,port=${port}`, ca};
      }
    }

    child.kill('SIGKILL');
  }

  throw new Error('swtpm did not start');
}

module.exports = {
  sha256,
  hasDebianTools,
  hasDocker,
  hasTpmCertificates,
  runAsync,
  makeGpgKey,
  buildDeb,
  writeAptSuite,
  serveDirectory,
  makeDpkgRoot,
  startContainer,
  startRegistry,
  startSwtpm,
};

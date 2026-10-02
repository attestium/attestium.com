'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const {execFileSync, spawn} = require('node:child_process');

/**
 * Temporary directory removed after the test.
 */
function tempDir(t, prefix = 'attestium-test-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => {
    try {
      fs.rmSync(directory, {recursive: true, force: true});
    } catch {
      execFileSync('chmod', ['-R', 'u+rwx', directory]);
      fs.rmSync(directory, {recursive: true, force: true});
    }
  });
  return directory;
}

/**
 * Write a map of relative path -> content under a directory.
 */
function writeFiles(root, files) {
  for (const [relativePath, content] of Object.entries(files)) {
    const full = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(full), {recursive: true});
    fs.writeFileSync(full, content);
  }
}

/**
 * Local HTTP server.  `routes` maps a path to a handler (req, res) or to
 * {status, body, headers}.  Unknown paths get 404.
 */
async function startServer(t, routes = {}) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({url: request.url, headers: request.headers});
    const route = routes[request.url.split('?')[0]];
    if (typeof route === 'function') {
      route(request, response);
      return;
    }

    if (!route) {
      response.writeHead(404);
      response.end('not found');
      return;
    }

    response.writeHead(route.status || 200, route.headers || {});
    response.end(route.body);
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  return {
    url: `http://127.0.0.1:${server.address().port}`, routes, requests, server,
  };
}

/**
 * Build a .tar.gz with the system tar from a map of path -> content.
 * `format` is passed to GNU tar (gnu, pax, ustar).
 */
function makeTarGz(t, files, {format = 'gnu', symlinks = {}} = {}) {
  const staging = tempDir(t, 'attestium-tar-');
  writeFiles(staging, files);
  for (const [link, target] of Object.entries(symlinks)) {
    fs.mkdirSync(path.dirname(path.join(staging, link)), {recursive: true});
    fs.symlinkSync(target, path.join(staging, link));
  }

  const roots = [...new Set([...Object.keys(files), ...Object.keys(symlinks)].map(file => file.split('/')[0]))].sort();
  const output = path.join(tempDir(t, 'attestium-tar-out-'), 'archive.tar.gz');
  execFileSync('tar', ['-czf', output, `--format=${format}`, '-C', staging, ...roots]);
  return fs.readFileSync(output);
}

function which(command) {
  try {
    execFileSync('which', [command], {stdio: 'ignore'});
    return true;
  } catch {
    return false;
  }
}

const hasTpmSimulator = process.platform === 'linux' && which('swtpm') && which('tpm2_quote');

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const {port} = server.address();
  await new Promise(resolve => {
    server.close(resolve);
  });
  return port;
}

/**
 * Start a fresh software TPM (swtpm) for a test file.
 * @returns {Promise<{tcti: string, port: number}>}
 */
async function portIsFree(port) {
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

async function portOpens(port) {
  for (let attempt = 0; attempt < 50; attempt++) {
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
      await new Promise(resolve => {
        setTimeout(resolve, 100);
      });
    }
  }

  return false;
}

/**
 * A software TPM on two consecutive free ports (the swtpm TCTI always uses
 * port + 1 as the control channel), retried when a test running in
 * parallel takes one of them first.
 */
async function startSwtpm(t) {
  const state = tempDir(t, 'attestium-swtpm-');
  for (let attempt = 0; attempt < 10; attempt++) {
    const port = await freePort();
    if (!(await portIsFree(port + 1))) {
      continue;
    }

    const child = spawn('swtpm', [
      'socket',
      '--tpm2',
      '--tpmstate',
      `dir=${state}`,
      '--server',
      `type=tcp,port=${port},bindaddr=127.0.0.1`,
      '--ctrl',
      `type=tcp,port=${port + 1},bindaddr=127.0.0.1`,
      '--flags',
      'not-need-init,startup-clear',
    ], {stdio: 'ignore'});
    let exited = false;
    child.once('exit', () => {
      exited = true;
    });
    t.after(() => {
      child.kill('SIGKILL');
    });
    if (await portOpens(port)) {
      // A simulator that lost a port race exits right away.
      await new Promise(resolve => {
        setTimeout(resolve, 100);
      });
      if (!exited) {
        return {tcti: `swtpm:host=127.0.0.1,port=${port}`, port};
      }
    }

    child.kill('SIGKILL');
  }

  throw new Error('swtpm did not start');
}

const sleep = ms => new Promise(resolve => {
  setTimeout(resolve, ms);
});

module.exports = {
  tempDir,
  writeFiles,
  startServer,
  makeTarGz,
  which,
  hasTpmSimulator,
  startSwtpm,
  freePort,
  sleep,
};

# Getting started

Install Attestium, collect evidence about a directory and a running process on your own machine, check that evidence, and then build a minimal attester and verifier in Node.js that talk over HTTP and compare a deployed directory with a reference.

## Install

```sh
npm install attestium
```

Attestium needs Node.js 18 or later. It runs its checks on Linux; on macOS and Windows, process checks that the platform cannot perform report `supported: false` instead of passing.

Some modules call system tools:

| Feature | Needs |
| --- | --- |
| TPM quotes | A TPM 2.0, [tpm2-tools](https://github.com/tpm2-software/tpm2-tools), access to `/dev/tpmrm0` (usually the `tss` group) |
| Signed Debian and Ubuntu archives, gpg-signed checksum lists | `gpgv`, and `dpkg-deb` for package contents |
| Composer and Bundler git sources | `git` |
| The monitor | `bpftrace`, run as root |

The examples below require the package by name. Run them in a directory where `npm install attestium` has run.

## Collect evidence locally

Two building blocks do most of the collection: `fileTree.walkTree()` hashes a directory, and `ProcessIntegrity` inspects a running process.

```js
const {fileTree, ProcessIntegrity} = require('attestium');

(async () => {
  // Every file under ./app: SHA-256, git mode, symbolic links recorded, never followed.
  const {entries, errors} = await fileTree.walkTree('./app');
  for (const entry of entries) {
    console.log(entry.mode, entry.sha256.slice(0, 12), entry.path);
  }

  console.log(`${errors.length} unreadable`);

  // This process: memory compared with the files it maps, injection
  // vectors, debuggers, open memfd objects, listening sockets.
  const report = new ProcessIntegrity().checkAll(process.pid);
  console.log(report.runtime, report.findings);

  // A clean report means something only when every check ran.
  console.log(report.passed ? 'passed' : 'not passed', report.incomplete);
})();
```

A finding has a severity: `critical` is evidence of tampering (for example code changed in memory, or a preload in `NODE_OPTIONS`), `warning` deserves attention, `info` is context. Checks that could not run are listed in `incomplete`, and `passed` is false while that list is not empty.

## Check evidence

Evidence is a JSON document in the format of [SPEC.md](../SPEC.md). The `evidence` module validates it against the published schema and computes its digest.

```js
const os = require('node:os');
const {evidence, util} = require('attestium');

const nonce = util.generateNonce();
const document = {
  type: evidence.TYPE,
  version: evidence.VERSION,
  nonce,
  collectedAt: new Date().toISOString(),
  attester: {name: 'example-attester', version: '1.0.0'},
  host: {hostname: os.hostname(), kernel: os.release()},
  services: [],
  executables: [],
  libraries: [],
};
document.evidenceDigest = evidence.evidenceDigest(document);

console.log(evidence.validateEvidence(document)); // {valid: true, errors: []}
console.log(evidence.evidenceDigest(document) === document.evidenceDigest); // true

document.host.hostname = 'other';
console.log(evidence.evidenceDigest(document) === document.evidenceDigest); // false
```

## An attester and a verifier

The example below has four files:

*   `attester.js` collects evidence for one directory service: its files, the processes running from it, and the files those processes run and map.
*   `attester-server.js` answers `GET /evidence?nonce=...` with that evidence.
*   `verifier.js` appraises evidence against a reference.
*   `verify.js` sends a fresh nonce, fetches the evidence and prints the result.

The deployed service lives in `./app`. The verifier's reference is `./reference`, a checkout of the commit that should be deployed.

### attester.js

```js
// attester.js
const fs = require('node:fs');
const os = require('node:os');
const {evidence, fileTree, util, ProcessIntegrity} = require('attestium');

async function hashDirectory(root) {
  const {entries, errors} = await fileTree.walkTree(root, {
    exclude: relative => relative === '.git' || relative === 'node_modules',
  });
  const files = {};
  for (const entry of entries) {
    const hash = entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256;
    util.setOwn(files, entry.path, [hash, entry.mode]);
  }

  return {files, fileCount: entries.length, errors};
}

function inspectProcesses(realRoot) {
  const inspector = new ProcessIntegrity();
  const processes = [];
  for (const info of inspector.listProcesses({cwdPrefix: realRoot})) {
    const report = inspector.checkAll(info.pid);
    processes.push({
      pid: Number(info.pid),
      ppid: info.ppid,
      uid: info.uid,
      cwd: info.cwd,
      exe: info.exe,
      exeDeleted: Boolean(info.exeDeleted),
      cmdline: info.cmdline.slice(0, 32).map(argument => argument.slice(0, 512)),
      startTime: new Date(info.startTimeMs).toISOString(),
      runtime: report.runtime,
      integrity: {
        passed: report.passed,
        findings: report.findings.map(finding => ({type: finding.type, severity: finding.severity, detail: String(finding.detail)})),
        incomplete: report.incomplete,
        libraries: report.memoryMaps.libraries || [],
      },
    });
  }

  return processes;
}

async function hashRunningFiles(processes) {
  const executables = new Map();
  const libraries = new Map();
  for (const item of processes) {
    // Read the executable through /proc/<pid>/exe: the file the process
    // runs, even if its path now names another file.
    if (item.exe && !executables.has(item.exe)) {
      executables.set(item.exe, {path: item.exe, container: null, ...await hashOrError(() => fs.promises.readFile(`/proc/${item.pid}/exe`))});
    }

    for (const library of item.integrity.libraries) {
      if (library !== item.exe && !libraries.has(library)) {
        libraries.set(library, {path: library, container: null, ...await hashOrError(() => fs.promises.readFile(library))});
      }
    }
  }

  return {executables: [...executables.values()], libraries: [...libraries.values()]};
}

async function hashOrError(read) {
  try {
    return {sha256: util.sha256(await read())};
  } catch (error) {
    return {error: error.code || error.message};
  }
}

async function collect(nonce, {name, root}) {
  const collectedAt = new Date().toISOString();
  const realRoot = fs.realpathSync(root);
  const processes = inspectProcesses(realRoot);
  const document = {
    type: evidence.TYPE,
    version: evidence.VERSION,
    nonce: util.normalizeNonce(nonce),
    collectedAt,
    attester: {name: 'example-attester', version: '1.0.0', platform: process.platform, arch: process.arch, node: process.version},
    host: {hostname: os.hostname(), kernel: os.release()},
    services: [{
      name,
      kind: 'directory',
      root,
      realRoot,
      git: {commit: null, error: 'not collected'},
      ...await hashDirectory(root),
      installs: [],
      processes,
      userProcesses: [],
    }],
    ...await hashRunningFiles(processes),
  };
  document.evidenceDigest = evidence.evidenceDigest(document);
  return document;
}

module.exports = {collect};
```

`util.normalizeNonce()` throws unless the nonce is 16 to 64 bytes of hex, so a malformed request never reaches the evidence. The digest is computed last, over everything collected.

### attester-server.js

```js
// attester-server.js
const http = require('node:http');
const {collect} = require('./attester');

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (request.method !== 'GET' || url.pathname !== '/evidence') {
    response.writeHead(404).end();
    return;
  }

  try {
    const document = await collect(url.searchParams.get('nonce'), {name: 'app', root: './app'});
    response.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify(document));
  } catch (error) {
    response.writeHead(400, {'content-type': 'application/json'}).end(JSON.stringify({error: error.message}));
  }
});

server.listen(7070, '127.0.0.1');
```

In production, do not expose the attester to the network. Audit Status, for example, runs its attester as the forced command of a dedicated SSH key.

### verifier.js

```js
// verifier.js
const {evidence} = require('attestium');

function appraise(document, {nonce, maxAgeMs = 300_000, service, manifest, pinned = new Set()}) {
  const fail = [];
  const inconclusive = [];

  // 1. Shape, freshness and binding, before any other field is used.
  const shape = evidence.validateEvidence(document);
  if (!shape.valid) {
    return {status: 'fail', fail: shape.errors, inconclusive};
  }

  if (document.nonce !== nonce) {
    fail.push('evidence answers another nonce');
  }

  const age = Date.now() - Date.parse(document.collectedAt);
  if (!(age >= -60_000 && age <= maxAgeMs)) {
    fail.push('evidence is outside the accepted time window');
  }

  if (evidence.evidenceDigest(document) !== document.evidenceDigest) {
    fail.push('evidence digest does not match its contents');
  }

  if (fail.length > 0) {
    return {status: 'fail', fail, inconclusive};
  }

  // 2. Every file of the service against the reference.
  const record = document.services.find(item => item.name === service);
  if (!record || record.kind !== 'directory') {
    return {status: 'fail', fail: [`no directory service named ${service}`], inconclusive};
  }

  for (const [file, [hash, mode]] of Object.entries(manifest.files)) {
    const found = Object.hasOwn(record.files, file) ? record.files[file] : null;
    if (!found) {
      fail.push(`missing: ${file}`);
    } else if (found[0] !== hash || found[1] !== mode) {
      fail.push(`modified: ${file}`);
    }
  }

  for (const file of Object.keys(record.files)) {
    if (!Object.hasOwn(manifest.files, file)) {
      fail.push(`not in the reference: ${file}`);
    }
  }

  if (record.truncated || record.errors.length > 0) {
    inconclusive.push(`${record.errors.length} file(s) could not be read`);
  }

  // 3. Every process: critical findings fail, checks that did not run are inconclusive.
  for (const item of record.processes) {
    for (const finding of item.integrity.findings.filter(finding => finding.severity === 'critical')) {
      fail.push(`process ${item.pid}: ${finding.type} ${finding.detail}`);
    }

    for (const missing of item.integrity.incomplete) {
      inconclusive.push(`process ${item.pid}: ${missing.check} did not run (${missing.error})`);
    }
  }

  // 4. Every running file must be explained; here only by a pinned hash.
  for (const file of [...document.executables, ...document.libraries]) {
    if (file.error) {
      inconclusive.push(`${file.path}: ${file.error}`);
    } else if (!pinned.has(file.sha256)) {
      inconclusive.push(`${file.path}: not explained by any reference`);
    }
  }

  const status = fail.length > 0 ? 'fail' : (inconclusive.length > 0 ? 'inconclusive' : 'pass');
  return {status, fail, inconclusive};
}

module.exports = {appraise};
```

The order matters. Validate the shape first, so no later step reads a field of the wrong type. Then check the nonce, the time and the digest. Only then look at the facts.

### verify.js

```js
// verify.js
const {evidence, util} = require('attestium');
const {appraise} = require('./verifier');

(async () => {
  // The reference: the public commit, checked out by the verifier.
  const manifest = await evidence.createManifest('./reference', {repository: 'example/app', commit: 'a'.repeat(40)});

  const nonce = util.generateNonce();
  const response = await fetch(`http://127.0.0.1:7070/evidence?nonce=${nonce}`);
  const document = await response.json();

  const result = appraise(document, {nonce, service: 'app', manifest});
  console.log(result.status);
  console.log(result);
})();
```

`evidence.createManifest()` lists every file of a directory with its SHA-256 and mode, in the same form as a directory service's `files`. It needs a repository name and a full commit id, because a CI build publishes the same manifest for releases deployed without git (see [SPEC.md](../SPEC.md#release-manifests)).

### Run it

```sh
(cd app && node server.js &)  # the service; its working directory is ./app
node attester-server.js &     # the attester
node verify.js                # the verifier
```

The attester finds processes by their working directory. With `./app` equal to `./reference` and a process running from `./app`, the result is `inconclusive`: the files match, but the Node.js binary and the shared libraries it maps are not explained by any reference yet. Change a file in `./app` and the result is `fail`.

## Explain the running files

A verifier explains each executable and library by a reference it fetches itself. For the Node.js binary, the reference is the official release:

```js
const {ReleaseVerification} = require('attestium');

(async () => {
  // Compares process.execPath with bin/node inside the official archive.
  // In a verifier, pass {sha256, version, platform, arch} from the evidence.
  const result = await new ReleaseVerification().verifyNodeRelease();
  console.log(result.passed, result.details.officialSource);
})();
```

Shared libraries from Debian or Ubuntu are explained by their package in the signed archive. Installed packages of each ecosystem are compared with the files their lockfile pins. See [Ecosystems and references](ecosystems.md).

## Next steps

*   [Concepts](concepts.md): roles, references, binding, evidence levels.
*   [Hardware](hardware.md): bind evidence to a TPM quote or a confidential VM report.
*   [API reference](api.md): every module and function.
*   [Audit Status](https://github.com/auditstatus/auditstatus.com) is a ready-made attester and verifier built on these modules.

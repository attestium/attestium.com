# API reference

Every module Attestium exports, with each function's signature, parameters, return value and errors, and a short example per module. Types are in [`lib/index.d.ts`](../lib/index.d.ts). All modules are CommonJS; functions that do input or output return promises, the rest are synchronous.

## Importing

The main export is the `Attestium` class. Every module is also a property of it, and most have their own subpath:

```js
const Attestium = require('attestium');
const {evidence, ProcessIntegrity, Tpm} = require('attestium');
const sigstore = require('attestium/sigstore');
```

| Subpath | Property of the main export | Contents |
| --- | --- | --- |
| `attestium` | | [The `Attestium` class](#the-attestium-class) |
| `attestium/evidence` | `evidence` | [Evidence format](#evidence) |
| `attestium/schema/evidence.schema.json` | | The JSON Schema |
| `attestium/schema` | `schema` | [JSON Schema validator](#schema) |
| `attestium/util` | `util` | [Canonical JSON, hashing, validation](#util) |
| `attestium/file-tree` | `fileTree` | [Directory hashing](#filetree) |
| `attestium/signing` | `signing` | [Ed25519 envelopes](#signing) |
| `attestium/http` | `http` | [Hardened HTTPS GET](#http) |
| `attestium/process-integrity` | `ProcessIntegrity` | [Running processes](#processintegrity) |
| `attestium/runtimes` | `runtimes` | [Language runtime profiles](#runtimes) |
| `attestium/release-verification` | `ReleaseVerification` | [Node.js releases and npm packages](#releaseverification) |
| `attestium/ecosystems` | `ecosystems` | [Package ecosystems](#ecosystems) |
| `attestium/elf` | `elf` | [Go and Rust build information](#elf) |
| `attestium/containers` | `containers` | [Containers, attester side](#containers) |
| `attestium/oci` | `oci` | [Container images, verifier side](#oci) |
| `attestium/distro` | `distro` | [Debian and Ubuntu packages](#distro) |
| `attestium/checksums` | `checksums` | [Published checksum lists](#checksums) |
| `attestium/sigstore` | `sigstore` | [Sigstore bundles](#sigstore) |
| `attestium/tuf` | `tuf` | [TUF client](#tuf) |
| `attestium/attestations` | `attestations` | [GitHub attestations, npm provenance](#attestations) |
| `attestium/git-trees` | `gitTrees` | [Git trees of pinned commits](#gittrees) |
| `attestium/tpm` | `Tpm` | [TPM 2.0](#tpm) |
| `attestium/tpm-identity` | `tpmIdentity` | [EK certificates, credential activation](#tpmidentity) |
| `attestium/ima` | `ima` | [IMA log](#ima) |
| `attestium/confidential` | `confidential` | [SEV-SNP and TDX](#confidential) |
| `attestium/monitor` | `monitor` | [eBPF monitor](#monitor) |
| `attestium/zip`, `attestium/toml`, none for `asn1` | `zip`, `toml`, `asn1` | [Parsers](#parsers) |

Some modules export more names than listed here (for example `ProcessIntegrity.parseMapsLine`). Those are helpers the modules and tests use; they are not described.

The examples run in a directory where `npm install attestium` has run, and where `./app` is a small project directory.

## The Attestium class

File manifests of a project directory, signed baselines, a challenge-response for remote verifiers, runtime tracking of CommonJS modules, continuous re-verification, and TPM-bound reports. It is independent of the evidence format: use it to check one directory on the machine itself, or to answer a verifier with a signed tree digest.

### `new Attestium(options?)`

| Option | Default | Meaning |
| --- | --- | --- |
| `projectRoot` | `process.cwd()` | Directory to hash. Throws if it does not exist. |
| `includePatterns` | `Attestium.DEFAULT_INCLUDE` | Globs of files to include (source, assets, docs) |
| `excludePatterns` | `Attestium.DEFAULT_EXCLUDE` | Globs to exclude (`node_modules`, VCS directories, keys, `.env*`, editor files) |
| `enableGitignoreInheritance` | `false` | Also exclude the root `.gitignore` patterns (negations are skipped) |
| `signingKey` | none | Ed25519 private key (PEM, DER or `KeyObject`) for signed exports and responses. Throws if it is not Ed25519. |
| `enableRuntimeHooks` | `false` | Record CommonJS modules as they are compiled |
| `continuousVerification` | `false` | Start periodic re-verification |
| `verificationInterval` | `60000` | Milliseconds, or `'random'` (15 to 120 seconds) |
| `customCategories` | `{}` | `{name: RegExp}` file categories, checked first |
| `gitCommit`, `deployTime` | `GIT_COMMIT`, `DEPLOY_TIME` environment | Recorded in reports |
| `enableTpm` | `true` | Allow TPM use when one is available |
| `tpm` | `{}` | Options for [`Tpm`](#tpm) |
| `logger` | `console` | Object with a `log(message)` method |

Options can also come from a data-only file in the project root: `.attestiumrc`, `.attestiumrc.json`, `.attestiumrc.yaml`, `.attestiumrc.yml`, `attestium.config.json`, `attestium.config.yaml`, `attestium.config.yml`, or an `attestium` key in `package.json`. Constructor options win. JavaScript configuration files are never loaded.

### Reports and baselines

*   `generateVerificationReport(): Promise<VerificationReport>` hashes every included file. Returns `{timestamp, attestiumVersion, projectRoot, gitCommit, deployTime, files, errors, digest, summary}`. Each file is `{relativePath, checksum, gitBlobId, mode, size, category, verified: true}`. `digest` is `fileTree.manifestDigest()` of the files. Symbolic links are recorded, never followed. `verifiedFiles` counts files read and hashed; comparing them is a separate step.
*   `exportVerificationData(): Promise<Baseline>` returns `{metadata, files, summary, digest}` and, with a `signingKey`, a `signature` `{alg, keyId, publicKey, value}` over the rest.
*   `compareWithBaseline(baseline, {publicKey}?): Promise<{valid, signature, added, removed, modified, errors}>` re-hashes the tree and compares. With `publicKey`, the baseline must be signed by that key. Without it, a signed baseline is checked only for self-consistency (`signature.trusted` is `false`): always pass the key you trust. `valid` is true only when nothing was added, removed, modified or unreadable, and the signature (if checked) verifies. Returns `{valid: false, errors: [{error: 'Malformed baseline'}]}` for a baseline without `files`.
*   `verifyImportedData(baseline, options?): Promise<boolean>` is `compareWithBaseline(...).valid`, with a log line on mismatch.
*   `scanProjectFiles(): Promise<string[]>` returns absolute paths of the included files.
*   `calculateFileChecksum(file)`, `generateFileChecksum(file): Promise<string>` return a file's SHA-256. They reject for symbolic links (`ELOOP`) and unreadable files.
*   `verifyFileIntegrity(file): Promise<{checksum, verified, timestamp, category?, size?, error?}>` never rejects; `verified` is false with an `error` code.
*   `shouldInclude(path)`, `shouldExclude(path)`, `matchesPattern(path, glob)`, `categorizeFile(path)` apply the patterns and categories (`source`, `test`, `config`, `documentation`, `static_asset`, `dependency`, or a custom one).
*   `parseGitignorePatterns(text): string[]` and `loadGitignorePatterns()` convert `.gitignore` lines to globs.

### Challenge-response

*   `generateVerificationResponse(nonce): Promise<SignedEnvelope>` answers a verifier's nonce with `{type: 'attestium-verification-response', nonce, timestamp, attestiumVersion, gitCommit, digest, summary}`, signed with `signingKey`. Without a key it returns `{payload, signature: null}`. Throws `TypeError` unless the nonce is 16 to 64 bytes of hex.
*   `Attestium.verifyVerificationResponse(response, {nonce, publicKey, digest?, maxAgeMs?}): {valid, errors}` checks the signature with the trusted key, the payload type (`attestium-verification-response`, so another statement signed by the same key is refused), the nonce, the age (default at most 300000 ms old, at most 60 seconds in the future) and, when given, the tree digest.
*   Carry the nonce and the response over SSH, with the verifier's key restricted to the attester command and the server's host key pinned; [`examples/ssh-verification.js`](../examples/ssh-verification.js) does both halves. The signature proves only that the holder of the signing key answered: a key on the verified machine is readable by its root user, who can sign any digest ([Forged answers](forged-answers.md)).
*   `generateChallenge(ttlMs = 300000): {nonce, timestamp, expiresAt}`, `validateChallenge(challenge): boolean` and `verifyChallenge(challenge, nonce): Promise<boolean>` manage challenges on the verifier side.

### TPM-bound reports

*   `isTpmAvailable(): Promise<boolean>` is false when `enableTpm` is false or no TPM answers.
*   `initializeTpm(): Promise<{handle, publicKey, keyId}>` returns the persistent AK, creating it on first use. Throws when the TPM is disabled.
*   `generateHardwareAttestation(nonce, {pcrList}?): Promise<HardwareAttestation>` returns `{type: 'hardware-backed', nonce, reportDigest, softwareVerification, hardwareAttestation, timestamp}`: a verification report and a TPM quote with qualifying data `SHA-256(nonce ‖ report digest)`. Throws when no TPM is available.
*   `Attestium.verifyHardwareAttestation(attestation, {nonce, publicKey, expectedPcrs?}): {valid, errors}` recomputes the report digest from the file list, checks the nonce, and verifies the quote with `Tpm.verifyQuote()`.
*   `generateHardwareRandom(length = 32): Promise<{bytes, source: 'tpm' | 'os'}>` returns TPM random bytes, or the operating system's when no TPM answers.
*   `getTpmInstallationInstructions(): string`, `getSecurityStatus(): Promise<Object>`.

### Runtime tracking and continuous verification

*   `setupRuntimeHooks()` records the SHA-256 of every CommonJS module's source as it is compiled (installed once per process; ES modules are not covered) and emits `moduleLoaded`.
*   `getRuntimeVerificationStatus(): Promise<{enabled, totalModules, changedOnDisk, modules}>` lists the recorded modules, each with `diskSha256` and `changedOnDisk`.
*   `startContinuousVerification(interval?)`, `stopContinuousVerification()` re-hash the tree periodically (the timer does not keep the process alive). `runVerificationCycle(): Promise<violations[]>` runs one cycle; the first records the baseline.
*   `cleanup(): Promise<void>` stops timers and detaches runtime listeners.

Events: `integrityViolation` (`{type: 'fileChanged' | 'fileAdded' | 'fileRemoved', file, ..., timestamp}`), `fileChanged` (`file, previousChecksum, newChecksum`), `moduleLoaded` (`{filename, sha256, loadedAt}`), `verificationError` (`error`).

Statics: `Attestium.VERSION`, `Attestium.DEFAULT_INCLUDE`, `Attestium.DEFAULT_EXCLUDE`, `Attestium.digestOf(value)` (same as `util.digestOf`).

```js
const Attestium = require('attestium');

(async () => {
  // Sign the baseline in CI; keep the private key off the verified machine.
  const {publicKey, privateKey} = Attestium.signing.generateKeyPair();
  const signer = new Attestium({projectRoot: './app', signingKey: privateKey, logger: {log() {}}});
  const baseline = await signer.exportVerificationData();

  // On the machine: compare with the baseline, trusting only publicKey.
  const checker = new Attestium({projectRoot: './app', logger: {log() {}}});
  const result = await checker.compareWithBaseline(baseline, {publicKey});
  console.log(result.valid, result.modified, result.added, result.removed);

  // A remote verifier: fresh nonce, signed answer, pinned key, expected digest.
  const nonce = Attestium.util.generateNonce();
  const response = await signer.generateVerificationResponse(nonce);
  console.log(Attestium.verifyVerificationResponse(response, {nonce, publicKey, digest: baseline.digest}));
})();
```

## evidence

The evidence format of [SPEC.md](../SPEC.md).

| Name | Value |
| --- | --- |
| `TYPE` | `'attestium-evidence'` |
| `VERSION` | `2` |
| `MANIFEST_TYPE` | `'attestium-manifest'` |
| `MANIFEST_NAME` | `'.attestium-manifest.json'` |

*   `validateEvidence(value): {valid: boolean, errors: string[]}` checks a value against `schema/evidence.schema.json`. At most 20 errors are reported, each naming the path (`$.services[0].files is required`).
*   `evidenceDigest(evidence): string` returns the lowercase hex SHA-256 of the canonical JSON of the evidence without `evidenceDigest`, `tpm`, `ima` and `confidential`. Throws `TypeError` for values canonical JSON refuses (see [util](#util)).
*   `createManifest(directory, {repository, commit, exclude?}): Promise<Manifest>` lists every file of a directory (without `.git` and the manifest itself; `exclude` takes globs) as `{type: 'attestium-manifest', version: 1, repository, commit, files: {path: [sha256 or 'symlink:<target>', mode]}}`. Throws `TypeError` unless `repository` is `owner/name` and `commit` is 40 hex digits, and throws if any file cannot be read.
*   `parseManifest(text | Buffer): Manifest` parses and checks a manifest's shape. Throws `SyntaxError` for invalid JSON and `Error('Not an Attestium manifest')` for any other shape.

```js
const {evidence} = require('attestium');

(async () => {
  const manifest = await evidence.createManifest('./app', {repository: 'example/app', commit: 'a'.repeat(40)});
  const parsed = evidence.parseManifest(JSON.stringify(manifest));
  console.log(Object.keys(parsed.files));

  console.log(evidence.validateEvidence({type: evidence.TYPE, version: evidence.VERSION}).errors.slice(0, 3));
})();
```

## schema

*   `compile(schema, {maxErrors = 20}?): (value) => {valid, errors}` compiles the JSON Schema subset the evidence schema uses (see [Other languages](other-languages.md#what-to-implement)). Unknown keywords and unresolvable `$ref`s throw when compiling, so a schema cannot silently skip a check.

```js
const {schema} = require('attestium');

const check = schema.compile({type: 'object', required: ['name'], additionalProperties: false, properties: {name: {type: 'string', maxLength: 8}}});
console.log(check({name: 'web-1'})); // {valid: true, errors: []}
console.log(check({name: 'a-very-long-name', port: 1}).errors);
```

## util

*   `canonicalize(value): string` returns canonical JSON: sorted keys, no whitespace, members with `undefined` values left out. Throws `TypeError` for non-finite numbers, `undefined` in an array, and anything that is not null, a boolean, a number, a string, an array or a plain object.
*   `digestOf(value): string` is `sha256(canonicalize(value))`.
*   `sha256(data: string | Buffer | Uint8Array): string` returns lowercase hex.
*   `safeEqual(a, b): boolean` compares two strings in constant time; false for non-strings or different lengths.
*   `generateNonce(bytes = 32): string` returns random hex.
*   `normalizeNonce(nonce): string` returns the nonce in lowercase. Throws `TypeError` unless it is 16 to 64 bytes of hex.
*   `normalizePid(pid): string` accepts a positive integer (number or decimal string) or `'self'`. Throws `TypeError` otherwise, which keeps untrusted input out of `/proc` paths.
*   `exists(file): boolean` tests by `stat()`, which honors file capabilities, unlike `fs.existsSync()` (`access()`).
*   `isPlainObject(value): boolean`.
*   `parallelMap(tasks: Array<() => Promise<T>>, concurrency): Promise<T[]>` runs thunks with a concurrency limit, keeping order.
*   `setOwn(object, key, value)` sets an own enumerable property, even one named `__proto__`. Use it to build file maps from untrusted paths.

```js
const {util} = require('attestium');

console.log(util.canonicalize({b: 1, a: [true, null, 'x'], c: undefined})); // {"a":[true,null,"x"],"b":1}
console.log(util.digestOf({b: 2, a: 1}) === util.sha256('{"a":1,"b":2}')); // true

const files = {};
util.setOwn(files, '__proto__', 'a file name');
console.log(Object.keys(files)); // ['__proto__']

try {
  util.normalizeNonce('abc');
} catch (error) {
  console.log(error.message); // Nonce must be 16 to 64 bytes of hex
}
```

## fileTree

*   `walkTree(root, {exclude?, concurrency = 16, root?, rootOwnedLinks?}?): Promise<{entries, errors}>` walks a directory without following symbolic links. On Linux each directory is entered through its parent's open descriptor, so a directory replaced by a link during the walk is not followed. `exclude(relativePath, isDirectory)` returns true to skip. Each entry is `{path, type: 'file' | 'symlink', mode: '100644' | '100755' | '120000', size, sha256, gitBlobId, ctimeMs, mtimeMs, target?}`; a symbolic link's hashes are of its target text. Unreadable entries, and paths longer than `PATH_MAX`, go to `errors` as `{path, error}` with the error code; anything that is not a regular file, a directory or a symbolic link (a FIFO, socket or device) is never opened and goes to `errors` with `ENOTFILE`, since a program may still read or load it. With the option `root`, the directory is found inside that root as `openInRoot` finds it.
*   `hashFile(file, {root?, rootOwnedLinks?, inode?}?): Promise<{sha256, gitBlobId, size}>` hashes a regular file in chunks. Opens without following symbolic links (rejects with `ELOOP`) or waiting on a FIFO, rejects anything but a regular file, and rejects if the file changes size while it is read. With `root`, the file is found inside that root (see `openInRoot`); with `inode`, it must be that inode.
*   `openInRoot(root, file, {flags?, rootOwnedLinks?}?): number` (Linux) opens a file inside a root directory (such as `/proc/<pid>/root`) the way a process with that root would find it: symbolic links, absolute or relative, and `..` resolve inside the root. Each step starts from an open directory, so a directory replaced by a link meanwhile is not followed. With `rootOwnedLinks`, only links owned by root are followed. Returns a file descriptor.
*   `gitBlobId(content): string` returns git's SHA-1 blob id.
*   `manifestDigest(entries): string` returns SHA-256 over the sorted lines `path\0sha256\n` (with `\0symlink` before the newline for links); independent of order, modes and times.
*   `globToRegExp(glob): RegExp`: `**/` matches zero or more directories, `**` anything, `*` anything but `/`, `?` one character but `/`.
*   `createMatcher(globs): (path) => boolean` matches any of the globs.
*   `toPosixRelative(root, fullPath): string`.

```js
const {fileTree} = require('attestium');

(async () => {
  const skip = fileTree.createMatcher(['**/*.log', 'tmp/**']);
  const {entries, errors} = await fileTree.walkTree('./app', {exclude: relative => relative === '.git' || skip(relative)});
  console.log(entries.map(entry => `${entry.mode} ${entry.path}`), errors);
  console.log(fileTree.manifestDigest(entries));
  console.log(fileTree.gitBlobId('hello\n')); // ce013625030ba8dba906f756967f9e9ca394464a
})();
```

## signing

*   `generateKeyPair(): {publicKey, privateKey}` returns an Ed25519 key pair in PEM.
*   `sign(payload, privateKey): {alg: 'ed25519', keyId, publicKey, payload, signature}` signs the canonical JSON of `payload`. Throws for keys that are not Ed25519 and for payloads canonical JSON refuses.
*   `verify(envelope, trustedPublicKey?): {valid, trusted, keyId, error?}` never throws. Without `trustedPublicKey`, it verifies with the envelope's own key and `trusted` is `false`.
*   `fingerprint(key): string` returns the SHA-256 of the public key's SPKI DER encoding (the `keyId`).
*   `toPublicKey(key): KeyObject`, `toPrivateKey(key): KeyObject` convert and check the algorithm.
*   `ALGORITHM` is `'ed25519'`.

See the example in [Signatures](signatures.md#ed25519-envelopes).

## http

*   `httpGet(url, options?): Promise<Buffer>` fetches over HTTPS (plain HTTP only for `localhost`, `127.0.0.1` and `::1`, or with `allowHttp: true`). Options: `headers`, `timeout` (idle, default 30000 ms), `deadline` (the whole response, however steadily it arrives, default 3600000 ms), `maxBytes` (default 256 MiB), `maxRedirects` (default 5), `maxRetries` (default 3), `retryDelay` (default 1000 ms, doubled per retry), `ca` (extra trusted CAs), `allowHttp`, `denyPrivateAddresses`, `lookup` (a resolver with `dns.lookup`'s signature). With `denyPrivateAddresses: true`, no connection reaches a private address (`isPrivateAddress`): an IP literal host is refused, and a host name is refused when any address it resolves to is private, checked by the lookup the connection itself uses (so DNS rebinding cannot reach one), on the first request and on every redirect; the error's `code` is `EPRIVATEADDRESS`. Use it for hosts named by evidence. Redirects never go from HTTPS to HTTP and never forward `authorization`, `cookie` or `proxy-authorization` to another host. Retries 429, 5xx, timeouts, refused and reset connections, honoring `Retry-After`. Rejects with `error.statusCode` set for other statuses (`HTTP 404 fetching ...`), and on oversize bodies.
*   `httpGetJson(url, options?): Promise<any>` also sends `accept: application/json` and parses the body.
*   `assertAllowedUrl(url: URL, {allowHttp, denyPrivateAddresses}?)` throws for URLs `httpGet` refuses.
*   `isPrivateAddress(address): boolean` is true for loopback, private (RFC 1918), carrier-grade NAT (`100.64.0.0/10`), link-local (including `169.254.169.254`), unspecified, IETF-reserved, benchmarking, multicast and reserved IPv4 addresses, for IPv6 unspecified, loopback, unique-local, link-local, site-local, multicast and local-use NAT64 addresses, for IPv4 addresses inside IPv6 ones (mapped, compatible, NAT64, 6to4) that are, and for anything that is not an IP address.
*   `privateAddressLookup(resolve = dns.lookup)` returns a lookup that fails with `EPRIVATEADDRESS` for a name resolving to any private address; `connectOptions({denyPrivateAddresses, lookup})` returns the `lookup` and `agent` options for `http.request` that enforce it (no shared agent, so no pooled socket is reused).

```js
const {http} = require('attestium');

(async () => {
  const {dist} = await http.httpGetJson('https://registry.npmjs.org/is-number/7.0.0');
  console.log(dist.integrity);
  await http.httpGet('https://registry.npmjs.org/-/no-such-package-here').catch(error => console.log(error.statusCode));
})();
```

## ProcessIntegrity

Inspects a running process rather than the files it was started from. Linux is fully supported through `/proc`; on macOS and Windows, checks their tooling cannot perform return `supported: false`.

### `new ProcessIntegrity(options?)`

| Option | Default | Meaning |
| --- | --- | --- |
| `expectedLibs` | none | Allowed shared libraries; others are reported as `unexpected-lib`. Empty means no allowlist. |
| `maxAnonExecRegions` | `512` | Anonymous executable regions (JIT code) above this are reported |
| `inspectorPorts` | `[]` | Ports that count as an open debugger, besides the runtime's defaults (9229 for Node.js) |
| `timeout` | `10000` | Timeout of platform commands, in ms |
| `procRoot` | `'/proc'` | Where procfs is mounted |
| `ldPreloadPath` | `'/etc/ld.so.preload'` | The dynamic linker's preload file |
| `platform`, `run` | `process.platform`, `execFileSync` | For other platforms' tooling and tests |

### Methods

Every method takes a process id (number, decimal string or `'self'`) and throws `TypeError` for anything else.

*   `checkAll(pid, {isNode?, runtime?}?): ProcessReport` runs every check and returns `{pid, platform, timestamp, runtime, memoryMaps, executablePages, linkerIntegrity, tracer, fileDescriptors, listeningSockets, inspectorPorts, findings, incomplete, passed}`. `findings` are `{check, type, severity: 'critical' | 'warning' | 'info', detail}`. `incomplete` lists checks that could not run (`{check, error}`), including executable regions that could not be compared. `passed` is true only with no critical finding and nothing incomplete.
*   `checkMemoryMaps(pid)` reports anomalies: `deleted-backing` (an executable mapping whose file was deleted) and `replaced-backing` (its path now names a different file), both warnings because they usually mean an upgrade without a restart; `memfd-exec` (fileless code), `file-wx` (a writable and executable file mapping), `unexpected-lib`. Returns `{supported, regions, anomalies, summary, libraries}`.
*   `checkExecutablePages(pid)` compares every file-backed executable mapping in memory with the same bytes of the file, read through `/proc/<pid>/root` for processes in containers. Returns `{supported, matched, regions, mismatched, skipped, error?}`. A mismatch is `code-modified-in-memory`, critical.
*   `checkLinkerIntegrity(pid, {runtime?, isNode?}?)` checks the dynamic linker's injection vectors (`LD_PRELOAD`, `LD_AUDIT`, `/etc/ld.so.preload`, `DYLD_INSERT_LIBRARIES`, `AppInit_DLLs`) and the runtime's (see [runtimes](#runtimes)). Returns `{supported, clean, findings, runtime, inspectorPorts, pm2?, cmdlineRewritten?, ...}`.
*   `checkTracerPid(pid)`: `{supported, traced, tracerPid}`; a tracer is `debugger-attached`, critical.
*   `checkFileDescriptors(pid)`: `{supported, totalFds, suspicious}`; an open `memfd` is `memfd-open`, critical.
*   `checkListeningSockets(pid)`: `{supported, listening: [{address, port}]}`; a listening inspector port is `inspector-listening`, critical.
*   `detectRuntime(pid, {libraries?, nodeRelease?}?)`: `{name, label, version, by}`.
*   `getProcessInfo(pid)`: `{pid, supported, name, ppid, uid, startTimeMs, cmdline, exe, exeDeleted?, cwd}`. Throws when the process does not exist.
*   `listProcesses({uid?, cwdPrefix?, exe?}?)`: process infos sorted by pid; Linux only, empty elsewhere.

Statics: `ProcessIntegrity.findNodeInjectionFlags(args, {hasScript = true}?)` returns `{preloads, inspector, ports}` found in Node.js arguments; `parsePm2Environment(json)` and `parsePm2Fields(fields)` read the options PM2 started an application with.

Reading another process's memory needs ptrace access to it; for another user's process, also `CAP_DAC_READ_SEARCH`.

```js
const {ProcessIntegrity} = require('attestium');

const inspector = new ProcessIntegrity();
const report = inspector.checkAll(process.pid);
console.log(report.runtime, report.passed, report.incomplete);
for (const finding of report.findings) {
  console.log(finding.severity, finding.type, finding.detail);
}

// The arguments after the executable name.
console.log(ProcessIntegrity.findNodeInjectionFlags(['--require', './hook.js', 'server.js']));
// {preloads: ['--require ./hook.js'], inspector: [], ports: []}
```

## runtimes

Profiles of language runtimes: how to detect them and their code-loading vectors. Detection uses the executable's name and the mapped libraries; nothing is executed.

*   `PROFILES`: `node`, `python`, `jvm`, `ruby`, `dotnet`, `beam`, `php`, `perl`, `deno`, `bun`, each with `name`, `label`, detection patterns and default debug ports, and for `dotnet` and `beam` the names of the memfds their JIT creates (`memfds`). `NATIVE` is the profile for everything else.
*   `runtimeMemfd(runtime, target): string|null` says what a memfd (`/memfd:<name>`) is when the runtime's profile names it: `doublemapper` for `dotnet` (W^X double mapping), `vmem` for `beam` (the JIT's dual mapping). `ProcessIntegrity` reports those as `memfd-exec` and `memfd-open` with severity `info`; any other memfd, or those names in another runtime, stays `critical`.
*   `bundlerSetup(environment): {lib, version}|null` recognizes exactly the `RUBYOPT` and `RUBYLIB` that `bundle exec` sets: `RUBYLIB` one `.../gems/bundler-<version>/lib` directory, and `RUBYOPT` only `-r<that directory>/bundler/setup` or `-rbundler/setup`. The Ruby profile then reports `bundler-setup` and `bundler-rubylib` (`info`) instead of `RUBYOPT-require` and `RUBYLIB`; a verifier should compare that gem directory with the published gem (`rubygems.compareGemDirectory`).
*   `standardBundlerSetup(environment, exe): {setup}|null` recognizes `bundle exec` with the Bundler in the interpreter's standard library (Debian, Ubuntu): `RUBYLIB` empty, and `RUBYOPT` only `-r<prefix>/lib/ruby/<version>/bundler/setup` for the interpreter `<prefix>/bin/ruby`. The Ruby profile then reports `bundler-setup` (`info`) alone.
*   `detectRuntime({exe, libraries = [], nodeRelease = false}): {name, label, version, by}`. `by` is `library`, `executable`, `release` or `default`. A library match wins over the executable name.
*   `inspectRuntime(runtime, {environment, cmdline, exe?, duplicates?, raw?, parentIsPm2?}): {findings, ports, extra}` checks a process's environment and command line for its runtime's injection vectors and the dynamic linker's.
*   `parseEnviron(text): {values, duplicates}` parses `/proc/<pid>/environ`, keeping the first of duplicate names and listing them.
*   `splitOptions(text): string[]` splits an options string as `NODE_OPTIONS` is split.
*   `findNodeInjectionFlags`, `parsePm2Environment`, `parsePm2Fields`: see [ProcessIntegrity](#processintegrity).

```js
const {runtimes} = require('attestium');

console.log(runtimes.detectRuntime({exe: '/usr/bin/java', libraries: ['/usr/lib/jvm/java-21-openjdk/lib/server/libjvm.so']}));
console.log(runtimes.parseEnviron('PATH=/usr/bin\0NODE_OPTIONS=--require x\0PATH=/tmp\0'));
const {findings} = runtimes.inspectRuntime('node', {environment: {NODE_OPTIONS: '--require /tmp/x.js'}, cmdline: ['node', 'server.js']});
console.log(findings);
```

## ReleaseVerification

The Node.js binary against the official release, and npm packages against lockfile-pinned registry tarballs. Collection and appraisal are separate, so a verifier can appraise what another machine collected.

### `new ReleaseVerification(options?)`

| Option | Default | Meaning |
| --- | --- | --- |
| `projectRoot` | `process.cwd()` | Project with `node_modules` and a lockfile |
| `nodeDistUrl` | `'https://nodejs.org/dist'` | Node.js releases |
| `registryUrl` | `'https://registry.npmjs.org'` | npm registry |
| `githubArchiveUrl` | `'https://codeload.github.com'` | Archives of GitHub commits |
| `cacheDir` | none | Cache of verified reference manifests |
| `nodeKeyring` | none | Keyring of Node.js release keys; when set, `SHASUMS256.txt` must be signed (checked with `gpgv`) |
| `timeout`, `maxRetries`, `retryDelay` | `30000`, `3`, `1000` | HTTP options |
| `concurrency` | `8` | Parallel downloads |

### Methods

The `verify*` methods never reject: failures are in `details.error` and `passed` is false.

*   `verifyNodeRelease({execPath, version, platform, arch, sha256}?): Promise<{name: 'node-release', passed, details}>` compares a Node.js binary (default: this process's) with `bin/node` in the official archive (`node.exe` from `SHASUMS256.txt` on Windows). Pass `sha256` to check a hash from evidence without the file.
*   `verifyModules(): Promise<CheckResult>` compares the project's `node_modules` with its lockfile.
*   `verifyGlobalPackage(dir, {node}?): Promise<CheckResult>` checks a global package (npm, pm2) and everything under it; npm and corepack are compared with the copies in the official Node.js archive.
*   `verifyAll({checkNode, node, globalDir, globalPackages, modules}?): Promise<{timestamp, platform, arch, nodeVersion, checks, passed, summary}>` runs the Node.js, global package (`npm`, `pnpm`, `pm2` by default) and module checks.
*   `scanInstalledPackages(nodeModulesDir?, {includeFiles}?): Promise<{packages, unaccounted, links, packageLinks, caches, errors}>` hashes every installed package (npm and pnpm layouts). Each package is `{name, version, path, digest, fileCount, files?, invalid?}`; `includeFiles` (boolean or predicate) adds per-file hashes. `links` lists links that do not resolve to an installed package (`{path, target, problem}`), `packageLinks` the others (`{path, target}`, the target a package's `path`).
*   `comparePackages({installed, references?, policy?, manifestProvider?, resolveFiles?}): Promise<{passed, summary, findings, files}>` appraises scanned packages. Without `references`, each package is looked up in the registry. `files` maps the path of each package that matched its reference (verified, patched or built) to the SHA-256 of each of its files, taken from the reference when the package matched by digest, so other records of those files (an IMA log) can be compared with the reference rather than with the attester's report. References with a `path` (from `package-lock.json`) bind each installed package to the one pinned at its path.
*   `readLockfile(root?): {format, lockfileVersion, packages}` reads `pnpm-lock.yaml` or `package-lock.json`; throws when there is neither.
*   `readPackagePolicy(root?): {patched, built}` reads pnpm patches and `onlyBuiltDependencies` from `package.json`.
*   `getNodeShasums(version): Promise<Map<file, sha256>>`, `getOfficialNodeBinary({version, platform, arch})`, `getOfficialNodeArchive({version, platform, arch}, shasums?)` fetch and check release files. They throw for malformed versions, missing entries and hash mismatches.
*   `getRegistryReference(name, version): Promise<{integrity, tarball}>`, `getPackageManifest(reference): Promise<PackageManifest>`, `getPackageFiles(reference, paths): Promise<Map<path, Buffer>>` fetch npm references. A tarball that does not match its integrity rejects with `... does not match integrity`.

Statics: `parseLockfile(text, 'pnpm' | 'npm')` (`{format, lockfileVersion, packages, links}`, `links` being what each link name may resolve to: `{importer, owners, declared}`), `parseShasums(text): Map`, `githubCommitOf(source)`, `filesNeeded(lock, policy)`, `retargetedLinks(packageLinks, packages, links?): string[]` (links pointing to a package other than the one the lockfile resolves the name to), `foreignCacheFiles(caches)`, `verifyIntegrity(data, sri): boolean`, `filesTouchedByPatch(patch)`, `packageManifestFromFiles(files)`, `nodeReleaseTarget(platform, arch)`, `isValidPackageName(name)`, `globalModulesDir(execPath?, platform?)`.

```js
const crypto = require('node:crypto');
const {ReleaseVerification} = require('attestium');

const data = Buffer.from('tarball bytes');
const sri = `sha512-${crypto.createHash('sha512').update(data).digest('base64')}`;
console.log(ReleaseVerification.verifyIntegrity(data, sri)); // true
console.log(ReleaseVerification.parseShasums(`${'ab'.repeat(32)}  node-v22.0.0-linux-x64.tar.gz\n`));
console.log(ReleaseVerification.githubCommitOf(`https://codeload.github.com/owner/repo/tar.gz/${'c'.repeat(40)}`));
```

## ecosystems

Installed-package plugins `npm`, `pypi`, `rubygems`, `hex`, `composer`, `maven`, `nuget` (also in `INSTALLED`), and compiled-in `go` and `cargo` (also in `COMPILED`). See [Ecosystems and references](ecosystems.md) for what each reads and compares.

Plugin shape (installed ecosystems):

*   `name`, `label`, `lockfiles`: identification and the lockfile names looked for.
*   `detect(root): string[]` returns install directories under a project root.
*   `installRoot(dir): string` returns the directory the install occupies.
*   `scan(dir, {root}?): Promise<Scan>` returns `{packages, unaccounted, links, caches, errors, meta?}`.
*   `readLock(repoDir, {lockfile}?)` reads the lockfile (`lockfile`: a path relative to the repository, for a lockfile not in its default place); throws `NoLockfileError` when there is none. npm reads the first of `pnpm-lock.yaml`, `npm-shrinkwrap.json` and `package-lock.json`, and the pnpm policy from the `package.json` next to the lockfile.
*   `compare({scan, lock, store, release?, gitTrees?, covered?}): Promise<{passed, summary, findings, issues}>`. `lock` may be `null` (every package then fails). A scan with `errors` (files it could not read) does not pass. `release` is a `ReleaseVerification` (npm). `gitTrees` is a `GitTrees` (Composer; default: one under `store.cacheDir`). `covered(file)` returns true for generated files another reference, such as a reproduced build, verifies (Composer, Maven, NuGet).

Other exports:

*   `detectInstalls(root, names?): Array<{ecosystem, dir, installRoot}>` runs `detect` of each (or the named) plugin. Throws for an unknown name.
*   `new ReferenceStore({cacheDir?, httpOptions?, urls?, concurrency = 8})` downloads and caches references for the plugins. `get(url, options?)` and `getJson(url, options?)` fetch with the store's HTTP options; `memo(key, compute, {persist = true}?)` caches a computed value in memory and, with `cacheDir`, on disk. `urls` defaults: `pypi` `https://pypi.org`, `pypiFiles` `https://files.pythonhosted.org`, `rubygems` `https://rubygems.org`, `hex` `https://repo.hex.pm`, `nuget` `https://api.nuget.org/v3-flatcontainer`, `maven` `https://repo1.maven.org/maven2`, `packagist` `https://repo.packagist.org`, `crates` `https://static.crates.io/crates`, `goproxy` `https://proxy.golang.org`.
*   `NoLockfileError`: thrown by `readLock`.
*   `compareFiles(installed, expected, {allowExtra?, allowMissing?, equivalent?}?): {modified, missing, added}` compares two `path -> sha256` maps.
*   `collect(results, issues?)` builds the common comparison shape from per-package results. `passed` is false when any issue has a severity other than `warn` or `info`.
*   `parseCsv(text): string[][]` parses CSV as Python's `csv` module writes it (a wheel's `RECORD`).
*   `go.readLock(repoDir, {dir}?)`: `{format: 'go.sum', module, sums}`; throws `NoLockfileError` without `go.mod`. `go.compareBuildInfo({info, lock, commit?, label?})`: a comparison.
*   `cargo.readLock(repoDir, {lockfile}?)`: `{format: 'cargo', file, packages}`; throws `NoLockfileError`. `cargo.compareAuditable({packages, lock})`: a comparison.

```js
const {ecosystems} = require('attestium');

const result = ecosystems.compareFiles(
  {'index.js': 'a'.repeat(64), 'extra.js': 'b'.repeat(64)},
  {'index.js': 'a'.repeat(64), 'README.md': 'c'.repeat(64)},
  {allowMissing: file => file.endsWith('.md')},
);
console.log(result); // {modified: [], missing: [], added: ['extra.js']}

console.log(ecosystems.detectInstalls('./app'));
```

## elf

*   `goBuildInfo(buffer): {goVersion, path, main, deps, settings, unsupported?} | null` reads Go build information (Go 1.18 and later) from an executable of any format; `null` when it is not a Go binary. `deps` carry `path`, `version`, `sum` and `replace`. For Go 1.17 and earlier, `unsupported` says why nothing was read.
*   `cargoAuditable(buffer): Array<{name, version, source, kind, root}> | null` reads the crate list cargo-auditable embeds in an ELF file; `null` when there is none. Throws for malformed data.
*   `parseElf(buffer)`, `sectionData(buffer, elf, name)` read ELF headers and sections.

```js
const fs = require('node:fs');
const {elf} = require('attestium');

console.log(elf.goBuildInfo(fs.readFileSync(process.execPath))); // null: Node.js is not a Go binary
console.log(elf.cargoAuditable(fs.readFileSync(process.execPath))); // null
```

## containers

Attester side. Linux only.

*   `containerOf(pid, procRoot = '/proc'): {id, runtime} | null` finds the container from the process's cgroup: `docker`, `containerd` (including Kubernetes), `cri-o`, `podman`.
*   `inspectDocker(id, socketPath = '/var/run/docker.sock'): Promise<{name, image: {reference, id, manifestDigest, repoDigests}, platform: {os, architecture}, labels}>` asks the Docker Engine API.
*   `inspectCri(id, {crictl = 'crictl'}?): Promise<...>` asks a CRI runtime through `crictl inspect`; adds `pod` for Kubernetes.
*   `walkRootfs(pid, {procRoot, maxFiles = 500000}?): Promise<{files, fileCount, errors, truncated?, mounts}>` hashes every file of the process's root filesystem through `/proc/<pid>/root`, leaving out other mounts. `files` maps paths (without a leading `/`) to `[sha256 or 'symlink:<target>', mode]`.
*   `walkUpper(upper): Promise<{files, deleted, errors}>` walks an overlayfs upper directory: files written, and whiteouts (deleted files).
*   `parseMountinfo(text)`, `externalMounts(mounts)` (mounts that bring files from outside the image: `{destination, source, root, fsType, readOnly}`), `rootOverlay(mounts)`.

```js
const fs = require('node:fs');
const {containers} = require('attestium');

console.log(containers.containerOf(process.pid)); // null outside a container
const mounts = containers.parseMountinfo(fs.readFileSync('/proc/self/mountinfo', 'utf8'));
console.log(containers.externalMounts(mounts).slice(0, 3));
```

## oci

Verifier side: images from an OCI registry, by digest.

*   `parseReference(text): {registry, repository, tag, digest}` normalizes Docker Hub names (`nginx` is `docker.io/library/nginx`). Throws for invalid references.
*   `new Registry({httpOptions?, endpoints?, credentials?}?)`. `endpoints` maps a registry name to a base URL (Docker Hub is `https://registry-1.docker.io`); `credentials` maps it to `{token}` or `{username, password}`. Anonymous pulls use the registry's token flow. A registry with no configured endpoint (a name taken from evidence), and the token service it names, is never reached at a private address unless `httpOptions.denyPrivateAddresses` is `false`.
    *   `manifest(reference, digest = reference.digest): Promise<Object>` fetches a manifest or index by digest and checks it. Throws for a missing digest or a mismatch.
    *   `blob(reference, digest, maxBytes = 2 GiB): Promise<Buffer>` fetches and checks a blob.
    *   `platformManifest(reference, {os, architecture, variant?}): Promise<{digest, manifest, index}>` resolves an index to the platform's manifest.
    *   `referrerBundles(reference, digest): Promise<Object[]>` returns Sigstore bundles attached as OCI referrers (empty when the registry has none).
*   `imageFiles(registry, reference, manifest, {maxBytes?}?): Promise<Map<path, [sha256 or 'symlink:<target>', mode]>>` applies the layers in order, whiteouts included. Layers are held in memory; an image whose layers together expand beyond `maxBytes` (default 4 GiB) is refused.
*   `compareRootfs(actual, expected, {ignore}?): {modified, missing, added, modeChanged}`.
*   `decompressLayer(blob, mediaType, maxBytes?)` (refuses a layer expanding beyond `maxBytes`, default 4 GiB), `applyLayers(tars)`.

```js
const {oci} = require('attestium');

console.log(oci.parseReference('nginx:1.27'));
// {registry: 'docker.io', repository: 'library/nginx', tag: '1.27', digest: null}
const expected = new Map([['bin/sh', ['a'.repeat(64), '100755']], ['etc/os-release', ['b'.repeat(64), '100644']]]);
console.log(oci.compareRootfs({'bin/sh': ['a'.repeat(64), '100755'], 'tmp/x': ['c'.repeat(64), '100644']}, expected));
// {modified: [], missing: ['etc/os-release'], added: ['tmp/x'], modeChanged: []}
```

## distro

Debian and Ubuntu packages.

*   `new DpkgDatabase({root = '/'}?)`: `available(): boolean`; `ownerOf(file): {name, version, arch, source, listedAs, installedAt} | null` (merged-`/usr` aliases are tried; `installedAt` is the time of the package's file list).
*   `new ArchiveReference({archives, store, gpgv = 'gpgv', dpkgDeb = 'dpkg-deb'})`:
    *   `files(name, version, arch, installedAt?): Promise<{path: sha256 or 'symlink:<target>'}>` returns the files of a published package (absolute paths). It verifies `InRelease` with the archive's keyring (refusing a signature by a revoked or expired key, from `gpgv`'s status lines on descriptor 3), the `Packages.gz` index and the `.deb` by their SHA-256. A version not in the archives is looked up in their snapshots near `installedAt`. Throws with `code: 'ENOTINARCHIVE'` when it is found nowhere, and throws when a signature or hash does not match.
    *   `locate(name, version, arch, installedAt?): Promise<{url, filename, sha256} | null>`.
*   `osRelease(root = '/'): {id, versionId, codename} | null`.
*   `defaultArchives({id, codename}, arch): Archive[]` for `debian` and `ubuntu` (empty for others). An archive is `{url, suites, components, keyring, snapshot?}`.
*   `parseStanzas(text)`, `aliases(file)`.

```js
const {distro} = require('attestium');

const release = distro.osRelease();
console.log(release);
const database = new distro.DpkgDatabase();
if (database.available()) {
  console.log(database.ownerOf('/bin/sh'));
}

console.log(distro.defaultArchives({id: 'debian', codename: 'bookworm'}, 'amd64').map(archive => archive.url));
```

## checksums

*   `parseChecksums(text): Map<file, sha256>` reads GNU and BSD checksum lines; other lines are ignored.
*   `fetchChecksums(source, {store, trustedRoot?}): Promise<{checksums, signed}>` fetches a list and verifies its signature first. `source` is `{url, signature?: {type: 'gpg' | 'minisign' | 'sigstore', url?, keyring?, publicKey?, identity?}}`; `identity` is required for `sigstore`. `trustedRoot` is a function returning the Sigstore trusted root. Rejects when the signature does not verify, for an unknown type, for a `sigstore` signature without `identity`, and on HTTP errors.
*   `verifyMinisign(data, signatureText, publicKey): boolean`.
*   `toIdentity(identity): Object` turns `/.../` strings into regular expressions.

```js
const {checksums} = require('attestium');

const list = checksums.parseChecksums([
  `${'ab'.repeat(32)}  app-linux-amd64`,
  `${'cd'.repeat(32)} *app-windows.exe`,
  `SHA256 (app-darwin) = ${'ef'.repeat(32)}`,
].join('\n'));
console.log(list);
```

See [Signatures](signatures.md#signed-checksum-lists) for signed lists.

## sigstore

*   `verifyBundle(bundle, {trustedRoot, identity?, subject?, payloadType?, artifact?, publicKeys?}): {statement, claims, signedAt, keyHint}` verifies a Sigstore bundle (v0.1 to v0.3). Throws `SigstoreError` on any failure. See [Signatures](signatures.md#sigstore-bundles) for what it checks.
*   `loadTrustedRoot(json): {authorities, logs}` parses a `trusted_root.json`.
*   `certificateClaims(certificate: X509Certificate): Object` returns the Fulcio identity claims.
*   `pae(payloadType, payload): Buffer` is the DSSE pre-authentication encoding.
*   `rootFromInclusionProof(index, size, leafHash, proof)`, `verifyCheckpoint(envelope, log)`, `verifyTimestamp(der, signature, trustedRoot)` are the transparency log and timestamp checks.
*   `SigstoreError`, `FULCIO_OIDS`.

```js
const {sigstore} = require('attestium');

console.log(sigstore.pae('application/vnd.in-toto+json', Buffer.from('{}')).toString());
// DSSEv1 28 application/vnd.in-toto+json 2 {}
try {
  sigstore.verifyBundle({mediaType: 'text/plain'}, {trustedRoot: {}});
} catch (error) {
  console.log(error instanceof sigstore.SigstoreError, error.message);
}
```

## tuf

*   `new TufClient({metadataUrl, targetsUrl?, initialRoot, cacheDir?, httpOptions?, now?})` implements the TUF 1.0 client workflow for a repository with consistent snapshots: root rotation, expiry, rollback, thresholds, lengths and hashes, and one level of delegated targets. `now` returns a `Date`. With `cacheDir`, verified root versions (used only when they chain from `initialRoot`) and the newest timestamp and snapshot (for rollback checks) are kept between runs.
    *   `target(name): Promise<Buffer>` downloads a target file, verified against its targets metadata. Throws `TufError`.
    *   `refresh()` runs the update workflow once and caches the result.
*   `canonicalJson(value)`: the OLPC canonical JSON TUF signs.
*   `TufError`, `verifyThreshold`, `checkHashes`, `matchPath`.

```js
const fs = require('node:fs');
const path = require('node:path');
const {tuf} = require('attestium');

(async () => {
  // The Sigstore root Attestium ships; in production, pin your own copy.
  const initialRoot = JSON.parse(fs.readFileSync(path.join(path.dirname(require.resolve('attestium')), 'data', 'sigstore-root.json'), 'utf8'));
  const client = new tuf.TufClient({metadataUrl: 'https://tuf-repo-cdn.sigstore.dev', initialRoot});
  const trustedRoot = JSON.parse(await client.target('trusted_root.json'));
  console.log(trustedRoot.tlogs.map(log => log.baseUrl));
})();
```

`attestations.SigstoreTrust` wraps this client with the shipped root; prefer it.

## attestations

*   `new SigstoreTrust({cacheDir?, httpOptions?, tufUrl?, initialRoot?, trustedRoot?, npmKeys?}?)`: `trustedRoot(): Promise<Object>` and `npmKeys(): Promise<{[hint]: {pem, validUntil}}>`, through TUF from the shipped root, or from the given values.
*   `githubIdentity({repository, workflow?, ref?, workflowRepository?}): {issuer, subjectAlternativeName: RegExp, sourceRepositoryURI}`. The subject alternative name must name the workflow file in `workflowRepository` (default `repository`), and the source repository must be `repository`: a public repository's reusable workflow can be called from any other repository, whose code it then builds.
*   `githubAttestations({repository, digest, httpOptions?, apiUrl?}): Promise<Object[]>` lists the bundles GitHub stores for a SHA-256 (empty on 404). Throws `TypeError` for a malformed repository or digest.
*   `verifyGithubAttestation({bundles, digest, signer, trust, predicateType?}): Promise<{statement, claims, signedAt}>` returns the first bundle that verifies; throws `SigstoreError` listing every failure otherwise.
*   `npmProvenance({name, version, integrity, trust, registryUrl?, httpOptions?}): Promise<{provenance, published?, repository?, commit?, workflow?, signedAt?}>` verifies npm provenance and publish attestations for the tarball a SHA-512 integrity names.
*   `snappyDecompress(buffer)`, `GITHUB_ISSUER`.

```js
const {attestations} = require('attestium');

const identity = attestations.githubIdentity({repository: 'example/app', workflow: '.github/workflows/release.yml', ref: 'refs/tags/v1.0.0'});
console.log(identity.issuer, identity.subjectAlternativeName.test('https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0'));
```

See [Signatures](signatures.md) for complete examples.

## gitTrees

*   `new GitTrees({cacheDir, git = 'git', timeout = 600000, allowFileUrls = false})` reads commits of other repositories from blobless clones in `cacheDir`. Git runs with hooks off, no prompts, no system or global configuration, and only `https` URLs (`file` only with `allowFileUrls`).
    *   `tree(url, commit): Promise<Map<path, {mode, blob}>>` lists every file of the commit's tree.
    *   `file(url, commit, path): Promise<Buffer | null>` returns one file's contents, fetched on demand.
*   `exportIgnore(gitattributesText): (path) => boolean` matches files a `.gitattributes` marks `export-ignore`.

```js
const {gitTrees} = require('attestium');

(async () => {
  const trees = new gitTrees.GitTrees({cacheDir: './git-cache'});
  const tree = await trees.tree('https://github.com/jonschlinkert/is-number.git', '98e8ff1da1a89f93d1397a24d7413ed15421c139');
  console.log(tree.get('index.js'));

  const ignored = gitTrees.exportIgnore('/tests export-ignore\n*.md export-ignore\n');
  console.log(ignored('tests/a.js'), ignored('README.md'), ignored('index.js'));
})();
```

## Tpm

Attester side through tpm2-tools; `Tpm.verifyQuote()` is plain Node.js.

### `new Tpm(options?)`

| Option | Default | Meaning |
| --- | --- | --- |
| `tcti` | none | TCTI string, for example `device:/dev/tpmrm0` or `swtpm:host=127.0.0.1,port=2321` |
| `akHandle` | `'0x81010002'` | Persistent AK handle (`0x81xxxxxx`); throws `TypeError` otherwise |
| `timeout` | `30000` | Command timeout, in ms |
| `devices` | `['/dev/tpmrm0', '/dev/tpm0']` | Device nodes checked when no `tcti` is set |
| `run` | `execFile` | Command runner, for tests |

### Methods

Commands that fail reject with `<tool> failed: <last line of its error output>`.

*   `checkAvailability(): Promise<{available, reason?, family?}>`, `isAvailable(): Promise<boolean>`.
*   `createAttestationKey({handle?, algorithm = 'rsa' | 'ecc', replace = false}?): Promise<{handle, publicKey, keyId}>` creates an AK under the EK (RSASSA or ECDSA with SHA-256) and makes it persistent. Rejects when a key exists at the handle, unless `replace`.
*   `getAttestationKey(handle?): Promise<{handle, publicKey, keyId}>` reads the AK's public key (PEM) and its SPKI SHA-256.
*   `getAttestationKeyPublicArea(handle?): Promise<string>` returns the AK's `TPM2B_PUBLIC`, base64, for enrollment.
*   `getEndorsement({algorithm = 'rsa'}?): Promise<{algorithm, publicArea, certificate}>` returns the EK public area and the manufacturer's certificate from NV (`null` when there is none), base64.
*   `activateCredential({credential, algorithm = 'rsa', handle?}): Promise<string>` recovers a secret made with `tpmIdentity.makeCredential()`, base64. Throws `TypeError` for anything that is not a credential blob.
*   `quote({nonce, pcrs = [0..7], bank = 'sha256', handle?}): Promise<Quote>` returns `{keyId, handle, hashAlg, message, signature, pcrs}` (base64 message and signature). `nonce` is 1 to 32 bytes of hex; hash longer values first.
*   `readPcrs(pcrs = [0..7], bank = 'sha256'): Promise<{index: hex}>`.
*   `extendPcr(pcr, bank, digest): Promise<void>` for application measurements.
*   `getRandom(length = 32): Promise<Buffer>`, 1 to 64 bytes.

Statics: `Tpm.verifyQuote({quote, publicKey, nonce, expectedPcrs?}): {valid, errors, attest, pcrs}` (see [Hardware](hardware.md#quote-and-verify)), `Tpm.parseAttest(buffer)`, `Tpm.parsePcrYaml(text)`, `Tpm.HASH_SIZES`.

See [Hardware](hardware.md#tpm-20) for examples.

## tpmIdentity

Verifier side of TPM enrollment, plain Node.js.

*   `parseTpmPublic(buffer): {type: 'rsa' | 'ecc', nameAlg, attributes, key: KeyObject, name: Buffer, symmetric, curve, raw}` parses a `TPM2B_PUBLIC`. Throws for truncated or unsupported structures.
*   `attestationKeyProblems(parsed): string[]` lists why a key is not an AK (empty when it is one).
*   `makeCredential({ek, akName, secret}): Buffer` encrypts a secret (at most 32 bytes) to the EK for the AK's name, in the format `tpm2_activatecredential` reads. Supports RSA 2048 and ECC P-256 EKs with AES-128-CFB; throws otherwise.
*   `verifyEkCertificate({certificate, ekKey, roots, intermediates = []}): {subject, issuer, chain}` checks that a DER EK certificate is for `ekKey` and chains to one of `roots` (`X509Certificate`s), with every CA currently valid and every intermediate a CA allowed to sign certificates. Throws otherwise.
*   `kdfa`, `kdfe`, `ATTRIBUTE`.

See [Hardware](hardware.md#enrollment) for an example.

## ima

*   `readLog(file = DEFAULT_LOG): Buffer` reads the binary measurement list (`/sys/kernel/security/ima/binary_runtime_measurements`).
*   `parseBinaryLog(buffer, {littleEndian = true}?): Entry[]` returns `{pcr, templateName, templateDigest, templateData, violation, fileHashAlgorithm?, fileHash?, path?}` for each entry. Throws for truncated logs.
*   `replay(entries, bank = 'sha256', pcr = 10): string` returns the PCR value the log produces. Throws for unsupported banks and templates.
*   `backedEntries(entries, quoted, bank = 'sha256', pcr = 10): Entry[] | null` returns the prefix of the log that replays to the quoted value, or `null` when none does.
*   `measurementsByPath(entries, {pcr = 10}?): Map<path, {algorithm, hash, count, hashes}>`, skipping other PCRs and violations.

```js
const crypto = require('node:crypto');
const {ima} = require('attestium');

// One ima-ng entry for PCR 10, as the kernel writes it (little-endian).
const u32 = value => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value);
  return buffer;
};
const field = data => Buffer.concat([u32(data.length), data]);
const fileHash = crypto.createHash('sha256').update('file contents').digest();
const templateData = Buffer.concat([field(Buffer.concat([Buffer.from('sha256:\0'), fileHash])), field(Buffer.from('/usr/bin/app\0'))]);
const log = Buffer.concat([u32(10), crypto.createHash('sha1').update(templateData).digest(), u32(6), Buffer.from('ima-ng'), field(templateData)]);

const entries = ima.parseBinaryLog(log);
const pcr10 = ima.replay(entries);
console.log(ima.measurementsByPath(ima.backedEntries(entries, pcr10)));
```

## confidential

*   `TSM_ROOT`: `/sys/kernel/config/tsm/report`.
*   `reportData(nonce, digest): Buffer` is `SHA-512(nonce ‖ digest)` over the decoded hex.
*   `collectReport(reportData, {entry?, root?}?): {provider, report, auxblob}` asks the kernel for a report over 64 bytes through configfs-tsm. Throws `TypeError` unless `reportData` is 64 bytes, and throws when another request changed the report in between (retry).
*   `verifyConfidential({provider, report, auxblob?}, expected, {vcek?, roots?, root?, qeIdentity?}?)` verifies an `sev_guest` or `tdx_guest` report (base64 fields) over `expected`. Returns `{type: 'sev-snp', measurement, product, key, tcb, policy, vmpl}` or `{type: 'tdx', measurement, qeSvn, rtmr, teeTcbSvn, mrConfigId, mrOwner}`; throws otherwise.
*   `verifySnpReport({report, reportData, vcek?, certificates?, roots?})`, `verifyTdxQuote({quote, reportData, root?, qeIdentity?})` are the two verifiers. A TDX quote must come from Intel's quoting enclave: its QE report's MRSIGNER, ISVPRODID, attributes and MISCSELECT must match `qeIdentity` (default `TD_QE_IDENTITY`, Intel's published `TD_QE` identity), since the PCK also signs reports of other enclaves allowed the provisioning key.
*   `parseSnpReport(buffer)`, `snpProduct(parsed)`, `tcbParts(tcb, product)`, `parseCertificateTable(auxblob)`, `vcekClaims(certificate)`, `vcekUrl(parsed, product, base?)`, `parseTdxQuote(buffer)`, `amdRoots()`.

```js
const {confidential, util} = require('attestium');

const nonce = util.generateNonce(16);
const digest = util.sha256('evidence');
console.log(confidential.reportData(nonce, digest).length); // 64
console.log(Object.keys(confidential.amdRoots())); // ['Milan', 'Genoa', 'Turin']
```

See [Hardware](hardware.md#confidential-vms) for the attester and verifier.

## monitor

Records programs started and files mapped executable with eBPF (bpftrace), so the next audit can report what ran since the last one.

*   `run({log, maxBytes = 64 MiB, bpftrace = 'bpftrace', mmap = true, maxStrlen = 200, onLine?}): {child, done}` runs bpftrace (as root, with `BPFTRACE_MAX_STRLEN=maxStrlen`) and appends `<ms> <exec|mmap> <pid> <uid> <path>` lines to `log`, rotating it to `log.1` at `maxBytes`. bpftrace prints each event with a random token before and after the path; the token is new for each run and only in a private file, so a path with line breaks cannot end its event early or add events. In the log, a line break in a path is written `\n`, a backslash `\\`, and a final `\+` marks a path bpftrace cut short (one of `maxStrlen - 1` bytes that is not the running program's path). Without kernel support for `fentry`, it restarts recording program starts only. `done` resolves with bpftrace's exit code.
*   `readLog(file, {since?, limit = 2000, maxBytes = 64 MiB}?): {since, until, execs, maps, truncated, malformed}` summarizes the log and its rotated predecessor: each distinct path with `count`, `uids`, `firstSeen`, `lastSeen`, and `error` for a path cut short.
*   `summarize(lines, {since?, limit?}?)`, `parseLine(line)`, `escapePath(path, cut?)`, `eventReader(onEvent, token)`, `script({mmap, token}?)` (the token is printed around each path; `run()` picks a random one per run and passes the program in a private file, never on the command line).

```js
const fs = require('node:fs');
const {monitor} = require('attestium');

const now = Date.now();
fs.writeFileSync('monitor.log', `${now} exec 42 0 /usr/bin/curl\n${now + 5} mmap 42 0 /usr/lib/libssl.so.3\n`);
console.log(monitor.readLog('monitor.log', {since: now - 60_000}));
```

## Parsers

Building blocks the other modules use, with limits for untrusted input:

*   `zip.listZip(buffer)`, `zip.readZipFiles(buffer, {stripFirstComponent?, maxUncompressedBytes = 1 GiB, filter?}?): Map<path, Buffer>`: ZIP archives (jars, wheels, `.nupkg`), with path checks and a size limit. A member whose local header names it differently, or with another compression method, than the central directory is refused.
*   `toml.parseToml(text): Object`: TOML (`Cargo.lock`, `uv.lock`, `pylock.toml`); throws `TomlError`.
*   `asn1.parse(der)`, `asn1.certificateExtensions(der): Map<oid, {critical, value}>`, and `oid`, `text`, `integer`, `time`, `content`, `raw`: DER decoding; throws `Asn1Error` (also for a certificate with a duplicate or malformed extension, and a time that names no real date).

```js
const {toml} = require('attestium');

console.log(toml.parseToml('[[package]]\nname = "serde"\nversion = "1.0.0"\n'));
```

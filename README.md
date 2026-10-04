# Attestium

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.svg">
  <img src="./assets/logo.svg" width="360" alt="Attestium">
</picture>

[![CI](https://github.com/attestium/attestium.com/actions/workflows/ci.yml/badge.svg)](https://github.com/attestium/attestium.com/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/attestium/attestium.com/badge.svg)](https://coveralls.io/github/attestium/attestium.com)
[![npm version](https://img.shields.io/npm/v/attestium.svg)](https://www.npmjs.com/package/attestium)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

Attestium is a Node.js library for remote attestation: proving that a server runs exactly the code that was published. It collects runtime evidence on a machine (files, installed packages, processes, every running executable and library, containers, TPM quotes, confidential VM reports) in an open, language-independent format, and verifies that evidence against references a verifier obtains itself: public commits, lockfile-pinned packages, signed archives, image digests, official releases and signatures.

<a href="https://forwardemail.net">
  <img src="https://forwardemail.net/img/logo-square.svg" width="100" alt="Forward Email">
</a>

**Attestium is a project by [Forward Email](https://forwardemail.net) – the 100% open-source, privacy-focused email service.** We use it, through [Audit Status](https://auditstatus.com), to publish verification results for our own production servers on [our status page](https://status.forwardemail.net).

Read the [technical whitepaper](./attestium-whitepaper.pdf) for the architecture, the security model, and what each kind of result does and does not prove.

## Table of contents

*   [Attestium and Audit Status](#attestium-and-audit-status)
*   [Install](#install)
*   [Example](#example)
*   [What can be verified](#what-can-be-verified)
*   [Evidence levels](#evidence-levels)
*   [Documentation](#documentation)
*   [Development](#development)
*   [Security](#security)
*   [License](#license)

## Attestium and Audit Status

Attestium and [Audit Status](https://auditstatus.com) serve different purposes:

*   **Attestium** is the library and the format. It gives you the pieces: collecting facts on a machine, the evidence format and its schema, and the checks against each kind of reference. Use it to build your own attester or verifier, to verify one thing (a TPM quote, a container image, a Sigstore bundle, a `node_modules` tree), or to implement the format in another language.
*   **Audit Status** is a ready-made tool built on Attestium. It ships as a single binary with two roles: an attester that a verifier invokes over a restricted SSH key, and a verifier that runs in CI, checks the evidence, and publishes reports and a status badge. Use it when you want remote attestation of your servers without writing code. Its [public registry](https://github.com/auditstatus/auditstatus.com/blob/main/docs/registry.md) verifies registered projects every hour from its own GitHub Actions: a project adds one YAML file and the registry's SSH key to its servers.

## Install

```sh
npm install attestium
```

Attestium needs Node.js 18 or later and runs its checks on Linux. Some features call system tools: tpm2-tools for TPM quotes, `gpgv` and `dpkg-deb` for Debian and Ubuntu archives and gpg-signed checksum lists, `git` for Composer and Bundler git sources, and `bpftrace` for the monitor. See [Getting started](docs/getting-started.md#install).

## Example

An attester answers a verifier's nonce with evidence about a deployed directory. The verifier checks the evidence's shape, nonce and digest, then compares every file with its own reference, here a checkout of the expected commit in `./reference`.

```js
const fs = require('node:fs');
const os = require('node:os');
const {evidence, fileTree, util} = require('attestium');

(async () => {
  // Verifier: a fresh nonce.
  const nonce = util.generateNonce();

  // Attester: hash the deployed files and answer the nonce.
  const {entries, errors} = await fileTree.walkTree('./app');
  const files = {};
  for (const entry of entries) {
    util.setOwn(files, entry.path, [entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256, entry.mode]);
  }

  const document = {
    type: evidence.TYPE,
    version: evidence.VERSION,
    nonce,
    collectedAt: new Date().toISOString(),
    attester: {name: 'example-attester', version: '1.0.0'},
    host: {hostname: os.hostname(), kernel: os.release()},
    services: [{
      name: 'app', kind: 'directory', root: './app', realRoot: fs.realpathSync('./app'), git: {commit: null}, files, fileCount: entries.length, errors, installs: [], processes: [], userProcesses: [],
    }],
    executables: [],
    libraries: [],
  };
  document.evidenceDigest = evidence.evidenceDigest(document);

  // Verifier: shape, nonce and digest first; then every file against the reference.
  const {valid} = evidence.validateEvidence(document);
  const bound = document.nonce === nonce && evidence.evidenceDigest(document) === document.evidenceDigest;
  const reference = await evidence.createManifest('./reference', {repository: 'example/app', commit: 'a'.repeat(40)});
  const service = document.services[0];
  const differ = [...new Set([...Object.keys(reference.files), ...Object.keys(service.files)])]
    .filter(file => String(reference.files[file]) !== String(service.files[file]));

  console.log(valid && bound && differ.length === 0 && service.errors.length === 0 ? 'pass' : `fail: ${differ.join(', ')}`);
})();
```

This example is software evidence: the attester could report anything, so it shows only that the files match while the attester is honest. [Forged answers](docs/forged-answers.md) shows how a server can fake its answer and what stops it.

[Getting started](docs/getting-started.md) extends this into an attester and a verifier that talk over SSH (the verifier's key may run only the attester, and the server's host key is pinned), inspect the service's processes, and account for every file those processes run.

## What can be verified

| Kind | What the attester reads | Reference the verifier uses |
| --- | --- | --- |
| Service files | Every file of a deployed directory, with its SHA-256 and git mode | The public git commit, a reproduced build, or a release manifest attested by CI |
| npm (npm, pnpm) | `node_modules` | Registry tarballs pinned by `pnpm-lock.yaml` or `package-lock.json`; GitHub commit archives |
| PyPI | Virtual environments | Wheels pinned by `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock` or hashed requirements |
| RubyGems | Bundler's `vendor/bundle` | `.gem` files pinned by the `CHECKSUMS` of `Gemfile.lock` |
| Hex | Mix's `deps/` | Tarballs pinned by the outer checksums of `mix.lock` |
| Composer | `vendor/` | The git tree of the commit `composer.lock` pins |
| Maven | Directories of jars | Jar hashes pinned by Gradle verification metadata or a Maven lockfile |
| NuGet | Published .NET applications | Packages pinned by the content hashes of `packages.lock.json` |
| Go binaries | Build information inside the binary | `go.sum` and the commit |
| Rust binaries | The cargo-auditable crate list | `Cargo.lock` |
| Native binaries | The running file's hash | A signed checksum list (gpg, minisign, Sigstore), a GitHub artifact attestation, or a pinned hash |
| Runtimes | Each process's runtime (Node.js, Python, JVM, Ruby, .NET, BEAM, PHP, Perl, Deno, Bun) and its code-loading vectors | The official Node.js release; other runtimes through their distribution package or signed checksums |
| Processes | Executable memory, preloads, debuggers, `memfd` code, open inspectors, listening ports | The files the process maps; no injection vector present |
| Containers | Image, mounts, writable layer, root filesystem | Image layers fetched by digest from the registry, and attestations attached to the image |
| Distribution packages | The owning Debian or Ubuntu package of each running file | The `.deb` reached from the signed `InRelease` file, or an archive snapshot for superseded versions |
| Hardware | TPM 2.0 quote, EK certificate, IMA log, AMD SEV-SNP or Intel TDX report | A pinned attestation key and PCR values, manufacturer CAs, the quoted PCR 10, AMD and Intel roots |

## Evidence levels

The strength of a result depends on what backs it. Report the level with every result.

| Level | Proves |
| --- | --- |
| Software evidence | Drift, failed deploys, modified files and packages, injected libraries, debuggers and unexplained programs. Not enough against root on the machine, which controls the attester. |
| TPM-bound | The evidence came from the enrolled machine, for this nonce, in its measured boot state. Root can still misreport what happened after boot. |
| TPM and IMA | The kernel's own record of the files it loaded, replayed to the quoted PCR 10. Holds against a hostile root user, not against a compromised kernel or firmware. |
| Confidential VM | The VM's launch measurement, signed by AMD or Intel, with debugging off, bound to this nonce. |

See [Concepts](docs/concepts.md#evidence-levels) and [Security model and limits](docs/security.md).

## Documentation

*   [Documentation index](docs/README.md)
*   [Getting started](docs/getting-started.md)
*   [Concepts](docs/concepts.md)
*   [API reference](docs/api.md)
*   [Ecosystems and references](docs/ecosystems.md)
*   [Hardware-backed evidence](docs/hardware.md)
*   [Signatures and trust](docs/signatures.md)
*   [Other languages](docs/other-languages.md)
*   [Security model and limits](docs/security.md)
*   [Evidence format specification](SPEC.md) and its [JSON Schema](schema/evidence.schema.json)
*   [Whitepaper](./attestium-whitepaper.pdf)

## Development

```sh
pnpm install
pnpm test          # node --test
pnpm run coverage  # c8: 100% statements, branches, functions and lines required
```

Node.js 18 or later. The tests are end to end: they attack real processes (patching `libc` through `/proc/<pid>/mem`, preloads, `SIGUSR1`, `ptrace`, `memfd`), serve real release archives, packages and signed archives from local servers, and use a software TPM. Tests whose tools are missing are skipped; install `swtpm`, `tpm2-tools`, `gnupg`, `dpkg`, `git`, `openssl` and the language toolchains (Python, Ruby, Go, Rust with cargo-auditable, Java, .NET, PHP, Erlang and Elixir) to run them all.

## Security

Report vulnerabilities privately as described in the [Forward Email security policy](https://forwardemail.net/security) ([security.txt](https://forwardemail.net/security.txt)). See [Security model and limits](docs/security.md) for the threat model.

## License

[MIT](LICENSE) © Forward Email LLC

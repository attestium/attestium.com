# Attestium evidence format, version 2

Evidence is what an attester reports about a machine so that a verifier, running somewhere else, can decide whether the machine runs what it claims to run. This document defines the format. It is independent of any language or transport: an attester or verifier written in another language interoperates by following it.

The machine-readable definition is [`schema/evidence.schema.json`](schema/evidence.schema.json) (JSON Schema 2020-12, using a subset that [`lib/schema.js`](lib/schema.js) implements). Where this document and the schema differ, the schema decides the shape and this document decides the meaning.

## Roles

*   **Attester**: runs on the audited machine, collects facts, and reports them. It never decides whether the machine passes.
*   **Verifier**: runs elsewhere (typically in CI), sends a fresh nonce, receives evidence, and compares every fact with a reference it obtains itself: a public commit, a reproduced build, a registry package, a container image, an official release, a signed distribution archive.
*   **Relying party**: reads the verifier's report (for example a status page).

These follow the IETF RATS architecture (RFC 9334): Attestium evidence is RATS evidence, and a verifier's report is an attestation result.

## Freshness and binding

1.  The verifier chooses a random nonce of 16 to 64 bytes and sends it hex-encoded.
2.  The attester collects everything below, then computes `evidenceDigest` (see "Digest").
3.  When hardware is available, the attester binds the nonce and the digest into hardware-signed statements:
    *   **TPM 2.0**: a quote whose qualifying data is `SHA-256(nonce || evidenceDigest)` (raw bytes, not hex), in the `tpm.quote` field.
    *   **Confidential VM** (AMD SEV-SNP, Intel TDX): a report whose 64 bytes of report data are `SHA-512(nonce || evidenceDigest)`, obtained through Linux configfs-tsm, in the `confidential` field.
4.  The IMA log, if any, is read after the quote and is authenticated by replaying it to the quoted PCR 10 in the SHA-256 bank. Only the prefix whose replay equals the quoted value is authenticated; entries after it were measured after the quote and are ignored.

A verifier accepts evidence only if `nonce` equals the nonce it sent, `collectedAt` is within its accepted window, and `evidenceDigest` equals the digest it recomputes.

The nonce makes evidence fresh; `collectedAt` is the attester's clock. Nothing in software evidence identifies the machine: an attester can forward the nonce to another machine and return that machine's evidence. Only a hardware statement verified with a key pinned for that machine (a TPM attestation key) binds evidence to it. A confidential VM report identifies the launch image, not the instance.

## Transport

This format defines no transport, and no transport makes software evidence true: the attester runs on the audited machine, so whoever controls that machine controls what it reports, including the nonce and the digest. A transport decides only who may ask and which machine answered. Reach the attester through a channel that authenticates both ends and runs nothing but the attester, such as an SSH key restricted to the attester command (`restrict,command="..."`) with the machine's host key pinned by the verifier. Do not serve evidence on a network endpoint: it would show anyone who can reach it the machine's files, packages and processes, and the verifier would trust whatever certificate authority or proxy stands in front of it. Only hardware statements, verified as below, make a forged answer fail.

## Digest

`evidenceDigest` is the lowercase hex SHA-256 of the canonical JSON encoding of the evidence object without the fields `evidenceDigest`, `tpm`, `ima` and `confidential`.

Canonical JSON:

*   `null`, `true`, `false` as in JSON.
*   Numbers: finite only, written as ECMAScript `JSON.stringify` writes them.
*   Strings: as ECMAScript `JSON.stringify` writes them.
*   Arrays: `[` items joined by `,` `]`; an undefined item is an error.
*   Objects: members whose value is undefined are left out; the remaining keys are sorted by UTF-16 code units; `{` then `"key":value` pairs joined by `,` then `}`.
*   No whitespace anywhere.

## Top level

| Field | Meaning |
| --- | --- |
| `type` | `"attestium-evidence"` |
| `version` | `2` |
| `nonce` | The verifier's nonce, lowercase hex |
| `collectedAt` | When collection started, ISO 8601 UTC |
| `attester` | `name` and `version` of the attester implementation, its `platform`, `arch`, runtime (`node`), and its own `executable` (`path`, `sha256` or `error`) so a verifier can match it with a published release |
| `host` | `hostname`, `kernel`, `bootId` (from `/proc/sys/kernel/random/boot_id`), `os` (`id`, `versionId`, `codename` from os-release) |
| `distro` | `{format: "dpkg", arch}` when executables and libraries carry their owning distribution package, else `null` |
| `services` | What runs on the machine; see "Services" |
| `executables` | Every running executable, once; see "Code" |
| `libraries` | Every file mapped executable into an inspected process, once |
| `globalPackages` | Optional: tools installed next to the Node.js runtime (npm, corepack, pnpm, pm2) with their files |
| `monitor` | Optional: what was executed or mapped since the previous window, or `{error}` when the record could not be read; see "Monitor" |
| `evidenceDigest` | See "Digest" |
| `tpm` | Optional: `{enabled: false}`, `{available: false, reason, required}`, `{available: true, error}` or `{available: true, quote}`; a quote is `{message, signature, pcrs, keyId, handle, hashAlg}` (base64 TPMS\_ATTEST and signature, the quoted PCR values by bank, the attestation key's id and persistent handle, and the signature's hash: `sha256`, `sha384` or `sha512`) |
| `confidential` | Optional: `{enabled: false}`, `{available: false, reason, required}`, `{available: true, error, required}` or `{available: true, provider, report, auxblob}` (base64) |
| `ima` | Optional: `{log}` (base64 binary measurement list) or `{error}` |

`required` tells the verifier the attester was configured to require the hardware, so its absence is a failure rather than a missing option.

## Services

A service is either a directory or a set of containers.

### Directory service (`kind: "directory"`)

| Field | Meaning |
| --- | --- |
| `name` | The service's name, matching the verifier's configuration |
| `root`, `realRoot` | The configured and resolved root |
| `git` | `{commit, ref}` read from `.git` without running git, or `{commit: null, error}` |
| `files` | Every file under the root except `.git` and installed package directories: `path -> [sha256 or "symlink:<target>", mode]`, mode being git's `100644`, `100755` or `120000` |
| `fileCount`, `truncated` | The number of files found, and whether `files` was cut at the attester's limit |
| `errors` | Files that could not be read: `{path, error}` |
| `manifest` | Optional: the contents (base64) of `.attestium-manifest.json`, for a release deployed without git; see "Release manifests" |
| `installs` | Installed packages, one entry per install directory; see "Installed packages" |
| `processes` | Every process whose working directory is inside the root (and whose user matches, when configured); see "Processes" |
| `userProcesses` | The same user's other processes, listed but not inspected: `{pid, exe, name, cwd}` (each but `pid` may be `null`) |

### Container service (`kind: "container"`)

`containers` lists every running container matching the service's filter:

| Field | Meaning |
| --- | --- |
| `id`, `runtime`, `name` | Container id (hex), runtime (`docker`, `containerd`, `cri-o`, `podman`), name |
| `image` | `reference`, `id`, `manifestDigest` (the platform manifest the runtime recorded), `repoDigests` (`registry/repository@sha256:...`) |
| `platform` | `os`, `architecture` (OCI names) |
| `mounts` | Mounts that bring in files from outside the image: `destination`, `source`, `root`, `fsType`, `readOnly` |
| `upper` | The overlay's writable layer: `files`, `deleted` (whiteouts), `errors` |
| `rootfs` | Optional: every file of the root filesystem (other mounts left out), with `fileCount`, `errors`, `truncated` |
| `processes` | The container's processes |
| `error` | The container could not be inspected |

## Installed packages

Each entry of `installs` has `ecosystem` (`npm`, `pypi`, `rubygems`, `hex`, `composer`, `maven`, `nuget`), `dir` (relative to the root when inside it), `packages`, `unaccounted` (files that belong to no package), `links` (links that do not resolve to an installed package: `{path, problem}`), for npm `packageLinks` (every link that resolves to an installed package: `{path, target}`, the target being that package's `path`; a verifier requires the package the lockfile resolves the link's name to), `caches` (bytecode caches: `{path, files}`), `errors`, and ecosystem-specific `meta`.

A package has `name`, `version`, `path` (relative to `dir`), `files` (`path -> sha256`, relative to the package), optionally `invalid: true` and `meta` (for example a wheel's generated scripts, a gem's specification, the blobs of a Composer package).

An npm package also has `digest` and `fileCount`: the lowercase hex SHA-256 of one line per file of the package (its own `node_modules` and `__pycache__` directories left out), `path` NUL `sha256` newline, or `path` NUL `sha256` NUL `symlink` newline for a symbolic link (hashed as its target), the lines sorted; and the number of files. Its `files` may then be left out: a verifier compares the digest with the reference's, and needs `files` for a package it compares file by file (a patched package) or whose files a process maps; when present, `files` must produce the digest.

The verifier reads the lockfile at the deployed commit, from its own checkout of the public repository, and compares each package with its reference: the registry tarball the lockfile's integrity names (npm), the wheel named by the lockfile's hash through its `RECORD` (PyPI), the `.gem` whose checksum Gemfile.lock pins (RubyGems), the Hex tarball by its outer checksum, the git tree of the commit composer.lock pins (with `export-ignore`), the jar hash Gradle's verification metadata or a Maven lockfile pins, the NuGet package whose content hash packages.lock.json pins.

## Processes

| Field | Meaning |
| --- | --- |
| `pid`, `ppid`, `uid`, `cwd`, `exe`, `exeDeleted` | From procfs |
| `cmdline` | At most 32 arguments of at most 512 characters |
| `startTime` | ISO 8601, or `null` |
| `runtime` | `{name, label, version, by}`: `node`, `python`, `jvm`, `ruby`, `dotnet`, `beam`, `php`, `perl`, `deno`, `bun`, or `native` |
| `integrity` | `findings` (`{type, severity: critical, warning or info, check, detail}`; a verifier treats a finding without `severity` as a warning), `incomplete` (checks that could not run), mapped `libraries` (every file mapped executable; empty when there are none), executable page comparison, dynamic linker state, tracer, suspicious file descriptors, listening sockets |
| `changedAfterStart`, `metadataChangedAfterStart` | Files of the service written, or whose status changed, after the process started; `...Truncated` when cut. Optional: an attester that does not track them leaves them out, and a verifier then has nothing to compare |
| `bundler` | For a Ruby process started by `bundle exec`: the bundler gem directory its RUBYLIB names, `{dir, version, files, errors}` (`files`: `path -> sha256`), for comparison with the published gem |

Runtime findings cover each runtime's code-injection vectors: environment variables that load code (`NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `RUBYOPT`, `DOTNET_STARTUP_HOOKS`, `ERL_FLAGS`, `PHP_INI_SCAN_DIR`, `PERL5OPT`, `LD_PRELOAD`, `LD_AUDIT` and others), command-line options that do the same, debugger and management ports, and attach mechanisms.

Some values runtimes set themselves are `info`: the memfd the .NET runtime maps its JIT code from (`doublemapper`, W^X double mapping) and the BEAM JIT's (`vmem`), each only in a process of that runtime; and exactly the RUBYOPT and RUBYLIB `bundle exec` sets (`bundler-setup`, `bundler-rubylib`: only Bundler's setup required, and only the bundler gem's `lib` directory on RUBYLIB), whose gem directory a verifier compares with the published gem.

A `critical` finding is evidence of tampering; `warning` deserves attention; `info` is context. A process with anything in `incomplete` cannot pass: a clean result means nothing unless every check ran.

## Code

`executables` and `libraries` list every file that an inspected process runs or maps executable, once per container (or the host):

| Field | Meaning |
| --- | --- |
| `path`, `container` | The path as the process sees it, and the container id or `null` |
| `sha256` or `error` | The hash of the running file, read through `/proc/<pid>/exe` or the process's root |
| `deleted` | The running copy was replaced on disk |
| `platform`, `arch`, `size` | Executables only: the attester's platform and architecture (Node.js names), and the file's size in bytes |
| `nodeVersion` | For official Node.js builds, the version from the release URL embedded in the binary |
| `go` | Go build information: `goVersion`, `main`, `deps` (with `go.sum` hashes and replacements), `settings` (including `vcs.revision`, `vcs.modified`, `-trimpath`) |
| `cargo` | `{packages}` recorded by cargo-auditable |
| `package` | The owning distribution package: `name`, `version`, `arch`, `listedAs`, `source` (its source package), `installedAt` |

A verifier explains each file by a reference: a service file that matched its commit, build or attested release; a package file; an image file; an official runtime release; a pinned hash or a signed published checksum list; or the file of the owning package in the distribution's signed archive (a snapshot from the install time for superseded versions). A file no reference explains is reported as unexplained; one that contradicts its reference fails.

The build information inside Go and Rust binaries is written by the build, so it proves nothing about the binary by itself; the binary's own hash does. It shows which dependencies were built in, and those are compared with the lockfile at the commit.

## Monitor

When a kernel-level monitor (eBPF) records program executions and executable mappings, `monitor` summarizes the window: `since`, `until`, `execs` and `maps` (`path`, `count`, `uids`, `firstSeen`, `lastSeen`, and the file's `sha256` and `package`, or `error` when it is gone), `truncated`, `malformed`. A verifier explains these files like running code; a program that ran and is gone is reported.

## Release manifests

A release deployed without git (a compiled binary, a bundle) carries `.attestium-manifest.json` at its root:

```json
{"type": "attestium-manifest", "version": 1, "repository": "owner/name", "commit": "<40 hex>", "files": {"path": ["<sha256 or symlink:target>", "<mode>"]}}
```

A CI workflow writes it from the build output and attests its SHA-256 (for example with GitHub artifact attestations, a Sigstore bundle signed by the workflow's identity). The verifier checks the attestation's signer (repository, workflow file, ref), that the attestation is for the commit the manifest names, that the commit is on the audited branch of the public repository, and every file against the manifest.

## Verifier obligations

A verifier implementing this format must:

*   check the evidence against the schema before using any field;
*   check the nonce, the time window and the digest;
*   verify hardware statements only with keys it pinned or chains to vendor roots it ships, never with keys taken from the evidence;
*   pin a distinct attestation key for each machine, so that one machine cannot answer for another;
*   decide from its own configuration which hardware statements each machine must provide, and fail when one is missing, rather than accept the lower level the evidence offers;
*   compare the IMA measurements it authenticated with its references, not with the hashes the evidence reports, and report a service none of whose files were measured;
*   obtain every reference itself, by digest where the reference is content-addressed;
*   treat checks that could not complete as inconclusive, never as passing;
*   report the evidence level of every result, since software evidence can be forged by whoever controls the attester.

## Versioning

`version` changes when a change could make a verifier misread evidence. Objects the schema closes (`additionalProperties: false`) reject unknown fields, so an attester adds fields there only with a new version; other objects may gain optional fields without one.

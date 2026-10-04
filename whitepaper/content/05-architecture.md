# Systems Architecture

This section describes the roles, the evidence format, and each kind of reference the verifier uses, then the Audit Status attester and verifier that run them.

## Roles and Trust Boundaries

The roles are those of RFC 9334 [@rats]:

* **Attester**: runs on the audited machine. It collects facts and binds them to the hardware when possible. It is trusted for nothing beyond what the hardware backs (Section 5).
* **Verifier**: runs on a separate machine, usually in CI. It chooses the nonce, checks the evidence, and obtains every reference itself, by digest wherever the reference is content-addressed.
* **Reference sources**: public repositories, package registries, container registries, official release sites, and distribution archives. The verifier authenticates each through hashes pinned by something it already trusts (a lockfile at a public commit, a signed archive index, a Sigstore bundle, a vendor certificate chain).
* **Relying parties**: read the verifier's attestation results.

In RATS terms, Attestium evidence is RATS evidence and a verifier's report is an attestation result. The verifier follows the background-check model: the relying party trusts the verifier, and the verifier holds the reference values and endorsements (pinned attestation keys, vendor roots, expected measurements).

## Evidence Format

Evidence version 2 is specified in the repository's `SPEC.md` and published as a JSON Schema (draft 2020-12). The verifier validates evidence against the schema before reading any field; the validator implements exactly the keywords the schema uses and rejects unknown keywords, so the schema cannot silently skip a check. Objects the schema closes reject unknown fields, and the version changes whenever a change could make a verifier misread evidence.

The top level holds:

| Field | Content |
|---|---|
| `nonce`, `collectedAt` | The verifier's nonce (16 to 64 bytes, hex) and the collection time |
| `attester` | Name, version, platform and the SHA-256 of the attester's own executable |
| `host` | Hostname, kernel, boot id, and operating system release |
| `services` | Directory services and container services (Section 4.3) |
| `executables`, `libraries` | Every file an inspected process runs or maps executable, once each, with its hash, owning distribution package, and embedded Go or Rust build information |
| `globalPackages` | Tools installed next to the Node.js runtime (npm, corepack, pnpm, pm2) |
| `monitor` | Programs executed and files mapped executable since the previous window (Section 4.9) |
| `evidenceDigest` | SHA-256 of the canonical encoding of everything above |
| `tpm`, `confidential`, `ima` | Hardware statements, added after the digest |

### Canonical Digest

`evidenceDigest` is the SHA-256 of the canonical JSON encoding of the evidence without the fields `evidenceDigest`, `tpm`, `ima` and `confidential`. The encoding writes numbers and strings as ECMAScript's `JSON.stringify` does, omits members whose value is undefined, sorts object keys by UTF-16 code units, and uses no whitespace. Any implementation that follows these rules computes the same digest for the same evidence.

### Freshness and Binding

1. The verifier chooses a random nonce and sends it hex-encoded.
2. The attester collects everything, then computes `evidenceDigest`.
3. When hardware is available, the attester binds both values into hardware-signed statements. A TPM 2.0 quote carries the qualifying data `SHA-256(nonce || evidenceDigest)`. A confidential VM report carries the 64 bytes of report data `SHA-512(nonce || evidenceDigest)`. Both concatenate raw bytes, not hex.
4. The IMA log is read after the quote and authenticated by replaying it to the quoted PCR 10 in the SHA-256 bank.

The verifier accepts evidence only if the nonce is its own, `collectedAt` is within its window (15 minutes by default), and the digest it recomputes equals `evidenceDigest`. Because the hardware statement signs the digest, and the digest covers every fact, a quote or report cannot be moved to other evidence or replayed for another nonce. Evidence also records whether the attester was configured to require each kind of hardware, so a missing statement from a machine that should have one fails instead of passing at a lower level.

## Services and Processes

### Directory Services

A directory service is a deployed tree, usually a git checkout. The attester reads the commit and ref from `.git` without running git, and records every file (except `.git` and package install directories) with its SHA-256 and git mode; symbolic links are recorded, never followed. A release deployed without git carries a release manifest instead (Section 4.6). The attester also scans installed packages of every detected ecosystem (Section 4.5) and inspects every process whose working directory is inside the root, and it lists the same user's other processes.

The verifier keeps a blobless clone of the public repository and checks out the reported commit into a worktree, so `.gitattributes` behave as on a normal checkout. It requires the commit to be on the audited branch and recent enough, compares every tracked file's hash and mode, fails on untracked files that the commit's `.gitignore` does not ignore, and fails on files the attester could not read unless the commit ignores them.

Deployments often generate files that the repository ignores, such as bundled browser code or a generated parser. When configured, the verifier runs the build in a clean checkout of the same commit, with a minimal environment, and compares every generated file with the server's copy. The build runs only for commits on the audited branch, so a server cannot make the verifier run arbitrary code, and the build must be reproducible [@reproducible_builds].

### Processes and Runtimes

For each inspected process the attester reports, from procfs:

* **Executable pages**: every executable, file-backed mapping (the program and each shared library) read from `/proc/<pid>/mem` and compared byte for byte with the same range of the file, read through `/proc/<pid>/root` so that processes in containers and chroots are compared with their own view of the filesystem. A single modified byte is reported with its offset. Mappings whose file was replaced since the process started cannot be compared and are reported as such.
* **Memory maps**: executable `memfd` mappings, writable and executable file mappings, deleted or replaced backing files, and libraries outside an optional allowlist. Anonymous executable memory is counted, because JIT compilers create it legitimately.
* **Dynamic linker**: `LD_PRELOAD`, `LD_AUDIT` and `/etc/ld.so.preload`.
* **Tracer, file descriptors and sockets**: an attached debugger, open `memfd` objects and deleted files, and listening ports, including a debugger or inspector opened at runtime.
* **Runtime**: the language runtime, detected from the executable name and the libraries mapped into the process (for example `libjvm.so` identifies a JVM whatever its launcher is called), and that runtime's code-injection vectors.
* **Files changed after start**: files and directories of the service, its installed packages and its process manager whose contents or status changed after the process started, which indicates a pending restart or code that was loaded and then restored. Linux updates a file's status-change time (ctime) on every write, mode change or rename, and no system call sets it back, so a file restored to its original contents and modification time still shows. A file added and then removed shows in its directory.

Runtime profiles exist for Node.js, Python, the JVM, Ruby, .NET, Erlang/Elixir (BEAM), PHP, Perl, Deno and Bun; any other process is treated as native code. Each profile names the environment variables that load code (`NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `RUBYOPT`, `DOTNET_STARTUP_HOOKS`, `ERL_FLAGS`, `PHP_INI_SCAN_DIR`, `PERL5OPT` and others), the command-line options that do the same, debugger and management ports, and attach mechanisms. For Node.js processes managed by PM2, the options PM2 passed are read from its environment, and a command line overwritten with `process.title`, which can hide the options a process started with, is recognized.

Findings carry a severity: `critical` is evidence of tampering, `warning` deserves attention, `info` is context. A process with any check in `incomplete` (for example for lack of permission) cannot pass. Linux is fully supported; macOS and Windows support the subset their tooling exposes, and unsupported checks report `supported: false` rather than passing.

## Explaining Every Executable and Library

The evidence lists every file that an inspected process runs or maps executable, once per host or container, with its SHA-256 read through the process. The verifier explains each one by the first reference that matches:

1. **Service files**: a file of a service that matched its commit, reproduced build or attested release.
2. **Packages**: a file of an installed package that matched its locked artifact.
3. **Image**: a file of a container's image, fetched by digest.
4. **Official runtime release**: for Node.js binaries, whose release URL is embedded in the binary, the `node` binary inside the official archive listed in `SHASUMS256.txt`, optionally with the release signature checked against the Node.js release keys.
5. **Pinned hash or signed checksum list**: a hash in the verifier's configuration, or a project's published checksum list (`SHA256SUMS`, `checksums.txt`) whose OpenPGP, minisign or Sigstore signature verifies.
6. **Distribution package**: the file of the Debian or Ubuntu package that owns it according to the dpkg database, taken from the distribution's archive.

A file that matches no reference is **unexplained** (a warning by default, configurable to fail). A file whose own reference says otherwise, such as a binary that claims to be an official Node.js release but differs from it, or a library that differs from the package that owns it, **fails**.

The distribution reference follows the archive's chain of trust [@debian_secureapt]. The verifier checks the `InRelease` signature with the distribution's keyring using `gpgv`, follows the SHA-256 in `InRelease` to the `Packages` index and from there to the `.deb`, extracts it, and compares the file. The dpkg database is only the server's claim about which package owns a file; a false claim fails, because the named package must contain the same bytes. A version that the archive no longer carries is looked up in the archive's snapshot service at the time the package was installed. The archive indexes may be fetched over plain HTTP, because their contents are authenticated by signature and hash rather than by transport.

Compiled Go and Rust binaries also carry the list of modules or crates built into them. Go writes its module list with `go.sum` hashes and its build settings (VCS revision, whether the tree was modified, `-trimpath`) into every binary; binaries built with cargo-auditable carry their crate list. The verifier compares these lists with `go.sum` or `Cargo.lock` at the deployed commit and flags a build from another commit or from a modified tree. This metadata is written by the build and proves nothing about the binary on its own: the binary's hash, matched against a reproduced build, an attested artifact or a signed checksum, is what proves it. The metadata shows which dependencies went into it.

## Package Ecosystems

Each ecosystem is a plugin with an attester half (find install directories and hash what is there) and a verifier half (read the lockfile at the public commit, fetch the artifacts it pins, and compare). The verifier always reads the lockfile from its own checkout of the public repository, never from the server.

| Ecosystem | Installed in | Reference |
|--|---|-----|
| npm | `node_modules` (npm and pnpm layouts) | Registry tarball whose SRI integrity `package-lock.json` or `pnpm-lock.yaml` pins; GitHub archive for a dependency pinned to a commit |
| PyPI | virtual environments (`site-packages` and scripts) | The wheel whose SHA-256 `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock` or a hashed requirements file pins, compared through its `RECORD` and the wheel install rules |
| RubyGems | Bundler's `vendor/bundle`, `GEM_HOME` | The `.gem` whose SHA-256 the `CHECKSUMS` section of `Gemfile.lock` pins |
| Hex | Mix's `deps/` | The tarball whose outer checksum `mix.lock` pins |
| Composer | `vendor/` | The git tree of the commit `composer.lock` pins, minus `export-ignore` files |
| Maven | directories of jars | The jar hash that Gradle's dependency verification metadata or a Maven lockfile pins; otherwise Maven Central by coordinates |
| NuGet | published .NET applications | The `.nupkg` whose content hash `packages.lock.json` pins |
| Go | inside the binary | `go.sum` at the commit |
| Cargo | inside the binary (cargo-auditable) | `Cargo.lock` at the commit |

Every comparison reports each package as verified, failed (it differs from its reference), unverifiable (no reference can exist, for example a package built on the server from a source distribution, or a dependency from an unpinned source), or error (the reference could not be fetched). Files that belong to no package are listed, because some runtimes execute them: Python runs `.pth` files and `sitecustomize.py` at start-up, and RubyGems loads gem specifications, which are Ruby code. Gem specifications must therefore consist only of literal values and agree with the gem's own metadata, and executable wrappers must match the template RubyGems generates.

Package managers make a few expected changes during installation, and each is accounted for explicitly rather than ignored: pnpm patches must produce the installed files exactly, packages allowed to run install scripts may add their build output, npm and pnpm rewrite a `bin` file's CRLF shebang line, and Python bytecode caches are listed rather than hashed. Dependencies bundled inside an npm package are matched against the bundling package's tarball.

## Releases, Attestations and Signed Checksums

A release deployed without git, such as a compiled binary or a bundle, carries `.attestium-manifest.json` at its root: the repository, the commit, and every file's SHA-256 and mode. A CI workflow writes the manifest from the build output and attests its SHA-256 with a GitHub artifact attestation [@github_attestations]. The verifier checks the attestation's signer (repository, workflow file and ref), that the attestation names the commit the manifest names, that the commit is on the audited branch, and every file against the manifest.

Attestations are Sigstore bundles [@sigstore_ccs] holding a DSSE envelope with an in-toto statement [@in_toto]. A bundle is accepted only when:

1. the signing certificate chains to a certificate authority in Sigstore's trusted root and was valid when the transparency log entry was made;
2. the transparency log entry is authentic (a signed entry timestamp, or an inclusion proof to a signed checkpoint) and matches this signature, certificate and payload;
3. the DSSE signature over the statement verifies with the certificate;
4. the certificate's identity (the workflow that signed, its issuer, repository, commit and ref) is the one the verifier requires; and
5. the statement names the artifact's digest as a subject.

Sigstore's trusted root and npm's registry keys are obtained with a TUF client [@tuf_spec] that implements root rotation, expiry, rollback, threshold, length and hash checks from an initial root shipped with the library. The same machinery verifies npm provenance, which links a package tarball to the repository, commit and workflow that published it, and container image attestations stored as OCI referrers.

For binaries whose projects publish a checksum list, the list is accepted when its signature verifies: a detached OpenPGP signature checked with `gpgv` and a configured keyring, a minisign (Ed25519) signature, or a Sigstore bundle with a required identity. An unsigned list is trusted only as far as HTTPS and its host, and the result says so.

## Containers

For a process in a container, the attester identifies the container from the process's cgroup (Docker, containerd, CRI-O, Podman, Kubernetes), asks the runtime which image it started from (the Docker Engine API, or `crictl` for CRI runtimes), lists the mounts that bring in files from outside the image, walks the overlay's writable layer including deletions, and hashes every file of the root filesystem through `/proc/<pid>/root`.

The runtime's claims about the image are not trusted. The verifier fetches the image from its registry by digest [@oci_image_spec]; manifests and layers are content-addressed, so every byte is checked against the digest that names it. It applies the layers in order, including whiteouts, to obtain the image's root filesystem as a map of file hashes, and compares it with the container's files, except the few files every runtime writes (such as `/etc/hosts`) and mounted paths. Optionally the image must be attested by a configured GitHub workflow, through a Sigstore bundle stored as an OCI referrer or in GitHub's attestation store. Volumes are listed, because code in them is outside the image. Image files are recorded as explained, and the container's processes are judged like any other.

## Hardware Binding

### TPM 2.0

The attester uses `tpm2-tools` to create an Attestation Key (AK) under the Endorsement Key (EK), make it persistent, and produce quotes over selected PCRs with the verifier's qualifying data [@tpm2_spec]. The verifier needs no TPM software: it parses `TPMS_ATTEST` and checks the signature (RSA or ECDSA) against the pinned AK, the structure's magic and type, the qualifying data, the digest of the reported PCR values, and any expected PCR values.

A verifier trusts an AK only after enrollment, which Audit Status performs in three steps:

1. the EK certificate, stored in the TPM by its manufacturer, must chain to a TPM manufacturer's CA that the verifier trusts and must certify the TPM's EK public key;
2. the AK's public area must describe a restricted signing key that cannot leave the TPM (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`);
3. the verifier encrypts a random secret to the EK, bound to the AK's name (`MakeCredential`), and the server must return it; only the TPM holding both keys can decrypt it (`ActivateCredential`).

The resulting AK public key is pinned in the verifier configuration. A TPM without an EK certificate, typically a virtual TPM, is enrolled only when the operator explicitly allows it; credential activation still binds the AK to that EK, but nothing then shows that the TPM is genuine, and enrollment says so. Results note whether the pinned key was enrolled against an endorsement certificate.

### IMA

With the kernel's Integrity Measurement Architecture enabled [@ima_sailer; @ima], the kernel hashes files as they are executed, mapped executable, or read (according to its policy), appends each measurement to a log, and extends the hash into PCR 10 before the file is used. The verifier parses the binary log (templates `ima-ng`, `ima-sig` and `ima-buf`) and replays it entry by entry until it reaches the quoted PCR 10 value. Only the SHA-256 bank is used, and only when the signed quote selected PCR 10 in it, because in the SHA-1 bank entries of unknown templates replay from digests the log itself supplies. Entries in the replayed prefix are backed by the TPM; entries logged after the quote are not. The verifier compares the kernel's measurements of the service's files with the public commit, and warns when the kernel also measured other contents for the same file since boot.

### Confidential Virtual Machines

In a confidential VM the CPU measures the VM's initial memory at launch and signs a report that includes 64 bytes chosen by the guest; the host operator cannot read the guest's memory or forge the report [@sev_snp; @tdx]. The attester obtains the report through Linux configfs-tsm [@configfs_tsm] with `SHA-512(nonce || evidenceDigest)` as report data, together with the certificates the host provides.

* **AMD SEV-SNP**: the report is signed (ECDSA P-384) by the chip's VCEK or a VLEK. The verifier checks the certificate up to AMD's ARK for the product (Milan, Genoa, Turin), through the ASK for a VCEK or the ASVK for a VLEK, all shipped with the library; requires the certificate's TCB values to match the report's; and rejects a guest policy that allows debugging.
* **Intel TDX**: the quote is signed by the quoting enclave's attestation key, which the QE report binds; the QE report is signed by the platform's PCK, whose certificate chain in the quote must lead to Intel's SGX root CA, shipped with the library. A TD in debug mode is rejected.

In both cases the verifier checks the report data against the nonce and digest and compares the launch measurement with the measurements pinned in its configuration; a report that verifies without a pinned measurement produces a warning.

## Monitoring Between Audits

An audit sees one moment. Code that ran and was removed before the audit leaves no file to find. The monitor runs a `bpftrace` program that records every program started and, where the kernel supports function tracing with BTF, every file mapped executable. The next audit includes a summary of that window: each distinct path, how often and by which users it was seen, and its current hash and owning package, or an error when the file is gone. The verifier explains these files like running code, and reports programs that ran and are no longer on disk. The log is written by root on the audited machine, so it is software evidence; IMA provides the same record with hardware backing.

## Audit Status: Attester, Verifier and Transports

Audit Status packages Attestium as a single executable (Node.js single executable application) for Linux x64, Linux arm64 and macOS arm64, and as a container image, with published SHA-256 checksums and build provenance for every release. The verifier checks the attester's own executable, as reported in the evidence, against the published checksums of the release it claims to be.

The attester accepts exactly three operations: `check <nonce>` (collect evidence), `enroll` (return the AK and EK, creating the AK if needed), and `activate <credential>` (complete credential activation). It reads its configuration from a root-owned file and accepts nothing else from the verifier. Two transports carry these operations:

* **SSH**: the verifier's key is installed with `command="auditstatus ssh",restrict` in `authorized_keys`, so the key can run only the attester. Host keys must be pinned in a `known_hosts` file; an unknown or changed host key fails the connection.
* **Kubernetes**: the attester runs as a DaemonSet (one pod per node) and serves the same operations on the pod's loopback interface (`auditstatus serve`). The verifier reaches it with `kubectl port-forward`, using a service account that may only list the attester pods and port-forward to them. No Service or open port is needed.

A third mode, `local`, runs the attester in the verifier's own process when both are the same machine. On servers, the attester is granted `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` so that it can read other users' processes and files without running as root. An Ansible role installs the attester, its account, its restricted keys, its capabilities and the optional monitor service; a Helm chart installs the DaemonSet with optional TPM and IMA access. `auditstatus init` inspects a repository and writes a starting verifier configuration, an attester configuration and a scheduled workflow; `auditstatus doctor` checks, on either side, that every check can run.

The verifier (`auditstatus verify`) runs the servers in parallel. For each it sends a fresh nonce, collects evidence, appraises it and writes the reports. Every finding has a severity: `fail` (the server differs from its references or the evidence is invalid), `warn`, `error` (the verifier could not complete a check, which makes the result inconclusive) and `info`. With a retry delay configured, a server that fails or is inconclusive is collected again, because a deployment in progress looks like tampering; the second result is reported, and the first attempt's findings remain in it as a warning. Values from evidence are escaped before they reach the Markdown report, so a server cannot inject links or markup into a published page.

## The Core Library API

Beneath the evidence format, the main module keeps the lower-level primitives: file manifests with SHA-256 and git blob ids, Ed25519-signed baselines and comparisons with them, challenge-response with signed verification responses, a single-manifest TPM attestation with qualifying data `SHA-256(nonce || report digest)`, and runtime tracking that records the hash of each CommonJS module's source as it is compiled. Configuration is data only: JavaScript configuration files are never loaded, because they would run code from the tree being verified.

# The Solution

Attestium is a set of small modules that together produce and appraise evidence of what a machine runs. It is organized around six principles.

1. **The attester reports; the verifier judges.** Nothing collected on the audited machine includes a verdict. The machine reports hashes, paths, process state and hardware statements; pass and fail are decided elsewhere.

2. **Every fact is compared with a reference the operator does not control.** A deployed file is compared with the public commit, a reproduced build, or an attested release. An installed package is compared with the registry artifact whose hash the lockfile at that commit pins. A running binary is compared with an official release, a signed checksum list, a container image fetched by digest, or the package that owns it in the distribution's signed archive.

3. **Every running executable and library must be explained.** The verifier does not stop at the application's directory. Every file that an inspected process runs or maps executable is matched with a reference, and a file that no reference explains is reported.

4. **Hardware binds the evidence when it is available.** A TPM quote or a confidential VM report binds the verifier's nonce and a digest of the whole evidence. Each result states which level of evidence it reached (Section 5).

5. **Incomplete is never passing.** A check that could not run, a reference that could not be fetched, or a package whose reference cannot exist makes the result inconclusive or unverifiable, never passing.

6. **The format is open.** Evidence follows a published specification and JSON Schema, independent of language and transport, so attesters and verifiers written in other languages interoperate.

## Components

* **Evidence format, version 2**: A JSON document with services, processes, executables, libraries, installed packages, an optional record of what ran between audits, and optional TPM, IMA and confidential VM statements, all covered by a canonical digest (Section 4.2).

* **Process integrity and runtime profiles**: The executable pages of every file-backed mapping compared byte for byte with the file, memory map anomalies, dynamic linker injection, tracers, `memfd` payloads and listening sockets, plus the code-injection vectors and debug ports of Node.js, Python, the JVM, Ruby, .NET, Erlang/Elixir, PHP, Perl, Deno and Bun.

* **Package ecosystems**: Installed packages of npm, PyPI, RubyGems, Hex, Composer, Maven and NuGet compared file by file with the artifacts their lockfiles pin; the dependencies compiled into Go and Rust binaries compared with `go.sum` and `Cargo.lock`.

* **Release references**: Official Node.js releases, release manifests with GitHub artifact attestations [@github_attestations], npm provenance, Sigstore bundle verification with a TUF client for Sigstore's trust root [@tuf_spec], and checksum lists signed with OpenPGP, minisign or Sigstore.

* **Operating system packages**: The owner of each executable and library in the dpkg database, checked against the Debian or Ubuntu archive through its signed `InRelease` file [@debian_secureapt].

* **Containers**: The image, mounts, writable layer and root filesystem of each container, compared with the image fetched from its registry by digest [@oci_image_spec].

* **Hardware attestation**: TPM 2.0 quotes and endorsement key enrollment, replay of the Linux IMA measurement log [@ima_sailer], and AMD SEV-SNP and Intel TDX reports obtained through configfs-tsm [@configfs_tsm], all verified in pure JavaScript on the verifier.

* **Monitor**: An eBPF program that records every program executed, and every file mapped executable, between two audits.

## The Stack

The system has three parts, each with a separate purpose:

1. **[Attestium](https://github.com/attestium/attestium.com) (library and format)**: The evidence format and the primitives to collect and appraise each part of it. It makes no decisions about policy and runs no network service.

2. **[Audit Status](https://github.com/auditstatus/auditstatus) (attester and verifier)**: A single executable built on Attestium. On a server it collects evidence (`auditstatus ssh` behind a restricted SSH key, or `auditstatus serve` on the loopback interface of a Kubernetes pod). Elsewhere it verifies that evidence against public references (`auditstatus verify`) and writes reports and a badge.

3. **Publication**: A scheduled job, typically a GitHub Actions workflow in a public repository, runs the verifier, commits its reports, opens an issue when a server does not pass, and serves a badge that a status page displays.

## Why GitHub Actions

Running the verifier in a public repository's Actions adds no new processor to a service's data pipeline: most open-source projects already trust GitHub with their source code and CI. The workflow definition, its logs and every committed result are public, so anyone can read what was checked and when, and can rerun the same verifier against the same references.

The pattern is not tied to GitHub. `auditstatus verify` is a stateless command that reads a configuration file and writes `report.json`, `report.md` and a Shields.io endpoint badge. It runs the same way in any CI system or on a separate host. The Audit Status GitHub Action wraps it with optional publication to a branch, an issue that opens when the audit stops passing and closes when it passes again, and a configurable failure threshold.

## The Verification Flow

The flow follows the RATS roles [@rats]. The verifier generates a random nonce and asks the attester for evidence over one of two transports: an SSH key whose `authorized_keys` entry forces the attester command, or a Kubernetes port-forward to an attester that listens only on its pod's loopback interface. The attester collects evidence, computes its digest, and asks the hardware to bind the nonce and the digest:

* TPM 2.0 quote, qualifying data: `SHA-256(nonce || evidenceDigest)`
* Confidential VM report, report data: `SHA-512(nonce || evidenceDigest)`

The verifier checks the evidence against the schema, the nonce, the time window and the recomputed digest, verifies the hardware statements with keys it pinned or vendor roots it ships, and appraises every fact against references it fetches itself.

```{.mermaid format=pdf}
graph LR
    V["Verifier<br/>(auditstatus verify)"] -->|1. nonce<br/>SSH or port-forward| A["Attester<br/>(auditstatus ssh / serve)"]
    A -->|2. collect| E["files, /proc, packages,<br/>containers, TPM, IMA,<br/>SEV-SNP / TDX, monitor"]
    A -->|3. evidence + digest<br/>+ hardware statements| V
    V -->|4. fetch references| R["commit, build, registries,<br/>images, releases,<br/>distribution archive"]
    V -->|5. attestation result| P["Relying parties<br/>(reports, badge,<br/>status page)"]
```

The server never decides whether it passed. It reports what it sees; the verdict comes from another machine, using references the server's operator does not control.

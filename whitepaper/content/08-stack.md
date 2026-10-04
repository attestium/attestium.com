# The Attestium Stack in Context

Attestium builds on existing work in system transparency, remote attestation and supply chain security. This section describes how it relates to that work, and then the components it is built from.

## Related Work

| Project | Focus | Relationship to Attestium |
|--|---|-----|
| **System Transparency** | Verifiable boot of a known operating system image | Attestium extends the same goal to the running application: its files, its executable memory, its dependencies and the libraries it maps. |
| **Keylime** | TPM and IMA remote attestation, with measured boot and runtime policies | Keylime attests the platform against IMA allowlists and boot policies. Attestium derives the expected value of each running file from public references (commits, lockfiles, images, releases, distribution archives) and adds process memory comparison, runtime injection checks and confidential VM reports. |
| **Sigstore** | Signing and verifying software artifacts | Attestium verifies Sigstore bundles as references, and checks what is installed and running after deployment. |
| **SLSA and in-toto** | Provenance and integrity of the build | They describe how an artifact was produced; Attestium checks that the deployed result still matches the artifact and that the running processes match the deployed files. |
| **Reproducible Builds** | Independently rebuilding artifacts from source | Attestium uses reproduced builds as references for generated files, and depends on reproducibility for any build output without an attestation. |
| **Socket.dev** | Analysis of what packages do | Socket judges package behavior; Attestium confirms that the installed files are exactly the artifacts the lockfile pinned. |

**System Transparency** [@mullvad_st; @mullvad_diskless; @system_transparency_overview] provides verifiable boot for Mullvad's VPN servers: a signed, reproducible operating system image, booted without persistent state. Attestium takes the same goal, that users can verify what a server runs, and applies it to the application layer, where most services change several times a day.

**Keylime** [@keylime] is a CNCF project for TPM-based remote attestation, including measured boot and IMA runtime policies. Its policies are lists of expected file hashes that an operator maintains. Attestium obtains the expected value of every running file from a public reference instead, which is what lets a third party with no relationship to the operator perform the check.

**Sigstore** [@sigstore; @sigstore_ccs], **SLSA** [@slsa] and **in-toto** [@in_toto] secure the path from source to artifact. Attestium consumes their output: GitHub artifact attestations and npm provenance are Sigstore bundles carrying in-toto statements with SLSA provenance, and Attestium verifies them as references for release manifests, container images and packages.

**Reproducible Builds** [@reproducible_builds] ensure that a given source always produces the same binary, which lets independent parties confirm that a binary came from its claimed source [@ieee_reproducible]. Attestium's comparisons are the runtime counterpart: they confirm that the binaries and packages on a server are the published ones, and that the processes in memory have not been modified since they were loaded.

The **IETF RATS** architecture [@rats] provides the vocabulary: attester, verifier, relying party, evidence, endorsements, reference values and attestation results. The **SCITT** architecture [@scitt] describes transparency services for signed supply chain statements, a natural place to record attestation results (Section 8).

## Architecture Overview

```{.mermaid format=pdf}
graph LR
    subgraph PUB["Publication"]
        U1["CI workflow"]
        U2["report.json / report.md"]
        U3["Badge, status page"]
    end
    subgraph AS["Audit Status"]
        A1["auditstatus verify"]
        A2["auditstatus ssh / serve"]
    end
    subgraph AT["Attestium"]
        C1["Evidence format"]
        C2["Process integrity, runtimes"]
        C3["Ecosystems, releases"]
        C4["Containers, OCI, distro"]
        C5["Sigstore, TUF, checksums"]
        C6["TPM, IMA, SEV-SNP, TDX"]
    end
    subgraph HW["Audited machine"]
        T1["TPM / CPU"]
        T2["/proc, eBPF"]
        T3["Files, packages, containers"]
    end
    subgraph EXT["References"]
        E1["Git hosts"]
        E2["Package registries"]
        E3["Container registries"]
        E4["Releases, archives"]
    end
    PUB --> AS --> AT --> HW
    A1 --> EXT
```

## Implementation

**Attestium** is a Node.js package (Node.js 18 or later) with two runtime dependencies: `cosmiconfig` for data-only configuration files and `js-yaml`. Everything a verifier needs to authenticate a reference is implemented in the library in JavaScript on top of Node.js's `crypto` module: parsing of TPM structures, X.509 path validation for TPM manufacturer, AMD and Intel chains, SEV-SNP and TDX report verification, Sigstore bundle verification, a TUF client, minisign, ASN.1, ELF, tar, zip and TOML readers, and a JSON Schema validator for the subset the evidence format uses. Every parser that reads data from the audited machine is bounds-checked. Downloads go through a hardened HTTP client: HTTPS only (plain HTTP only for loopback hosts, or for content authenticated by signature), bounded redirects that never forward credentials to another host, size limits, timeouts, and retries with back-off.

External programs are used only where a system interface requires them, always without a shell and with bounded time and output: `tpm2-tools` on the attester for TPM operations; `gpgv` on the verifier for OpenPGP signatures; `git` on the verifier for blobless clones of public repositories, with hooks, prompts and system configuration disabled; the Docker Engine API or `crictl` on the attester for container metadata; and `bpftrace` for the optional monitor. Nothing the attester collects is executed or loaded; binaries are hashed and scanned for build information, never run.

The test suite requires full statement, branch, function and line coverage. The tests are end-to-end: they attack real processes, serve real release archives, registry artifacts and container images from local servers, and use a software TPM.

**Audit Status** is built on Attestium and `js-yaml`. It is distributed as a Node.js single executable application for Linux x64, Linux arm64 and macOS arm64, and as a container image, with `SHA256SUMS` and GitHub build provenance for each release. Deployment tooling consists of an Ansible role for servers, a Helm chart for Kubernetes clusters, a systemd unit for the monitor, a GitHub Action for the verifier, and the public registry's workflows, which verify every registered service hourly and publish signed reports to a status branch. Configuration for both roles is YAML with strict validation: unknown keys are errors, so a misspelled setting cannot silently disable a check.

# Roadmap

This section lists what is implemented and what remains. The remaining items follow from the limits stated in Section 5 and from what the code reports as unsupported or unverifiable.

## Implemented

* **Open evidence format**: Evidence version 2, with a specification, a JSON Schema, a canonical digest, and binding of the nonce and digest into TPM quotes and confidential VM reports.
* **Attester and verifier separation**: Collection and appraisal are separate functions for every check, so evidence collected on one machine is appraised on another against references the verifier obtains itself.
* **Process memory integrity**: Byte-for-byte comparison of every file-backed executable mapping with its file, including processes in containers; detection of linker injection, `memfd` payloads, tracers, and debuggers or inspectors opened at runtime.
* **Runtime profiles**: Code-injection vectors and debug ports of Node.js, Python, the JVM, Ruby, .NET, Erlang/Elixir, PHP, Perl, Deno and Bun.
* **Explanation of every executable and library**: Service files, packages, image files, official Node.js releases, pinned hashes, signed checksum lists, and Debian and Ubuntu packages from the signed archive, with snapshot lookups for superseded versions; unexplained files are reported.
* **Package ecosystems**: npm, PyPI, RubyGems, Hex, Composer, Maven and NuGet installations compared with the artifacts their lockfiles pin; Go and Rust dependencies compared inside the binary.
* **Build output**: Reproduced builds of the deployed commit for files the repository ignores.
* **Releases without git**: Release manifests attested with GitHub artifact attestations.
* **Sigstore and provenance**: Bundle verification with a TUF client for Sigstore's trust root; npm provenance; container image attestations as OCI referrers.
* **Containers**: Image, mounts, writable layer and root filesystem compared with the image fetched from its registry by digest.
* **TPM 2.0**: Attestation keys, quotes verified in pure JavaScript, and enrollment through endorsement key certificates and credential activation.
* **IMA**: Log replay to the quoted PCR 10, and comparison of the kernel's measurements of service files with the public commit.
* **Confidential VMs**: AMD SEV-SNP and Intel TDX reports through configfs-tsm, verified to the vendors' roots, with pinned launch measurements.
* **Monitoring between audits**: An eBPF record of programs executed and files mapped executable since the previous audit.
* **Transports and deployment**: SSH forced commands with pinned host keys; a Kubernetes DaemonSet reached through port-forward; an Ansible role, a Helm chart, a GitHub Action, a public registry that verifies registered services every hour, and setup and diagnostic commands.

## Remaining Work

### Hardware and Platform

* **Measured boot policies**: Expected PCR values are currently pinned by hand. Parsing the TCG UEFI event log and appraising each boot event (firmware, bootloader, kernel, command line, Secure Boot state) against reference values would make boot measurements maintainable across kernel and firmware updates.
* **IMA for all code**: Use the kernel's measurements, not only the attester's report, to explain every executable and library, and verify IMA file signatures (`ima-sig`) where distributions sign their files. With that, the monitor's record between audits would also have hardware backing.
* **Confidential computing**: Evaluate the TDX platform TCB level against Intel's published TCB information (currently reported, not evaluated), support minimum TCB policies for SEV-SNP, derive expected launch measurements from published firmware and images, and support further environments such as Arm CCA and AWS Nitro Enclaves.
* **Other operating systems**: Evidence collection is complete on Linux. macOS and Windows support the subset of process checks their tooling exposes.

### References

* **More distributions**: Only dpkg-based distributions (Debian and Ubuntu) are explained from their archives. RPM-based distributions (Fedora, Red Hat Enterprise Linux and its rebuilds, openSUSE) with signed repository metadata, Alpine's `apk`, and Arch Linux remain.
* **More registries and lockfiles**: Yarn and Bun lockfiles for JavaScript; CPAN for Perl, whose runtime is profiled but has no package plugin; Conda; Swift and Dart packages; and git dependencies hosted outside GitHub, which are currently unverifiable.
* **Code built on the server**: Native extensions compiled at install time, packages built from source distributions, and bytecode caches have no reference. Reproducing them in the verifier, as is done for configured build outputs, would remove these exceptions.
* **Wider provenance**: Verify the provenance attestations that registries other than npm publish, such as PyPI's, and require provenance by policy for selected dependencies.
* **Certificate transparency**: Sigstore signing certificates are verified through the transparency log entry, but their embedded certificate transparency timestamps are not.

### Results

* **Signed and logged attestation results**: Verifier reports are published as files in a git repository. Signing each result and recording it in a transparency log, such as a SCITT transparency service [@scitt], would let relying parties check that the history of results has not been rewritten, and would let several independent verifiers publish results for the same server.
* **Standard result formats**: Express results in the attestation result formats defined by the IETF RATS working group, so other relying parties can consume them.
* **Attested verifiers**: Run the verifier in a confidential VM, so that its own execution can be attested to relying parties.

### Limits of the Approach

Some limits are not expected to go away. Code produced by a JIT compiler has no file to compare with. Software evidence cannot be made to hold against root on the audited machine; only hardware-backed evidence can. And a reference only proves sameness: a service that faithfully runs malicious published code passes. Attestium shows that what runs is what was published; reviewing what was published remains necessary.

## Community and Collaboration

Attestium and Audit Status are open-source projects. Contributions of ecosystem plugins, distribution references and attesters or verifiers in other languages are welcome; the evidence format is designed so that independent implementations interoperate.

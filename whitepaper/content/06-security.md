# Security Architecture

The security of the system rests on three things: where each fact comes from (the attester, the kernel, or the hardware), what each reference proves, and what the verifier refuses to accept. This section states each precisely, including what a result does not prove.

## Cryptographic Primitives

* **SHA-256**: file, package, memory region, manifest and evidence digests; TPM qualifying data. Comparisons use SHA-256, with one exception: Composer packages are compared with the git tree of the commit `composer.lock` pins, by git object ids (SHA-1 in most repositories), because the commit names that tree and no other hash of the files is published. Git blob ids are otherwise recorded only to locate files in git trees.
* **SHA-512**: confidential VM report data; npm and NuGet integrity hashes as lockfiles record them.
* **Ed25519**: signed baselines and challenge responses over canonical JSON, and minisign checksum signatures.
* **TPM 2.0 quotes**: RSA (PKCS#1 v1.5) or ECDSA signatures by a TPM-resident Attestation Key over `TPMS_ATTEST`.
* **Confidential VM reports**: ECDSA P-384 (SEV-SNP) and ECDSA P-256 (TDX), with X.509 chains to AMD's and Intel's roots.
* **Sigstore and TUF**: X.509 chains to Sigstore's certificate authority, transparency log signatures and inclusion proofs, DSSE envelopes, and threshold-signed TUF metadata.
* **OpenPGP**: signatures on distribution archive indexes, Node.js checksum lists and project checksum lists, verified with `gpgv` against configured keyrings.

All verification of TPM quotes, X.509 chains, confidential VM reports, Sigstore bundles and TUF metadata is implemented in JavaScript on top of Node.js's `crypto` module, so a verifier needs no vendor tooling.

## Evidence Levels

Every check that runs on the audited machine depends on software that the machine's root user controls. That sets a hard limit on what software alone can prove. The verifier therefore assigns each result an evidence level, named after the hardware statements that verified: `software`, `tpm`, `tpm+ima`, `sev-snp` or `tdx`, or a combination such as `tpm+ima+sev-snp`.

### Software Evidence

The attester's report, bound to the nonce by the digest and appraised against independent references.

* **Proves**: that whatever produced the evidence answered this nonce within the time window; and, if the attester reported honestly, that every compared file, package, image file and mapped library matched its reference.
* **Detects reliably**: drift, failed or partial deployments, unreviewed changes, stale processes, modified files and packages, injected libraries and preloads, attached debuggers and open inspectors, code that differs from the distribution package or official release it claims to be, and attacks by anyone without root on the machine.
* **Does not prove**: anything against an attacker with root who anticipates the audit. Such an attacker can run a modified attester, or feed the real one false data, and report whatever the verifier expects. The attester's own hash is checked against its published release, but a modified attester can report a false hash.

### TPM-Bound Evidence

The same evidence, with a TPM quote over `SHA-256(nonce || evidenceDigest)` signed by an enrolled Attestation Key.

* **Proves**: that the evidence was produced after the nonce was chosen, on the machine whose TPM holds the enrolled key (and, with EK certificate enrollment, that this is a genuine TPM), and that the platform's PCR values were those quoted. When expected PCR values are pinned, it proves the machine booted the measured firmware, bootloader and kernel configuration those values describe.
* **Does not prove**: that the files, packages and processes reported are true. Everything after boot is still reported by software that root controls. A quote without pinned PCR values proves identity and freshness only.

### TPM with IMA

The kernel measures files as they are executed, mapped executable or read, according to its policy, and extends each measurement into PCR 10 before the file is used. The verifier replays the log to the quoted PCR 10.

* **Proves**: that the measured files had the logged contents when the kernel loaded them, even against a hostile root user, because an entry cannot be removed from a PCR and the replay must match the signed value. The verifier compares the measurements of the service's files with the public commit, so a modified file that was loaded fails even if it was restored afterwards.
* **Does not prove**: anything about files outside the IMA policy; anything the kernel did not measure (code injected into memory without a file, JIT-compiled code); or anything against a compromised kernel or firmware, which the boot measurements are meant to reveal only when their expected values are pinned. Currently the verifier uses the kernel's measurements for the service's own files; the other executables and libraries are still explained from the attester's report.

### Confidential Virtual Machine

A SEV-SNP or TDX report with report data `SHA-512(nonce || evidenceDigest)`, signed by a key that chains to the CPU vendor's root.

* **Proves**: that the evidence came from a guest running on genuine AMD or Intel hardware with confidential computing enabled and debugging disabled, after the nonce was chosen, and that the guest's launch measurement is one the verifier pinned. The host operator, including a cloud provider, cannot read the guest's memory or forge the report.
* **Does not prove**: anything beyond the launch measurement. The measurement covers the initial image (firmware and, depending on the setup, the kernel and initial RAM disk); what the guest loads later is reported by software inside the guest, whose root user controls it. For TDX, the platform's TCB level is reported but not evaluated against Intel's TCB information, so a platform with known but unpatched vulnerabilities is not rejected on that ground.

## What Each Reference Proves

Matching a reference proves that a file is the same as that reference, and nothing more. The strength of the conclusion depends on what the reference itself shows.

* **Public commit**: the deployed file is the file at a commit that is on the public branch. It does not prove the commit was reviewed or benign.
* **Reproduced build**: the generated file is what the build of that commit produces on the verifier. It relies on the build being reproducible [@reproducible_builds; @ieee_reproducible].
* **Release manifest with attestation**: the files are those a named workflow built from a named commit. It relies on that workflow and its build environment.
* **Lockfile-pinned package**: the installed files are those of the artifact whose hash the lockfile at the commit pins. It does not prove that the artifact was built from its project's public source; npm provenance, where a package publishes it, links the tarball to a repository and commit. A jar that the build does not pin is compared with Maven Central by coordinates, which trusts the registry instead of the repository.
* **Container image by digest**: the container's files are the image's files. With an attestation, the image was built by a named workflow; without one, the image is only what the registry holds under that digest.
* **Official release, signed checksum list, distribution package**: the binary is the one its publisher signed. It is as trustworthy as that publisher's signing key.
* **Go and Rust build information**: the dependencies the build recorded are the ones the lockfile pins. Because the build writes this record, it shows nothing about the binary unless the binary's own hash is matched by one of the references above.

Some files have no possible reference, and are reported as such instead of passing: Python bytecode caches, native extensions compiled on the server, packages built from source distributions, dependencies from unpinned sources, and generated files such as Composer's autoloader unless a reproduced build covers them.

## What the Verifier Refuses

* Evidence that fails the schema, carries another nonce, is outside the time window, or whose digest does not match.
* Hardware statements verified with keys taken from the evidence. The verifier uses only attestation keys it pinned at enrollment and vendor roots it ships.
* References that are not authenticated by something it already trusts: archive indexes whose signature fails, registry artifacts whose hash differs from the lockfile, image layers whose digest differs, bundles whose certificate identity differs.
* Incomplete checks as passing. A process with any check in `incomplete`, a reference that could not be fetched, or a missing hardware statement from a machine configured to require it makes the result fail or inconclusive.
* Code from the audited server. The verifier never loads configuration or code from the evidence; a reproduced build runs only for commits on the audited branch of the public repository, with a minimal environment.

## Process Memory Integrity

File-level verification answers whether the file on disk is correct. It cannot answer whether the code executing in memory is the code on disk. An attacker with root, or with `ptrace` access to a process, can modify its executable memory without touching any file [@redcanary_fileless]:

* **`ptrace` injection**: attaching to a process and writing code into its address space.
* **`/proc/<pid>/mem` writes**: writing to a process's memory through the proc filesystem.
* **Linker hijacking**: `LD_PRELOAD`, `LD_AUDIT` or `/etc/ld.so.preload`, which load a library before all others.
* **Fileless payloads**: `memfd_create` objects that are executed without ever existing on disk.
* **Runtime-specific paths**: code loaded through a runtime's own options or environment (`NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS` agents, `RUBYOPT`, .NET start-up hooks), or a debugger or inspector opened at runtime and used to evaluate code.

The process integrity checks detect each of these, and the test suite demonstrates each against a live process: a byte of `libc` modified through `/proc/<pid>/mem`, preloads, an inspector opened with `SIGUSR1`, a `ptrace`-attached tracer, and a `memfd` payload. Code produced by a JIT compiler lives in anonymous memory with no file to compare against. For interpreted and JIT-compiled languages, what matters is the source that was loaded; that is covered by comparing the source with the public commit, by reproducing generated files, by reporting files changed after the process started, and, with IMA, by the kernel's own measurements.

## Threat Model

The system considers the following adversaries.

1. **External attacker without root**, for example through a remote code execution vulnerability in the application. The ways such an attacker changes what runs are reported: modified files and packages, preloads and runtime injection options, debuggers and inspectors, `memfd` payloads, and processes whose files changed after they started. Code kept only in a runtime's heap is not visible to memory comparison. A process started outside the service's directory under another user is not inspected, although the monitor records its execution.

2. **Attacker or insider with root.** Software evidence alone does not hold: root can replace the attester or the data it reads. Mistakes and casual changes are still reported. A deliberate attacker with root is detected only by hardware-backed evidence: IMA measurements of the files the kernel loaded, bound by a TPM quote, which root cannot erase. An attacker who can load a malicious kernel module or boot a modified kernel is detected only if the boot measurements are pinned and the kernel's integrity controls prevent unmeasured changes.

3. **Hosting or cloud operator.** An operator with physical or hypervisor access can read and modify a normal VM's memory. A confidential VM prevents this, and its report proves the launch measurement; the guest's later state is still reported by software inside it.

4. **Supply chain attacker**, who alters a package in a registry, a mirror or on disk. Lockfile-pinned hashes and file-by-file comparison detect any change after the lockfile was written. A malicious version that was published, reviewed and pinned before the change is outside this check; provenance attestations narrow the gap for packages that publish them.

5. **Compromised reference source.** The verifier trusts the public repository host, the registries through the lockfile's hashes, the distributions' signing keys, the Sigstore trust root, the TPM manufacturers' and CPU vendors' roots, and its own CI environment. A compromise of any of these affects results that depend on it. Content-addressed references (lockfile hashes, image digests, git commits) limit what a compromised transport can do.

6. **Compromised verifier.** A verifier that lies can publish false results. The verifier's code, configuration, logs and results are public, and anyone can run the same verifier against the same server if given access, but the results themselves are not yet signed or recorded in a transparency log (Section 8).

7. **Changes between audits.** A change made and undone between two audits leaves no file to find. The monitor records what ran between audits, with the strength of software evidence; IMA records the same with hardware backing until the next reboot.

Each layer narrows what an attacker can do unnoticed. Only hardware-backed evidence holds against an attacker who already controls the machine, and every result states which level it reached.

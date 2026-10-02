# Security model and limits

What Attestium defends against, what it cannot, and how to deploy it so its results mean what they say. Read this before you rely on a result: a root user on the checked machine, code compiled at run time, software keys, and the references themselves all limit what a result proves.

## What is trusted

| Component | Trusted for | If it is wrong |
| --- | --- | --- |
| The verifier and the machine it runs on | Everything: it makes the decision | Results mean nothing. Run it somewhere the audited machines cannot reach, such as CI. |
| References the verifier fetches | What the right code is | A compromised registry, repository or archive makes bad code look good; see [Trust in references](#trust-in-references) |
| Keys and roots the verifier pins | Hardware statements, signatures | A leaked or wrong key lets someone forge statements |
| The attester | Reporting facts truthfully | Without hardware, a compromised attester can report anything |
| The checked machine's kernel | Showing processes and files as they are | A compromised kernel can hide anything from software; IMA and a TPM detect a compromised boot chain, not a kernel exploit at run time |

The attester never decides whether the machine passes. The verifier obtains every reference itself, by digest where the reference is content-addressed, and never uses a key taken from the evidence.

## Adversaries

**An attacker without root** (a remote code execution bug in the application, a stolen deploy key, a malicious dependency update) has to change what runs in a way the attester reports: a modified file, a package that differs from its tarball, a preload in `NODE_OPTIONS`, `LD_PRELOAD`, an open inspector, an attached debugger, a `memfd` payload, a new program that the monitor records. Software evidence detects these.

**An attacker with root** on the checked machine controls the attester. They can run a modified attester, feed it false data, or answer the verifier with evidence from a clean copy. Software evidence cannot stop them ([Forged answers](forged-answers.md) shows such a forgery step by step). What holds:

*   A TPM quote binds the evidence to the enrolled machine and to its measured boot state. Root cannot forge a quote or reset a PCR.
*   IMA, with the log replayed to the quoted PCR 10, shows the hashes of files the kernel loaded. Root cannot remove entries.
*   Neither shows that the attester reported the rest truthfully. Root can still misreport processes, files outside the IMA policy, and anything decided after boot.

**A compromised kernel or firmware** can lie to everything above it. Boot measurements in PCRs 0 to 7 are designed to reveal a changed bootloader, kernel or firmware at boot, when you pin their expected values. A kernel exploited at run time is outside what Attestium can see.

**A malicious operator of the host** of a virtual machine can read and change the guest's memory, unless the guest is a confidential VM (AMD SEV-SNP, Intel TDX). Then the report proves the launch measurement and that debugging is off, signed by the CPU vendor's key.

**An attacker on the network** between verifier and attester can replay, change or answer in place of the server. The nonce stops replay; hardware statements stop forgery. Without hardware, only the transport stops the rest: reach the attester over SSH, with the verifier's key restricted to the attester command and the server's host key pinned, not through an HTTP endpoint, which answers anyone, depends on any public CA, and can be answered by a proxy in front of the server ([Forged answers](forged-answers.md#why-ssh-and-no-http-endpoint)).

## Root on the machine

State the evidence level with every result (see [Concepts](concepts.md#evidence-levels)). A software-evidence result is a statement about drift, mistakes and attacks without root. Do not present it as proof against a root attacker.

To raise the bar:

*   enable a TPM quote over PCRs 0 to 7 and 10, and pin the AK at enrollment through the EK certificate chain and credential activation ([Hardware](hardware.md));
*   enable IMA with a policy that measures executables and mapped libraries, and compare the IMA measurements with the evidence;
*   run in a confidential VM, and pin the expected launch measurement;
*   keep the attester minimal and verify its own binary (the evidence reports its path and hash in `attester.executable`) against a published release.

## Code compiled at run time

Just-in-time compilers (V8, the JVM, .NET, PyPy, LuaJIT) write machine code into anonymous memory. That code has no file to compare with. `ProcessIntegrity` counts anonymous executable regions but cannot check them, and it compares file-backed executable pages byte for byte with the files on disk.

For interpreted and JIT-compiled languages, what matters is the source and bytecode that were loaded:

*   compare the files on disk with the reference;
*   report files written or changed after the process started (`changedAfterStart`, `metadataChangedAfterStart`): the process may run an older or newer version than the disk shows;
*   avoid caches that cannot be verified, such as Python `.pyc` files written on the server;
*   check every runtime's code-loading vectors (environment, options, attach mechanisms, debug ports).

Code evaluated from data (`eval`, deserialization gadgets, a template engine) is outside what any file comparison can see.

## Software keys and TPM keys

An Ed25519 signature proves which key signed. A key stored in software on the machine being verified can be read by that machine's root user, who can then sign anything. So:

*   keep signing keys for baselines off the verified machine (sign in CI, pin the public key in the verifier);
*   pass the trusted public key when you verify: `signing.verify()` and `Attestium#compareWithBaseline()` without one only check that the envelope is self-consistent, and a baseline re-signed with another key still verifies;
*   for statements a machine makes about itself, use a TPM quote: the attestation key cannot leave the TPM (`fixedTPM`, `fixedParent`).

Pinning an AK without enrollment through the EK is trust on first use: it proves the same key signs later, not that the key lives in a real TPM. A TPM behind a hypervisor (a virtual TPM) is as trustworthy as the hypervisor, unless the VM is confidential.

## Trust in references

A result is as good as the reference behind it. Each kind of reference trusts someone:

| Reference | Trusts | Weaker when |
| --- | --- | --- |
| Public git commit | The repository host, and the review of what was merged | The deploy branch is not protected |
| Lockfile-pinned package (npm integrity, wheel hash, gem checksum, Hex outer checksum, NuGet content hash) | The lockfile at the commit; the registry only served bytes | The lockfile pins no hash (the package is then unverifiable) |
| Maven jar not pinned by the build | Maven Central | Always: pin jars with Gradle dependency verification or maven-lockfile |
| Gem without a `CHECKSUMS` entry | The registry's checksum | Always: run `bundle lock --add-checksums` |
| Composer commit tree | The source repository, by git blob id | Git blob ids are SHA-1; a colliding blob could pass. Prefer dist archives with a pinned hash where your policy requires SHA-256 |
| Official Node.js release | nodejs.org over HTTPS | `nodeKeyring` is not set; with it, the release team's signature is required |
| Debian or Ubuntu archive | The distribution's signing key | The keyring on the verifier is outdated or wrong |
| Signed checksum list | The publisher's key or Sigstore identity | The list is unsigned (`signed: false`): only HTTPS and the host |
| Sigstore bundle | Fulcio, Rekor, and the identity you require | No `identity` is required: any signer is accepted |
| Container image by digest | The image's content, not its builder | The image is not attested |
| TPM manufacturer CA, AMD and Intel roots | The vendors | A vendor key is compromised |

A reference proves that deployed code equals published code. It does not prove the published code is safe: a malicious commit, a malicious package version pinned in the lockfile, or a compromised build that produced a signed artifact all pass. Provenance (npm provenance, GitHub artifact attestations) narrows this by naming the repository, commit and workflow that built an artifact.

## Inconclusive is not passing

A check that could not complete never counts as a pass. Report it:

*   a process check that lacked permission (`incomplete`);
*   a file the attester could not read (`errors`), or a list cut at a limit (`truncated`);
*   a reference that could not be fetched (`error`);
*   a package with no possible reference (`unverifiable`);
*   hardware configured as required but unavailable (`required: true`).

The attester needs enough privilege to see what it reports. Reading another process's memory needs ptrace access (the same user with `kernel.yama.ptrace_scope` 0, or `CAP_SYS_PTRACE`); reading another user's `/proc/<pid>/environ` and `/proc/<pid>/mem` also needs `CAP_DAC_READ_SEARCH`. On Linux, Attestium checks for files by opening or stating them, never with `access()`, which ignores file capabilities.

## Hardening built into the library

*   Evidence is validated against a closed schema before any field is used; unknown fields in closed objects are rejected.
*   Canonical JSON refuses ambiguous values (non-finite numbers, `undefined` in arrays, non-plain objects) instead of coercing them.
*   HTTP fetches are HTTPS only (plain HTTP only for loopback, and for archive indexes whose content is signed), with bounded size, timeouts, bounded redirects that never forward credentials to another host, and retries only on 429, 5xx, timeouts and refused or reset connections.
*   Archives (tar, zip, gzip) are read in memory with path checks and size limits; nothing is extracted to disk from a reference except `.deb` files handed to `dpkg-deb`.
*   Git runs with hooks off, no prompts, no system or global configuration, and only `https` URLs.
*   Configuration files of the `Attestium` class are data only (JSON, YAML); JavaScript configuration is never loaded, because it would run code from the tree being verified.
*   Process ids, nonces, PCR indexes, handles and package names are validated before they reach `/proc` paths or command arguments; commands run without a shell.

## Reporting a vulnerability

Report vulnerabilities privately as described in the [Forward Email security policy](https://forwardemail.net/security).

# Concepts

This page explains the ideas behind Attestium: who produces evidence and who checks it, what evidence and references are, how a nonce and a digest make evidence fresh and tamper-evident, why every running file must be explained, how a failing result differs from an inconclusive one, and what each evidence level proves.

## Roles

Attestium follows the IETF remote attestation architecture, RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)).

| Role | Runs where | Does what |
| --- | --- | --- |
| Attester | On the machine being checked | Collects facts and reports them. It never decides whether the machine passes. |
| Verifier | Somewhere else, typically in CI | Sends a fresh nonce, receives evidence, obtains references itself, and compares. |
| Relying party | Anywhere | Reads the verifier's result, for example on a status page. |

In RATS terms, Attestium evidence is RATS evidence, and a verifier's report is an attestation result. The references are what RATS calls reference values and endorsements.

The split matters because the attester runs on the machine under test. If that machine is compromised, its attester may be too. A verifier that trusts nothing from the machine except what it can check against an outside reference, or what hardware signs, keeps the decision out of the attacker's hands.

## Evidence

Evidence is a JSON document in the format defined by [SPEC.md](../SPEC.md) and [`schema/evidence.schema.json`](../schema/evidence.schema.json). It lists facts:

*   the files of each service directory, with their SHA-256 and git mode;
*   the installed packages of each ecosystem, with the hash of every file;
*   every running process of each service: executable, command line, runtime, integrity findings;
*   every executable and every library mapped executable, once, with its hash and owning distribution package;
*   containers: the image the runtime names, mounts, the writable layer, the root filesystem;
*   optionally: a TPM quote, a confidential VM report, the IMA log, and a record of programs run since the last audit.

Evidence contains no verdicts. A process's `integrity.findings` are facts too (for example "`LD_PRELOAD` is set"); the verifier decides what they mean.

## References

A reference is what the verifier compares a fact with. The verifier obtains every reference itself, never from the evidence:

| Fact | Reference |
| --- | --- |
| A service's files | The public git commit, a reproduced build, or a release manifest attested by CI |
| An npm package | The registry tarball whose integrity the lockfile at the commit pins |
| A Python wheel | The wheel whose hash the lockfile pins |
| A container's files | The image layers, fetched by digest from the registry |
| The Node.js binary | The binary inside the official release archive listed in `SHASUMS256.txt` |
| A distribution file | The `.deb` reached from the signed `InRelease` file of the Debian or Ubuntu archive |
| A downloaded binary | A pinned hash, or a signed published checksum list |
| A TPM quote | The attestation key pinned at enrollment, and expected PCR values |
| A confidential VM report | The vendor's root certificate, shipped with the verifier |

Where a reference is content-addressed (a registry tarball with an integrity hash, an image layer, a git commit), fetch it by digest and check the digest. A reference that could not be fetched makes the check inconclusive; it never makes it pass.

## Nonce and digest binding

A verifier must know that evidence is fresh and has not been changed. Attestium does this in three steps:

1.  The verifier picks a random nonce of 16 to 64 bytes and sends it hex encoded.
2.  The attester collects the evidence, puts the nonce in it, and computes `evidenceDigest`: the SHA-256 of the canonical JSON of the evidence without `evidenceDigest`, `tpm`, `ima` and `confidential`.
3.  When hardware is present, the attester asks it to sign both values:
    *   a TPM quote with qualifying data `SHA-256(nonce || evidenceDigest)`;
    *   a confidential VM report with report data `SHA-512(nonce || evidenceDigest)`.

The verifier checks that the nonce is its own, that `collectedAt` is inside its time window, and recomputes the digest. Then it checks the hardware statement with keys it trusts. A replayed answer fails the nonce check. Changed evidence fails the digest check. Evidence produced elsewhere fails the hardware check.

Without hardware, the digest proves only that the evidence was not changed after the digest was computed. Anyone who controls the attester can compute a new digest over forged evidence. See [Evidence levels](#evidence-levels) and [Forged answers](forged-answers.md).

## Explaining every running file

A server runs more than the application: an interpreter, shared libraries, helper programs, tools started by cron. Any of them can carry an attacker's code. So the evidence lists every file that an inspected process runs or maps executable, and the verifier must explain each one by a reference:

*   a service file that matched its commit, build or attested release;
*   a file of a verified package;
*   a file of the container image;
*   an official runtime release (Node.js);
*   a pinned hash, or an entry in a signed published checksum list;
*   the file of its owning Debian or Ubuntu package in the signed archive, using an archive snapshot from the install time when the version was superseded.

A file that matches no reference is unexplained. A file that contradicts its reference (the dpkg database says package `libssl3` owns it, but the file differs from the one in that package) fails.

The same applies to the monitor's record. A program that ran between two audits and was then deleted leaves no file to hash; the record still names it, and the verifier reports it.

Build information inside Go and Rust binaries is written by the build, so it proves nothing about the binary by itself. The binary's own hash does. The build information shows which dependencies were compiled in, and those are compared with the lockfile at the commit.

## Pass, fail and inconclusive

Every check ends in one of three states:

| State | Meaning | Examples |
| --- | --- | --- |
| Pass | The fact matches a reference the verifier obtained itself | Every file equals the commit's file |
| Fail | The fact contradicts its reference, or shows tampering | A modified file, a critical process finding, a quote over another nonce |
| Inconclusive | The check could not complete | A file the attester could not read, a truncated list, a process check that lacked permission, a registry that did not answer, a package with no pinned hash |

Treat inconclusive as not passing. A clean result means nothing unless every check ran. Attestium reports this explicitly:

*   `ProcessIntegrity#checkAll()` returns `incomplete`, and `passed` is false when it is not empty.
*   Ecosystem comparisons return per-package statuses `failed`, `unverifiable` and `error`; any of them makes `passed` false.
*   Evidence fields `truncated`, `errors` and `incomplete` tell the verifier where the attester could not see.

## Evidence levels

The strength of a result depends on what backs it. Report the level with every result.

| Level | Backed by | Proves | Does not prove |
| --- | --- | --- | --- |
| Software evidence | The attester's report, bound to the nonce by the digest | Drift, failed deploys, modified files and packages, injected libraries, attached debuggers, open inspectors, unexplained programs | Anything against an attacker with root who anticipates the check: root can run a modified attester |
| TPM-bound | A TPM 2.0 quote over `SHA-256(nonce ‖ digest)`, signed by an attestation key pinned at enrollment | The report came from the enrolled machine, now; with pinned PCR values, that it booted the expected firmware, bootloader and kernel | That root did not misreport files and processes after boot |
| TPM and IMA | The above, plus the kernel's IMA log replayed to the quoted PCR 10 | The logged file hashes are the files the kernel loaded, even against a hostile root user | Files outside the IMA policy, or a compromised kernel or firmware |
| Confidential VM | An AMD SEV-SNP or Intel TDX report over `SHA-512(nonce ‖ digest)`, chained to the vendor's root | The report came from a VM with the reported launch measurement, with debugging off, that the host cannot read | That the guest's software after launch is what the evidence says, unless the launch measurement covers it |

Hardware statements are checked only with keys the verifier pinned or with chains to vendor roots it ships, never with keys taken from the evidence.

## Where to go next

*   [Getting started](getting-started.md) builds an attester and a verifier.
*   [Security](security.md) describes the threat model and limits.
*   [SPEC.md](../SPEC.md) defines the format.

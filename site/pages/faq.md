<!--
title: Frequently asked questions
description: Answers about Attestium: remote attestation, TPM requirements, languages, containers, root on the server, other tools such as SLSA and Keylime, and the license.
label: FAQ
keywords: attestium faq, remote attestation questions, tpm required, slsa vs attestation, keylime comparison
-->

# Frequently asked questions

Short answers, with links to the documentation for the details.

## What is remote attestation?

Remote attestation lets a verifier check what another machine runs without trusting that machine's own opinion. The machine's attester reports facts; the verifier checks that the report is fresh and unchanged, then compares every fact with references it obtains itself, such as the public commit or the registry tarball a lockfile pins. See [Remote attestation](/remote-attestation/).

## Is Attestium a library or a tool?

A library and a format. It provides the pieces to collect facts on a machine, the evidence format and its schema, and the checks against each kind of reference. [Audit Status](https://auditstatus.com) is a ready-made tool built on it, with an attester binary, a verifier for CI and published reports.

## Does it need a TPM?

No. Without hardware, evidence is bound to the verifier's nonce by its digest and still reveals drift, failed deploys, modified files and packages, injected libraries and debuggers. A TPM quote adds proof of which machine answered and how it booted, and IMA adds the kernel's record of the files it loaded. See [TPM attestation](/tpm-attestation/).

## Which languages and package ecosystems are supported?

Installed packages from npm and pnpm, PyPI, RubyGems, Hex, Composer, Maven and NuGet; Go and Rust binaries through their build information; native binaries through signed checksum lists, attestations or pinned hashes; the official Node.js release; Debian and Ubuntu packages through the signed archive. Process checks recognize Node.js, Python, the JVM, Ruby, .NET, BEAM, PHP, Perl, Deno and Bun. See [Ecosystems and references](/docs/ecosystems/).

## Does the attester have to be written in Node.js?

No. The format is language-independent. An attester or verifier in another language interoperates by following the [specification](/spec/), the JSON Schema, the canonical JSON rules and the test vectors in [Other languages](/docs/other-languages/).

## Which operating systems does it run on?

The checks run on Linux. Attestium needs Node.js 18 or later. On macOS and Windows, process checks that the platform cannot perform report `supported: false` instead of passing.

## Does it work with containers and Kubernetes?

Yes. For a process in a container, the attester reports the container, the image the runtime names, mounts, the writable layer and every file of the root filesystem. The verifier fetches the image by digest from the registry and compares the files. Docker, containerd, CRI-O, Podman and Kubernetes are recognized. See [Containers and OCI images](/docs/ecosystems/#containers-and-oci-images).

## What can root on the server hide?

With software evidence only, root controls the attester and can report anything. A TPM quote stops root from forging which machine answered or replaying an old answer, but not from misreporting files after boot. With IMA, root cannot remove the kernel's measurements of files it loaded. State the evidence level with every result. See [Security model and limits](/docs/security/).

## How is it different from SLSA and Sigstore?

SLSA provenance describes how an artifact was built; Sigstore records who signed it. Neither shows that a server runs that artifact. Attestium checks the server and can use SLSA provenance, Sigstore bundles and GitHub artifact attestations as references. See [Supply chain verification](/supply-chain-verification/).

## How is it different from Keylime?

Keylime is a TPM-based remote attestation system that checks measured boot and IMA measurements against policies of allowed hashes. Attestium also verifies TPM quotes and IMA logs, and adds checks against public sources: files against a git commit, packages against lockfiles and registries, containers against image digests, system files against the signed distribution archive, and process integrity. It works without a TPM, at a lower evidence level.

## Does it support confidential VMs?

Yes. AMD SEV-SNP and Intel TDX reports are requested through configfs-tsm, bound to the nonce and digest, and verified against AMD's and Intel's roots, with debugging required off. See [Confidential computing](/confidential-computing/).

## What happens when a registry or reference is unavailable?

The check is inconclusive, never passing. A result is clean only when every check ran. Package comparisons report `error` for a reference that could not be fetched, and `passed` is false.

## Does it catch code that ran and was deleted before the check?

With the monitor, yes. It records, with eBPF, every program started and every file mapped executable between checks, and the verifier explains each entry. Without it, an audit sees the server at one moment.

## What does it cost, and under which license?

Nothing. Attestium is open source under the MIT license, published on npm and [GitHub](https://github.com/attestium/attestium.com).

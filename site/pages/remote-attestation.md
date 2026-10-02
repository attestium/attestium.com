<!--
title: Remote attestation for servers
description: What remote attestation is, how an attester and a verifier prove what a server runs, and what each kind of evidence can and cannot show.
label: Remote attestation
keywords: remote attestation, server attestation, RATS, RFC 9334, attester, verifier, runtime integrity
-->

# Remote attestation for servers

Remote attestation lets one machine, the verifier, check what another machine, the attester, is running, without trusting the attester's own opinion. Attestium implements it for servers: the attester reports facts about files, packages, processes and hardware, and the verifier compares every fact with a reference it obtains itself.

## The problem it solves

Publishing source code shows what a service could run. It does not show what runs in production. A server may run an older commit, a patched file, a package that differs from the registry, a library injected with `LD_PRELOAD`, or a debugger attached to the process. None of that is visible from the outside.

Remote attestation turns "production runs the published code" from a claim into something anyone can check: a verifier asks the server for evidence, checks that the evidence is fresh and unchanged, and compares it with public references.

## Roles

Attestium follows the IETF remote attestation architecture, RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)).

| Role | Runs where | Does what |
| --- | --- | --- |
| Attester | On the server being checked | Collects facts and reports them as evidence. It never decides whether the server passes. |
| Verifier | Somewhere else, typically in CI | Sends a nonce, receives the evidence, obtains references itself and compares. |
| Relying party | Anywhere | Reads the verifier's result, for example on a status page. |

The split matters because the attester runs on the machine under test. If that machine is compromised, its attester may be too. A verifier that trusts nothing from the machine except what it can check against an outside reference, or what hardware signs, keeps the decision out of an attacker's hands.

## One round

1.  The verifier picks a random nonce of 16 to 64 bytes and sends it.
2.  The attester collects the evidence, puts the nonce in it, and computes `evidenceDigest`, the SHA-256 of its canonical JSON.
3.  With hardware, the attester asks a TPM or the CPU to sign the nonce and the digest together.
4.  The verifier checks the nonce, the time window and the digest, then the hardware signature with keys it pinned.
5.  The verifier fetches references by digest and compares every fact: files with the public commit, packages with the tarballs the lockfile pins, containers with their image layers, system files with the signed distribution archive.
6.  The result is pass, fail or inconclusive, reported with its evidence level.

A replayed answer fails the nonce check. Changed evidence fails the digest check. Evidence produced elsewhere fails the hardware check. See [Nonce and digest binding](/docs/concepts/#nonce-and-digest-binding).

## Every running file must be explained

A server runs more than the application: an interpreter, shared libraries, helper programs, tools started by cron. Any of them can carry an attacker's code. The evidence lists every file that an inspected process runs or maps executable, and the verifier must explain each one by a reference: a service file that matches its commit, a verified package, an image layer, an official runtime release, a signed checksum list, or the owning Debian or Ubuntu package. A file that matches no reference is unexplained; a file that contradicts its reference fails.

## What the evidence proves

| Level | Proves | Does not prove |
| --- | --- | --- |
| Software evidence | Drift, failed deploys, modified files and packages, injected libraries, debuggers, unexplained programs | Anything against root that anticipates the check |
| TPM-bound | The evidence came from the enrolled machine, for this nonce, in its measured boot state | That root did not misreport files and processes after boot |
| TPM and IMA | The kernel's own record of the files it loaded | Files outside the IMA policy, or a compromised kernel |
| Confidential VM | The VM's launch measurement, signed by AMD or Intel, with debugging off | Software loaded after launch, unless the measurement covers it |

Report the level with every result. See [TPM attestation](/tpm-attestation/) and [Confidential computing](/confidential-computing/).

## Pass, fail and inconclusive

A check that could not complete is inconclusive, never passing: a file the attester could not read, a registry that did not answer, a package with no pinned hash. A clean result means something only when every check ran.

## Start

*   [Getting started](/docs/getting-started/) builds a minimal attester and verifier in Node.js.
*   [Concepts](/docs/concepts/) covers roles, evidence, references and levels in depth.
*   [Audit Status](https://auditstatus.github.io/auditstatus/) is a ready-made attester and verifier that publishes results to a status page.

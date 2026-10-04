<!--
title: TPM attestation and IMA for Linux servers
description: TPM 2.0 quotes, attestation key enrollment and IMA log replay: how Attestium binds evidence to a machine and its boot state, and what root still controls.
label: TPM attestation
keywords: TPM attestation, TPM 2.0 quote, IMA, PCR, attestation key, endorsement key, measured boot, Linux
-->

# TPM attestation and IMA for Linux servers

A TPM 2.0 is a separate chip with keys that cannot be exported and registers (PCRs) that can be extended but never set. Attestium uses it to bind evidence to one machine and its boot state, and uses the Linux Integrity Measurement Architecture (IMA) to show which files the kernel loaded, even to a root user who controls the attester.

## What a quote proves

Firmware, bootloader and kernel extend PCRs 0 to 7 with what they load; IMA extends PCR 10. A quote is a TPM signature over selected PCR values and qualifying data chosen by the caller.

Attestium sets the qualifying data to `SHA-256(nonce || evidenceDigest)`. A verified quote then proves that a key held by this TPM signed these PCR values together with this nonce and this exact evidence, after the verifier created the nonce. With pinned PCR values, it also proves that the machine booted the expected firmware, bootloader and kernel.

It proves nothing unless the verifier trusts the attestation key. That is what enrollment is for.

## Enrollment

Enrollment happens once per machine and gives the verifier an attestation key (AK) to pin:

1.  The TPM's endorsement key (EK) certificate is checked against the manufacturer's CA.
2.  The AK is created inside the TPM, and credential activation proves that it lives in the same TPM as the EK.
3.  The verifier pins the AK's public key, and the expected PCR values when the boot chain is known.

From then on, `Tpm.verifyQuote()` runs in plain Node.js on the verifier: no TPM software is needed there. Details: [Enrollment](/docs/hardware/#enrollment) and [Quote and verify](/docs/hardware/#quote-and-verify).

## IMA: the kernel's record

IMA makes the kernel hash files as they are executed, mapped executable or read, depending on the policy, append each measurement to a log, and extend PCR 10 before the file is used. Entries cannot be removed from a PCR.

The verifier replays the log entry by entry until the running value equals the quoted PCR 10. The entries up to that point are backed by the TPM. Each running file's hash in the evidence is then compared with its IMA measurement: a file that IMA measured with another hash contradicts the attester's report.

Supported: the binary log with the `ima-ng`, `ima-sig` and `ima-buf` templates, replayed into the SHA-256 or SHA-1 bank.

## What root can and cannot hide

| With | Root on the server can | Root cannot |
| --- | --- | --- |
| Software evidence only | Run a modified attester and report anything | Nothing is held against root |
| TPM quote | Misreport files and processes after boot | Forge a quote, reset a PCR, answer for another machine, replay an old answer |
| TPM and IMA | Misreport files outside the IMA policy (with `tcb`, an interpreted service's scripts) | Remove IMA entries for files the kernel loaded |

A compromised kernel or firmware can lie to everything above it. Boot measurements are designed to reveal a changed bootloader, kernel or firmware at boot when their expected values are pinned; a kernel exploited at run time is outside what any of this can see. See [Security model and limits](/docs/security/).

## Virtual machines

Many cloud providers offer virtual TPMs. A vTPM is operated by the hypervisor, so it proves which virtual machine answered and how it booted, but the host operator is trusted. To remove the host from the trust base, use a [confidential VM](/confidential-computing/).

## Next

*   [Hardware-backed evidence](/docs/hardware/): the full API for TPM quotes, enrollment and IMA replay.
*   [Remote attestation](/remote-attestation/): roles and the round trip.
*   [Audit Status hardware evidence](https://auditstatus.com/docs/hardware/): enroll a server's TPM with one command.

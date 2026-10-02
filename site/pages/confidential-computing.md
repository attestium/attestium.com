<!--
title: Confidential computing attestation with SEV-SNP and TDX
description: Verify AMD SEV-SNP and Intel TDX confidential VM reports bound to fresh evidence: launch measurement, vendor certificate chains, debug policy and limits.
label: Confidential computing
keywords: confidential computing, AMD SEV-SNP, Intel TDX, confidential VM, attestation report, launch measurement, VCEK, configfs-tsm
-->

# Confidential computing attestation with SEV-SNP and TDX

In a confidential VM, the CPU encrypts the guest's memory and measures its initial state at launch. The host operator can neither read the memory nor forge the CPU's signed report. Attestium asks the guest's kernel for such a report, binds it to fresh evidence, and verifies it against the vendor's root certificates.

## How the report is bound

The attester computes `evidenceDigest` over the evidence, then requests a report whose 64 bytes of report data are `SHA-512(nonce || evidenceDigest)`. The request goes through the kernel's configfs-tsm interface, which serves both vendors.

The verifier recomputes the digest, checks the report data, and verifies the report. A report for another nonce, or for other evidence, fails.

## AMD SEV-SNP

The report is signed by the chip's VCEK (or a VLEK). Attestium checks:

*   the report data equals `SHA-512(nonce || evidenceDigest)`;
*   the VCEK certificate chains through the ASK to AMD's ARK for Milan, Genoa or Turin; the roots ship with Attestium, with fingerprints to compare with AMD's published values;
*   the TCB values and chip id in the certificate equal those in the report;
*   the ECDSA P-384 signature over the report;
*   the guest policy does not allow debugging.

When the host does not supply the VCEK certificate, the verifier fetches it from AMD's key distribution service.

## Intel TDX

The quote (version 4 or 5) is signed by the quoting enclave's attestation key. Attestium checks:

*   the TD report data equals `SHA-512(nonce || evidenceDigest)`;
*   the PCK certificate chain ends at Intel's SGX root CA (shipped) and verifies link by link;
*   the quoting enclave report is signed by the PCK and binds the attestation key;
*   the quote signature;
*   the TD is not in debug mode.

The platform's TCB level is reported, not evaluated: compare `teeTcbSvn` with your own policy.

## The launch measurement

A verified report proves which image was launched. The verifier must still compare the measurement (SEV-SNP `measurement`, TDX `MRTD`) with the value it expects for the image it deployed. Pin it in the verifier's configuration.

## What it does not prove

A confidential VM protects the guest from its host, not from root inside the guest. The report proves the launch state; it says nothing about software loaded after launch unless the measured image enforces it, for example with a measured and verified root filesystem. Combine it with the rest of the evidence: files, packages and processes compared with their references. See [Security model and limits](/docs/security/).

| Threat | Confidential VM |
| --- | --- |
| Host operator reads or changes guest memory | Prevented |
| Host operator forges the attestation report | Prevented |
| Root inside the guest changes running code | Not prevented; other evidence reports it |
| Debugging the guest | Rejected by the policy check |

## Next

*   [Confidential VMs](/docs/hardware/#confidential-vms): the API, with code for the attester and the verifier.
*   [TPM attestation](/tpm-attestation/): machines without confidential computing.
*   [Evidence format](/evidence-format/): where the report sits in the evidence.

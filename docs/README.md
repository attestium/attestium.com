# Attestium documentation

The guides and reference for Attestium, the library for collecting and verifying runtime evidence: what each page covers and where to start.

## Start here

*   [Getting started](getting-started.md): install, collect evidence locally, check it, and build a minimal attester and verifier in Node.js.
*   [Concepts](concepts.md): attester, verifier and relying party; evidence and references; nonce and digest binding; explaining every running file; failing versus inconclusive; evidence levels.

## Guides

*   [Ecosystems and references](ecosystems.md): per ecosystem, what is read on the machine, which reference the verifier uses, and what fails or is unverifiable. Also Go and Rust binaries, native binaries, the official Node.js release, containers and OCI images, and Debian and Ubuntu packages.
*   [Hardware-backed evidence](hardware.md): TPM quotes and enrollment, IMA log replay, AMD SEV-SNP and Intel TDX reports, and how the nonce and digest are bound.
*   [Signatures and trust](signatures.md): Sigstore bundles, GitHub artifact attestations, npm provenance, signed checksum lists, release manifests and pinned hashes.
*   [Other languages](other-languages.md): implement a compatible attester or verifier from the specification, with canonical JSON rules and test vectors.
*   [Forged answers](forged-answers.md): how a server can fake software evidence, with diagrams of where a forgery fails against a TPM, IMA and confidential VMs, and the rules a verifier must follow.
*   [Security model and limits](security.md): threat model, root on the machine, code compiled at run time, software keys versus TPM keys, trust in references.

## Reference

*   [API reference](api.md): every module, class and function.
*   [Evidence format specification](../SPEC.md): the evidence format, version 2.
*   [JSON Schema](../schema/evidence.schema.json): the machine-readable definition of the format.
*   [Whitepaper](../attestium-whitepaper.pdf): architecture, security model and background.

## Related

*   [Audit Status](https://github.com/auditstatus/auditstatus): a ready-made attester and verifier built on Attestium, which publishes results to a status page.

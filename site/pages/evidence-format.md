<!--
title: An open evidence format for remote attestation
description: The Attestium evidence format, version 2: a language-independent JSON format with a JSON Schema, canonical digest, hardware binding and verifier obligations.
label: Evidence format
keywords: attestation evidence format, JSON Schema, canonical JSON, evidence digest, interoperability, specification
-->

# An open evidence format for remote attestation

Attestium evidence is a JSON document that an attester produces and any verifier can check. The format is independent of language and transport: an attester or verifier written in Go, Python or Rust interoperates by following the [specification](/spec/) and the published [JSON Schema](/schema/evidence.schema.json).

## What evidence contains

Evidence lists facts and no verdicts.

| Field | Content |
| --- | --- |
| `type`, `version` | `"attestium-evidence"`, `2` |
| `nonce`, `collectedAt` | The verifier's nonce and when collection started |
| `attester` | The attester's name, version, platform and its own executable hash |
| `host` | Hostname, kernel, boot id, operating system |
| `services` | Directory services (files with SHA-256 and git mode, installed packages, processes) and container services (image, mounts, writable layer, root filesystem) |
| `executables`, `libraries` | Every running executable and every file mapped executable, once, with hash and owning distribution package |
| `monitor` | Optional: programs and libraries loaded since the previous window |
| `evidenceDigest` | SHA-256 of the canonical JSON of the rest |
| `tpm`, `ima`, `confidential` | Optional hardware statements over the nonce and digest |

A process's integrity findings are facts too, for example "`LD_PRELOAD` is set". The verifier decides what they mean.

## Canonical JSON and the digest

`evidenceDigest` is the lowercase hex SHA-256 of the canonical JSON of the evidence without `evidenceDigest`, `tpm`, `ima` and `confidential`. Canonical JSON has no whitespace, sorts object keys by UTF-16 code units, leaves out undefined members, and writes numbers and strings as ECMAScript `JSON.stringify` does. [Other languages](/docs/other-languages/) gives the rules in detail, a reference implementation in Python, and test vectors.

## Hardware binding

| Statement | Bound value |
| --- | --- |
| TPM 2.0 quote | `SHA-256(nonce || evidenceDigest)` as qualifying data |
| AMD SEV-SNP report, Intel TDX quote | `SHA-512(nonce || evidenceDigest)` as report data |
| IMA log | Replayed to the quoted PCR 10 |

The hash is taken over the raw bytes of the nonce and the digest, not over their hex text.

## Verifier obligations

A verifier implementing the format must:

*   check the evidence against the schema before using any field;
*   check the nonce, the time window and the digest;
*   verify hardware statements only with keys it pinned or chains to vendor roots it ships, never with keys taken from the evidence;
*   obtain every reference itself, by digest where the reference is content-addressed;
*   treat checks that could not complete as inconclusive, never as passing.

## Release manifests

A release deployed without git carries `.attestium-manifest.json` at its root: the repository, the commit and every file's hash and mode. CI writes it from the build output and attests its SHA-256, so a verifier can explain a compiled or bundled release file by file.

## Validate with the schema

The schema uses JSON Schema 2020-12 and is published at `https://attestium.com/schema/evidence-v2.json`, its `$id`:

```sh
curl -O https://attestium.com/schema/evidence.schema.json
```

Objects the schema closes reject unknown fields, so a new field there comes with a new version.

## Next

*   [Specification](/spec/): every field.
*   [Other languages](/docs/other-languages/): canonical JSON, test vectors and verifier checks.
*   [Remote attestation](/remote-attestation/): how evidence is used.

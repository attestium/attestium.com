# The Solution

We designed Attestium as a layered, practical, and open-source solution for verifiable runtime integrity. It is not a monolithic system but a modular stack that can be adapted to different environments and needs. Attestium addresses the gaps in existing solutions by providing:

* **Runtime Code Verification**: Continuous monitoring of running application code, real-time detection of unauthorized modifications, and in-memory integrity checking capabilities.

* **Third-Party Verification APIs**: RESTful APIs for external verification, nonce-based challenge-response protocols, and cryptographically signed verification reports.

* **Developer-Friendly Design**: A simple npm package installation, minimal configuration requirements, and seamless integration with existing Node.js applications.

* **Granular File Categorization**: Intelligent categorization of source code, tests, configuration, and dependencies, with customizable include/exclude patterns and Git integration for baseline establishment.

* **Cryptographic Proof Generation**: SHA-256 checksums for all monitored files, signed verification reports, and tamper-evident audit trails.

* **Modern Workflow Integration**: Git commit hash tracking, CI/CD pipeline integration, and Cosmiconfig-based configuration management.

## The Attestium Stack

Our architecture consists of three layers:

1. **[Attestium](https://github.com/attestium/attestium) (Core Engine)**: A Node.js library that provides the low-level primitives for verification. It interacts with the TPM for hardware-backed attestation and provides APIs for measuring running processes and file integrity.

2. **[Audit Status](https://github.com/auditstatus/auditstatus) (Monitoring Tool)**: A command-line tool that uses Attestium to perform periodic server checks. It's a single, self-contained binary that can be easily deployed and configured via a simple YAML file.

3. **[Upptime](https://github.com/upptime/upptime) (Uptime Monitor)**: We extended this popular open-source uptime monitor with a new `ssh-audit` check. It connects to a remote server, runs Audit Status, and parses the results, enabling continuous, third-party verifiable attestation.

## Why GitHub Actions

A key design decision was how to orchestrate these checks without introducing a new processor or subprocessor into our data pipeline. We already trust GitHub — our source code lives there, our CI runs there, and our team authenticates through it every day. Adding another third-party service just to run periodic integrity checks would mean onboarding a new vendor, negotiating a new DPA, and expanding our attack surface for no good reason.

That's why we built the orchestration layer on top of GitHub Actions via [Upptime](https://github.com/upptime/upptime). Upptime runs as a scheduled GitHub Actions workflow — no additional infrastructure, no new credentials to manage, and no new trust relationships to establish. The checks run in GitHub's environment, and the results are committed directly to the repository as structured data.

But this approach isn't limited to Upptime or even GitHub. The same pattern works with any task runner or CI/CD system. You could wire up the same `auditstatus check --json` command in a plain GitHub Actions workflow file, a GitLab CI pipeline, a Jenkins job, or even a simple cron job on a bastion host. The Audit Status binary is self-contained and stateless — it takes CLI flags, runs its checks, and outputs JSON. That makes it trivially composable with whatever orchestration you already have in place.

## The Verification Flow

Our verification flow follows the IETF RATS architecture (RFC 9334)[^rats]. Upptime acts as the Relying Party, initiating an attestation request. The ssh-audit helper acts as the Verifier, connecting to the remote server and executing Audit Status, the Attester. Audit Status collects evidence from the system (TPM, /proc, filesystem), generates a report, and sends it back up the chain.

```{.mermaid format=pdf}
graph LR
    A["Relying Party<br/>(Upptime)"] -->|1. Request| B["Verifier<br/>(SSH Client)"]
    B -->|2. SSH| C["Attester<br/>(Audit Status)"]
    C -->|3. Collect| D["/proc, TPM, FS"]
    C -->|4. Report| B
    B -->|5. Result| A
```

This architecture provides a clean separation of concerns and a secure, flexible flow for remote verification. In the following sections, we will explore each layer in greater detail.

[^rats]: H. Birkholz, et al., "Remote Attestation Procedures Architecture," IETF RFC 9334, 2022: https://datatracker.ietf.org/doc/rfc9334/

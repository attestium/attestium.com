<!--
title: Supply chain verification at run time
description: How runtime attestation relates to SLSA, Sigstore, in-toto and reproducible builds, and how Attestium checks deployed code against them.
label: Supply chain verification
keywords: supply chain security, SLSA, Sigstore, in-toto, reproducible builds, provenance, runtime verification, lockfile
-->

# Supply chain verification at run time

Supply chain tools describe how software was built and who published it. They stop at the artifact. Attestium checks the last step: that the server runs those artifacts, unchanged, and nothing else.

## What each tool proves

| Tool | Proves | Does not prove |
| --- | --- | --- |
| [SLSA](https://slsa.dev) provenance | How and where an artifact was built, from which source | That a server runs that artifact |
| [Sigstore](https://www.sigstore.dev) | Who signed an artifact, recorded in a public transparency log | That the signed artifact is good, or deployed |
| [in-toto](https://in-toto.io) | That the steps of a supply chain were performed by the expected parties | What happens after the last step |
| Reproducible builds | That anyone can rebuild the same bytes from the source | That the bytes on a server are those bytes |
| Lockfiles with hashes | Which exact package versions a project depends on | That the installed files match them |
| Attestium | That the files, packages and processes on a server match these references, now | That the references themselves are good |

These tools complement each other. Attestium uses the others as references.

## Using supply chain evidence as references

The verifier explains every running file by a reference it obtains itself:

*   **Lockfiles.** Installed packages are compared file by file with the registry tarballs that `pnpm-lock.yaml`, `package-lock.json`, `uv.lock`, `Gemfile.lock`, `mix.lock`, `composer.lock`, `packages.lock.json` or Gradle verification metadata pin, read from the verifier's own checkout of the deployed commit. See [Ecosystems and references](/docs/ecosystems/).
*   **Sigstore bundles.** `sigstore.verifyBundle()` checks the Fulcio certificate chain, the Rekor log entry and the signer identity the verifier requires, with a trusted root distributed through TUF. See [Signatures and trust](/docs/signatures/).
*   **GitHub artifact attestations.** A release built by a workflow is explained by an attestation for its SHA-256, signed for the expected repository, workflow file and ref.
*   **npm provenance.** The SLSA provenance statement of a package published with `--provenance` can be required for npm dependencies.
*   **Signed checksum lists.** `SHA256SUMS` files signed with gpg, minisign or Sigstore explain downloaded binaries.
*   **Release manifests.** A release deployed without git carries `.attestium-manifest.json`, which lists every file and is attested by CI. See [Release manifests](/spec/#release-manifests).
*   **Reproduced builds.** Files the deploy generates are compared with a build of the same commit that the verifier runs itself.

## A signature is not a verdict

A signature proves who signed, not that what they signed is good. Require the identity you expect: the repository, workflow and ref of a CI build, or the key of a release manager. Without an identity, any certificate from the trusted CA would be accepted.

## Where the chain still depends on trust

A compromised registry, repository or archive makes bad code look good. Attestium reduces what has to be trusted: content-addressed references are fetched by digest and checked, lockfiles are read from the verifier's own checkout rather than from the server, and Debian and Ubuntu packages are reached through the signed `InRelease` file. See [Trust in references](/docs/security/#trust-in-references).

## Next

*   [Ecosystems and references](/docs/ecosystems/): per ecosystem, what is compared with what.
*   [Signatures and trust](/docs/signatures/): Sigstore, GitHub attestations, npm provenance, checksum lists.
*   [Remote attestation](/remote-attestation/): the round trip between attester and verifier.

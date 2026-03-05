# The Problem

The software supply chain is broken. We have focused intensely on securing software before it's deployed, but we've largely ignored what happens after. This is the critical gap where trust evaporates.

## Build-Time Security is Not Enough

We have made great strides with initiatives like SLSA[^slsa] and Sigstore[^sigstore], creating a chain of trust from source code to binary. But that chain breaks at runtime. As Google's engineers noted, build-time enforcement alone cannot protect infrastructure from compromised code[^google_bab]. A runtime mechanism is not just a nice-to-have; it is a necessity.

## Where Existing Solutions Fall Short

Before developing Attestium, we conducted extensive research into existing verification, attestation, and integrity monitoring solutions. Our analysis revealed seven critical gaps that existing solutions couldn't address for our specific requirements:

1. **Runtime Application Verification Gap**: Most solutions focus on build-time, deployment-time, or infrastructure-level verification. They cannot detect runtime tampering or code injection attacks.

2. **Third-Party Verification API Gap**: Existing solutions lack standardized APIs for external verification, making it difficult for auditors to independently verify system integrity.

3. **Developer Experience Gap**: Hardware-based solutions require specialized knowledge and infrastructure, creating a high barrier to adoption for typical web applications.

4. **Node.js Ecosystem Gap**: Most solutions are language-agnostic or focused on other platforms, with poor integration into Node.js applications and workflows.

5. **Cost and Complexity Gap**: Many solutions are expensive or too complex for many applications and organizations.

6. **Granular Monitoring Gap**: File integrity tools monitor files, and application tools monitor performance, but no solution provides granular application code verification.

7. **Continuous Verification Gap**: Most solutions provide point-in-time verification, which cannot detect tampering between verification intervals.

We need a solution that is holistic, layered, and developer-first. This is why we built Attestium.

[^slsa]: SLSA, "Supply-chain Levels for Software Artifacts": https://slsa.dev/
[^sigstore]: Sigstore, "A new standard for signing, verifying, and protecting software": https://www.sigstore.dev/
[^google_bab]: Google Cloud, "Binary Authorization for Borg": https://cloud.google.com/docs/security/binary-authorization-for-borg

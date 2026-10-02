# Conclusion

Build-time security establishes what should run. Nothing in a typical deployment shows users what does run. Attestium closes that gap with an open evidence format and a verifier that compares every fact about a server with a reference the server's operator does not control: the public commit, a reproduced build, the artifacts a lockfile pins, a container image by digest, an official release, a signed checksum list, or the distribution's signed archive.

The approach does not depend on a language or a packaging method. Every executable and library that a process runs or maps is either explained by such a reference or reported as unexplained; every process is checked for the code-injection vectors of its runtime and for executable memory that differs from its files; and every check that cannot complete makes the result inconclusive, never passing.

The paper has also been precise about limits. Software evidence detects drift, failed deployments and tampering by anyone without root, but it cannot stand alone against an attacker who controls the machine. TPM quotes bind evidence to an enrolled machine and its boot state, IMA adds kernel measurements that root cannot rewrite, and confidential VMs remove the host operator from the trusted base. Every result states which of these it rests on.

Attestium is the building block; Audit Status is a ready-made attester and verifier on top of it; Forward Email's public status page is a working deployment. The remaining work, including measured boot policies, more distributions and registries, and signed, logged attestation results, is listed in Section 8. Contributions, independent implementations of the evidence format, and additional adopters are welcome.

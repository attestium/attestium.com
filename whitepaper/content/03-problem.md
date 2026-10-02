# The Problem

Most software supply chain security work secures software before it is deployed. What happens after deployment is largely unchecked, and that is where a user's trust in a service actually rests.

## Build-Time Security is Not Enough

SLSA [@slsa], in-toto [@in_toto] and Sigstore [@sigstore; @sigstore_ccs] create a verifiable chain from source code to a signed artifact. That chain ends when the artifact is deployed. Google's description of Binary Authorization for Borg makes the same point: alongside checks at deploy time, it continuously re-validates what is already running [@google_bab]. A service that publishes its source code gives its users something to read, but not a way to confirm that the published code is what answers their requests.

## Where Existing Solutions Fall Short

A survey of existing verification, attestation and integrity monitoring tools found nine gaps that none of them closed:

1. **Runtime Application Verification Gap**: Most tools verify at build time, at deployment time, or at the level of the boot chain. They do not check what an application is running now.

2. **Third-Party Verification Gap**: Few tools produce evidence that an outside party can check independently. Most report a verdict computed on the machine being checked, which is only as trustworthy as that machine.

3. **Explanation Gap**: File integrity tools compare files with an earlier snapshot of the same machine. A snapshot taken after a compromise is a bad baseline. What is needed is a reference the operator does not control for every file that runs, and an explicit report of every file that has none.

4. **Language and Binary Coverage Gap**: A real service runs an interpreter or a compiled binary, libraries from its operating system distribution, packages from one or more language registries, and often containers. Tools that cover one ecosystem leave the rest unchecked.

5. **Hardware Binding Gap**: Hardware roots of trust (TPMs, confidential virtual machines) prove which machine produced a statement and how it booted, but they say nothing about the application unless its evidence is bound into the hardware-signed statement.

6. **Continuous Verification Gap**: A point-in-time audit cannot detect a change that was made and undone between two audits.

7. **Process Memory Integrity Gap**: File checks verify files on disk, not what is running in memory. An attacker who injects code with `ptrace`, writes to `/proc/<pid>/mem`, or loads a library with `LD_PRELOAD` passes every file-level check because the file on disk is unchanged [@redcanary_fileless]. Each language runtime adds its own injection paths: `NODE_OPTIONS`, `PYTHONPATH`, Java agents, `RUBYOPT`, .NET start-up hooks and debug ports.

8. **Supply Chain Provenance Gap**: A package in a registry can differ from its public source, and a package on disk can differ from what the registry served. Provenance attestations help for packages that publish them [@npm_provenance], but most packages do not, and nothing in a typical deployment checks the installed files against the exact artifacts the lockfile pinned.

9. **Cost and Complexity Gap**: Hardware-based attestation frameworks require specialized knowledge and infrastructure. Small teams need something that installs as one binary and runs in the CI system they already use.

These gaps motivate the approach described in the next section.

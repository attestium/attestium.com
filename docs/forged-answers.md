# Forged answers

The attester runs on the machine being checked. Whatever answers the verifier, the forced SSH command in [Getting started](getting-started.md#an-attester-and-a-verifier) and in Audit Status or any other transport, can be replaced by a program that returns the answer the verifier expects. This page shows such a forgery, which checks it passes, and what makes it fail. In short: no transport stops it, only hardware does, and only for what the hardware measures.

## Contents

*   [The forgery](#the-forgery)
*   [Why the software checks do not stop it](#why-the-software-checks-do-not-stop-it)
*   [Why SSH, and no HTTP endpoint](#why-ssh-and-no-http-endpoint)
*   [What stops it](#what-stops-it)
*   [What IMA must measure](#what-ima-must-measure)
*   [Relaying to an honest machine](#relaying-to-an-honest-machine)
*   [Other ways to fake an answer](#other-ways-to-fake-an-answer)
*   [Rules for a verifier](#rules-for-a-verifier)
*   [What the getting-started example proves](#what-the-getting-started-example-proves)

## The forgery

Someone with root on the server, or the operator, runs modified code. They keep a clean copy of the published commit, and answer the verifier from it. SSH still pins the server's host key and allows only the forced command, and root changes that command:

```js
// forged-attester-command.js: run by root in place of attester-command.js.
const {collect} = require('./attester');

(async () => {
  const nonce = /^check ([\da-f]+)$/.exec(process.env.SSH_ORIGINAL_COMMAND)[1];
  // The verifier's own nonce, the current time, and a digest computed
  // over the forged document: every value the verifier checks.
  const document = await collect(nonce, {name: 'app', root: '/srv/clean-copy'});
  process.stdout.write(JSON.stringify(document));
})();
```

```text
 verifier                           server: modified code runs in /srv/app
 nonce = 32 random bytes
 ssh attester@server          ------->  forged attester
   "check <nonce>"                        hashes /srv/clean-copy
                                            instead of /srv/app
                                          copies the nonce
                                          collectedAt = now
                                          digest = SHA-256(forged document)
 evidence                     <-------
 schema          ok
 nonce           ok   (it is the verifier's nonce)
 time window     ok   (the server's clock says now)
 digest          ok   (computed over the forged document)
 files           ok   (the clean copy equals the commit)
 result: pass, software evidence
```

Every check of software evidence passes. The forgery does not even need the clean copy: the references are public, so a forger can write the expected hashes directly. Nor does it have to list the processes that run the modified code: with no process listed, there is no running file left to explain.

## Why the software checks do not stop it

Each value in software evidence comes from the attester, so each can be produced by a forger:

| Check | What it proves | Why a forger passes it |
| --- | --- | --- |
| Nonce | The answer was made after the verifier chose the nonce: no replay of an old answer | The forger copies the nonce into the new answer |
| `collectedAt` | The attester says when it collected | The forger's clock |
| `evidenceDigest` | The evidence was not changed after the digest was computed | It is a hash, not a signature: anyone can compute it over any document |
| A software signature (`generateVerificationResponse()`) | The holder of the key signed | The key is on the server; root can read it and sign anything |
| SSH host key, or a TLS certificate | The verifier reached the machine that holds that key | The machine is the right one; the software on it is what lies |
| The forced command in `authorized_keys` | The verifier's key runs only the attester | Root edits `authorized_keys`, or replaces the program it names |
| `attester.executable` (the attester's own hash) | The attester says which binary it is | A modified attester reports the genuine binary's hash |
| Process findings, file lists, package hashes | What the attester observed | The attester chooses what it reports |

So software evidence holds only while the attester is honest. It detects mistakes, drift, failed deploys and attackers who do not control the attester (see [Security](security.md#adversaries)). It does not hold against root on the machine, and a result backed only by software evidence must say so.

## Why SSH, and no HTTP endpoint

Attestium's examples and Audit Status reach the attester only through SSH, as a user whose `authorized_keys` entry forces the attester command (`restrict,command="..."`). An HTTP endpoint (`GET /evidence?nonce=...`) is not used, because it is weaker on every count the transport does decide:

| Question | SSH forced command | HTTP endpoint |
| --- | --- | --- |
| Who can ask | Only the holder of the verifier's private key | Anyone who can reach the port, unless you add client authentication |
| What they learn | Nothing without the key | The server's files, packages, processes and versions: a map for an attacker |
| Which machine answered | The host key pinned in the verifier's `known_hosts`; an unknown or changed key fails | A certificate from any public CA that will issue one for the name, and DNS |
| Who else can answer | Nobody without the host's private key | A reverse proxy, load balancer or CDN that terminates TLS answers for the server |
| What the request can reach | One fixed program; the request is only its `SSH_ORIGINAL_COMMAND`, parsed as `check <hex>` | A request parser, headers, routing and the HTTP server's own code |
| Listening on the network | Nothing new; `sshd` is already there | A new port, on every server |

Kubernetes is the one exception in Audit Status: its attester listens on the pod's loopback interface only, and the verifier reaches it through the API server with `kubectl port-forward`, which needs the verifier's cluster credentials. That is a tunnel to one pod, not an endpoint on the network. It is weaker than SSH in one place: it passes through the API server's connection to the node's kubelet, which is authenticated only when the API server verifies the kubelet's certificate.

None of this makes the answer true. The transport decides who may ask and which machine answered; root on that machine still controls what it says. The rest of this page is about that.

## What stops it

A forged answer fails only when part of the answer comes from something the forger cannot control: a key that never leaves a chip, and measurements the kernel makes before any code runs.

```text
 verifier                               server
 pinned: AK public key, PCR 0-7 values
 nonce = 32 random bytes
 request(nonce)               ------->  attester
                                          evidence, evidenceDigest
                                          TPM quote: the AK signs
                                            SHA-256(nonce || digest),
                                            PCR 0-7 and PCR 10
                                          IMA log (every file the kernel
                                            measured since boot)
 evidence, quote, IMA log     <-------

 check                                      a forgery fails when
 1. quote signed by the pinned AK           another TPM or a key signed
 2. quote data = SHA-256(nonce || digest)   it covers another document
 3. PCR 0-7 = pinned values                 another kernel booted
 4. IMA log replays to the quoted PCR 10    the log was edited or cut
 5. IMA hashes = the references            modified code ran
 result: pass, TPM and IMA
```

Why each step holds against root:

1.  **The key cannot be copied.** The attestation key (AK) is created inside the TPM as a restricted, non-exportable signing key (`fixedTPM`, `fixedParent`). Enrollment checks this, checks the endorsement certificate against the manufacturer's CA, and proves with credential activation that this TPM holds this AK ([Hardware](hardware.md#enrollment)). The verifier pins the AK public key and never takes a key from the evidence.
2.  **The quote covers this nonce and this document.** Root can ask the real TPM to quote a forged document. That only ties the forged document to this machine and this moment; the next steps decide whether its content is true.
3.  **PCRs cannot be set, only extended.** Firmware, boot loader and kernel extend PCRs 0 to 7 before they run what they load. A changed kernel or boot loader gives other values, and the pinned values no longer match.
4.  **The IMA log cannot be edited.** The kernel extends PCR 10 with each file before the file is used. Removing or changing an entry changes the replay, which no longer equals the quoted PCR 10.
5.  **Modified code leaves its hash, if the IMA policy measures it.** If modified code ran since boot, the kernel measured its hash. The verifier compares every measurement under the service's root with the commit, the packages' references or the build output (never with the hashes the attester reports), and the measurements of each running executable and library with the hashes in the evidence. A forger who reports clean files contradicts the kernel's record. See [What IMA must measure](#what-ima-must-measure).

```text
 forged evidence:  app/index.js  sha256 3f1c...  (the commit's file)
 quoted IMA log:   app/index.js  sha256 9b0e...  (what the kernel loaded)
 result: fail, the kernel measured a project file that differs
         from the commit
```

## What IMA must measure

IMA records only what its policy tells the kernel to measure, and the verifier cannot see the policy, only what was measured.

*   **Scripts are read, not executed.** The common `tcb` policy measures programs executed, files mapped executable, and files read by root. The JavaScript, Python, Ruby or PHP files of a service that runs as another user are never measured, so IMA says nothing about them, and a forged report of those files passes even with TPM and IMA. Measure the reads of the service's user: `measure func=FILE_CHECK mask=^MAY_READ uid=<the service's uid>`.
*   **Measure by the reading user, not the file's owner.** Root can give a modified file another owner; `fowner=` rules would then skip it. A `uid=` rule measures whatever the service's processes read.
*   **Other users.** A `uid=` rule does not measure code run as another user. Root could run the modified service as another user and leave it out of the evidence. Add a rule for every user that runs code, or measure all reads and leave out data directories.
*   **An empty record is a finding.** A verifier should report a service under whose root the kernel measured nothing, and fail it when IMA is required. Audit Status does.
*   **The policy itself.** Root can reboot with a weaker policy. Load the policy from the initramfs and pin the PCRs that measure the initramfs and the kernel command line (PCR 9 and 8 with GRUB), so another policy changes a pinned value.

Audit Status's [hardware guide](https://github.com/auditstatus/auditstatus/blob/main/docs/hardware.md#enable-ima) gives a complete policy.

### What a forger can still do with TPM and IMA

*   Run code the IMA policy does not measure: files outside the policy's rules (see above), or code evaluated from data inside a verified interpreter (`eval`, a deserialization gadget).
*   Run modified code from outside the service's root, as the service's user, and leave its process out of the evidence. The kernel measures those files, but the IMA log does not say which user or process read them, so a verifier compares only the measurements under the service's root and at the paths of the executables and libraries the evidence lists.
*   Report false facts that no measurement covers, such as which processes run or files no process maps.
*   Exploit the kernel or firmware at run time. The kernel makes the measurements, so a compromised kernel can falsify them.

### Confidential VMs

An AMD SEV-SNP or Intel TDX report is signed by a key in the CPU, chained to the vendor's root, and its report data is `SHA-512(nonce ‖ evidenceDigest)`. The host operator cannot forge it or read the guest's memory. The launch measurement identifies the image that started. A forger inside the guest must run in a VM with the expected measurement. If the attester and the application are part of the measured image, and the image cannot be changed after launch, a modified attester changes the measurement and fails. Otherwise, root inside the guest can forge software evidence there as on any server.

## Relaying to an honest machine

A forger can also forward the nonce to an honest machine that runs the published code, and return that machine's answer:

```text
 verifier --- nonce ---> server A (modified) --- nonce ---> server B (honest)
 verifier <-- evidence -- server A          <-- evidence -- server B
```

| Evidence | Result |
| --- | --- |
| Software evidence | Pass. The host name and addresses in the evidence are reported by the attester, so nothing names the machine. |
| TPM quote, one AK pinned per server | Fail. B's quote is signed by B's AK, and the verifier checks A's answer with A's pinned AK. |
| TPM quote, one AK pinned for several servers | Pass. Pin a different key for each server; Audit Status refuses one key for two servers. |
| Confidential VM report | Pass if B runs the same image. The launch measurement identifies an image, not an instance. Pin a TPM key per server, or a per-instance value the platform signs. |

## Other ways to fake an answer

| Attempt | Stopped by | Software evidence alone |
| --- | --- | --- |
| Replay an earlier answer | The nonce | Yes |
| Precompute answers | A nonce of 32 random bytes chosen at each audit | Yes |
| Change the answer in transit | SSH with pinned host keys, and hardware signatures | Yes, with SSH |
| Answer in place of the server (DNS, network, a proxy) | SSH with pinned host keys, and a quote with the pinned AK | Yes, with SSH |
| Report genuine packages while a modified one runs | IMA measurements of the package files, compared with the package's reference | No |
| Boot with an IMA policy that does not measure the service's files | A finding when nothing under the service's root was measured; pinned PCRs for the policy | No |
| Leave out the quote, and claim the server has no TPM | A verifier that requires a quote for each server with a pinned AK, and fails without one | No |
| Send a quote signed by another key | Keys pinned by the verifier, never taken from the evidence | No |
| Boot a modified kernel, then quote | Pinned PCR 0 to 7 values | No |
| Run modified code, then restore the genuine file before the audit | The IMA log keeps every measurement since boot, and the verifier reports earlier contents of the same path | No |
| Leave out processes, so their files need no explanation | A minimum process count per service, and the IMA measurements of what ran | Only with a minimum process count |
| Report the genuine attester's hash for a modified attester | Comparing the IMA measurement at the attester's path with its published release | No |

## Rules for a verifier

A verifier that follows these rules turns each forgery above into a failed or inconclusive result, up to the limits of its evidence level:

1.  Decide the required evidence level per server from your own configuration, never from the evidence. A server with a pinned AK that answers without a quote fails.
2.  Pin keys and expected values at enrollment: the AK per server, PCR 0 to 7 values, the confidential VM launch measurement. Never use a key taken from the evidence.
3.  Choose a fresh nonce of at least 16 random bytes for each request, and accept an answer only once.
4.  Check the nonce, the time window and the digest before using any other field, then the hardware statements, then the facts.
5.  Replay the IMA log to the quoted PCR 10, compare every measurement under the service's root with the references (not with the evidence), compare the measurements of running executables and libraries with the evidence, and report a service whose files were not measured at all.
6.  Reach the attester over SSH with pinned host keys and a forced command, not through an HTTP endpoint.
7.  Run the verifier where the checked machines cannot change it, such as CI.
8.  Report the evidence level with every result. A pass backed only by software evidence is not proof against root.

## What the getting-started example proves

The attester and verifier in [Getting started](getting-started.md#an-attester-and-a-verifier) exchange software evidence over SSH, with the verifier's key restricted to the attester and the server's host key pinned. They show the format and the order of the checks, and that only the verifier can ask and only the server can answer. They detect a changed file when the attester is honest. They prove nothing against root on the server, who controls the attester. For a result that holds against root, add a TPM quote with a pinned AK and IMA with a policy that measures the service's files ([Hardware](hardware.md)), or run in a confidential VM, and apply the rules above. [Audit Status](https://github.com/auditstatus/auditstatus) applies them, and its report and badge name the evidence level of every result.

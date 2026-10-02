# Hardware-backed evidence

Bind evidence to hardware so that a verifier does not have to trust the attester alone: TPM 2.0 quotes signed by an attestation key, enrollment of that key through the TPM's endorsement key certificate, the Linux IMA log replayed to the quoted PCR 10, and AMD SEV-SNP and Intel TDX confidential VM reports. Every statement signs the verifier's nonce together with the evidence digest.

## Binding, in short

The attester computes `evidenceDigest` over the evidence (see [SPEC.md](../SPEC.md#digest)), then asks the hardware to sign a value derived from the verifier's nonce and that digest. Both are hex strings; the hash is taken over their raw bytes, not over the hex text.

| Statement | Bound value | Where it goes |
| --- | --- | --- |
| TPM 2.0 quote | Qualifying data `SHA-256(nonce ‖ evidenceDigest)`, 32 bytes | `tpm.quote` |
| AMD SEV-SNP report, Intel TDX quote | Report data `SHA-512(nonce ‖ evidenceDigest)`, 64 bytes | `confidential` |
| IMA log | Not signed itself; authenticated by replay to the quoted PCR 10 | `ima.log` |

`evidenceDigest` leaves out `tpm`, `confidential` and `ima`, because they are added after the digest is computed.

A verifier checks hardware statements only with keys it pinned, or with certificate chains that end at vendor roots it ships. It never uses a key taken from the evidence.

## TPM 2.0

A TPM is a separate chip with keys that cannot be exported and platform configuration registers (PCRs) that can be extended but never set. Firmware, bootloader and kernel extend PCRs 0 to 7 with what they load; IMA extends PCR 10.

A quote is a TPM signature over selected PCR values and qualifying data chosen by the caller. A verified quote proves that a key held by the TPM signed those PCR values together with your nonce, after you created the nonce. It proves nothing about the machine unless the attestation key is trusted and the PCR values are compared with known-good values or an event log.

The `Tpm` class drives [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) on the attester. `Tpm.verifyQuote()` runs in plain Node.js, so the verifier needs no TPM software.

### Enrollment

Enrollment happens once per machine. It gives the verifier an attestation key (AK) to pin.

1.  The attester creates an AK under the endorsement key (EK) and makes it persistent (default handle `0x81010002`).
2.  The attester sends the EK public area, the EK certificate (when the manufacturer stored one), and the AK public area.
3.  The verifier checks that the EK certificate chains to a TPM manufacturer CA it trusts and certifies this EK.
4.  The verifier checks that the AK is a restricted signing key created in the TPM that cannot leave it (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `restricted`, `sign`, not `decrypt`).
5.  The verifier runs MakeCredential: it encrypts a random secret to the EK, bound to the AK's name. Only that TPM, holding that AK, can recover it with ActivateCredential.
6.  The attester returns the secret. When it matches, the verifier pins the AK public key.

Without steps 3 to 6, pinning the AK is trust on first use: the verifier knows it talks to the same key later, not that the key lives in a real TPM.

Attestium ships no TPM manufacturer certificates. Download the CA certificates of the manufacturers (or cloud providers) you accept and pass them as `roots`. Intermediate CAs go in `intermediates`, or in `roots` if you accept them as trust anchors.

```js
const crypto = require('node:crypto');
const fs = require('node:fs');
const {Tpm, tpmIdentity} = require('attestium');

(async () => {
  // Attester. Without a tcti, the TPM at /dev/tpmrm0 is used.
  const tpm = new Tpm({tcti: process.env.TPM2TOOLS_TCTI});
  const endorsement = await tpm.getEndorsement(); // RSA EK: {publicArea, certificate} in base64
  const ak = await tpm.getAttestationKey().catch(() => tpm.createAttestationKey());
  const akPublicArea = await tpm.getAttestationKeyPublicArea();

  // Verifier: the EK certificate chains to a manufacturer CA you trust.
  const ek = tpmIdentity.parseTpmPublic(Buffer.from(endorsement.publicArea, 'base64'));
  const roots = fs.readdirSync('tpm-roots').map(name => new crypto.X509Certificate(fs.readFileSync(`tpm-roots/${name}`)));
  const {chain} = tpmIdentity.verifyEkCertificate({certificate: Buffer.from(endorsement.certificate, 'base64'), ekKey: ek.key, roots});

  // Verifier: the AK is a restricted signing key bound to the TPM, and the one the attester reports.
  const akArea = tpmIdentity.parseTpmPublic(Buffer.from(akPublicArea, 'base64'));
  const problems = tpmIdentity.attestationKeyProblems(akArea);
  const spki = key => (typeof key === 'string' ? crypto.createPublicKey(key) : key).export({type: 'spki', format: 'der'});
  const sameKey = spki(akArea.key).equals(spki(ak.publicKey));

  // Verifier: a secret only this TPM can recover, and only for this AK.
  const secret = crypto.randomBytes(32);
  const credential = tpmIdentity.makeCredential({ek, akName: akArea.name, secret});

  // Attester: recover it.
  const answer = await tpm.activateCredential({credential: credential.toString('base64')});

  // Verifier: pin ak.publicKey when everything holds.
  const activated = crypto.timingSafeEqual(Buffer.from(answer, 'base64'), secret);
  console.log({chain, problems, sameKey, activated});
})();
```

`verifyEkCertificate()` throws when the certificate is for another key, when it does not chain to one of `roots`, or when a CA certificate in the chain is not currently valid. An intermediate counts only when it is a CA (basicConstraints `cA`) and, when it has a keyUsage extension, may sign certificates (`keyCertSign`). It does not check the EK certificate's own validity period, because many EK certificates carry none that is usable.

`makeCredential()` supports the default EK templates: RSA 2048 and ECC NIST P-256, with SHA-256 and AES-128-CFB. Pass `{algorithm: 'ecc'}` to `getEndorsement()` and `activateCredential()` for an ECC EK.

### Quote and verify

The quote's nonce is the qualifying data, at most 32 bytes. Attestium binds `SHA-256(nonce ‖ evidenceDigest)`, which is exactly 32 bytes.

```js
const {Tpm, util} = require('attestium');

(async () => {
  const tpm = new Tpm({tcti: process.env.TPM2TOOLS_TCTI});

  // Enrollment (once): the verifier pins the AK and the known-good boot PCRs.
  const ak = await tpm.getAttestationKey().catch(() => tpm.createAttestationKey());
  const expectedPcrs = {sha256: await tpm.readPcrs([0, 1, 2, 3, 4, 5, 6, 7], 'sha256')};

  // Each audit: the verifier's nonce, and the attester's evidence digest.
  const nonce = util.generateNonce();
  const evidenceDigest = util.sha256('stands for evidence.evidenceDigest(document)');
  const qualifyingData = util.sha256(Buffer.concat([Buffer.from(nonce, 'hex'), Buffer.from(evidenceDigest, 'hex')]));

  // Attester.
  const quote = await tpm.quote({nonce: qualifyingData, pcrs: [0, 1, 2, 3, 4, 5, 6, 7, 10]});

  // Verifier: recompute the qualifying data from its own nonce and the digest it recomputed.
  const result = Tpm.verifyQuote({quote, publicKey: ak.publicKey, nonce: qualifyingData, expectedPcrs});
  console.log(result.valid, result.errors, result.attest.clockInfo);
})();
```

`Tpm.verifyQuote()` returns `{valid, errors, attest, pcrs}`. It checks:

*   the signature, with the pinned AK public key (RSASSA-PKCS1-v1\_5 or ECDSA; SHA-1 is refused);
*   that the signed structure is a `TPMS_ATTEST` quote generated by the TPM;
*   that its extra data equals the expected qualifying data (a stale or replayed quote fails);
*   that the reported PCR values hash to the signed PCR digest, and that no value is reported without being quoted;
*   each PCR in `expectedPcrs`.

`attest.clockInfo` holds the TPM's `resetCount` and `restartCount`; a change between audits means the machine rebooted or resumed.

Which PCRs to pin depends on the platform. PCRs 0 to 7 cover firmware and boot; their values change with firmware and kernel updates, so update the pinned values when you update the machine. Quote PCR 10 when you use IMA, but do not pin its value: it grows with every measurement.

## IMA

The Linux Integrity Measurement Architecture makes the kernel hash files as they are executed, mapped executable, or read (depending on the policy), append each measurement to a log, and extend PCR 10 before the file is used. Entries cannot be removed from a PCR. So when the log replays to the PCR 10 value in a verified quote, the logged hashes are the files the kernel loaded, even if the machine's root user is hostile.

The attester reads the log after the quote: `ima.readLog()` reads `/sys/kernel/security/ima/binary_runtime_measurements` (root or `CAP_DAC_READ_SEARCH` needed), and the evidence carries it base64 encoded in `ima.log`.

The log keeps growing after the quote. The verifier replays it entry by entry until the running value equals the quoted one. The entries up to that point are backed by the TPM; later ones are not.

```js
const {ima} = require('attestium');

/**
 * @param {Object} quote - verified with Tpm.verifyQuote, covering sha256 PCR 10
 * @param {string} log - the evidence's ima.log (base64)
 * @returns {Map<string, {algorithm: string, hash: string, count: number, hashes: string[]}>}
 */
function imaMeasurements(quote, log) {
  const entries = ima.parseBinaryLog(Buffer.from(log, 'base64'));
  const backed = ima.backedEntries(entries, quote.pcrs.sha256['10'], 'sha256');
  if (!backed) {
    throw new Error('The IMA log does not replay to the quoted PCR 10');
  }

  // Path -> the measured hash (the latest), and every hash seen for it.
  return ima.measurementsByPath(backed);
}

module.exports = {imaMeasurements};
```

Compare each running file's hash in the evidence with its IMA measurement. A file that IMA measured with another hash contradicts the attester's report.

Supported: the binary log with the `ima-ng`, `ima-sig` and `ima-buf` templates, replayed into the SHA-256 or SHA-1 bank; the legacy `ima` template only into SHA-1. Violation entries (a file opened for writing while measured) extend the PCR with all-ones and are skipped by `measurementsByPath()`, as are `ima-buf` entries, which measure buffers (keys, the kexec command line) under a name that is not a file's. What is measured depends entirely on the IMA policy in force.

## Confidential VMs

In a confidential VM, the CPU measures the VM's initial memory at launch and signs a report that includes 64 bytes chosen by the guest. The host operator can neither read the guest's memory nor forge the report. The attester asks the kernel for a report through configfs-tsm (`/sys/kernel/config/tsm/report`, Linux 6.7 and later).

```js
const {confidential} = require('attestium');

/**
 * Attester: the confidential field of the evidence, over (nonce, digest).
 * Needs a confidential VM with configfs-tsm, and root (or a report entry
 * directory prepared by root, passed as {entry}).
 */
function confidentialEvidence(nonce, evidenceDigest) {
  try {
    const result = confidential.collectReport(confidential.reportData(nonce, evidenceDigest));
    return {
      available: true,
      provider: result.provider,
      report: result.report.toString('base64'),
      auxblob: result.auxblob ? result.auxblob.toString('base64') : null,
    };
  } catch (error) {
    return {available: true, error: error.code || error.message, required: false};
  }
}

/**
 * Verifier: check the report and compare its launch measurement.
 */
function verifyConfidentialEvidence(document, nonce, expectedMeasurement) {
  const result = confidential.verifyConfidential(document.confidential, confidential.reportData(nonce, document.evidenceDigest));
  if (result.measurement !== expectedMeasurement) {
    throw new Error(`Unexpected launch measurement ${result.measurement}`);
  }

  return result;
}

module.exports = {confidentialEvidence, verifyConfidentialEvidence};
```

`verifyConfidential()` throws on any failure and returns `{type, measurement, ...}` on success. The verifier must still compare `measurement` with the value it expects for the VM image it deployed.

### AMD SEV-SNP

Provider `sev_guest`. The report is signed by the chip's VCEK, or by a VLEK (a key AMD issues to a cloud provider, which loads it into its chips; AWS uses them). The report says which. Attestium checks:

*   the report data equals `SHA-512(nonce ‖ evidenceDigest)`;
*   a VCEK certificate chains through the ASK, a VLEK certificate through the ASVK, to AMD's ARK for Milan, Genoa or Turin. The ARK, ASK and ASVK certificates ship in `lib/data/vendor-roots.js`, with their SHA-256 fingerprints so you can compare them with AMD's published values. An intermediate in the host's certificate table (its ASK entry holds the ASVK on VLEK hosts) is used instead when the ARK signed it, it is a CA, and it is not the other kind's;
*   the TCB values in the certificate equal the report's reported TCB, and, for a VCEK, the certificate's chip id equals the report's;
*   the ECDSA P-384 signature over the report;
*   the guest policy does not allow debugging, nor a migration agent (which the host chooses at launch, the report does not name, and which can export the VM's memory). Pass `{allowMigrationAgent: true}` to accept one.

The VCEK or VLEK certificate comes from the host (the `auxblob` certificate table) when the host provides it. Otherwise pass it as `{vcek}` (either kind). A VCEK can be fetched from AMD's key distribution service; a VLEK certificate only from the cloud provider:

```js
const {confidential, http} = require('attestium');

async function fetchVcek(reportBase64) {
  const parsed = confidential.parseSnpReport(Buffer.from(reportBase64, 'base64'));
  // Reports of version 3 and later name their product; try the older ones otherwise.
  const product = confidential.snpProduct(parsed) || 'Milan';
  return http.httpGet(confidential.vcekUrl(parsed, product));
}

module.exports = {fetchVcek};
```

The result has `type: 'sev-snp'`, `measurement` (hex), `product`, `key` (`'vcek'` or `'vlek'`), `tcb`, `policy` and `vmpl`. AMD's certificate revocation lists are not checked, and the TCB is reported, not compared with a minimum: compare `tcb` and `vmpl` with your own policy.

### Intel TDX

Provider `tdx_guest`. The quote (version 4 or 5) is signed by the quoting enclave's attestation key. Attestium checks:

*   the TD report data equals `SHA-512(nonce ‖ evidenceDigest)`;
*   the PCK certificate chain in the quote ends at Intel's SGX root CA (shipped) and verifies link by link;
*   the quoting enclave report is signed by the PCK and binds the attestation key;
*   the quote signature;
*   the TD is not in debug mode.

The result has `type: 'tdx'`, `measurement` (MRTD), `rtmr`, `teeTcbSvn`, `mrConfigId` and `mrOwner`. The platform's TCB level (Intel's TCB info) is reported, not evaluated, and Intel's PCK certificate revocation lists are not checked: compare `teeTcbSvn` with your own policy.

## What hardware does not cover

*   A TPM quote proves which machine and which boot state. It does not prove that the attester reported files and processes honestly after boot. IMA narrows that gap for the files its policy measures.
*   A confidential VM report proves the launch measurement. It says nothing about what the guest loaded after launch unless the measured image enforces it.
*   Firmware and kernel bugs, and physical attacks on the TPM bus, are outside the model.

See [Security](security.md) for the full threat model.

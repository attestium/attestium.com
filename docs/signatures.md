# Signatures and trust

A verifier explains a binary or a release by a reference someone signed. This page covers the trust modules: Sigstore bundles (DSSE envelopes, the Rekor transparency log, Fulcio certificate identities, the TUF-distributed trusted root), GitHub artifact attestations and npm provenance built on them, signed checksum lists (gpg, minisign, Sigstore), release manifests, and pinned hashes.

## Which reference to use

| You deploy | Reference | Module |
| --- | --- | --- |
| A binary from a project that publishes `SHA256SUMS` with a signature | The signed checksum list | `checksums` |
| An artifact built by a GitHub Actions workflow with `actions/attest` | The GitHub artifact attestation | `attestations` |
| An npm package | The lockfile's integrity; optionally its npm provenance | `ecosystems`, `attestations` |
| A container image | The image digest; optionally attestations attached as OCI referrers | `oci`, `sigstore` |
| Your own release deployed without git | A release manifest attested by your CI | `evidence`, `attestations` |
| Anything else you reviewed | A pinned SHA-256 in the verifier's configuration | none |

A signature proves who signed. It does not prove that what they signed is good. Require the identity you expect: the repository, workflow and ref of a CI build, or the key of a release manager.

## Sigstore bundles

A Sigstore bundle holds a signature, the signing certificate (or a key hint) and a transparency log entry. `sigstore.verifyBundle()` accepts bundle versions 0.1 to 0.3 and throws `SigstoreError` unless all of the following hold:

1.  The signing certificate chains to a certificate authority in the trusted root (Fulcio), and was valid when the entry was logged.
2.  The transparency log entry is authentic: the log's signed entry timestamp verifies (Rekor v1), or an inclusion proof leads to a signed checkpoint. The entry matches this signature, certificate and payload.
3.  The signature verifies. For a DSSE envelope, over the pre-authentication encoding of the statement; for a message signature (`cosign sign-blob`), over the artifact you pass.
4.  The certificate's identity claims equal (or match, for a `RegExp`) the `identity` you pass.
5.  With `subject`, the in-toto statement names the artifact's digest.

Signing time comes from the log's signed entry timestamp, or from RFC 3161 timestamps by a timestamp authority in the trusted root (required for Rekor v2, whose entries carry no time). The log's key and the certificate authority must have been valid at every one of these times. Certificate transparency SCTs are not checked; the certificate itself is in the verified log entry.

Bundles signed with a public key instead of a certificate (npm's publish attestations) are accepted only when the key hint names a key in `publicKeys`.

### The trusted root

Sigstore distributes its trusted root (CA certificates and log keys) through [The Update Framework](https://theupdateframework.io/). `attestations.SigstoreTrust` runs a TUF client from a root shipped with Attestium (`lib/data/sigstore-root.json`): each new root must be signed by a threshold of the previous root's keys and its own, and every other file is reached through timestamp, snapshot and targets metadata, with version, expiry, length and hash checks. Pass `cacheDir` to keep verified metadata between runs: each root version, used only when it chains from the shipped root, and the newest timestamp and snapshot, which a later timestamp, snapshot or targets version may not go below.

For a private Sigstore instance or offline tests, pass `{trustedRoot}` (a `trusted_root.json`) instead.

### Verify a signed release

CPython signs each release file with Sigstore. The release manager's identity is an email address issued by Google's OIDC provider.

```js
const {attestations, http, sigstore} = require('attestium');

(async () => {
  const url = 'https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz';
  const artifact = await http.httpGet(url);
  const bundle = JSON.parse(await http.httpGet(`${url}.sigstore`));

  const trust = new attestations.SigstoreTrust({cacheDir: './sigstore-cache'});
  const result = sigstore.verifyBundle(bundle, {
    trustedRoot: await trust.trustedRoot(),
    artifact,
    identity: {subjectAlternativeName: 'thomas@python.org', issuer: 'https://accounts.google.com'},
  });
  console.log(result.claims, result.signedAt);
})();
```

`result.statement` is `null` for a message signature, and the parsed in-toto statement for a DSSE envelope.

### Identity claims

`identity` keys are claims of the Fulcio certificate: `subjectAlternativeName`, `issuer`, and the Fulcio extensions such as `buildSignerURI`, `sourceRepositoryURI`, `sourceRepositoryDigest` (the commit), `sourceRepositoryRef`, `buildConfigURI`, `buildTrigger` and `runInvocationURI`. `sigstore.FULCIO_OIDS` lists them all. A claim that the certificate lacks is `undefined` and fails any requirement on it. A requirement that is neither a string nor a `RegExp` is an error.

Without `identity`, any certificate from the trusted CA is accepted. Always pass one.

## GitHub artifact attestations

A workflow that runs `actions/attest-build-provenance` (or `actions/attest`) signs an in-toto statement naming the artifact's SHA-256, with a certificate that names the repository, the workflow file and the ref.

```js
const {attestations} = require('attestium');

/**
 * Verify that a workflow of `repository` attested `digest` (sha256 hex).
 */
async function verifyRelease(digest) {
  const bundles = await attestations.githubAttestations({repository: 'example/app', digest});
  const trust = new attestations.SigstoreTrust({cacheDir: './sigstore-cache'});
  return attestations.verifyGithubAttestation({
    bundles,
    digest,
    signer: {repository: 'example/app', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main'},
    trust,
  });
}

module.exports = {verifyRelease};
```

`githubAttestations()` calls the GitHub API (`GET /repos/{owner}/{repo}/attestations/sha256:{digest}`); pass a token in `httpOptions.headers.authorization` for private repositories or higher rate limits. `verifyGithubAttestation()` returns the first bundle that verifies, and throws with every failure when none does. `githubIdentity(signer)` builds the identity it requires: issuer `https://token.actions.githubusercontent.com`, a subject alternative name for that repository, workflow (any when omitted) and ref (any when omitted), and that repository as the source repository. A reusable workflow of a public repository can be called from any other repository, and the certificate then names the called workflow while the code built is the caller's; the source repository claim tells them apart. For a release built by a shared workflow of another repository, pass `workflowRepository` (where the workflow file lives) as well as `repository` (whose code it built). Pass `predicateType` to require a statement type, such as `https://slsa.dev/provenance/v1`.

The claims include `sourceRepositoryDigest`, the commit the workflow ran on. Compare it with the commit you expect.

## npm provenance

npm packages published with `--provenance` carry a SLSA provenance statement signed by the publishing workflow, and the registry adds a publish attestation signed with its own key.

```js
const {attestations, http} = require('attestium');

(async () => {
  const {dist} = await http.httpGetJson('https://registry.npmjs.org/sigstore/3.0.0');
  const trust = new attestations.SigstoreTrust({cacheDir: './sigstore-cache'});
  const result = await attestations.npmProvenance({name: 'sigstore', version: '3.0.0', integrity: dist.integrity, trust});
  console.log(result);
  // {provenance: true, published: true, repository, commit, workflow, signedAt}
})();
```

Pass the integrity your lockfile pins, not the registry's: the statement must name that tarball's SHA-512, and its predicate type must be the one the registry lists. A publish attestation counts only when signed with a registry key, never with a certificate. A package without attestations returns `{provenance: false}`. The registry's keys come through the same TUF repository (`registry.npmjs.org/keys.json`); a publish attestation signed after its key expired is rejected.

Provenance says which repository, commit and workflow built the tarball. It does not say the source is safe.

## Container image attestations

Registries that support OCI referrers list Sigstore bundles attached to an image (`cosign attest --new-bundle-format`, `actions/attest-build-provenance` with `push-to-registry`). Fetch them by the image's manifest digest and verify each with the digest as the subject:

```js
const {attestations, oci, sigstore} = require('attestium');

async function verifyImage(reference, identity) {
  const registry = new oci.Registry();
  const image = oci.parseReference(reference); // must include @sha256:...
  const bundles = await registry.referrerBundles(image, image.digest);
  const trustedRoot = await new attestations.SigstoreTrust().trustedRoot();
  const subject = {algorithm: 'sha256', digest: image.digest.slice('sha256:'.length)};
  return bundles.map(bundle => sigstore.verifyBundle(bundle, {trustedRoot, identity, subject}));
}

module.exports = {verifyImage};
```

## Signed checksum lists

Many projects publish `SHA256SUMS` or `checksums.txt` with their releases. `checksums.parseChecksums()` reads the GNU (`<hash>  <file>`, with an optional `*`) and BSD (`SHA256 (<file>) = <hash>`) forms. `checksums.fetchChecksums()` downloads a list and, when you configure a signature, verifies it before parsing:

| `signature.type` | Default signature URL | Needs | Checks |
| --- | --- | --- | --- |
| `gpg` | `<url>.sig` | `keyring`, a keyring file of the publisher's keys; `gpgv` | The detached OpenPGP signature, by a key of the keyring that is neither revoked nor expired |
| `minisign` | `<url>.minisig` | `publicKey`, the base64 key (second line of the `.pub` file) | The Ed25519 signature (prehashed `ED` or legacy `Ed`) and the trusted comment's global signature |
| `sigstore` | `<url>.sigstore.json` | `identity` (required), the certificate claims to require; a trusted root | A message signature over the list, or a DSSE statement whose subject names the list's SHA-256 |

A DSSE bundle over a checksum list must name the SHA-256 of that exact list as a subject; a statement about anything else fails. Identity values given as strings of the form `/.../` are turned into regular expressions by `checksums.toIdentity()`.

```js
const {checksums, ecosystems, attestations} = require('attestium');

(async () => {
  const store = new ecosystems.ReferenceStore({cacheDir: './cache'});
  const trust = new attestations.SigstoreTrust({cacheDir: './cache'});
  const {checksums: list, signed} = await checksums.fetchChecksums({
    url: 'https://downloads.example.org/app/1.0.0/SHA256SUMS',
    signature: {type: 'minisign', publicKey: 'RWTGGHgdLHl5L11jEc3WtcLl6pnxLw7ih71gpGWHCp57UlD3NXPft8ui'},
  }, {store, trustedRoot: () => trust.trustedRoot()});
  console.log(signed, list.get('app-linux-amd64'));
})();
```

Without a signature, the list is trusted as far as HTTPS and its host; `signed` is then `false`. Report that as weaker than a signed list.

To check a minisign signature over bytes you already have:

```js
const fs = require('node:fs');
const {checksums} = require('attestium');

const publicKey = fs.readFileSync('minisign.pub', 'utf8').split('\n')[1];
const valid = checksums.verifyMinisign(fs.readFileSync('SHA256SUMS'), fs.readFileSync('SHA256SUMS.minisig', 'utf8'), publicKey);
console.log(valid);
```

## Release manifests

A release deployed without git (a compiled binary, a bundle) carries `.attestium-manifest.json` at its root: the repository, the commit and every file's hash and mode. Your CI writes it from the build output and attests its SHA-256:

```js
const fs = require('node:fs');
const {evidence} = require('attestium');

(async () => {
  // In CI, after the build, in the output directory.
  const manifest = await evidence.createManifest('./dist', {
    repository: 'example/app',
    commit: process.env.GITHUB_SHA || 'a'.repeat(40),
    exclude: ['**/*.map'],
  });
  fs.writeFileSync(`./dist/${evidence.MANIFEST_NAME}`, JSON.stringify(manifest));
  // Then attest ./dist/.attestium-manifest.json, for example with actions/attest-build-provenance.
})();
```

The attester includes the manifest's contents (base64) in the service's `manifest` field. The verifier:

1.  parses it with `evidence.parseManifest()`;
2.  verifies the attestation over its SHA-256, requiring the repository, the workflow file and the ref;
3.  checks that the attestation's `sourceRepositoryDigest` is the commit the manifest names, and that the commit is on the audited branch of the public repository;
4.  compares every deployed file with the manifest.

## Pinned hashes

For a file no one signs, review it once and pin its SHA-256 in the verifier's configuration. A pinned hash is the strongest and least flexible reference: it breaks on every update, which is the point.

## Ed25519 envelopes

The `signing` module signs canonical JSON with Ed25519. The `Attestium` class uses it for signed baselines and challenge responses. Pass the trusted public key to `signing.verify()`: without it, the result only says the envelope is self-consistent, and `trusted` is `false`.

```js
const {signing} = require('attestium');

const {publicKey, privateKey} = signing.generateKeyPair();
const envelope = signing.sign({release: '1.0.0', digest: 'ab'.repeat(32)}, privateKey);
console.log(signing.verify(envelope, publicKey)); // {valid: true, trusted: true, keyId}
console.log(signing.verify(envelope)); // {valid: true, trusted: false, keyId}
```

A software key on the machine being verified can be read by that machine's root user. Keep signing keys off the verified machine, and use hardware quotes for statements the machine makes about itself.

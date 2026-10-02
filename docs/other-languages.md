# Other languages

Write an attester or a verifier in another language that interoperates with Attestium. The contract is [SPEC.md](../SPEC.md) and [`schema/evidence.schema.json`](../schema/evidence.schema.json); this page adds what you need to get the canonical JSON, the digest and the hardware binding byte for byte right, lists the checks a verifier must make, and gives test vectors.

## What to implement

| You write | You must produce or check |
| --- | --- |
| An attester | Evidence that validates against the schema, with `evidenceDigest` computed as below, and hardware statements over the binding values below |
| A verifier | Schema validation first, then the nonce, the time window, the digest, the hardware statements, and every fact against a reference you obtain yourself |

The schema is JSON Schema 2020-12. It uses a small set of keywords (`type`, `properties`, `required`, `additionalProperties`, `patternProperties`, `propertyNames`, `items`, `minItems`, `maxItems`, `enum`, `const`, `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, `anyOf`, `oneOf`, local `$ref` to `$defs`), so any conforming validator works. Patterns are ECMAScript regular expressions with the `u` flag; they use only common syntax. `maxLength` and `minLength` count Unicode code points.

## Canonical JSON

`evidenceDigest` is the SHA-256 of a canonical encoding. Every byte counts, so follow ECMAScript's `JSON.stringify` exactly:

*   `null`, `true`, `false` as in JSON.
*   Numbers: finite only. Write them as ECMAScript's Number-to-String does. The schema allows only integers where it types a number, so `str(integer)` is enough there; `-0` is written `0`. Open objects (`meta`, `go`, `cargo`, `pcrs`) may carry any JSON; if yours carry non-integers, implement ECMAScript's algorithm (for example `1e+21`, `1e-7`, `0.1`).
*   Strings: `"` and `\` escaped with a backslash; `\b`, `\f`, `\n`, `\r`, `\t` for those controls; other code points below U+0020 as `\u00XX` with lowercase hex; lone surrogates as `\uXXXX` with lowercase hex. Everything else is written as is, in UTF-8: no `\/`, no escaping of U+2028, U+2029 or non-ASCII.
*   Arrays: `[`, items joined by `,`, `]`.
*   Objects: `{`, members joined by `,`, `}`. Each member is `"key":value` with the key encoded as a string. Keys are sorted by UTF-16 code units, which is not the same as code point order for characters above U+FFFF: `U+1F600` (surrogates `D83D DE00`) sorts before `U+E000`.
*   A member whose value is absent is left out. There is no `undefined` in JSON, but mind languages where a missing optional value becomes `null`: `null` is a value and is encoded.
*   No whitespace anywhere.

Hash the UTF-8 bytes of the result.

## Digest

1.  Take the evidence object.
2.  Remove the members `evidenceDigest`, `tpm`, `ima` and `confidential`.
3.  Canonicalize the rest.
4.  `evidenceDigest` is the lowercase hex SHA-256 of those bytes.

The removed members are added after the digest is computed: hardware reports sign the digest, and the IMA log is authenticated by replay.

## Hardware binding

`nonce` and `evidenceDigest` are hex strings. Decode both to bytes and concatenate them, nonce first.

| Statement | Value |
| --- | --- |
| TPM quote qualifying data | `SHA-256(nonce ‖ digest)`, 32 bytes; tpm2-tools takes it as hex (`tpm2_quote -q`) |
| SEV-SNP and TDX report data | `SHA-512(nonce ‖ digest)`, 64 bytes, written to configfs-tsm's `inblob` |

## A reference in Python

The functions below reproduce the test vectors. They restrict numbers to integers, as the evidence schema does.

```python
import hashlib
import json


def canonicalize(value):
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Evidence holds integers only; other numbers need ECMAScript's
        # Number-to-String algorithm, which Python's repr does not follow.
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))
        raise TypeError('non-integer numbers are not supported here')
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return '[' + ','.join(canonicalize(item) for item in value) + ']'
    if isinstance(value, dict):
        # Sort by UTF-16 code units, as ECMAScript does, not by code points.
        keys = sorted(value, key=lambda key: key.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(key, ensure_ascii=False) + ':' + canonicalize(value[key]) for key in keys) + '}'
    raise TypeError(f'cannot canonicalize {type(value).__name__}')


def evidence_digest(evidence):
    rest = {key: item for key, item in evidence.items() if key not in ('evidenceDigest', 'tpm', 'ima', 'confidential')}
    return hashlib.sha256(canonicalize(rest).encode('utf-8')).hexdigest()


def qualifying_data(nonce, digest):
    return hashlib.sha256(bytes.fromhex(nonce) + bytes.fromhex(digest)).hexdigest()


def report_data(nonce, digest):
    return hashlib.sha512(bytes.fromhex(nonce) + bytes.fromhex(digest)).digest()
```

Python's `json.dumps(..., ensure_ascii=False)` escapes strings the way ECMAScript does, except for lone surrogates, which Python cannot encode to UTF-8. Evidence from a real attester does not contain them.

## Test vectors

The first two vectors come from Attestium's tests (`test/core.test.js`). The others were computed with `lib/util.js` and `lib/evidence.js`, and reproduced with the Python functions above. Inputs are given as ECMAScript literals; hashes are over the UTF-8 bytes of the canonical output.

| Input | Canonical output | SHA-256 |
| --- | --- | --- |
| `{b: 1, a: [true, null, 'x'], c: undefined}` | `{"a":[true,null,"x"],"b":1}` | `54a65415ad370228851a1da4b31b6fd42dc58b19a50d35cae759325f7388ce64` |
| `{b: 2, a: 1}` | `{"a":1,"b":2}` | `43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777` |
| `{z: {y: [], x: {}}, a: [{c: 1, b: 2}]}` | `{"a":[{"b":2,"c":1}],"z":{"x":{},"y":[]}}` | `437894c054553a7d0fd239f3e80916b06a11ae5996a90f880bfb6c109accf380` |
| `['\u00e9', '\u2028', '\u0007', '"\\/', '\u{1F600}', '\n\t']` | `["é","<U+2028>","\u0007","\"\\/","<U+1F600>","\n\t"]`, where each `<U+...>` stands for that character, unescaped | `0805c852656cdd659e75ecf87a98651d80a44573fd90ae9806bf31b81c708722` |
| `{b: 1, a: 2, A: 3, '\uE000': 4, '\u{1F600}': 5, '': 6, aa: 7}` | `{"":6,"A":3,"a":2,"aa":7,"b":1,"<U+1F600>":5,"<U+E000>":4}` | `b139461352772b889ac8045cfdcc3ce655a1684709f6bc2d9384ba6ace6a0cc3` |

Rejected inputs (an implementation must refuse them rather than encode something): `NaN`, `Infinity`, an array containing `undefined`, and any value that is not null, a boolean, a number, a string, an array or a plain object (for example a date).

A minimal evidence document:

```json
{
  "type": "attestium-evidence",
  "version": 2,
  "nonce": "00112233445566778899aabbccddeeff",
  "collectedAt": "2000-01-01T00:00:00.000Z",
  "attester": {"name": "example-attester", "version": "1.0.0"},
  "host": {"hostname": "web-1", "kernel": "6.8.0"},
  "services": [],
  "executables": [],
  "libraries": []
}
```

| Value | Result |
| --- | --- |
| Canonical form | `{"attester":{"name":"example-attester","version":"1.0.0"},"collectedAt":"2000-01-01T00:00:00.000Z","executables":[],"host":{"hostname":"web-1","kernel":"6.8.0"},"libraries":[],"nonce":"00112233445566778899aabbccddeeff","services":[],"type":"attestium-evidence","version":2}` |
| `evidenceDigest` | `d8240a4859b1d74332c2d2819f5268211bbf5748db25da964669b4f3ba8ddbe4` |
| TPM qualifying data | `1e30e25b46b0dc405177c72d2aa209eb3eb54ccca7a8469b1bc681f5f1728232` |
| Confidential VM report data | `901272da3f7f0600907065dea08214959c4d96888d23f50486ca2edb0f68249f0cae1ffff619eae601547abc4abf425287eed2a100cdef9f4da5cc7ee2f97ce4` |

Adding `"evidenceDigest"`, `"tpm"`, `"ima"` or `"confidential"` members does not change the digest. The document validates against the schema once `evidenceDigest` is added.

## Verifier checks

A verifier must, in this order:

1.  Validate the evidence against the schema. Use no field before this.
2.  Check that `type` is `attestium-evidence` and `version` is `2`. Refuse other versions rather than guess.
3.  Check that `nonce` equals the nonce you sent, for this machine and this audit.
4.  Check that `collectedAt` is inside your accepted window (allow a small clock skew into the future).
5.  Recompute `evidenceDigest` and compare.
6.  Verify hardware statements only with keys you pinned, or certificate chains that end at vendor roots you ship. For a TPM quote: the signature, the qualifying data, the PCR digest against the reported values, and your expected PCR values. When `tpm` or `confidential` says `required: true` and the statement is missing or has an `error`, fail.
7.  When an IMA log is present and PCR 10 was quoted, replay the log to the quoted value; use only the entries up to the point where it matches.
8.  Obtain every reference yourself, by digest where it is content-addressed, and compare every fact: service files, installed packages, container files, and every executable, library and monitored file.
9.  Treat every check that could not complete as inconclusive, never as passing: `incomplete` entries of a process, `truncated` lists, `errors`, `error` fields, references you could not fetch.

## Attester notes

*   Read the nonce as hex, 16 to 64 bytes, and refuse anything else.
*   Record `collectedAt` when collection starts, in ISO 8601 UTC with a `Z` (the schema's time format is `YYYY-MM-DDTHH:MM:SS[.fraction]Z`).
*   Hash running executables through `/proc/<pid>/exe` and mapped files through `/proc/<pid>/root` when the process is in another mount namespace, so the hash is of the file the process uses.
*   Report what you could not read (`errors`, `incomplete`, `error`) instead of leaving it out. A verifier cannot tell a missing fact from a clean one.
*   Never run or load what you inspect. Hash binaries and scan them for build information; do not execute them.
*   Compute the digest last, then ask the hardware to sign the binding values, then read the IMA log.

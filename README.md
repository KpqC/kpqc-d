# KpqC

KpqC provides synchronous D APIs for the AIMer and HAETAE signature schemes
and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). This D package
is independently maintained and is not an official distribution from the
algorithm authors.

## Requirements

- A D compiler and Dub
- CMake 3.18 or newer
- A C11 compiler
- macOS or Linux

The package bundles its native algorithm sources and builds them locally. It
does not download native libraries during compilation.

## Install

Add `kpqc` to the dependencies in `dub.json` or run:

```sh
dub add kpqc
```

## Available schemes

| Algorithm | Type | Values |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | KEM | `ntruPlus768`, `ntruPlus864`, `ntruPlus1152` |
| **SMAUG&#8209;T** | KEM | `smaugT128`, `smaugT192`, `smaugT256`, `timer` |

### Signatures

```d
import std.string : representation;
import kpqc;

const keys = SignatureAlgorithm.aimer128f.generateKeyPair;
const message = "release-manifest:v3".representation;
const signature = SignatureAlgorithm.aimer128f.sign(
    message, keys.secretKey);
assert(SignatureAlgorithm.aimer128f.verify(
    message, signature, keys.publicKey));
```

`sign` and `verify` accept an optional context containing at most 255 bytes.
Verification fails when the supplied context differs from the signing context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```d
import kpqc;

const recipient = KemAlgorithm.smaugT192.generateKeyPair;
const outbound = KemAlgorithm.smaugT192.encapsulate(recipient.publicKey);
const inbound = KemAlgorithm.smaugT192.decapsulate(
    outbound.ciphertext, recipient.secretKey);
assert(inbound == outbound.sharedSecret);
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets are byte
slices. Invalid input lengths and native operation failures throw
`KpqCException`; invalid signatures return `false`.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid ciphertext;
it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Value | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Value | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruPlus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruPlus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruPlus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugT128` | 672 | 832 | 672 | 32 |
| `smaugT192` | 1,088 | 1,312 | 992 | 32 |
| `smaugT256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

The same values are available through `sizes`. `signatureAlgorithms` and
`kemAlgorithms` list every supported parameter set.

## Tests

Run the public API suite with:

```sh
dub test
```

The optional known-answer suite validates all 1,600 records from the pinned
[`kpqc-test-vectors` revision `d75490bf824f`](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da):

```sh
KPQC_TEST_VECTORS=../kpqc-test-vectors \
dub run --root=tests/kat --build=release
```

The KAT package selects a separate `kat` build configuration. Deterministic
entropy hooks are not present in normal library builds.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Secret values are returned as managed D
arrays, so callers should not assume that every in-memory copy can be reliably
scrubbed. Assess these constraints before using the package with sensitive
production keys.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and may differ from
other revisions of the same algorithms.


## Description

wolfProvider is a library that can be used as a Provider in OpenSSL.

## Supported OpenSSL Versions

wolfProvider supports all release versions of OpenSSL 3.x

## Replace Default Mode

wolfProvider can be configured to replace OpenSSL's default provider, making wolfSSL's
cryptographic implementations the default for all OpenSSL operations. This ensures
applications use wolfSSL crypto without code changes. See the [Integration Guide](docs/INTEGRATION_GUIDE.md) for details.

## Documentation

Information on how to configure, build, and test wolfProvider can be found here:

- [wolfProvider FIPS Integration Guide](docs/FIPS_INTEGRATION_GUIDE.md) - FIPS baseline and production builds
- [wolfProvider Integration Guide](docs/INTEGRATION_GUIDE.md) - General integration and replace-default mode

## Features

### Digests
* MD5
* SHA-1
* SHA-2: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
* SHA-3: SHA3-224, SHA3-256, SHA3-384, SHA3-512
* SHAKE-256

### Symmetric Ciphers
* AES (128, 192, 256-bit keys)
    * ECB, CBC, CTR, CFB, CTS
    * GCM, CCM (AEAD)
    * Key Wrap
* 3DES-CBC

### MACs
* HMAC
* CMAC
* GMAC

### KDFs
* HKDF
* PBKDF2
* PKCS12 KDF
* TLS 1.3 KDF
* TLS1 PRF
* KBKDF
* KRB5 KDF
* SSHKDF

### Random
* CTR-DRBG
* Hash-DRBG

### RSA
* Signing, Verification (PKCS#1 v1.5, PSS)
* Encryption, Decryption
* Key generation

### DH
* Key exchange
* Key generation

### ECC
* ECDSA (signing, verification)
* ECDH (key exchange)
* Key generation
* Curves: P-192, P-224, P-256, P-384, P-521

### Curve25519/448
* X25519, X448 (key exchange)
* Ed25519, Ed448 (signatures)

### Post-Quantum (NIST FIPS 203 / 204)
PQC is opt-in and requires wolfSSL master/v5.9.2-stable+ and OpenSSL 3.6+.

* With the script: `./scripts/build-wolfprovider.sh --enable-pqc`
  (or `--enable-mlkem` / `--enable-mldsa` for one only)
* Building wolfProvider directly: `./configure --enable-pqc`
  (or `--enable-mlkem` / `--enable-mldsa`); build wolfSSL with the matching
  `--enable-mlkem` / `--enable-mldsa` and link an OpenSSL 3.6+

Without an enable flag no PQC code is compiled, regardless of what wolfSSL enables.

* ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024 (key encapsulation)
* ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87 (signatures, pure mode with empty context per FIPS 204 sec 5.2)


## SBOM / EU CRA Compliance

wolfProvider generates a Software Bill of Materials (SBOM) in CycloneDX 1.6 and
SPDX 2.3 formats to support compliance with the EU Cyber Resilience Act (CRA).
The SBOM records the configured build options, hashes the built `libwolfprov`
library artifact (shared or static; ELF, Mach-O, or PE), and (with a
sufficiently new `gen-sbom`) lists both wolfSSL and OpenSSL as dependencies so
vulnerability scanners can associate wolfSSL and OpenSSL advisories with a
wolfProvider deployment. Output is reproducible: set `SOURCE_DATE_EPOCH` (or
build from a git checkout, which uses the last commit time) and repeated runs
are byte-identical.

```sh
make sbom WOLFSSL_DIR=/path/to/wolfssl
```

Requires `python3` and `pyspdxtools` (`pip install spdx-tools`). `WOLFSSL_DIR`
must point to a wolfssl source tree containing `scripts/gen-sbom` (branch
`feat/sbom-embedded`, or `master` once wolfSSL/wolfssl#10343 merges); note that
`--with-wolfssl` normally points at an install prefix, which does not ship
`gen-sbom`, so pass a source tree here.

Output: `wolfprovider-<version>.cdx.json`, `wolfprovider-<version>.spdx.json`, `wolfprovider-<version>.spdx`

Optional overrides:

- `SBOM_LICENSE_OVERRIDE` - SPDX expression to use instead of the licence
  parsed from `COPYING` (e.g. `LicenseRef-wolfSSL-Commercial` for commercial
  licensees). Defaults to `GPL-3.0-or-later` (the per-file header licence).
- `SBOM_LICENSE_TEXT` - path to the licence text for any `LicenseRef-*` used in
  `SBOM_LICENSE_OVERRIDE` (required by SPDX 2.3).
- `SBOM_WOLFSSL_VERSION` - version recorded for the wolfSSL dependency;
  auto-detected from `WOLFSSL_DIR/wolfssl/version.h` (or wolfSSL's `pkg-config`
  entry) when unset.
- `SBOM_OPENSSL_VERSION` - version recorded for the OpenSSL dependency;
  resolved via OpenSSL's `pkg-config` entry when unset.

```sh
make install-sbom    # installs to $(datadir)/doc/wolfprov/
make uninstall-sbom
```

Note: recording wolfSSL and OpenSSL as dependencies and emitting
wolfProvider-specific project URLs require the `gen-sbom` from
wolfSSL/wolfssl#10343. Against an older `gen-sbom`, `make sbom` still succeeds
and produces a valid SBOM, but omits the dependency entries and inherits
wolfSSL's project URLs.

For further CRA guidance see [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md).

## Support

- [GitHub Issues](https://github.com/wolfssl/wolfProvider/issues)
- [wolfSSL Support](https://www.wolfssl.com/products/support-and-maintenance/)

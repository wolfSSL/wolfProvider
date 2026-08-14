# wolfProvider Integration Guide

## Overview

wolfProvider is an OpenSSL 3.x Provider that uses wolfSSL's cryptographic implementations. It allows applications using OpenSSL to leverage wolfSSL's crypto algorithms without code changes.

This guide covers building, configuring, testing, and debugging wolfProvider for non-FIPS use cases. For FIPS integration, see the [FIPS Integration Guide](FIPS_INTEGRATION_GUIDE.md).


## Building

The quickest method is to use the build script:

```bash
./scripts/build-wolfprovider.sh
```

This retrieves dependencies (OpenSSL and wolfSSL) and compiles them as necessary.

### Build Script Options

| Option | Description |
|--------|-------------|
| `--debug` | Enable debug logging |
| `--debug-log=/path/to/file` | Write debug output to file |
| `--clean` | Clean build artifacts |
| `--distclean` | Remove all source directories |
| `--openssl-ver=VERSION` | Use specific OpenSSL version (e.g., `openssl-3.5.0`) |
| `--wolfssl-ver=VERSION` | Use specific wolfSSL version (e.g., `v5.8.0-stable`) |
| `--openssl-dir=/path` | Use existing OpenSSL installation |
| `--replace-default` | Make wolfProvider the default provider |
| `--enable-replace-default-testing` | Enable unit testing with replace-default |
| `--enable-pqc` | Enable ML-KEM and ML-DSA (adds `--enable-mlkem --enable-mldsa` to wolfSSL). Requires wolfSSL v5.9.2-stable or later and OpenSSL 3.6 or later. |
| `--enable-lms` | Enable verification-only LMS support. Requires wolfSSL v5.9.2-stable or later and OpenSSL 3.6 or later. |

**Examples:**

```bash
# Debug build with specific versions
./scripts/build-wolfprovider.sh --debug --openssl-ver=openssl-3.5.0 --wolfssl-ver=v5.8.0-stable

# Use existing OpenSSL installation
./scripts/build-wolfprovider.sh --openssl-dir=/path/to/openssl/source

# Clean and rebuild
./scripts/build-wolfprovider.sh --clean
./scripts/build-wolfprovider.sh
```

### Manual Build

For more control, you can manually compile each component.

#### OpenSSL

```bash
git clone --depth=1 -b openssl-3.0.0 https://github.com/openssl/openssl.git
cd openssl
./config no-fips shared
make
sudo make install
```

#### wolfSSL

```bash
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=1024" --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --with-eccminsz=192
make
sudo make install
```

**Optional wolfSSL configure flags:**

| Flag | Purpose |
|------|---------|
| `--enable-aesgcm-stream` | Better AES-GCM support |
| `--enable-curve25519` | X25519 Key Exchange |
| `--enable-curve448` | X448 Key Exchange |
| `--enable-ed25519` | Ed25519 signatures and certificates |
| `--enable-ed448` | Ed448 signatures and certificates |
| `--enable-pwdbased` | PKCS#12 support |
| `--enable-hmac-copy` | Faster repeated HMAC with same key (wolfSSL 5.7.8+) |
| `--enable-sp=yes,asm --enable-sp-math-all` | SP Integer maths |
| `--enable-mlkem --enable-mldsa` | ML-KEM and ML-DSA post-quantum algorithms (wolfSSL v5.9.2-stable or later). The `build-wolfprovider.sh --enable-pqc` flag sets these automatically. |
| `--enable-lms=verify-only,sha256-192,shake256` | LMS verification with the SHA-256 and SHAKE256 parameter families used by the OpenSSL vectors. `verify-only` defines `WOLFSSL_LMS_VERIFY_ONLY` so keygen and signing are not built, matching wolfProvider's verification-only surface. The `build-wolfprovider.sh --enable-lms` flag sets this automatically. |

**Optional CPPFLAGS:**

| Flag | Purpose |
|------|---------|
| `-DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384` | Enable 6144/8192-bit DH |
| `-DSP_INT_BITS=8192` | Replace `-DFP_MAX_BITS=16384` when using SP math |

#### wolfProvider

```bash
./autogen.sh
./configure
make
```

To build using a different OpenSSL installation directory:

```bash
./configure --with-openssl=/usr/local/ssl
make
export LD_LIBRARY_PATH=/usr/local/ssl/lib
make check
```

---

## Replace Default Mode

wolfProvider can be configured to replace OpenSSL's default provider, making wolfSSL's cryptographic implementations the default for all OpenSSL operations.

### Replace Default vs. Standard Provider Mode

**Standard Provider Mode:** When wolfProvider is loaded alongside OpenSSL's default provider, applications can still access OpenSSL's native crypto implementations:
- When an application explicitly requests a specific provider (e.g., "default")
- When wolfProvider doesn't implement a particular algorithm
- If the execution environment doesn't pick up the configuration file

**Replace Default Mode:** This mode patches OpenSSL to disable fallback paths:
- wolfProvider becomes the primary cryptographic provider
- Requests for "default", "fips", and "wolfProvider" providers are redirected to wolfProvider
- Ensures maximum use of wolfSSL's cryptographic implementations

This makes replace default mode useful for testing scenarios where you want to ensure wolfSSL's implementations are used throughout the system.

### Building with Replace Default

```bash
# Basic replace-default
./scripts/build-wolfprovider.sh --replace-default

# Replace-default with unit testing support
./scripts/build-wolfprovider.sh --replace-default --enable-replace-default-testing
```

### Important Notes

**For `--replace-default`:**
- Can be used standalone in production or testing environments
- Makes wolfProvider the default cryptographic provider

**For `--enable-replace-default-testing`:**

**Warning:** This option patches OpenSSL to export internal symbols that are not part of the public API. This configuration:
- Should only be used for development and testing
- Is not suitable for production deployments

---

## Post-Quantum Cryptography (ML-KEM, ML-DSA, and LMS)

wolfProvider supports NIST's post-quantum algorithms via the wolfSSL backend:

| Algorithm | Standard | Parameter Sets |
|-----------|----------|----------------|
| ML-KEM (key encapsulation) | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA (digital signature)  | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| LMS (digital signature verification) | RFC 8554 / SP 800-208 | OpenSSL-compatible XDR public keys |

ML-DSA uses pure mode with an empty context string (FIPS 204 sec 5.2, Algorithm 22), interoperable with OpenSSL 3.5+'s native ML-DSA.

### Requirements

- **wolfSSL**: v5.9.2-stable or later. v5.9.1-stable does not provide the complete public interfaces required by wolfProvider.
- **OpenSSL**: 3.6 or later when these features are enabled.

### Building with PQC

```bash
./scripts/build-wolfprovider.sh --enable-pqc
```

This adds `--enable-mlkem --enable-mldsa` to the wolfSSL configure step. wolfProvider auto-detects the resulting `WOLFSSL_HAVE_MLKEM` / `WOLFSSL_HAVE_MLDSA` macros via `include/wolfprovider/settings.h` (gated on `__has_include` of `<wolfssl/wolfcrypt/wc_mlkem.h>` / `<wolfssl/wolfcrypt/wc_mldsa.h>`) and registers the six PQC algorithms.

LMS is enabled separately because it is a stateful signature scheme and is
verification-only in OpenSSL 3.6. Build it with `--enable-lms`; wolfProvider
uses wolfSSL's `wc_LmsKey_ImportPubRaw()` and `wc_LmsKey_Verify()` APIs and
accepts OpenSSL's raw XDR public-key representation. OpenSSL removes the
single-level HSS header from LMS public keys and signatures, so wolfProvider
restores that wrapper only while calling wolfCrypt. The provider does not
generate, import, or sign with LMS private keys, so wolfSSL should be built
verify-only (`--enable-lms=verify-only,...`) to keep the keygen and signing
code out of the build entirely.

### Usage Example

```bash
# Generate an ML-DSA-65 key with wolfProvider
OPENSSL_CONF=provider.conf openssl genpkey -algorithm ML-DSA-65 -out key.pem

# Sign and verify with ML-DSA-65
OPENSSL_CONF=provider.conf openssl pkeyutl -sign -inkey key.pem -in msg.bin -out sig.bin
OPENSSL_CONF=provider.conf openssl pkeyutl -verify -pubin -inkey pub.pem -sigfile sig.bin -in msg.bin
```

The OpenSSL CLI can also enumerate available algorithms:

```bash
OPENSSL_CONF=provider.conf openssl list -kem-algorithms -provider libwolfprov
OPENSSL_CONF=provider.conf openssl list -signature-algorithms -provider libwolfprov
```

### Validation

A standalone three-way interop validator (`test/pqc_interop.test`) cross-checks every ML-KEM / ML-DSA combination against:
- OpenSSL 3.5+'s native default provider
- wolfSSL's `wc_*` APIs directly (no provider abstraction)

This proves wolfProvider's raw-key, ciphertext, and signature bytes are FIPS 203 / 204 standards-compliant. The CI workflow `.github/workflows/wolfssl-versions-pqc.yml` runs this validator on every PR, plus a backward-compatibility build against pre-PQC wolfSSL to verify the no-symbol path still builds cleanly.

The `.github/workflows/wolfssl-pqc-kat.yml` workflow runs OpenSSL's unmodified
ML-KEM, ML-DSA, and LMS EVP vectors. LMS contributes 320 verification cases
covering valid and corrupted messages, signatures, and public keys. The matrix
tests combined PQC builds across the latest stable wolfSSL and master in
replace-default, standard-provider, and force-fail configurations, and also
contains an LMS-only build and KAT run.

---

## Testing

### Unit Tests

```bash
make test
```

---

## Debugging

To enable wolfProvider debug logging, build with `--debug`:

```bash
./scripts/build-wolfprovider.sh --debug
```

This enables exit messages, error messages, and informational messages.

### Log Filtering

To filter logging by level or component, set these in `include/wolfprovider/wp_logging.h` before building:

- `WOLFPROV_LOG_LEVEL_FILTER` - Which severity levels to log (ERROR, ENTER, LEAVE, INFO, VERBOSE, DEBUG, TRACE)
- `WOLFPROV_LOG_COMPONENTS_FILTER` - Which components to log (e.g., `WP_LOG_COMP_RSA`, `WP_LOG_COMP_HKDF`)

See comments in that file for examples.

### Debug Log to File

```bash
./scripts/build-wolfprovider.sh --debug --debug-log=/path/to/logfile
```

---

## Verifying Installation

After building and installing wolfProvider, confirm that it is working correctly.

### Check Provider Availability

```bash
openssl list -providers
```

This should list wolfProvider among the available providers.

### Run Unit Tests

```bash
make test
```

If any tests fail, enable debug logging (see the [Debugging](#debugging) section) and review the output for details.

---

## Support

- [GitHub Issues](https://github.com/wolfssl/wolfProvider/issues)
- [wolfSSL Support](https://www.wolfssl.com/products/support-and-maintenance/)

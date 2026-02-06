# wolfProvider FIPS Integration Guide

## Overview

wolfProvider enables OpenSSL 3.x applications to use wolfSSL's FIPS-validated cryptography. Integration follows a two-step process:

1. **FIPS Baseline Verification** - Establish an application test load that is verified to be FIPS compliant
2. **Production FIPS Build** - Verify application integration with wolfProvider

FIPS compliance requires that your application only uses approved algorithms with approved parameters. The baseline step catches compatibility issues early, ensuring a smooth FIPS integration process.

For non-FIPS builds and general wolfProvider setup, see the [Integration Guide](INTEGRATION_GUIDE.md).

## Prerequisites

- OpenSSL 3.x source
- wolfSSL FIPS bundle
- Build tools: gcc, make, autotools, git

---

## Step 1: FIPS Baseline Verification

### Patch OpenSSL

Apply FIPS baseline restrictions to your OpenSSL source tree. This mode disables non-FIPS approved algorithms so one can evaluate their application before integrating wolfProvider. See [FIPS Baseline Patches](../patches/openssl-fips-baseline/README.md) for detailed options and common errors.

```bash
./scripts/patch-openssl-fips.sh --openssl-src=/path/to/openssl-3.x
```

Then build OpenSSL as usual:

```bash
cd /path/to/openssl-3.x
./Configure --prefix=/usr/local/openssl-fips-baseline
make -j$(nproc)
make install
```

### Verify Baseline is Active

```bash
openssl list -providers
# Should show: OpenSSL Default Provider (wolfProvider FIPS Baseline)
```

### FIPS Restrictions Enforced

| Restriction | Requirement |
|-------------|-------------|
| RSA Key Size | 2048 bits minimum |
| SHA1 Signing | Blocked for signing (verification and hashing/digests still allowed) |
| ECDSA Curves | P-256, P-384, P-521 only |
| PBKDF2 Password | 14 bytes minimum |
| DH Groups | FFDHE only (no MODP) |

### Run Your Tests

Run your application's test suite against the baseline build. Fix any failures before proceeding.
The goal should be an application test suite that only uses FIPS compliant algorithms.

If you encounter failures, consult the **Common Failures** table below for quick fixes. For additional
assistance, contact [wolfSSL support](mailto:support@wolfssl.com) for consulting.

```bash
# Example tests
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048  # Should succeed
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024  # Should fail

/path/to/your/application/test-suite # Ensure your application test suite works properly
```

### Common Failures

| Issue | Symptom | Solution |
|-------|---------|----------|
| RSA key too small | `unsupported` error | Use 2048+ bit keys |
| P-192 ECDSA | `unsupported` error | Use P-256 or larger |
| SHA1 signing | Sign fails, verify works | Use SHA-256+ |
| Short PBKDF2 password | `invalid salt length` | Use 14+ byte passwords |
| MODP DH groups | Group not available | Use FFDHE groups |

### Important Limitations

> **Note:** FIPS baseline testing filters non-approved algorithms at the OpenSSL provider level, but passing these tests does not guarantee full FIPS compliance. You should also review your application for:
>
> - **Inline cryptography** - Custom crypto implementations that don't use OpenSSL APIs
> - **Legacy OpenSSL 1.x APIs** - Some older APIs bypass the provider architecture entirely
> - **Non-provider operations** - Direct calls to low-level OpenSSL functions
>
> A thorough code review is recommended to ensure all cryptographic operations route through OpenSSL's provider interface.

---

## Replace Default Mode (Recommended for FIPS)

FIPS certification applies system-wide, meaning all cryptographic operations should use the FIPS-validated module. wolfProvider's replace-default mode ensures this by making wolfProvider the primary cryptographic provider for all OpenSSL operations. In this model it is impossible for an application to use the default provider, any attempts to do so will yield wolfProvider instead.

**Why use replace-default for FIPS:**
- Ensures all crypto operations use wolfSSL's FIPS-validated implementations
- Prevents accidental use of non-FIPS algorithms via OpenSSL's default provider
- Intercepts requests for "default", "fips", and "wolfProvider" providers

---

## Step 2: FIPS Build

Once baseline testing passes, build wolfProvider with your FIPS bundle. You have two options:

- **Build Script (Recommended)** - A convenience wrapper that fetches dependencies (OpenSSL, wolfSSL) and handles configuration automatically
- **Manual Build** - Build each component directly using autotools

Choose the approach that fits your workflow.

### Option A: Build Script (Recommended)

The build script (`scripts/build-wolfprovider.sh`) is a convenience wrapper that automates:

1. **OpenSSL**: Fetches source (if needed) and applies the replace-default patch
2. **wolfSSL**: Extracts your FIPS bundle and builds with required flags
3. **wolfProvider**: Runs autotools configure and make with appropriate options

Use `--distclean` to remove all source directories when switching configurations.

### Build

```bash
./scripts/build-wolfprovider.sh --distclean
./scripts/build-wolfprovider.sh --replace-default --fips-bundle=/path/to/fips-bundle --fips-check=v5
```

### FIPS Check Options

The `--fips-check` option tells the build system which FIPS bundle type you have. The tag can be derived from your bundle filename:

**Bundle Naming Convention:** `wolfssl-<version>-commercial-fips-<tag>.7z`

| Bundle Name Example | `--fips-check` Value |
|---------------------|----------------------|
| `wolfssl-5.8.4-commercial-fips-ready.7z` | `ready` |
| `wolfssl-5.8.4-commercial-fips-linuxv5.7z` | `linuxv5` |
| `wolfssl-5.8.4-commercial-fips-linuxv5.2.1.7z` | `linuxv5.2.1` |
| `wolfssl-5.8.4-commercial-fips-v6.0.0.7z` | `v6.0.0` |

---

### Option B: Manual Build (Autotools)

For more control, build each component directly using autotools—the core build system for wolfProvider. This approach is useful when integrating into existing build pipelines or when you need precise control over compiler flags and installation paths.

**Note:** Replace-default mode requires patching OpenSSL.

### OpenSSL (with Replace-Default Patch)

```bash
git clone --depth=1 -b openssl-3.5.0 https://github.com/openssl/openssl.git
cd openssl

# Apply replace-default patch (recommended for FIPS)
patch -p1 < /path/to/wolfProvider/patches/openssl3-replace-default.patch

./config shared --prefix=/usr/local/openssl no-external-tests no-tests
make -j$(nproc)
sudo make install
```

### wolfSSL (FIPS Bundle)

Extract your FIPS bundle and build:

```bash
# Extract the bundle
7z x wolfssl-5.8.4-commercial-fips-ready.7z
cd wolfssl-5.8.4-commercial-fips-ready

./configure --enable-fips=ready \
    --enable-opensslcoexist \
    --prefix=/usr/local/wolfssl-fips \
    CPPFLAGS="-I/usr/local/openssl/include -DWOLFSSL_OLD_OID_SUM -DWOLFSSL_DH_EXTRA"
make -j$(nproc)
sudo make install
```

Replace `--enable-fips=ready` with your bundle's tag (see FIPS Check Options above).

**Required flags:**
- `--enable-opensslcoexist` - Prevents symbol conflicts with OpenSSL (mandatory)
- `-DWOLFSSL_OLD_OID_SUM` - Required for certificate compatibility (mandatory)
- `-DWOLFSSL_DH_EXTRA` - Required for DH key operations (mandatory)
- `-I/usr/local/openssl/include` - Path to your OpenSSL headers (adjust as needed)

### wolfProvider

Build wolfProvider with replace-default to ensure FIPS compliance system-wide:

```bash
./autogen.sh
./configure --with-openssl=/usr/local/openssl \
    --with-wolfssl=/usr/local/wolfssl-fips \
    --enable-replace-default
make -j$(nproc)
```

---

## Testing

### Production Builds

Standard replace-default builds skip unit tests by design. The test harness needs to load both wolfProvider and OpenSSL's default provider, but replace-default mode intercepts all provider loading.

```bash
# Production build - tests skipped
./scripts/build-wolfprovider.sh --replace-default --fips-bundle=/path/to/bundle --fips-check=v5
```

### Development/Testing Builds

To run unit tests with replace-default mode, use `--enable-replace-default-testing`:

```bash
./scripts/build-wolfprovider.sh --replace-default --enable-replace-default-testing \
    --fips-bundle=/path/to/bundle --fips-check=v5
make test
```

**What this does:**

This option patches OpenSSL's `util/libcrypto.num` to export six internal provider symbols that are not part of OpenSSL's public API. The test harness uses these symbols to directly load OpenSSL's default provider (bypassing replace-default interception) so it can test wolfProvider algorithms against OpenSSL's implementations.

**Exported symbols:**
- `ossl_provider_new`, `ossl_provider_activate`, `ossl_provider_deactivate`
- `ossl_provider_add_to_store`, `ossl_provider_free`, `ossl_default_provider_init`

> **Warning:** Builds with `--enable-replace-default-testing` export internal OpenSSL symbols that may change between versions. Use only for development and testing—never deploy to production.

### Switching Between Modes

Always use `--distclean` when switching between production and testing builds:

```bash
./scripts/build-wolfprovider.sh --distclean
./scripts/build-wolfprovider.sh --replace-default --fips-bundle=/path/to/bundle --fips-check=v5
```

---

## Algorithm Reference

### Approved

| Category | Algorithms |
|----------|------------|
| Digests | SHA-224, SHA-256, SHA-384, SHA-512, SHA3-* |
| Symmetric | AES-128/192/256 (ECB, CBC, CTR, GCM, CCM) |
| Asymmetric | RSA (2048+), ECDSA (P-256, P-384, P-521) |
| Key Exchange | ECDH (P-256, P-384, P-521), DH (FFDHE-2048+) |
| MACs | HMAC, CMAC, GMAC |
| KDFs | HKDF, PBKDF2, TLS1.3 KDF, TLS PRF |

### Blocked

| Category | Algorithms |
|----------|------------|
| Digests | MD5, SHA-1 (signing), BLAKE2, SM3 |
| Symmetric | DES, 3DES, ChaCha20, RC4 |
| Asymmetric | RSA < 2048, DSA, Ed25519/Ed448 |
| Key Exchange | X25519/X448, DH (MODP) |
| Curves | P-192 |

---

## Troubleshooting

### Debug Logging

```bash
./scripts/build-wolfprovider.sh --enable-fips-baseline --debug
```

### Build Mode Switching

Always run `--distclean` when switching between build configurations:

```bash
./scripts/build-wolfprovider.sh --distclean
./scripts/build-wolfprovider.sh --enable-fips-baseline
```

### Mutual Exclusivity

`--enable-fips-baseline` and `--replace-default` cannot be used together.

---

## Support

- [GitHub Issues](https://github.com/wolfssl/wolfProvider/issues)
- [wolfSSL Support](https://www.wolfssl.com/products/support-and-maintenance/)

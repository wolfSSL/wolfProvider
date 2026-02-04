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

## Support

- [GitHub Issues](https://github.com/wolfssl/wolfProvider/issues)
- [wolfSSL Support](https://www.wolfssl.com/products/support-and-maintenance/)

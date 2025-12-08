
## Description

wolfProvider is a library that can be used as a Provider in OpenSSL.

## Features

* MD5-1
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* SHA-512/224
* SHA-512/256
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512
* SHAKE 256
* AES
    * 128, 192, and 256 bit keys
    * ECB
    * CBC
    * CTR
    * GCM
    * CCM
* DRBG
* RSA, RSA-PSS
    * Signing, Verification
    * Asymmetric Encrypt, Decrypt
    * Key generation
* DH
* ECC
    * ECDSA
    * ECDH
    * Key generation
    * Curve P-192
    * Curve P-224
    * Curve P-256
    * Curve P-384
    * Curve P-521
* HMAC
* CMAC
* GMAC
* HKDF
* PBKDF2
* PKCS12 PBKDF2
* TLS1_3 KDF
* TLS1 PRF

## Building
The quickest method is to use the `scripts/build-wolfprovider.sh` script as follows:

```
./scripts/build-wolfprovider.sh
```

It will retrieve the dependencies and compile them as necessary. To use other than the default (such as different releases) you can set various environment variables prior to calling the script:

```
OPENSSL_TAG=openssl-3.5.0 WOLFSSL_TAG=v5.8.0-stable WOLFPROV_DEBUG=1 scripts/build-wolfprovider.sh
```

Or you can set them with variables like so:

```
./scripts/build-wolfprovider.sh --debug --openssl-ver=openssl-3.5.0 --wolfssl-ver=v5.8.0-stable
```

To clean the build, use the following:
```
./scripts/build-wolfprovider.sh --clean
```

To remove all source directories, use the following:
```
./scripts/build-wolfprovider.sh --distclean
```

Alternatively, you can manually compile each component using the following guide.

### OpenSSL

```
git clone --depth=1 -b openssl-3.0.0 https://github.com/openssl/openssl.git
cd openssl
./config no-fips shared
make
sudo make install
```

### wolfSSL

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=1024" --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --with-eccminsz=192
make
sudo make install
```

Add `--enable-aesgcm-stream` if available for better AES-GCM support.
Add `--enable-curve25519` to include support for X25519 Key Exchange.
Add `--enable-curve448` to include support for X448 Key Exchange.
Add `--enable-ed25519` to include support for Ed25519 signatures and certificates..
Add `--enable-ed448` to include support for Ed448 signature and certificates.

Add `--enable-pwdbased` to the configure command above if PKCS#12 is used in OpenSSL.

Add to CPPFLAGS `-DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384` to enable predefined 6144-bit and 8192-bit DH parameters.

Add to `--enable-hmac-copy` if performing HMAC repeatedly with the same key to improve performance. (Available with wolfSSL 5.7.8+.)

Add `--enable-sp=yes,asm' '--enable-sp-math-all'` to use SP Integer maths. Replace `-DFP_MAX_BITS=16384` with -DSP_INT_BITS=8192` when used.

Remove `-DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER` and add `--enable-fips=v2` to the configure command above if building from a FIPS v2 bundle and not the git repository. Change `--enable-fips=v2` to `--enable-fips=ready` if using a FIPS Ready bundle.

If '--with-eccminsz=192' is not supported by wolfSSL, add '-DECC_MIN_KEY_SZ=192' to the CPPFLAGS.

### wolfProvider

```
./autogen.sh
./configure
make
```

To build using a different OpenSSL installation directory (e.g. one at /usr/local/ssl) use:

```
./configure --with-openssl=/usr/local/ssl
make
export LD_LIBRARY_PATH=/usr/local/ssl/lib
make check
```

## Building with FIPS

To build and test with our prebuilt FIPS bundle, use the following command to build wolfProvider with FIPS enabled. You can refer to `.github/workflows/fips-ready.yml` for the workflow that does this.

Go to our website to download the FIPS bundle. [here](https://www.wolfssl.com/download/) and select  wolfssl-5.8.2-gplv3-fips-ready.zip.

or you can use wget to download the FIPS bundle like so:
```
wget -O wolfssl-fips-ready.zip https://www.wolfssl.com/wolfssl-5.8.2-gplv3-fips-ready.zip
unzip wolfssl-fips-ready.zip
```

Then use the following command to build wolfProvider with FIPS enabled.
```
./scripts/build-wolfprovider.sh --fips-bundle="path/to/fips-bundle" --fips-check=ready --distclean
```

## Building with Replace Default

wolfProvider can be configured to replace OpenSSL's default provider, making wolfProvider the default cryptographic provider for all OpenSSL operations. This is useful for applications that want to use wolfSSL's cryptographic implementations without modifying their code.

### Replace Default vs. Standard Provider Mode

Replace default mode is fundamentally different from the standard provider approach:

**Standard Provider Mode:** When wolfProvider is loaded as a standard provider alongside OpenSSL's default provider, applications can still access OpenSSL's native crypto implementations in several ways:
- When an application explicitly requests a specific provider (e.g., "default") for an algorithm
- When wolfProvider doesn't implement a particular algorithm, OpenSSL falls back to its built-in implementations
- If the execution environment does not pick up the specified configuration file enabling
use of wolfProvider

**Replace Default Mode:** This mode patches OpenSSL to disable many of these fallback paths.
When replace default is enabled:
- wolfProvider becomes the primary cryptographic provider
- Requests for the "default" provider are redirected to wolfProvider
- Requests for the "fips" provider are redirected to wolfProvider
- Requests for the "wolfProvider" provider are redirected to wolfProvider
- This ensures maximum use of wolfSSL's cryptographic implementations for testing and validation

This makes replace default mode particularly useful for comprehensive testing scenarios where you want to ensure that wolfSSL's implementations are being used throughout the entire system.

### Basic Replace Default

To build wolfProvider as a replacement for OpenSSL's default provider:

```bash
./scripts/build-wolfprovider.sh --replace-default
```

This patches OpenSSL so that wolfProvider becomes the default provider.

### Replace Default with Testing Support

For unit testing with replace-default enabled, you need additional support to load the real OpenSSL default provider alongside wolfProvider. This requires both flags:

```bash
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

### Examples

Build with replace-default only:
```bash
./scripts/build-wolfprovider.sh --replace-default
```

Build with replace-default and unit testing support:
```bash
./scripts/build-wolfprovider.sh --replace-default --enable-replace-default-testing
```

## Testing

### Unit Tests

To run automated unit tests:
* `make test`

### Command Tests

To run the command tests:
* `./scripts/cmd_test/do-cmd-tests.sh`

### Integration Tests

To run the cipher suite testing:
* `./scripts/test-wp-cs.sh`

## Debugging

To enable wolfProvider debug logging, build with `--debug` which enables exit messages, error messages, and informational messages. If you want to filter logging a certain way or increase detail level, set `WOLFPROV_LOG_LEVEL_FILTER` and `WOLFPROV_LOG_COMPONENTS_FILTER` in `include/wolfprovider/wp_logging.h` as needed. See comments in that file for examples.

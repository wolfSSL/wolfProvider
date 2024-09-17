
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
The quickest method is to use the `scripts/build-wolfprovider.sh` script. It will retreive the dependencies and compile them as necessary. To use other than the default (such as different releases) you can set various environment variables prior to calling the script. An example is:
    OPENSSL_TAG=openssl-3.2.0 WOLFSSL_TAG=v5.7.2-stable WOLFPROV_DEBUG=1 scripts/build-wolfprovider.sh

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
./configure --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=1024" --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16
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

Add `--enable-sp=yes,asm' '--enable-sp-math-all'` to use SP Integer maths. Replace `-DFP_MAX_BITS=16384` with -DSP_INT_BITS=8192` when used.

Remove `-DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER` and add `--enable-fips=v2` to the configure command above if building from a FIPS v2 bundle and not the git repository. Change `--enable-fips=v2` to `--enable-fips=ready` if using a FIPS Ready bundle.

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

## Testing

### Unit Tests
To run automated unit tests:

* `make test`

### Integration Tests

To run the cipher suite testing:
* ./scripts/test-wp-cs.sh


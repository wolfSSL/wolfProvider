
## Description

wolfProvider is a library that can be used as an Provider in OpenSSL.

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

### OpenSSL

```
git clone https://github.com/openssl/openssl.git
cd openssl
./config no-fips
make
sudo make install
```

### wolfSSL

```
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-des3 --enable-aesctr --enable-aesccm --enable-x963kdf CPPFLAGS="-DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"
make
sudo make install
```

Add `--enable-pwdbased` to the configure command above if PKCS#12 is used in OpenSSL.

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
* ./scripts/wp-cs-test.sh


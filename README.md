
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


## Support

- [GitHub Issues](https://github.com/wolfssl/wolfProvider/issues)
- [wolfSSL Support](https://www.wolfssl.com/products/support-and-maintenance/)

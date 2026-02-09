# wolfProvider version 1.1.1 (February 09, 2026)

Release 1.1.1 has been developed according to wolfSSL's development and QA
process and successfully passed the quality criteria.

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request
number where the code change was added.

## New Feature Additions
* Add OpenSSL FIPS baseline process implementation (PR 357)
* Add seed-src handling for wolfProvider (PR 350)
* Add EC public key auto derivation from private key (PR 338)
* Add text encoder for ECC (PR 348)
* Add option for debug output to default to silent (PR 356)
* Add static analysis CI tools (PR 349)
* Add option to enable unit testing for replace default mode (PR 331)

## Enhancements and Optimizations
* Optimize FIPS CAST startup tests (PR 351)
* Update TLS 1.3 KDF to use proper wolfcrypt FIPS APIs (PR 352)
* Restrict DH keygen to 2048 bits and above for FIPS builds (PR 336)
* Update wolfSSL version to v5.8.4 and OpenSSL to v3.5.4 (PR 334)
* Don't modify system config when installing in standalone mode (PR 335)
* Add RSA-PSS PKI encoding/decoding support (PR 333)

## Bug Fixes
* Fix NULL salt handling in HKDF (PR 328)
* Fix EC public key auto-derive version check for OpenSSL 4.0.0+ (PR 355)
* Fix RSA-PSS command test (PR 344)
* Fix const issue with x509 test code (PR 346)
* Fix provider cmd test (PR 347)
* Fix size_t issue in test_ecc.c (PR 343)
* Fix RD detection when running cmdline tests (PR 354)

# wolfProvider version 1.1.0 (October 29, 2025)

Release 1.1.0 has been developed according to wolfSSL's development and QA
process and successfully passed the quality criteria.

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request
number where the code change was added.

## New Feature Additions
* Add KBKDF (Key-Based Key Derivation Function) implementation (PR 204)
* Add KRB5KDF (Kerberos 5 Key Derivation Function) implementation (PR 203)
* Add AES-CTS (Ciphertext Stealing) cipher mode implementation (PR 189)
* Add RSA encrypt/decrypt operations without padding (PR 110)
* Add option to replace OpenSSL default provider with wolfProvider (PR 260)
* Add command-line integration tests for AES, RSA, RSA-PSS, Hash, and ECC operations (PR 95)
* Add dynamic logging capabilities based on environment variables (PR 312)
* Add Debian packaging support (PR 234)

## Enhancements and Optimizations
* Improve FIPS support and testing capabilities (PR 191, PR 269)
* Revamp debug selection and output system (PR 259)
* Add FIPS-ready CI testing (PR 269)
* Add environment setup script for provider configuration (PR 168)
* Add WOLFPROV_FORCE_FAIL testing support for failure scenarios (PR 123)
* Add ASAN (Address Sanitizer) workflow for enhanced testing (PR 126)
* Add library path support for aarch64 builds (PR 146)

## New Integration Testing
* Add integration testing with gRPC (PR 103)
* Add integration testing with OpenSSH (PR 138)
* Add integration testing with libssh2 (PR 219)
* Add integration testing with OpenSC/PKCS11 (PR 226)
* Add integration testing with OpenLDAP (PR 104)
* Add integration testing with IPMItool (PR 113)
* Add integration testing with Stunnel (PR 98)
* Add integration testing with socat (PR 99)
* Add integration testing with SSSD (PR 102)
* Add integration testing with net-snmp (PR 143)
* Add integration testing with liboauth2 (PR 157)
* Add integration testing with tnftp (PR 177)
* Add integration testing with systemd (PR 202)
* Add integration testing with X11VNC (PR 201)
* Add integration testing with sscep (PR 229)
* Add integration testing with TPM2 tools (PR 241)
* Add integration testing with Python3 NTP (PR 214)
* Add integration testing with libeac (PR 184)
* Add integration testing with xmlsec (PR 192)
* Add integration testing with Qt5 Network (PR 205)
* Add integration testing with rsync (PR 232)
* Add integration testing with libwebsockets (PR 161)
* Add integration testing with tcpdump (PR 162)
* Add integration testing with cjose (PR 153)
* Add integration testing with iperf (PR 160)
* Add integration testing with KRB5 (PR 254)
* Add integration testing with libcryptsetup (PR 244)
* Add integration testing with libtss2 (PR 188)
* Add integration testing with ppp (PR 176)
* Add integration testing with pam-pkcs11 (PR 170)
* Add integration testing with kmod (PR 186)
* Add integration testing with libfido2 (PR 179)
* Add multi-compiler testing (PR 100)

## Bug Fixes
* Fix AES-GCM stream handling for FIPS builds (PR 181, PR 150)
* Fix AES-GCM authentication tag failure handling with FIPS (PR 228)
* Fix AES-GCM uninitialized variable (PR 199)
* Fix AES-CBC IV handling for consecutive calls (PR 193)
* Fix AES cipher handling to accept NULL/0 input (PR 133)
* Fix RSA decode and empty keygen OID handling with FIPS (PR 196)
* Fix RSA PSS decoding to properly reject non-PKCS8 keys (PR 108)
* Fix RSA key import edge case (PR 224)
* Fix RSA keygen with FIPS retry loop (PR 213)
* Fix RSA certificate display with BIO_printf refactor (PR 208)
* Fix ECC public key validation (PR 221)
* Fix ECC public key parameter handling (PR 115)
* Fix ECC signing with SHA1 restriction only for FIPS (PR 227)
* Fix ECC type-specific public key encode/decode (PR 206)
* Fix ECC get private key handling (PR 134)
* Fix ECC private lock handling during key encoding (PR 173)
* Fix ECX test build without ED448 support (PR 171)
* Fix ECX uninitialized variable in Debian builds (PR 256)
* Fix EdDSA key clamping on import/export (PR 125)
* Fix DH for FIPS builds (PR 217, PR 216, PR 215)
* Fix DH public key decoding and add new decoder registrations (PR 187)
* Fix DH type-specific SPKI decoder (PR 198)
* Fix DH PKI decode handling (PR 128)
* Fix DH get private key handling (PR 136)
* Fix DH get params functionality (PR 152, PR 141)
* Fix DH privSz parameter handling (PR 251)
* Fix HKDF test with changing OpenSSL master behavior (PR 120)
* Fix core libctx handling to create new child libctx (PR 220)
* Fix locking around signature operations (PR 172)
* Fix NULL reinit handling for signatures (PR 154)
* Fix RSA/RSA-PSS/ECC/ECX DER encoding (PR 96)
* Fix pid_t bug with dh->ctx override (PR 190)
* Fix WPFF runtime checks for key management functions (PR 248)
* Fix hang with RSA command test and other bugs (PR 253)
* Fix FIPS error messaging for silent wolfSSL errors (PR 268)
* Fix OpenSSL patching detection (PR 291)
* Fix FIPS check when building wolfSSL (PR 297)
* Fix build script issues for Debian packages (PR 315, PR 314)
* Fix version header changes after builds (PR 114)
* Fix macOS directory age comparison in scripts (PR 116)
* Fix missing files from dist package (PR 94)
* Fix SM3/SM4 build errors on Android (PR 107)

# wolfProvider version 1.0.2 (March 21, 2025)

Release 1.0.2 has been developed according to wolfSSL's development and QA
process and successfully passed the quality criteria.

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request
number where the code change was added.

## New Feature Additions
* Add RSA X931 signature algorithm implementation (PR 63)
* Add DES3-CBC cipher implementation (PR 58)
* Add PSS encoding support for PKCS8 private keys (PR 73)
* Add option to build from FIPS bundle (PR 85)

## Enhancements and Optimizations
* Improve AES-GCM performance (PR 69)
* Set minimum RSA key size to 1024 bits (PR 53)
* Add integration testing with nginx (PR 71)
* Add integration testing with curl (PR 72)
* Add integration testing with OpenVPN (PR 75)
* Add feature to force failure if environment variable is set (PR 74)

## Bug Fixes
* Fix RSA key type setting on import (PR 81)
* Fix RSA parameter handling when getting parameters (PR 82)
* Fix RSA import for Python use cases (PR 77)
* Fix RSA and ECC keypair matching (PR 62)
* Fix AES-GCM stream IV handling for OpenSSH workflows (PR 78)
* Fix AES-CBC IV handling on reinit with NULL IV (PR 65)
* Fix PKCS8 decoder to properly allow fallback decoding on failure (PR 59)
* Fix parameter handling for EC encoding in OpenSSL genpkey flow (PR 80)
* Fix HKDF handling to allow setting NULL/0 salt (PR 83)
* Fix size_t conversion for macOS (PR 56)
* Fix params get uint to properly set 'set' flag (PR 67)
* Fix FIPS build issues (PR 61)
* Fix TLS PRF test build (PR 79)
* Fix nginx-related issues (PR 68)

# wolfProvider version 1.0.1 (Sept 10, 2024)
* Add test-sanity script
* Add FIPS testing
* Add a sanity check to make sure we can connect to external servers
* Fix for openssl denying connections
* Add more logging of calls
* Add helpful failure messages
* Fix 'make check' failures
* Fix wp_corebio_get_bio
* Add in simple logging for wolfProvider
* Use custom list of supported settable parameters
* Explicit ignore of generated content
* Add simple Github Action
* Add in declarations and calls to tests
* Add AES CFB encryption/decryption + tests

# wolfProvider version 1.0.0 (July 17, 2024)

This is the first release of wolfProvider. It is similar to wolfEngine (which
creates a library to interface with OpenSSL 1.x). WolfProvider interfaces with
OpenSSL 3.x using our wolfCrypt cryptography module.

This first release has sample applications for Android as well as XCode (iOS).
In addition, there are utility scripts added as a convenience for compiling
all the dependencies of wolfProvider.

Refer to README.md for more details

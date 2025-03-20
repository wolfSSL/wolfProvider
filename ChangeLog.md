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

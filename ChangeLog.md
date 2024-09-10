# wolfProvider version 1.0.1 (Sept 10, 2024)
Add test-sanity script
Add FIPS testing
Add a sanity check to make sure we can connect to external servers
Fix for openssl denying connections
Add more logging of calls
Add helpful failure messages
Fix 'make check' failures
Fix wp_corebio_get_bio
Add in simple logging for wolfProvider
Use custom list of supported settable parameters
Explicit ignore of generated content
Add simple Github Action
Add in declarations and calls to tests
Add AES CFB encryption/decryption + tests

# wolfProvider version 1.0.0 (July 17, 2024)

This is the first release of wolfProvider. It is similar to wolfEngine (which
creates a library to interface with OpenSSL 1.x). WolfProvider interfaces with
OpenSSL 3.x using our wolfCrypt cryptography module.

This first release has sample applications for Android as well as XCode (iOS).
In addition, there are utility scripts added as a convenience for compiling
all the dependencies of wolfProvider.

Refer to README.md for more details

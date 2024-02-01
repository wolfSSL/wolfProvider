This example will create the artifacts necessary for building applications using XCODE. It consists of 3 parts:
- Building OpenSSL (build-openssl-framework.sh)
- Building WolfSSL (build-wolfssl-framework.sh)
- Building WolfProvider (build-wolfprovider-framework.sh)

Using the `build-all.sh` script it will invoke all the required steps with the necessary dependencies. Once the artifacts are created in each of the respective source directories the `run_openssl.sh` script can be used to run a few simple tests of libwolfprov with the specific version of OpenSSL. Most of the examples use `libwolfprov.so/dll/dylib` so we do a simple trick to create a symbolic link that has the proper filename.

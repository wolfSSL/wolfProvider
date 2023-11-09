#!/bin/bash

set -e
WORKSPACE=$(pwd)

DEBIAN_FRONTEND=noninteractive apt update && apt install -y git make autoconf libtool android-tools-adb unzip wget

# https://developer.android.com/ndk/downloads/
export ANDROID_NDK_ROOT=${WORKSPACE}/android-ndk-r26b
PATH="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
if [ ! -e ${ANDROID_NDK_ROOT} ]; then
    wget https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
    unzip android-ndk-r26b-linux.zip
fi

# Compile OpenSSL
export OPENSSL_ALL_CIPHERS="-cipher ALL -ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"
if [ ! -e ${WORKSPACE}/openssl ]; then
    git clone https://github.com/openssl/openssl.git ${WORKSPACE}/openssl
    cd ${WORKSPACE}/openssl && \
        ./Configure android-x86_64 --prefix=${WORKSPACE}/openssl-install && \
        sed -i 's/-ldl//g' Makefile && \
        sed -i 's/-pie//g' Makefile && \
        make -j && \
        make -j install
fi
export LD_LIBRARY_PATH="${WORKSPACE}/openssl-install/lib64:$LD_LIBRARY_PATH"

# Compile WolfSSL
export WOLFSSL_CONFIG_OPTS='--enable-debug --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --enable-aesgcm-stream --enable-curve25519 --enable-curve448 --enable-ed25519 --enable-ed448 --enable-pwdbased'
export WOLFSSL_CONFIG_CPPFLAGS=CPPFLAGS="-I${WORKSPACE}/openssl-install -DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"
export UNAME=Android
export CROSS_COMPILE=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android34-
export CC=x86_64-linux-android34-clang
if [ ! -e ${WORKSPACE}/wolfssl ]; then
    git clone https://github.com/wolfssl/wolfssl ${WORKSPACE}/wolfssl
    cd ${WORKSPACE}/wolfssl && \
        ./autogen.sh && \
        ./configure ${WOLFSSL_CONFIG_OPTS} "${WOLFSSL_CONFIG_CPPFLAGS}" -prefix=${WORKSPACE}/wolfssl-install --host=x86_64-linux-android --disable-asm CFLAGS=-fPIC && \
        make -j install
fi
export LD_LIBRARY_PATH="${WORKSPACE}/wolfssl-install/lib:$LD_LIBRARY_PATH"
export LIBRARY_PATH="${WORKSPACE}/wolfssl-install/lib:$LIBRARY_PATH"

if [ ! -e ${WORKSPACE}/wolfProvider ]; then
    git clone https://github.com/wolfssl/wolfProvider ${WORKSPACE}/wolfProvider
    cd ${WORKSPACE}/wolfProvider && \
        ./autogen.sh && \
        ./configure --with-openssl=${WORKSPACE}/openssl-install --with-wolfssl=${WORKSPACE}/wolfssl-install --host=x86_64-linux-android CFLAGS="-lm -fPIC" --enable-debug && \
        make -j
fi

#!/bin/bash

set -e
WORKSPACE=$(pwd)

AUTO_INSTALL_TOOLS=${AUTO_INSTALL_TOOLS:-true}
if [ "${AUTO_INSTALL_TOOLS}" == "true" ]; then
    DEBIAN_FRONTEND=noninteractive apt update && apt install -y git make autoconf libtool android-tools-adb unzip wget
fi

# https://developer.android.com/ndk/downloads/
export ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT:-${WORKSPACE}/android-ndk-r26b}
if [ ! -e ${ANDROID_NDK_ROOT} ]; then
    wget -q https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
    unzip android-ndk-r26b-linux.zip
fi
PATH="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"

# Compile OpenSSL
export OPENSSL_ALL_CIPHERS="-cipher ALL -ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"
if [ ! -e ${WORKSPACE}/openssl-install ]; then
    git clone https://github.com/openssl/openssl.git ${WORKSPACE}/openssl-source
    cd ${WORKSPACE}/openssl-source && \
        ./Configure android-x86_64 --prefix=${WORKSPACE}/openssl-install && \
        sed -i 's/-ldl//g' Makefile && \
        sed -i 's/-pie//g' Makefile && \
        make -j && \
        make -j install
fi
export LD_LIBRARY_PATH="${WORKSPACE}/openssl-install/lib64:$LD_LIBRARY_PATH"

# Compile WolfSSL
export WOLFSSL_CONFIG_OPTS='--enable-debug --enable-opensslcoexist --enable-cmac --enable-keygen --enable-sha --enable-aesctr --enable-aesccm --enable-x963kdf --enable-compkey --enable-certgen --enable-aeskeywrap --enable-enckeys --enable-base16 --enable-aesgcm-stream --enable-curve25519 --enable-curve448 --enable-ed25519 --enable-pwdbased --enable-fips=ready'
export WOLFSSL_CONFIG_CPPFLAGS=CPPFLAGS="-I${WORKSPACE}/openssl-install -DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DECC_MIN_KEY_SZ=192 -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DFP_MAX_BITS=16384 -DWOLFSSL_DH_EXTRA -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER"
export UNAME=Android
export CROSS_COMPILE=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android34-
if [ ! -e ${WORKSPACE}/wolfssl-install ]; then
    if [ ${USE_FIPS_CHECK} = "true" ]; then
        git clone https://github.com/wolfssl/wolfssl ${WORKSPACE}/wolfssl
        cd ${WORKSPACE}/wolfssl && ./fips-check.sh fips-ready keep
        mv ${WORKSPACE}/wolfssl/XXX-fips-test ${WORKSPACE}/wolfssl-source
        rm -rf ${WORKSPACE}/wolfssl
        cd ${WORKSPACE}/wolfssl-source && ./autogen.sh
    else
        wget -O ${WORKSPACE}/wolfssl-fips.zip https://www.wolfssl.com/wolfssl-5.6.4-gplv3-fips-ready.zip && \
            cd ${WORKSPACE} && unzip wolfssl-fips.zip && \
            mv ${WORKSPACE}/wolfssl-5.6.4-gplv3-fips-ready ${WORKSPACE}/wolfssl-source && \
            rm ${WORKSPACE}/wolfssl-fips.zip
    fi
    cd ${WORKSPACE}/wolfssl-source
    CC=x86_64-linux-android34-clang ./configure ${WOLFSSL_CONFIG_OPTS} "${WOLFSSL_CONFIG_CPPFLAGS}" -prefix=${WORKSPACE}/wolfssl-install --host=x86_64-linux-android --disable-asm CFLAGS=-fPIC && \
    make && \
    adb push --sync src/.libs/libwolfssl.so ./wolfcrypt/test/.libs/testwolfcrypt /data/local/tmp/ && \
    NEWHASH=$(adb shell "LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/testwolfcrypt 2>&1 | sed -n 's/hash = \(.*\)/\1/p'") && \
    sed -i "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c && \
    make -j install
fi
export LD_LIBRARY_PATH="${WORKSPACE}/wolfssl-install/lib:$LD_LIBRARY_PATH"
export LIBRARY_PATH="${WORKSPACE}/wolfssl-install/lib:$LIBRARY_PATH"

# If running in wolfProvider/IDE/Android, then 'ln -s ../../ wolfProvider'
if [ ! -e ${WORKSPACE}/wolfProvider ]; then
    git clone https://github.com/wolfssl/wolfProvider ${WORKSPACE}/wolfProvider
fi
cd ${WORKSPACE}/wolfProvider && \
    ./autogen.sh && \
    CC=x86_64-linux-android34-clang ./configure --with-openssl=${WORKSPACE}/openssl-install --with-wolfssl=${WORKSPACE}/wolfssl-install --host=x86_64-linux-android CFLAGS="-lm -fPIC" --enable-debug && \
    make -j

${CROSS_COMPILE}clang ${WORKSPACE}/wolfProvider/examples/openssl_example.c -I ${WORKSPACE}/openssl-install/include/ -L ${WORKSPACE}/openssl-install/lib/ -lcrypto -o ${WORKSPACE}/wolfProvider/examples/openssl_example

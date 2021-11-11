#!/bin/sh

# commit-tests.sh
#
# Tests executed on each commit

# WOLFPROV_OPENSSL_INSTALL - environment variable that when set will use
# the specified OpenSSL installation path for commit tests, setting the path
# with --with-openssl=WOLFPROV_OPENSSL_INSTALL at configure time.

# make sure current config is ok
echo -e "\n\nTesting current config...\n\n"
make clean; make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCurrent config make test failed" && exit 1

# allow developer to set OpenSSL installation path using env variable
if test -n "$WOLFPROV_OPENSSL_INSTALL"; then
    WITH_OPENSSL="--with-openssl=$WOLFPROV_OPENSSL_INSTALL"
    echo -e "WOLFPROV_OPENSSL_INSTALL is set: $WOLFPROV_OPENSSL_INSTALL"
    export LD_LIBRARY_PATH=$WOLFPROV_OPENSSL_INSTALL/lib:$LD_LIBRARY_PATH
else
    WITH_OPENSSL=""
    echo -e "WOLFPROV_OPENSSL_INSTALL not set."
fi

# make sure default config is ok
echo -e "\n\nTesting default config:\n"
./configure $WITH_OPENSSL
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault config ./configure failed" && exit 1

make -j 8 test
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault config make test failed" && exit 1
 
# make sure default debug config is ok
echo -e "\n\nTesting default debug config:\n"
./configure $WITH_OPENSSL --enable-debug
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault debug config ./configure failed" && exit 1

make -j 8 test
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nDefault debug config make test failed" && exit 1

exit 0

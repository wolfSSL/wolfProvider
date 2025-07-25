#!/bin/bash
# test_sscep.sh
#
# Copyright (C) 2006-2024 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
TEST_SSCEP_FAIL=0

cleanup(){
    [ -f ca.crt     ] && rm -f  ca.crt
    [ -d ca-dir     ] && rm -rf ca-dir
    [ -f client.log ] && rm -f  client.log
    [ -f server.log ] && rm -f  server.log
}

killall scepserver &> /dev/null
cleanup

touch client.log server.log

# begin by setting up and starting the scep server
scepserver ca -depot ca-dir -init &>> server.log
scepserver -depot ca-dir -port 8080 -debug &>> server.log &

sleep 1

# now test sscep

# getca
sscep getca -u "http://localhost:8080/scep" -c ca.crt -v -d &>> client.log

if [ $? -eq 0 ] && [ -f ca.crt ] \
    && diff -y ca.crt ca-dir/ca.pem &>> client.log
then
    echo "[ PASSED ] getca"
else
    echo "[ FAILED ] getca"
    TEST_SSCEP_FAIL=1
fi

# getnextca
# could not get certificate chaining to work. Not sure if it's the servers fault
#   or mine.

# enroll
# first generate ca request (sscep has a script for this)
timeout 10 ./mkrequest -ip 1.2.3.4

if [ $? -eq 0 ]; then
    # then enroll -> sscep WILL fail this.
    # scepserver uses des-cbc (which is not supported) when sending a cert back, so
    #   to test just check that the .csr got over to the server. This way at least
    #   some of its functionality can be tested
    sscep enroll -u "http://localhost:8080/scep" -c ca.crt -k local.key -r local.csr -l local.crt -v -d &>> client.log

    if [ -f ca-dir/1.2.3.4*.pem ];
    then
        echo "[ PASSED ] enroll"
    else
        echo "[ FAILED ] enroll"
        TEST_SSCEP_FAIL=1
    fi
else
    echo "[ FAILED ] enroll"
    TEST_SSCEP_FAIL=1
fi

killall scepserver &> /dev/null

cleanup

$GITHUB_WORKSPACE/.github/scripts/check-workflow-result.sh $TEST_SSCEP_FAIL "$WOLFPROV_FORCE_FAIL_STR" sscep
TEST_SSCEP_FAIL=$?

if [[ $TEST_SSCEP_FAIL -eq 1 ]]; then
    echo "TEST FAILURE: check server.log and client.log for more information"
fi

exit $TEST_SSCEP_FAIL

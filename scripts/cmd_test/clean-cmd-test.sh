#!/bin/bash
#
# Copyright (C) 2006-2025 wolfSSL Inc.
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
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.

# Function to clean up specific command test artifacts
clean_cmd_test() {
    local test_type=$1

    # Clean up specific log file
    rm -f "./scripts/cmd_test/${test_type}-test.log"

    # Clean up corresponding output directory
    rm -rf "./${test_type}_outputs"
}

# Function to clean up all command test artifacts
clean_all_cmd_tests() {
    rm -rf ./scripts/cmd_test/*.log
    rm -rf ./aes_outputs
    rm -rf ./ecc_outputs
    rm -rf ./hash_outputs
    rm -rf ./rsa_outputs
    rm -rf ./test.txt
}

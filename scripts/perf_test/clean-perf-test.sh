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

if [ -z "${DO_CMD_TESTS:-}" ]; then
    echo "This script is designed to be called from do-perf-tests.sh"
    echo "Do not run this script directly - use do-perf-tests.sh instead"
    exit 1
fi

clean_perf_test() {
    rm -f "./scripts/perf_test/perf-test.log"
    rm -rf "./perf_outputs"
}

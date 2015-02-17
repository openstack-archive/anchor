#!/bin/bash

# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

set -eu

function usage {
    echo "Usage: $0 [OPTION]..."
    echo "Run Keystone's test suite(s)"
    echo ""
    echo "  -V, --virtual-env        Always use virtualenv.  Install automatically if not present"
    echo "  -N, --no-virtual-env     Don't use virtualenv.  Run tests in local environment"
    echo "  -x, --stop               Stop running tests after the first error or failure."
    echo "  -f, --force              Force a clean re-build of the virtual environment. Useful when dependencies have been added."
    echo "  -u, --update             Update the virtual environment with any newer package versions"
    echo "  -p, --pep8               Just run flake8"
    echo "  -8, --8                  Just run flake8, don't show PEP8 text for each error"
    echo "  -P, --no-pep8            Don't run flake8"
    echo "  -c, --coverage           Generate coverage report"
    echo "  -h, --help               Print this usage message"
    echo ""
    echo "Note: with no options specified, the script will try to run the tests in a virtual environment,"
    echo "      If no virtualenv is found, the script will ask if you would like to create one.  If you "
    echo "      prefer to run tests NOT in a virtual environment, simply pass the -N option."
    exit
}

function process_option {
    case "$1" in
        -h|--help) usage;;
        -V|--virtual-env) always_venv=1; never_venv=0;;
        -N|--no-virtual-env) always_venv=0; never_venv=1;;
        -x|--stop) failfast=1;;
        -f|--force) force=1;;
        -u|--update) update=1;;
        -p|--pep8) just_flake8=1;;
        -8|--8) short_flake8=1;;
        -P|--no-pep8) no_flake8=1;;
        -c|--coverage) coverage=1;;
        -*) testropts="$testropts $1";;
        *) testrargs="$testrargs $1"
    esac
}

venv=.venv
with_venv=tools/with_venv.sh
always_venv=0
never_venv=0
force=0
failfast=0
testrargs=
testropts=--subunit
wrapper=""
just_flake8=0
short_flake8=0
no_flake8=0
coverage=0
update=0

for arg in "$@"; do
    process_option $arg
done

TESTRTESTS="python setup.py testr"

# If enabled, tell nose to collect coverage data
if [ $coverage -eq 1 ]; then
    TESTRTESTS="$TESTRTESTS --coverage"
fi

function run_tests {
    set -e
    echo ${wrapper}
    if [ $failfast -eq 1 ]; then
        testrargs="$testrargs -- --failfast"
    fi
    ${wrapper} $TESTRTESTS --testr-args="$testropts $testrargs" | \
        ${wrapper} subunit-2to1 | \
        ${wrapper} tools/colorizer.py
}

function run_flake8 {
    FLAGS=--show-pep8
    if [ $# -gt 0 ] && [ 'short' == ''$1 ]; then
        FLAGS=''
    fi

    echo "Running flake8 ..."
    # Just run flake8 in current environment
    echo ${wrapper} flake8 $FLAGS | tee pep8.txt
    ${wrapper} flake8 $FLAGS | tee pep8.txt
}

if [ $never_venv -eq 0 ]; then
    # Remove the virtual environment if --force used
    if [ $force -eq 1 ]; then
        echo "Cleaning virtualenv..."
        rm -rf ${venv}
    fi
    if [ $update -eq 1 ]; then
        echo "Updating virtualenv..."
        python tools/install_venv.py
    fi
    if [ -e ${venv} ]; then
        wrapper="${with_venv}"
    else
        if [ $always_venv -eq 1 ]; then
            # Automatically install the virtualenv
            python tools/install_venv.py
            wrapper="${with_venv}"
        else
            echo -e "No virtual environment found...create one? (Y/n) \c"
            read use_ve
            if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
                # Install the virtualenv and run the test suite in it
                python tools/install_venv.py
                wrapper=${with_venv}
            fi
        fi
    fi
fi

# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

if [ $just_flake8 -eq 1 ]; then
    run_flake8
    exit
fi

if [ $short_flake8 -eq 1 ]; then
    run_flake8 short
    exit
fi


run_tests

# NOTE(sirp): we only want to run flake8 when we're running the full-test
# suite, not when we're running tests individually. To handle this, we need to
# distinguish between options (testropts), which begin with a '-', and arguments
# (testrargs).
if [ -z "$testrargs" ]; then
    if [ $no_flake8 -eq 0 ]; then
        run_flake8
    fi
fi

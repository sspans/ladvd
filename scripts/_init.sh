#!/usr/bin/env bash

set -e

NAME="ladvd"
BASE=$(pwd)
RELEASE="${BASE}/release"

# prepare
git pull
git log --date=short --pretty=format:'%ad [%h] [%an]: %s' > ${BASE}/doc/ChangeLog

# create release dir
if [ -n "${CLEAN}" ]; then
    [ -d ${RELEASE} ] && rm -rf ${RELEASE}
    mkdir -p ${RELEASE}
fi


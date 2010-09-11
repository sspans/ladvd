#!/usr/bin/env bash

set -e

NAME="ladvd"
BASE=$(pwd)
RELEASE="${BASE}/release"

# prepare
hg pull -u
hg log --style=changelog > ${BASE}/doc/ChangeLog

# create release dir
[ -d ${RELEASE} ] && rm -rf ${RELEASE}
mkdir -p ${RELEASE}


#!/bin/bash

BASE=$(pwd)
RELEASE="${BASE}/release"

# prepare
svn -q up
svn log | ${BASE}/scripts/gnuify-changelog.pl > ${BASE}/doc/ChangeLog
autoreconf -fi

# create release dir
[ -d ${RELEASE} ] && rm -rf ${RELEASE}
mkdir -p ${RELEASE}/debian

# create dist tarball
./configure 
make distcheck
mv *tar.gz ${RELEASE}

# create debian sources
cd ${RELEASE}/debian
tar xf ../*tar.gz
cd ladvd-*
dpkg-buildpackage -S
cd ${RELEASE}/debian
rm -rf ladvd-*

# return to the root
cd ${BASE}

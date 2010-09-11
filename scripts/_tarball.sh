#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh

# create dist tarball
autoreconf -fi
./configure 
make distcheck
mv *tar.gz ${RELEASE}

# create signature
gpg -ba ${RELEASE}/*tar.gz


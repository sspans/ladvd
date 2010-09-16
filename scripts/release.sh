#!/usr/bin/env bash

CLEAN=1

. scripts/_init.sh
. scripts/_tarball.sh
. scripts/_debian.sh
. scripts/_obs.sh

tgz=$(basename ${RELEASE}/*tar.gz)
ver=$(echo ${tgz%.tar.gz}| sed s/${NAME}-//)

echo for Googlecode uploads run:
echo googlecode_upload -p ${NAME} -s \"The ${ver} Release\" ${RELEASE}/${tgz}
echo for OpenSuSE BuildService uploads run:
echo "cd ${RELEASE}/osc/${NAME}-unstable && osc commit"
echo "cd ${RELEASE}/osc/${NAME} && osc commit"


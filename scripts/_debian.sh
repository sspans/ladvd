#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh

[ -d ${RELEASE}/debian ] || mkdir -p ${RELEASE}/debian
cd ${RELEASE}/debian

# create debian sources
tgz=$(basename ../*tar.gz)
cp ../${tgz} $(echo ${tgz%.tar.gz}| tr - _).orig.tar.gz
tar xf *tar.gz
cd ${NAME}-*
rsync -av ${BASE}/debian .
dpkg-buildpackage -S -sa
cd ${RELEASE}/debian
rm -rf ${NAME}-*

cd ${BASE}

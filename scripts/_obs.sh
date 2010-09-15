#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh

# create osc repository
mkdir ${RELEASE}/osc.$$
cd ${RELEASE}/osc.$$
osc checkout home:sten-blinkenlights
mv home\:sten-blinkenlights ${RELEASE}/osc
rm -rf ${RELEASE}/osc.$$
cp ${RELEASE}/*.tar.gz ${RELEASE}/osc/${NAME}-unstable
cp ${BASE}/rpm/* ${RELEASE}/osc/${NAME}-unstable
[ -d ${RELEASE}/debian ] && \
    cp ${RELEASE}/debian/* ${RELEASE}/osc/${NAME}-unstable

cd ${BASE}


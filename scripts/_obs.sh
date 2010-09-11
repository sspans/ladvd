#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh

# create osc repository
mkdir ${RELEASE}/osc.$$
cd ${RELEASE}/osc.$$
osc checkout home:sten-blinkenlights ${NAME}
mv home\:sten-blinkenlights/${NAME} ${RELEASE}/osc
rm -rf ${RELEASE}/osc.$$
cp ${RELEASE}/*.tar.gz ${RELEASE}/osc
cp ${BASE}/rpm/* ${RELEASE}/osc
[ -d ${RELEASE}/debian ] && cp ${RELEASE}/debian/* ${RELEASE}/osc

cd ${BASE}


#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh
[ -f ${RELEASE}/*tar.gz ] || . scripts/_tarball.sh

# create osc repository
mkdir ${RELEASE}/osc.$$
cd ${RELEASE}/osc.$$
osc checkout home:sten-blinkenlights
mv home\:sten-blinkenlights ${RELEASE}/osc
rm -rf ${RELEASE}/osc.$$

cp ${RELEASE}/*.tar.gz ${RELEASE}/osc/${NAME}-unstable
cp ${BASE}/rpm/* ${RELEASE}/osc/${NAME}-unstable

[ -d ${RELEASE}/debian_osc ] || return
for flavour in "" "-unstable" "-static"; do
    cp ${RELEASE}/debian_osc/${NAME}${flavour}_*dsc \
	${RELEASE}/osc/${NAME}${flavour}/${NAME}.dsc
    cp ${RELEASE}/debian_osc/${NAME}${flavour}_*debian.tar.gz \
	${RELEASE}/osc/${NAME}${flavour}/debian.tar.gz
done

cd ${BASE}


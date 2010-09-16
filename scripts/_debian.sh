#!/usr/bin/env bash

[ -n "${BASE}" ] || . scripts/_init.sh
[ -f ${RELEASE}/*tar.gz ] || . scripts/_tarball.sh

[ -d ${RELEASE}/debian ] || mkdir -p ${RELEASE}/debian
[ -d ${RELEASE}/debian_osc ] || mkdir -p ${RELEASE}/debian_osc

tgz=$(basename ${RELEASE}/*tar.gz)
ver=$(echo ${tgz%.tar.gz}| sed s/${NAME}-//)

# create regular debian sources
cd ${RELEASE}/debian
cp ${RELEASE}/${tgz} ${NAME}_${ver}.orig.tar.gz
tar xf ${NAME}_${ver}.orig.tar.gz
cd ${NAME}-${ver}
rsync -av ${BASE}/debian .
dpkg-buildpackage -S -sa
cd ${RELEASE}/debian
rm -rf ${NAME}-${ver}*


# and now osc hackjobs
cd ${RELEASE}/debian_osc
cp ${RELEASE}/${tgz} ${NAME}_${ver}.orig.tar.gz
cp ${RELEASE}/${tgz} ${NAME}-unstable_${ver}.orig.tar.gz
cp ${RELEASE}/${tgz} ${NAME}-static_${ver}.orig.tar.gz
tar xf ${NAME}_${ver}.orig.tar.gz
cd ${NAME}-${ver}
rsync -av ${BASE}/debian .
dpkg-buildpackage -S -sa -us -uc

# create unstable sources
sed -ie "s/^${NAME}/${NAME}-unstable/" debian/changelog
sed -ie "s/${NAME}\$/${NAME}-unstable/" debian/control
dpkg-buildpackage -S -sa -us -uc

# create static sources
sed -ie "s/^${NAME}-unstable/${NAME}-static/" debian/changelog
sed -ie "s/${NAME}-unstable\$/${NAME}-static/" debian/control
sed -ie "s/CFLAGS/--enable-static-libevent CFLAGS/" debian/rules
dpkg-buildpackage -S -sa -us -uc

cd ${RELEASE}/debian_osc
rm -rf ${NAME}-${ver}*

for dsc in *dsc; do
    flavour=${dsc/_*}
    sed -i 's/^Format:.*/Format: 1.0/' ${dsc}
    sed -i '/^Build-Depends/q' ${dsc}
    echo Debtransform-Files-Tar: debian.tar.gz >> ${dsc}
    echo Debtransform-Tar: ${tgz} >> ${dsc}
    rm ${flavour}_${ver}.orig.tar.gz 
done

cd ${BASE}

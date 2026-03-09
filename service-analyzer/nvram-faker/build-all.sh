#!/bin/bash

cd $(dirname $0)

BUILDROOT_VERSION=2024.02.4
BUILDROOT_TARBALL=buildroot-${BUILDROOT_VERSION}.tar.gz
BUILDROOT_URL=https://buildroot.org/downloads/${BUILDROOT_TARBALL}

PACKAGES=(nvram-fuzz)
# ARCHES=(arm mips mipsel arm64 mips64 mips64el)
# ARCHES=(arm mips mipsel)
ARCHES=(mips)
CLIBS=(glibc musl uclibc)

echo "PACKAGES: ${PACKAGES[@]}"
echo "ARCHES: ${ARCHES[@]}"
echo "CLIBS: ${CLIBS[@]}"

build_one () {
    arch=$1
    clib=$2

    br_dir=buildroots/br-${arch}-${clib}
    if [ ! -d $br_dir ]; then
        if [ ! -f ${BUILDROOT_TARBALL} ]; then
            wget ${BUILDROOT_URL}
        fi
        mkdir -p buildroots
        tar -xf ${BUILDROOT_TARBALL}
        mv buildroot-${BUILDROOT_VERSION} $br_dir
    fi

    cp confs/${arch}-${clib}.config $br_dir/.config

    out_dir=buildroots/output/${arch}/${clib}
    mkdir -p $out_dir

    for p in ${PACKAGES[@]}
    do
        if [ -d package/$p ]; then
            rm -rf $br_dir/package/$p
            cp -r package/$p $br_dir/package/

            make -C $br_dir $p-dirclean
            make -C $br_dir $p
            cp "${br_dir}/output/target/usr/lib/lib${p}.so" "${out_dir}/lib${p}.so"
        fi
    done
}

# Prepare source code

for arch in ${ARCHES[@]}; do
    for clib in ${CLIBS[@]}; do
        echo "Building for ${arch}-${clib}"
        build_one $arch $clib
    done
done

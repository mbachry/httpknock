#!/usr/bin/bash -ue

rm -rf build dist

for arch in x86-64 aarch64; do
    rm -f result
    nix-build -A knock_$arch
    tardir=dist/$arch/httpknock
    mkdir -p $tardir
    cp result/{httpknock-server,httpknock-addcred,httpknock} $tardir/
    ( cd dist/$arch && tar zcf ../httpknock-$arch.tar.gz httpknock )
    rm -rf dist/$arch
done

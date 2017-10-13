#!/bin/sh -e

exec 1>&2

ln -fs /data /kcdata

ls -lR /data

yum install -y rpm-build

LIBCARE_DIR="/data"
KPATCH_PATH="/data/src"
export LIBCARE_DIR KPATCH_PATH
make -C $KPATCH_PATH clean all
make -C /data/execve clean all

/kcdata/scripts/pkgbuild $@ /kcdata/package
ls /kcdata -lR

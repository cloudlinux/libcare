Use toil-based build script to build patches for the `glibc`. For that simple
run::

```shell
$ LIBCARE_DIR=~/libcare-opensource
$ pip install -r $LIBCARE_DIR/scripts/toil/requirements.txt
$ python $LIBCARE_DIR/scripts/toil/pkgbuild.py workdir pkgfile.yaml
...
```

This should build the following files:
```shell
$ ls /tmp/build.orig-glibc-2.17-55.el7.x86_64.rpm.tgz /tmp/kpatch-glibc-2.17-55.el7.x86_64.tgz
/tmp/build.orig-glibc-2.17-55.el7.x86_64.rpm.tgz
/tmp/kpatch-glibc-2.17-55.el7.x86_64.tgz
```

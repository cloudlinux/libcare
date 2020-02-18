RHEL7 ``glibc`` sample
----------------------

Most of the binaries in the system are coming from distribution packages so
building patches for them is different from the above. Here is how to do it.

This example builds ``glibc`` patch for an old fashioned CVE-2015-0235 GHOST_
vulnerability for RHEL7. The build is done using `scripts/pkgbuild`_ and
package files are stored in ``packages/rhel7/glibc/glibc-2.17-55.el7``.

Preparing environment
~~~~~~~~~~~~~~~~~~~~~

First, we need the exact versions of tools and libs. Let's build a
Docker_ image and a container for it:

.. code:: console

        $ docker build -t kernelcare/centos7:gcc-4.8.2-16.el7 \
                docker/kernelcare/centos7/gcc-4.8.2-16.el7
        ...
        $ docker run -v $PWD:/libcare --cap-add SYS_PTRACE -it \
                kernelcare/centos7:gcc-4.8.2-16.el7 /bin/bash
        [root@... /]#

Now, from inside the container let's install vulnerable version of glibc:

.. code:: console

        [root@... /]# yum downgrade -y --enablerepo=C7.0.1406-base \
                glibc-2.17-55.el7 glibc-devel-2.17-55.el7 \
                glibc-headers-2.17-55.el7 glibc-common-2.17-55.el7
        ...

Also we have to downgrade elfutils since newer versions of ``eu-unstrip``
fail to work with glibc utilities:

.. code:: console

        [root@... /]# yum downgrade -y --enablerepo=C7.0.1406-base \
                elfutils-devel-0.158-3.el7.x86_64 elfutils-0.158-3.el7.x86_64 \
                elfutils-libs-0.158-3.el7.x86_64 elfutils-libelf-0.158-3.el7.x86_64 \
                elfutils-libelf-devel-0.158-3.el7.x86_64
        ...

Build the ``libcare`` tools:

.. code:: console

        [root@... /]# make -C /libcare/src clean all && make -C /libcare/tests/execve
        ...

Now build and run the sample GHOST app that runs 16 threads to constantly check
whether the ``glibc`` is vulnerable to GHOST_ and prints a dot every time it
detects a buffer overflow in the ``gethostbyname_r`` function.
The downgraded ``glibc`` is vulnerable:

.. code:: console

        [root@... /]# cd /libcare/samples/ghost
        [root@... ghost]# make
        ...
        [root@... ghost]# ./GHOST
        ............^C

Press Ctrl+C to get your console back and let's start building the patch for
``glibc``.

Building and applying the patch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The build is done in two stages.

First, the original package build is repeated with all the `intermediate
assembly files`_ stored and saved for later. This greatly helps to speed up
builds against the same base code. Run the following from inside our docker
container to pre-build ``glibc`` package:

.. code:: console

        [root@... /]# cd /libcare/
        [root@... /libcare]# ./scripts/pkgbuild -p packages/rhel7/glibc/glibc-2.17-55.el7
        ...

This should download the package, do a regular RPM build with ``kpatch_cc``
wrapper substituted for GCC and store the pre-built data into the archive under
``/kcdata`` directory:

.. code:: console

        [root@... /libcare]# ls /kcdata
        build.orig-glibc-2.17-55.el7.x86_64.rpm.tgz  glibc-2.17-55.el7.src.rpm

Now let's build the patch, the output will be verbose since it contains tests run
by the ``kp_patch_test`` defined in ``packages/rhel7/glibc/glibc-2.17-55.el7/info``:

.. code:: console

        [root@... /libcare]# ./scripts/pkgbuild packages/rhel7/glibc/glibc-2.17-55.el7
        ...
        [root@... /libcare]# ls /kcdata/kpatch*
        /kcdata/kpatch-glibc-2.17-55.el7.x86_64.tgz

Unwrap patches and run the GHOST_ sample:

.. code:: console

        [root@... /libcare]# cd /kcdata
        [root@... /kcdata]# tar xf kpatch*
        [root@... /kcdata]# /libcare/samples/ghost/GHOST 2>/dev/null &
        [root@... /kcdata]# patient_pid=$!

And, finally, patch it. All the threads of the sample must stop when the GHOST
vulnerability is patched:

.. code:: console

        [root@... /kcdata]# /libcare/src/libcare-ctl -v patch -p $patient_pid \
                        root/kpatch-glibc-2.17-55.el7.x86_64
        ...
        1 patch hunk(s) have been successfully applied to PID '...'
        (Press Enter again)
        [1]+  Done                    /libcare/samples/ghost/GHOST 2> /dev/null

You can patch any running application this way:

.. code:: console

        [root@... /kcdata]# sleep 100 &
        [root@... /kcdata]# patient_pid=$!
        [root@... /kcdata]# /libcare/src/libcare-ctl -v patch -p $patient_pid \
                        root/kpatch-glibc-2.17-55.el7.x86_64
        ...
        1 patch hunk(s) have been successfully applied to PID '...'

Congratulations on finishing this rather confusing sample!

.. _GHOST: https://access.redhat.com/articles/1332213
.. _docker: https://www.docker.com/

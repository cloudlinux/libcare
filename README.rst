LibCare -- Patch Userspace Code on Live Processes
=================================================

.. image:: https://travis-ci.org/cloudlinux/libcare.svg?branch=master
    :target: https://travis-ci.org/cloudlinux/libcare

Welcome to LibCare --- Live Patch Updates for Userspace Processes and Libraries.

LibCare delivers live patches to any of your Linux executables or libraries at
the runtime, without the need for restart of your applications.  Most
frequently it is used to perform critical security updates such as glibc's
GHOST_ (aka CVE-2015-0235, see how we deal with it in `GHOST sample`_) and
QEMU's `CVE-2017-2615`_, but can also be used for serious bug fixes on the fly
to avoid interruption of service (see `server sample`_).

See https://kernelcare.com for live Linux Kernel updates also.

.. _GHOST: https://access.redhat.com/articles/1332213
.. _`GHOST sample`: samples/ghost/README.rst
.. _`CVE-2017-2615`: https://www.rapid7.com/db/vulnerabilities/centos_linux-cve-2017-2615
.. _`server sample`: samples/server/README.rst

FAQ
~~~

How the live patches are generated?
-----------------------------------

We use the same code generating procedure we used in production for years in
kernelcare.com:

#. both original and patched source code are translated to assembler,
#. corresponding assembler files are compared and new instrumented assembler
   code is generated, where patches are stored into special ELF sections,
#. instrumented assembler code is compiled using target project's build system
   while patch ELF sections are collected in binaries',
#. binary patch files are extracted from the ELF sections.

The `libcare-patch-make`_ script is a handy script for the patch generation for a
makeable project. Just do:

.. code:: shell

        $ src/libcare-patch-make some_serious_bug.patch

And find binary patches for all the deliverables of the project in the
``patchroot`` directory. See our `simple server <samples/server/README.rst>`__
for usage sample.

For more details follow to the `patch preparation
<docs/internals.rst#patch-preparation>`__ chapter of the `internals
<docs/internals.rst>`__.

.. _`libcare-patch-make`: docs/libcare-patch-make.rst

How the live patches are applied?
---------------------------------

It is a lot like loading a shared library into another process' memory:

#. our binary `libcare-ctl`_ (the doctor) attaches to a patient via
   `ptrace(2)`_,
#. patient's objects are examined by the doctor,
#. doctor puppets the patient to allocate patch memory near the original
   object,
#. references in the patch are resolved by the doctor, the patch
   code is ready to be executed now,
#. doctor rewrites targeted original functions with unconditional jumps to the
   appropriate patched versions, ensuring that no thread of patient is
   executing them first.

.. _`ptrace(2)`: http://man7.org/linux/man-pages/man2/ptrace.2.html
.. _libcare-ctl: docs/libcare-ctl.rst

Now the patient executes patched versions of the functions.

For more details follow to the `Patching <docs/internals.rst#Patching>`__
chapter of the `internals <docs/internals.rst>`__.

Will my patches re-apply if I restart the process?
--------------------------------------------------

Not at the moment. We only track start of the new processes for the tests, see
`here <tests/execve/README.rst>`__.

Does live patching affect performance?
--------------------------------------

Negligibly. Since code patches simply redirect execution from original code
functions to the new ones the overhead is small and comparable to
additional “jmp” instruction.

Installation and dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _`installation`:
.. _`installation guide`:

All the Linux-distros with available ``libunwind``, ``elfutils`` and ``binutils``
packages are supported.

However, the ``libcare`` is only tested on Ubuntu from 12.04 to 16.04 and on
CentOS from 6.8 to 7.x.

Dependencies
------------

To install the dependencies on RHEL/CentOS do the following:

.. code:: console

        $ sudo yum install -y binutils elfutils elfutils-libelf-devel libunwind-devel

To install the dependencies on Debian/Ubuntu do the following:

.. code:: console

        $ sudo apt-get install -y binutils elfutils libelf-dev libunwind-dev

Building ``libcare``
--------------------

To build ``libcare`` emit at project's root dir:

.. code:: console

        $ make -C src
        ...

This should build all the utilities required to produce a patch out of some
project's source code.

It is highly recommended to run the tests as well, enabling Doctor
``libcare-ctl`` to attach ``ptrace``\ cles to any of the processes first:

.. code:: console

        $ sudo setcap cap_sys_ptrace+ep ./src/libcare-ctl
        $ make -C tests && echo OK
        ...
        OK

Now all the required tools are built and we can build some patches. Skip to
`server sample`_ for that.

How does it work?
-----------------

Internals are quite confusing and are described `here <docs/internals.rst>`__.

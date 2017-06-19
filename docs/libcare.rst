LibCare
=======

Welcome to the LibCare project documentation. Our aim is to be able to patch
any of your executables or libraries at the run, so you don't have to restart
your servers whenever a new wild CVE appears.

Overview
========

First, we `prepare project patch`_ by
`examining the differences in assembler files`_ generated during the original
and the patched source code build. Finally, users invoke the ``libcare-doctor`` that
`applies the patches`_. This is a lot like loading a shared object (library)
into other process memory and then changing original code to unconditionally
jump to the new version of the code.

.. _`prepare project patch`: `Patch preparation`_
.. _`applies the patches`: libcare-doctor.rst
.. _`examining the differences in assembler files`: `Manual Patch Creation`_
.. _`Manual Patch Creation`: internals.rst#manual-patch-creation

#. `Patch preparation`_

#. `Project patch building`_

#. `Patch application`_

.. _`Patch application`: libcare-doctor.rst

Patch preparation
-----------------

Binary patches are built from augmented assembly files. Augmented files are
made via ``kpatch_gensrc`` which notes the difference in assembly files
produced from the original and the patched source code.

This is done in two steps, both are described detailed in `Manual Patch
Creation`_.

Building originals
~~~~~~~~~~~~~~~~~~

.. _libcare-cc:

First, the original code is built as is either by invoking ``make`` directly or
by the packaging system. The build is done with compiler substituted to
``libcare-cc`` wrapper. Wrapper's behaviour is configured via environment
variables.

.. _`intermediate assembly files`:

When ``libcare-cc`` is invoked with ``KPATCH_STAGE=original`` it simply builds
the project while keeping intermediate assembly files under the name
``.kpatch_${filename}.original.s`` invoking the real compiler twice: first with the
``-S`` flag to produce the assembly files from the original code and then with
the ``-c`` flag to produce object files out of these intermediate assembly
files.

Project binaries built during the ``original`` stage are stashed and later used in
the patch preparation. When building patches for a package from distribution the
objects built during ``original`` stage must be compatible with those from the
distro's binary package.

Assembly files resulting from the correct ``original`` build can be stored to speed
up patch builds later on.

Building patches
~~~~~~~~~~~~~~~~

Next, source code patches are applied and the build is redone.
This time the ``libcare-cc`` wrapper is instructed by environment variable
``KPATCH_STAGE=patched`` to build a special patch-containing object.

Wrapper first calls real compiler with ``-S`` flag to produce an assembly file
for the patched version, which is stored under file name
``.kpatch_${filename}.patched.s``. It then calls ``kpatch_gensrc`` that
compares original and patched files and produces a patch-containing assembly
where all the changes in the code are put in the ``.kpatch``-prefixed sections
while original code is left as is.  This assembly is finally compiled to a
patch-containing object file by calling compiler with the ``-c`` flag.

Linking done by the project build system carries these sections to the target
binary and shared object files. During the link stage ``libcare-cc`` adds ``ld``
argument ``-q`` that instructs linker to keep information about all the
relocations. This is required for the `Patch application`_ to (dynamically)
link patch into running binary.

Then the sanity check is done, checking that the symbols originating from the
non-\ ``kpatch`` sections in the patched binary are equal to those from the
original binary or its debuginfo.

The last part is postprocessing the patch-containing binaries: stripping off
the original binary sections, fixing relocations and prepending the resulting
ELF content with a common kpatch header. Look at `Manual Patch Creation`_ for
details.

Project patch building
----------------------

The above algorithm is implemented in two various helper scripts. The first is
`libcare-patch-make`_ that can build patches for any project buildable via
``make`` and the second aims at building patches for applications and libraries
coming from distribution packages ``scripts/pkgbuild``.

.. _libcare-patch-make: libcare-patch-make.rst

Both are using libcare-cc_ wrapper described below. It is recommended to go
through `Manual Patch Creation`_ at least once.

Building patch for a package via ``scripts/pkgbuild``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _`scripts/pkgbuild`:

The ``scripts/pkgbuild`` is responsible for the building of the patch
and pre-building the original package and assembly files. At the moment
it only supports the building of the RPM-based packages.

Each package has its own directory ``packages/$distro/$package`` with
different package versions as subdirectories. For instance, the directory
``packages/rhel7/glibc/`` contains subdirectory ``glibc-2.17-55.el7`` that has the
configuration and scripts for building and testing of the sample security
patches for that version of ``glibc`` package for RHEL7.

The project directory contains three main files:

#. Shell-sourceable ``info`` that has the necessary environment variables
   specified along with the hooks that can alter package just before
   the build and test patch before it is packed. For instance,
   ``packages/rhel7/glibc/glibc-2.17-55.el7/info`` contains both hooks and a
   ``kp_patch_test`` function that runs glibc test suite with each invocation
   being patched with the built patch.

#. The list ``plist`` of the patches to be applied. File names are
   relative to the top-level directory ``patches``.

#. YAML file ``properties.yaml`` containing version-specific
   configuration, such as URLs for pre-build storage, original source
   packages URL, and Docker container images with toolchain
   (GCC/binutils) version is required to properly build the package.

   This is not used at the moment and left as an information source for the users.

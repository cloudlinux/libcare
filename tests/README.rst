Test infrastructure ``./tests``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _tests:

This directory contains the tests and the infrastructure to run them. To keep
the ``tests`` directory clean, each test is placed in its own directory.

Each directory containing a file `desc` is considered to be a directory test
and is build by the makesystem and run by the `run_tests.sh` script.

To run the tests emit:

::

    $ make

this will build and run all the tests discovered for all types of build
and all flavors of the ``libcare-ctl`` usage.

There are two types of test builds.

The first one is the regular build done
by manually emitting assembler files for both original and patched
source files, and then applying ``kpatch_gensrc`` to them and compiling
the result into a kpatch-containing object where from it was extracted from by the
utils, as described in `Manual Patch Creation`_ section.

The second one is the build done by the ``libcare-patch-make`` tool which uses ``libcare-cc``
compiler wrapper, as described in `libcare-patch-make`_ section. The build results for
each build type are placed in their own subfolder ina test directory.

A test can be built with the particular build type using either ``make
build-$test`` or ``make libcare-patch-make-$test`` commands.

Sometimes it is necessary to debug a particular test so all changes MUST
retain the ability to run the tests manually. The manual run is done by
executing an appropriate binary (with the ``LD_LIBRARY_PATH`` set as
needed) and target ``libcare-ctl patch`` at its process.

However, it is recommended to run tests by the ``./run_tests.sh`` script,
available in the ``tests`` directory.

The ``run_tests.sh`` script accepts the following options:

-f FLAVOR
  execute ``FLAVOR`` of tests from those listed in `test flavors`_.


-d DESTDIR
  assume that test binaries are located in ``DESTDIR`` subdirectory of a
  test. The ``build`` subdirectory is a default one. Use ``libcare-patch-make`` to run
  the tests build with the libcare-patch-make with binaries stored in the subdirectory
  with the same name.

-v
  be verbose

The only argument it accepts is a string with space separated names of
tests to execute. The default is to execute all the tests discovered.

Test flavors
^^^^^^^^^^^^

There are the following test flavors. Most of the tests are executed in all
flavors, it depends on what ``should_skip`` function of ``run_tests.sh``
returns. Some of the tests have different success criteria between different
flavors: e.g.  ``fail_*`` tests check that binary is succesfully patched upon
execution with ``test_patch_startup`` flavor.

The flavors are:

``test_patch_files``
     (default) that simply executes a test process and points ``kpatch_ctl
     patch`` to it, doing so for present patches for both binary and
     shared libraries.
  
``test_patch_dir``
     that executes a test and patches it with a per-test patch-containing
     directory fed to ``kpatch_ctl patch``.
  
``test_patch_startup``
     that starts a ``kcare_genl_sink`` helper that listens to notifications
     about a start of a listed binary and executes ``kpatch_ctl patch``
     with the directory containing patches for all the tests discovered.

``test_patch_patchlevel``
     that checks that patchlevel_ code works as expected. This applies two
     patches with different patch levels to the ``patchlevel`` test and checks
     that the patching is done to the latest one.

Adding or fixing a test
^^^^^^^^^^^^^^^^^^^^^^^

Each test has its own directory that MUST have the file named ``desc``
which contains a one-line description of the test. The ``desc`` files are
used to discover the tests.

The makefile inside the test directory MUST compile the code into a
binary. The binary name MUST coincide with the directory and test name, the
library name (if present) must be equal to ``lib$test.so``. The source
code is typically called ``$test.c`` for the binary and ``lib$test.c``
for the library. Patch files are ``$test.diff`` and ``lib$test.diff``.

When the above rules are followed the test can simply include
``../makefile.inc`` file that will provide build system for all of the
build types described above.

The ``tests/makefile.inc`` file itself includes either
``makefile-libcare-patch-make.inc`` file when the ``CC`` variable equals
``libcare-cc`` or ``makefile-patch.inc`` otherwise. The former provides a set
of rules that meet ``libcare-patch-make``\ s criteria described in
`libcare-patch-make`_.  The later provides a set of rules described in `Manual
Patch Creation`_, except for the libraries output that is broken with them and
requires including of a makefile ``makefile-patch-link.inc`` that links the
shared library to extract proper names of the sections for the kpatch.  For the
usage example take a look at the test ``both`` that tests patching of both
binary and a library it loads.

``fastsleep.so``
^^^^^^^^^^^^^^^^

To speed up test execution while allowing them to be run manually we had to
adjust tests with a ``LD_PRELOAD``\ ed library that redefines ``sleep`` and
``nanosleep`` to change their arguments so the code sleeps faster. The code is
in the file ``fastsleep.c``.

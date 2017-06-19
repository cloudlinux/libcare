Using ``libcare-patch-make``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``libcare-patch-make`` script can be used to build patches for a project built locally
via ``./configure && make && make install``.

The usage is simple, just call ``libcare-patch-make`` with a list of source patches as
arguments and ``libcare-patch-make`` will build the binary patches and store them to
``patchroot`` directory.

``libcare-patch-make`` requires the following simple criteria to be met on the build system:

1. The default target SHOULD be the one that builds all the files in
   the project. This is by default the ``all`` target in most of the projects.

2. The ``install`` target MUST install the project deliverables
   into the directory specified as ``DESTDIR`` environment variable.
   This is default for most projects. Other projects are either
   patched by distributions to include that target or have it under a
   different environment variable.

3. The ``clean`` target SHOULD be the one that cleans the project.

The typical usage is the following for the ``configur``\ able project:

.. code:: console

 $ cd project_dir
 $ KPATCH_STAGE=configure CC=libcare-cc ./configure
 $ libcare-patch-make first.patch second.patch
 BUILDING ORIGINAL CODE
 ...
 INSTALLING ORIGINAL OBJECTS INTO libcare-patch-make
 ...
 applying patch ~/first.patch
 ...
 applying patch ~/second.patch
 ...
 BUILDING PATCHED CODE
 ...
 INSTALLING PATCHED CODE
 ...
 MAKING PATCHES
 patch for foobar is in patchroot/${buildid}.patch
 ...

Available options are:

--help, -h              display a short help,

--update                just update the ``kpatches``. Useful when working on the kpatch tools,

--clean                 invoke ``make clean`` before building,

--srcdir DIR            change to the ``DIR`` before applying patches.

Note that ``libcare-patch-make`` uses ``libcare-cc`` under the hood. Read about it
`libcare-cc`_.

.. _libcare-cc: libcare.rst#building-originals

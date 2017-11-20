The Doctor: ``libcare-ctl``
------------------------------

Detailed description is in the `internals <internals.rst#patching>`__.

All the job is done by the ``libcare-ctl``. It is called ``doctor`` hereafter
and the targets of operations are thus called ``patients``.

The doctor accepts a few arguments that are common for all types of operations:

-v      enable verbose output
-h      show commands list

Applying patches via ``patch``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


The ``patch`` mode patches a process with ID given as an argument to ``-p`` option
or all of them except self and ``init`` when the argument is ``all``. The patch
(or directory with patches) to be applied should be specified as the only
positional argument:

.. code:: console

 $ libcare-ctl patch -p <PID_or_all> some_patch_file.kpatch

The patches are basically ELF files of relocatable type ``REL`` with binary
meta-information such as BuildID and name of the patch target prepended.
Loading patches is thus a lot like loading a shared object (library)
into a process. Except we are puppeting it by strings going through a
keyhole in other process' memory.

First, the memory near the original object is allocated, then all the
relocations and symbols are resolved in a local copy of patch content. This
pre-baked patch is copied to the patient's memory and, finally, original
functions are overwritten with the unconditional jumps to the patched version.

For more details look at the `Patching`_.

.. _Patching: internals.rst#Patching

Cancelling patches via ``unpatch``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``unpatch`` mode makes doctor remove patches listed by target BuildID from
the patients' memory. It simply restores the original code of the patched
functions from a stash allocated along with the patch and puppets patients to
``munmap`` the memory areas used by patches.

Showing info via ``info``
~~~~~~~~~~~~~~~~~~~~~~~~~

The last entry to the ``libcare-ctl`` is the ``info`` command that lists all
the objects and their BuildIDs for the set of the processes requested. Its
primary use is as the utility for the book-keeping software.

Patchlevel support
~~~~~~~~~~~~~~~~~~

.. _patchlevel:

Since patches to the objects such as libraries can be updated, there is a way to
distinguish them, called ``patchlevel``. This information is parsed
from the layout of the directory where the patches are stored. If on
patching stage a patch with a bigger ``patchlevel`` is found, the old one is
removed and the new one is applied.

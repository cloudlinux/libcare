``execve(2)`` wrapper
---------------------

The code in ``execve.c`` file is the wrapper for the family of
`execve(2) <http://man7.org/linux/man-pages/man2/execve.2.html>`__
library calls. It is compiled into a shared object ``execve.so`` and
is ``LD_PRELOAD``\ ed, so the dynamic linker takes implementation of
the ``execve(2)``-like library calls from this object.

The wrapper first checks if the target executable path matches a
`fnmatch(3) <https://linux.die.net/man/3/fnmatch>`__ pattern specified by the environment
variable ``KP_EXECVE_PATTERN``. If it is, the wrapper sends current process pid to a 
TCP socket at address 127.0.0.1 and port 4233, waits for response and calls for
interrupt #3, which is a software breakpoint at the x86-64 arch.

Then the appropriate library call is done and, if successful, code of the new
binary takes control over the process.


.. _`libcare-ctl`: ../../docs/libcare-ctl.rst


``libcare-ctl`` part
-----------------------

``libcare-ctl`` is instructed with the ``-r`` option that it should expect
the process that is currently executing the ``execve`` wrapper code.

The doctor attaches to the patient as usual.
It then sends 4-byte to the file descriptor specified as an argument to the
``-r`` option. The patient receives that and continues the wrapper code up to
the software breakpoint ``int $3``. When the patient hits breakpoint the doctor
receives a ``SIGTRAP`` signal and checks if the code causing it was indeed a
``int $3`` (``0xcc``).

The corresponding code is in the file ``src/kpatch_process.c`` function
``kpatch_process_load_libraries``.

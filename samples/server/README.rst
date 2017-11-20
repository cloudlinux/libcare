Sample ``samples/server``
-------------------------

For instance, your backend developer made a typo during server development.
This typo introduced a stack overflow vulnerability exploitable from the client
side. Common automatic checks were disabled for the sake of performance and now
your server is vulnerable to anyone who can find the vulnerability.

The sample code is in ``samples/server/server.c`` where function
``handle_connection`` supplies wrong buffer size to the ``recv(2)`` at line 24:

.. code:: c

	void handle_connection(int sock)
	{
		char buf[16];

		(void) recv(sock, buf, 128, 0); // bug is here
                fprintf(stdout, "Got %s\n", buf);
		close(sock);
	}

1. Build the original server and run it:

   .. code:: console

        $ cd samples/server
	$ make install DESTDIR=vuln
	cc -o server server.c -fno-stack-protector -fomit-frame-pointer
	$ ./vuln/server

2. Now let's install dependencies and build utils. Refer to `installation`_ for
   more details on the installation procedure and supported OSes.

   For RHEL-based distros do:

   .. code:: console

        $ sudo yum install -y binutils elfutils elfutils-libelf-devel nc libunwind-devel
        ...
        $ make -C ../../src
        ...

   For Debian-based distros do:

   .. code:: console

        $ sudo apt-get install -y binutils elfutils libelf-dev netcat-openbsd libunwind-dev
        ...
        $ make -C ../../src
        ...

.. _installation: ../../README.rst#installation

3. Try to connect to the server using freshly installed `netcat`_:

   .. code:: console

        $ echo 'Hi!' | nc localhost 3345

   The server should print on its console:

   .. code:: console

        $ ./vuln/server
        Got Hi!

.. _`netcat`: https://www.freebsd.org/cgi/man.cgi?query=nc&sektion=1

4. Now exploit the server via the ``hack.sh`` script. The script analyzes binary
   and builds a string that causes server's buffer to overflow. The string
   rewrites return address stored on the stack with the address of
   ``you_hacked_me`` function, which prints "You hacked me!" as a server.

   Open another console and run ``./hack.sh`` there:

   .. code:: console

        $ ./hack.sh

   Server console should print:

   .. code:: console

        Got 0123456789ABCDEF01234567@
        You hacked me!

   This sample emulates a packaged binary network server vulnerable to
   `return-to-libc attack`_.

.. _`return-to-libc attack`: https://en.wikipedia.org/wiki/Return-to-libc_attack

5. Now build the patch for this code via `lcmake`_:

   .. code:: console

        $ ../../src/libcare-patch-make --clean server.patch
        ...
        patch for $HOME/libcare/samples/server/lcmake/server is in ...

   Please note that this overwrites ``./server`` binary file with a
   patch-containing file, storing the original vulnerable server into
   ``./lcmake/server``.

6. Examine ``patchroot`` directory and find patches there:

   .. code:: console

        $ ls patchroot
        2d0e03e41bd82ec8b840a973077932cb2856a5ec.kpatch

7. Apply patch to the running application via `libcare-ctl`_:

   .. code:: console

        $ ../../src/libcare-ctl -v patch -p $(pidof server) patchroot
        ...
        1 patch hunk(s) have been successfully applied to PID '31209'

8. And check the hack again, ``You hacked me!`` string should go away:

   .. code:: console

        (console2) $ ./hack.sh
        (console1) $ # with running ./vuln/server
        Got 0123456789ABCDEF@


Congratulations on going through this sample! Go on and learn how the magic of
`libcare-patch-make`_ script works, read how the patch is `built under the hood`_ and how
it is applied by the `libcare-ctl`_. Or even jump to our `hacking guide`_!

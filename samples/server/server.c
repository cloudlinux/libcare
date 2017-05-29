
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/ip.h>

void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void you_hacked_me()
{
	fprintf(stdout, "You hacked me!\n");
}

void handle_connection(int sock)
{
	char buf[16];

	(void) recv(sock, buf, 128, 0); /* bug is here */
	fprintf(stdout, "Got %s\n", buf);
	close(sock);
}

int main()
{
	static int sock;
	int rv, len;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		die("socket");

	rv = 1;
	rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));
	if (rv == -1)
		die("setsockopt");

	addr.sin_family = AF_INET;
	addr.sin_port = htons(3345);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	rv = bind(sock, (const struct sockaddr *)&addr, sizeof(addr));
	if (rv == -1)
		die("bind");

	rv = listen(sock, 10);
	if (rv == -1)
		die("listen");

	while (1) {
		len = sizeof(addr);
		rv = accept(sock, (struct sockaddr *)&addr, &len);
		if (rv == -1)
			die("accept");

		handle_connection(rv);
	}
}

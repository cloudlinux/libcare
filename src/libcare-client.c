#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define handle_error(errstr) do { perror(errstr); exit(EXIT_FAILURE); } while (0)

int main(int argc, char **argv)
{
	int sock, rv, buflen, i;
	struct sockaddr_un sockaddr;
	char *buffer = NULL, *p;

	if (argc < 3) {
		printf("%s: SOCKET ARG0 [ARG1] [ARG2]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		handle_error("socket(AF_UNIX)");

	sockaddr.sun_family = AF_UNIX;
	strncpy(sockaddr.sun_path, argv[1], sizeof(sockaddr.sun_path));

	rv = connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (rv == -1)
		handle_error("connect");

	buflen = 0;
	for (i = 2; i < argc; i++) {
		buflen += strlen(argv[i]) + 1;
	}
	buflen++;

	p = buffer = malloc(buflen);
	if (buffer == NULL)
		handle_error("malloc");
	for (i = 2; i < argc; i++) {
		p = stpcpy(p, argv[i]);
		p++;
	}
	*p++ = '\0';

	rv = send(sock, (void *)buffer, buflen, 0);
	if (rv == -1)
		handle_error("send");

	if (buflen < 4096) {
		free(buffer);
		buflen = 4096;
		buffer = malloc(buflen);
	}

	while (1) {
		rv = recv(sock, buffer, buflen, 0);
		if (rv == 0)
			break;
		if (rv < 0)
			handle_error("recv");
		write(1, buffer, rv);
	}

	close(sock);
	free(buffer);

	return 0;
}

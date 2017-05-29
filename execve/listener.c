/*
 * Counterpart for the execve(2) wrapper that accepts incoming connections
 * and executes patch as appropriate.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static const char *kpatch_tools = "../src";
static const char *patch_root = NULL;

int main()
{
	int sock;
	int rv, incoming;
	pid_t pid;
	struct sockaddr_in sockaddr;

	kpatch_tools = getenv("KPATCH_TOOLS") ?: kpatch_tools;
	patch_root = getenv("PATCH_ROOT");

	sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(4233);
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	rv = 1;
	rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));
	if (rv == -1) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	rv = bind(sock, &sockaddr, sizeof(sockaddr));
	if (rv == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	rv = listen(sock, 1024);
	if (rv == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	while (1) {
		char buf[1024];
		do {
			rv = accept(sock, NULL, NULL);
		} while (rv == -1 && errno == EINTR);

		if (rv == -1) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		incoming = rv;

		rv = recv(incoming, &pid, sizeof(pid), 0);
		if (rv == -1) {
			perror("recv");
			exit(EXIT_FAILURE);
		}

		sprintf(buf, "%s/kpatch_user patch-user -s -p %d -r %d %s",
			kpatch_tools, pid, incoming, patch_root);
		fprintf(stderr, "Executing %s\n", buf);
		rv = system(buf);
		/* Error occured, kill the patient violently */
		if (rv != 0) {
			kill(pid, SIGKILL);
		}

		close(incoming);
	}
}

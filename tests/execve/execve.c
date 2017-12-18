/*
 * execve(2) wrapper notifying us about the test application
 * about to be executed. Used instead of `binfmt` handler in
 * Docker tests.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <limits.h>
#include <unistd.h>
#include <dlfcn.h>

#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>

#include <fnmatch.h>

static const char *pattern;
static int exact_match;
static int debug;
static int verbose;
static int (*real_execve)(const char *filename,
			  char *const argv[],
			  char *const envp[]);
static int (*real_execvpe)(const char *filename,
			  char *const argv[],
			  char *const envp[]);

__attribute__((constructor))
void init_execve(void)
{
	real_execve = dlsym(RTLD_NEXT, "execve");
	real_execvpe = dlsym(RTLD_NEXT, "execvpe");

	pattern = getenv("KP_EXECVE_PATTERN");
	exact_match = getenv("KP_EXECVE_PATTERN_PATHNAME") != NULL;
	debug = getenv("KP_EXECVE_DEBUG") != NULL;
	verbose = getenv("KP_EXECVE_VERBOSE") != NULL;
}

#define dprintf(fmt...) do {			\
	if (debug) {				\
		int errsv = errno;		\
		fprintf(stderr, fmt);		\
		errno = errsv;			\
	}					\
} while (0)

static int
is_listed_binary(const char *filename)
{
	int rv;

	if (pattern == NULL)
		return 0;

	rv = fnmatch(pattern, filename,
		     (exact_match ? FNM_PATHNAME : 0) |
		     FNM_EXTMATCH);
	dprintf("Match pattern '%s' against '%s', result is %d\n",
		pattern, filename, rv);

	return rv == 0;
}

static void
notify_listener(void)
{
	int sock, rv;
	struct sockaddr_un sockaddr;
	const char *unix_path = "/var/run/libcare.sock";
	char buf[128], *p;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		dprintf("socket() error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	dprintf("socket()\n");

	p = getenv("LIBCARE_CTL_UNIX");
	if (p)
		unix_path = p;

	sockaddr.sun_family = AF_UNIX;
	strncpy(sockaddr.sun_path, unix_path, sizeof(sockaddr.sun_path));

	rv = connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (rv == -1) {
		fprintf(stderr, "libcare-execve: connect() error: %s(%d)\n", strerror(errno), errno);
		(void) close(sock);
		return;
	}
	dprintf("connect()\n");

	p = stpcpy(buf, "execve") + 1;
	sprintf(p, "%d", (int) syscall(SYS_gettid));
	p += strlen(p) + 1;
	*p = '\0';
	p++;

	do {
		rv = send(sock, buf, p - buf, 0);
	} while (rv == -1 && errno == EINTR);

	if (rv == -1) {
		fprintf(stderr, "send() error: %s(%d)\n", strerror(errno), errno);
		(void) close(sock);
		return;
	}
	dprintf("send()\n");

	do {
		rv = recv(sock, buf, sizeof(int), 0);
	} while (rv == -1 && errno == EINTR);

	if (rv == -1) {
		fprintf(stderr, "recv() error: %s(%d)\n", strerror(errno), errno);
	}
	dprintf("recv()\n");

	(void) close(sock);

	asm (".align 8;\n"
	     " int $3;\n"
	     ".align 8;\n");
}

#define PRELOAD_ENV_STR	"LD_PRELOAD="
#define PRELOAD_ENV_LEN	(sizeof(PRELOAD_ENV_STR) - 1)
#define EXECVE_SO_STR "/execve.so"
#define EXECVE_SO_LEN (sizeof(EXECVE_SO_STR) - 1)

static char**
filter_environ(char *const *envp)
{
	int i = 0, j = 0;
	char **newenvp = NULL;

	while (envp[i++] != NULL);

	newenvp = malloc(sizeof(char *) * i);
	if (newenvp == NULL) {
		dprintf("ERROR: no place for newenvp: %d\n", errno);
		return NULL;
	}

	for (i = 0, j = 0; envp[i] != NULL; i++) {
		if (!strncmp(envp[i], PRELOAD_ENV_STR, PRELOAD_ENV_LEN)) {
			char *val = envp[i] + PRELOAD_ENV_LEN;
			char *sep = strchr(val, ':');
			char *newval;
			char *has_this_lib = strstr(val, EXECVE_SO_STR);

			if (has_this_lib == NULL || sep == NULL) {
				newenvp[j++] = envp[i];
				continue;
			}

			newval = malloc(strlen(val));
			if (newval == NULL) {
				dprintf("ERROR: no place for newval: %d\n",
					errno);
				return NULL;
			}

			sep = has_this_lib;

			while (*sep != ':' && sep > val)
				sep--;

			strcpy(newval, PRELOAD_ENV_STR);
			strncat(newval, val, sep - val);
			strcat(newval, has_this_lib + EXECVE_SO_LEN + 1);
			printf("%s\n", newval);

			newenvp[j++] = newval;
		} else
			newenvp[j++] = envp[i];
	}
	newenvp[j] = NULL;

	return newenvp;
}

int execve(const char *filename,
	   char *const argv[],
	   char *const envp[])
{
	int to_be_patched = 0, rv, errnosv;
	dprintf("%s\n", __func__);

	if (*filename != '/' && strchr(filename, '/') != NULL) {
		char path[PATH_MAX];
		realpath(filename, path);
		dprintf("realpath('%s', '%s')\n", filename, path);
		to_be_patched = is_listed_binary(path);
	}
	else {
		to_be_patched = is_listed_binary(filename);
	}

	if (to_be_patched) {
		int i;

		envp = filter_environ(envp);
		if (envp == NULL)
			return -1;
		notify_listener();

		if (verbose) {
			fprintf(stderr, "KPEXECVE %d '%s'",
				getpid(), filename);
			for (i = 0; argv[i] != NULL; i++)
				fprintf(stderr, " '%s'", argv[i]);
			fprintf(stderr, "\n");
		}

	}

	dprintf("real_execve('%s', ...)\n", filename);
	rv = real_execve(filename, argv, envp);

	if (to_be_patched) {
		errnosv = errno;
		free((void *)envp);
		errno = errnosv;
	}

	return rv;
}

int execv(const char *filename,
	  char *const argv[])
{
	dprintf("%s\n", __func__);
	return execve(filename, argv, __environ);
}

int execvpe(const char *filename,
	    char *const argv[],
	    char *const envp[])
{
	dprintf("%s\n", __func__);
	if (strchr(filename, '/') != NULL) {
		return execve(filename, argv, envp);
	}
	dprintf("real_execvpe('%s', ...)\n", filename);
	return real_execvpe(filename, argv, envp);
}

int execvp(const char *filename,
	   char *const argv[])
{
	dprintf("%s\n", __func__);
	return execvpe(filename, argv, __environ);
}

int vexecle(const char *filename,
	    const char *arg,
	    va_list args,
	    int has_envp,
	    int search_path)
{
#define INITIAL_ARGV_SIZE	1024
	const char *initial_argv[INITIAL_ARGV_SIZE];
	const char **argv = initial_argv;
	char *const *envp = __environ;
	size_t i = 0;
	int ret;

	argv[0] = arg;

	while (argv[i++] != NULL) {
		if (i == INITIAL_ARGV_SIZE) {
			dprintf("Not implemented execl argc>=%d\n",
				INITIAL_ARGV_SIZE);
			errno = ENOSYS;
			return -1;
		}

		argv[i] = va_arg(args, const char *);
	}

	if (has_envp)
		envp = va_arg(args, char *const *);

	va_end(args);

	if (search_path == 0)
		return execve(filename, (char *const *)argv, envp);
	else
		return execvpe(filename, (char *const *)argv, envp);
}

int execl(const char *filename, const char *arg, ...)
{
	va_list args;

	va_start(args, arg);

	dprintf("%s\n", __func__);
	return vexecle(filename, arg, args, 0, 0);
}

int execlp(const char *filename, const char *arg, ...)
{
	va_list args;

	va_start(args, arg);

	dprintf("%s\n", __func__);
	return vexecle(filename, arg, args, 0, 1);
}

int execle(const char *filename, const char *arg, ...)
{
	va_list args;

	va_start(args, arg);

	dprintf("%s\n", __func__);
	return vexecle(filename, arg, args, 1, 0);
}

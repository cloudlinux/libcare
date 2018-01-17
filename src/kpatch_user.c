#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "kpatch_user.h"
#include "kpatch_storage.h"
#include "kpatch_patch.h"
#include "kpatch_process.h"
#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "list.h"
#include "kpatch_log.h"

/* Global variables */
static char storage_dir[PATH_MAX] = "/var/lib/libcare";


/*****************************************************************************
 * Utilities.
 ****************************************************************************/

/* Return -1 to indicate error, -2 to stop immediately */
typedef int (callback_t)(int pid, void *data);

static int
processes_do(int pid, callback_t callback, void *data);


static int
processes_patch(kpatch_storage_t *storage,
		int pid, int is_just_started, int send_fd)
{
	struct patch_data data = {
		.storage = storage,
		.is_just_started = is_just_started,
		.send_fd = send_fd,
	};

	return processes_do(pid, process_patch, &data);
}

/* Check if system is suitable */
static int kpatch_check_system(void)
{
	return 1;
}

static int usage_patch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl patch [options] <-p PID> <-r fd> <patch>\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "  -s          - process was just executed\n");
	fprintf(stderr, "  -p <PID>    - target process\n");
	fprintf(stderr, "  -r fd       - fd used with LD_PRELOAD=execve.so.\n");
	return err ? 0 : -1;
}

int cmd_patch_user(int argc, char *argv[])
{
	kpatch_storage_t storage;
	int opt, pid = -1, is_pid_set = 0, ret, start = 0, send_fd = -1;

	if (argc < 4)
		return usage_patch(NULL);

	while ((opt = getopt(argc, argv, "hsp:r:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_patch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		case 'r':
			send_fd = atoi(optarg);
			break;
		case 's':
			start = 1;
			break;
		default:
			return usage_patch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set)
		return usage_patch("PID argument is mandatory");

	if (!kpatch_check_system())
		goto out_err;

	ret = storage_init(&storage, argv[argc - 1]);
	if (ret < 0)
		goto out_err;


	ret = processes_patch(&storage, pid, start, send_fd);

	storage_free(&storage);

out_err:
	return ret;
}

static int
processes_unpatch(int pid, char *buildids[], int nbuildids)
{
	struct unpatch_data data = {
		.buildids = buildids,
		.nbuildids = nbuildids
	};

	return processes_do(pid, process_unpatch, &data);
}

static int usage_unpatch(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl unpatch [options] <-p PID> "
		"[Build-ID or name ...]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "  -p <PID>    - target process\n");
	return err ? 0 : -1;
}

int cmd_unpatch_user(int argc, char *argv[])
{
	int opt, pid = -1, is_pid_set = 0;

	if (argc < 3)
		return usage_unpatch(NULL);

	while ((opt = getopt(argc, argv, "hp:")) != EOF) {
		switch (opt) {
		case 'h':
			return usage_unpatch(NULL);
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			is_pid_set = 1;
			break;
		default:
			return usage_unpatch("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (!is_pid_set)
		return usage_patch("PID argument is mandatory");

	if (!kpatch_check_system())
		return -1;

	return processes_unpatch(pid, argv, argc);
}

static
int usage_info(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl info [options] [-b BUILDID] [-p PID] [-s STORAGE] [-r REGEXP]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -h		- this message\n");
	fprintf(stderr, "  -n		- don't print patch descriptions\n");
	fprintf(stderr, "  -b <BUILDID>	- output all processes having object with specified BuildID loaded\n");
	fprintf(stderr, "  -p <PID>	- target process, 'all' or omitted for all the system processes\n");
	fprintf(stderr, "  -s <STORAGE>	- only show BuildIDs of object having patches in STORAGE, default %s\n",
		storage_dir);
	fprintf(stderr, "  -r <REGEXP>	- only show BuildIDs of object having name matching REGEXP\n");
	return err ? 0 : -1;
}

struct info_data {
	const char *buildid;
	kpatch_storage_t *storage;
	regex_t *name_re;
	int print_description;
	int may_update, vulnerable;
};

const char *RED   	= "\x1B[31m";
const char *GREEN	= "\x1B[32m";
const char *YELLOW	= "\x1B[33m";
const char *RESET	= "\x1B[0m";

static void
init_colors(void)
{
	if (!isatty(fileno(stdout))) {
		RED = GREEN = YELLOW = RESET = "";
	}
}

static int
object_info(struct info_data *data, struct object_file *o,
	    int *pid_printed)
{
	const char *buildid;
	kpatch_process_t *proc = o->proc;
	int pid = proc->pid;
	struct kpatch_storage_patch *patch = NULL;
	int patch_found = PATCH_NOT_FOUND;

	if (!o->is_elf || is_kernel_object_name(o->name))
		return 0;


	if (data->name_re != NULL &&
	    regexec(data->name_re, o->name,
		    0, NULL, REG_EXTENDED) == REG_NOMATCH)
		return 0;

	buildid = kpatch_get_buildid(o);
	if (buildid == NULL) {
		kpinfo("can't get buildid for %s\n", o->name);
		return 0;
	}

	if (data->buildid) {
		if (!strcmp(data->buildid, buildid)) {
			printf("pid=%d comm=%s\n", pid, proc->comm);
			printf("%s %s\n", o->name, buildid);
			return 1;
		}
		return 0;
	}

	if (data->storage)
		patch_found = storage_have_patch(data->storage,
						 buildid,
						 &patch);

	if (o->applied_patch == NULL && !patch_found)
		return 0;

	if (!*pid_printed) {
		printf("pid=%d comm=%s\n", pid, proc->comm);
		*pid_printed = 1;
	}

	printf("%s buildid=%s", o->name, buildid);
	if (o->applied_patch != NULL) {
		int patchlvl = o->kpfile.patch->user_level;
		printf(" patchlvl=%d", patchlvl);
	}
	if (storage_patch_found(patch) && patch->patchlevel) {
		printf(" latest=%d", patch->patchlevel);
	}

	/* empty patch patchlevel=0 with description of bugs in the version */
	if (patch && patch->patchlevel == 0 && o->applied_patch == NULL) {
		printf(" %sVULNERABLE%s\n", RED, RESET);

		if (data->print_description) {
			char *desc;

			desc = storage_get_description(data->storage, patch);
			printf("\n%sVULNERABLE VERSION:\n", RED);

			printf("%s%s", desc, RESET);
		}

		data->vulnerable ++;
	}

	printf("\n");

	/* Old or no patch applied but we have one in storage */
	if (patch && patch->patchlevel != 0 &&
	    (o->applied_patch == NULL || patch->patchlevel > o->kpfile.patch->user_level)) {
		if (data->print_description) {
			char *desc;

			printf("\n%snew patch description:\n", YELLOW);

			desc = storage_get_description(data->storage, patch);
			printf("%s%s", desc, RESET);
		}

		data->may_update++;
		return 0;
	}

	/* patch applied and is latest version. show descripition for it */
	if (patch && o->applied_patch != NULL && data->print_description) {
		char *desc;

		printf("\n%slatest patch applied\n", GREEN);

		desc = storage_get_description(data->storage, patch);
		printf("%s%s", desc, RESET);
		return 0;
	}

	return 0;
}

static int
process_info(int pid, void *_data)
{
	int ret, pid_printed = 0;
	kpatch_process_t _proc, *proc = &_proc;
	struct info_data *data = _data;
	struct object_file *o;

	ret = kpatch_process_init(proc, pid, /* start */ 0, /* send_fd */ -1);
	if (ret < 0)
		return -1;

	ret = kpatch_process_mem_open(proc, MEM_READ);
	if (ret < 0)
		goto out;

	ret = kpatch_process_map_object_files(proc);
	if (ret < 0)
		goto out;


	list_for_each_entry(o, &proc->objs, list)
		if (object_info(data, o, &pid_printed))
			break;

	if (pid_printed && data->print_description)
		printf("========================================\n");
out:
	kpatch_process_free(proc);

	return ret;
}

static int
processes_info(int pid,
	       const char *buildid,
	       const char *storagepath,
	       const char *regexp,
	       int print_description)
{
	int ret = -1;
	struct info_data data = { 0, };
	kpatch_storage_t storage;
	regex_t regex;

	init_colors();

	data.buildid = buildid;
	data.print_description = print_description;
	data.may_update = 0;
	data.vulnerable = 0;

	if (regexp != NULL) {
		ret = regcomp(&regex, regexp, REG_EXTENDED);
		if (ret != 0) {
			ret = -1;
			goto out_err;
		}
		data.name_re = &regex;
	}

	if (storagepath != NULL) {
		ret = storage_init(&storage, storagepath);
		if (ret < 0)
			goto out_err;
		data.storage = &storage;
	}

	ret = processes_do(pid, process_info, &data);

	if (data.vulnerable) {
		printf("%s%d object(s) are vulnerable%s\n", RED, data.vulnerable, RESET);
	}

	if (data.may_update) {
		printf("%s%d object(s) may be updated to the latest patch%s\n",
		       YELLOW, data.may_update, RESET);
		printf("\n%sRun: libcare-client update%s\n",
		       RED, RESET);
	}

out_err:
	if (data.storage != NULL) {
		storage_free(data.storage);
	}
	if (data.name_re != NULL) {
		regfree(data.name_re);
	}

	return ret;
}

int cmd_info_user(int argc, char *argv[])
{
	int opt, pid = -1, verbose = 0, print_description = 1;
	const char *buildid = NULL;
	const char *storagepath = storage_dir;
	const char *regexp = NULL;

	while ((opt = getopt(argc, argv, "hb:p:s:r:vn")) != EOF) {
		switch (opt) {
		case 'b':
			buildid = optarg;
			break;
		case 'p':
			if (strcmp(optarg, "all"))
				pid = atoi(optarg);
			break;
		case 's':
			storagepath = optarg;
			if (storagepath[0] == '\0' ||
			    !strcmp(storagepath, "/dev/null"))
				storagepath = NULL;
			break;
		case 'n':
			print_description = 0;
			break;
		case 'r':
			regexp = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			return usage_info(NULL);
		default:
			return usage_info("unknown arg");
		}
	}

	if (!verbose)
		log_level = LOG_ERR;

	if ((regexp != NULL && buildid != NULL)  ||
	    (buildid != NULL && storagepath != NULL)) {
		return usage_info("regexp & buildid | buildid & storage are mutual");
	}


	return processes_info(pid, buildid, storagepath, regexp,
			      print_description);
}


/* Server part. Used as a start-up notification listener. */
#define SERVER_STOP	(1<<30)

static int
execute_cmd(int argc, char *argv[]);

static int
cmd_execve_startup(int fd, int argc, char *argv[], int is_just_started)
{
	int rv, pid;
	char pid_str[64], send_fd_str[64];
	char *patch_pid_argv_execve[] = {
		"patch",
		"-s",
		"-p",
		pid_str,
		"-r",
		send_fd_str,
		storage_dir
	};
	char *patch_pid_argv_startup[] = {
		"patch",
		"-p",
		pid_str,
		"-r",
		send_fd_str,
		storage_dir
	};

	rv = sscanf(argv[1], "%d", &pid);
	if (rv != 1) {
		kperr("can't parse pid from %s", argv[1]);
		return -1;
	}

	sprintf(pid_str, "%d", pid);
	sprintf(send_fd_str, "%d", fd);

	optind = 1;
	if (is_just_started)
		rv = cmd_patch_user(ARRAY_SIZE(patch_pid_argv_execve),
				    patch_pid_argv_execve);
	else
		rv = cmd_patch_user(ARRAY_SIZE(patch_pid_argv_startup),
				    patch_pid_argv_startup);

	if (rv < 0)
		kperr("can't patch pid %d\n", pid);

	return 0;
}

static void
kill_and_wait(int pid)
{
	int status;

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, &status, 0);
}

static int childpid;

static int
cmd_run(int argc, char *argv[])
{
	int pid;

	if (childpid) {
		kill_and_wait(childpid);
		childpid = 0;
	}

	pid = fork();
	if (pid == -1) {
		kplogerror("can't fork()\n");
		return -1;
	}

	if (pid == 0) {
		return execl("/bin/sh", "sh", "-c", argv[1], (char *)NULL);
	}

	childpid = pid;
	printf("%d\n", pid);
	return 0;
}

static int
cmd_kill(int argc, char *argv[])
{
	int pid;

	if (sscanf(argv[1], "%d", &pid) != 1) {
		kperr("can't parse pid from %s\n", argv[1]);
		return -1;
	}

	kpdebug("killing %d\n", pid);
	kill_and_wait(pid);

	return 0;
}

static int
cmd_storage(int argc, char *argv[])
{
	strncpy(storage_dir, argv[1], PATH_MAX - 1);
	return 0;
}

static int
cmd_update(int argc, char *argv[])
{
	char *patch_all[] = {
		"patch",
		"-p",
		"all",
		storage_dir
	};

	optind = 1;
	return cmd_patch_user(ARRAY_SIZE(patch_all), patch_all);
}

static int
server_execute_cmd(int fd, int argc, char *argv[])
{
	char *cmd = argv[0];
	int old_stdout, old_stderr, rv;
	optind = 1;

	if (!strcmp(cmd, "execve"))
		return cmd_execve_startup(fd, argc, argv, 1);
	if (!strcmp(cmd, "startup"))
		return cmd_execve_startup(fd, argc, argv, 0);
	if (!strcmp(cmd, "update"))
		return cmd_update(argc, argv);
	if (!strcmp(cmd, "storage"))
		return cmd_storage(argc, argv);
	if (!strcmp(cmd, "stop"))
		return SERVER_STOP;

	old_stdout = dup3(1, 101, O_CLOEXEC);
	old_stderr = dup3(2, 102, O_CLOEXEC);

	(void) dup3(fd, 1, O_CLOEXEC);
	(void) dup3(fd, 2, O_CLOEXEC);


	if (!strcmp(cmd, "run"))
		rv = cmd_run(argc, argv);
	else if (!strcmp(cmd, "kill"))
		rv = cmd_kill(argc, argv);
	else
		rv = execute_cmd(argc, argv);

	fflush(stdout);
	fflush(stderr);

	(void) dup2(old_stdout, 1);
	(void) dup2(old_stderr, 2);

	return rv;
}

static int
handle_client(int fd)
{
	char msg[4096], *argv[32], *p;
	ssize_t off = 0, r;
	int argc;

	do {
		r = recv(fd, msg + off, sizeof(msg) - off, 0);
		if (r == -1 && errno == EINTR)
			continue;

		if (r == 0)
			goto out_close;
		off += r;
	} while (off < sizeof(msg) &&
		 (off < 2 ||
		  msg[off - 2] != '\0' ||
		  msg[off - 1] != '\0'));

	if (off == sizeof(msg)) {
		kperr("possible buffer overflow\n");
		goto out_close;
	}

	argv[0] = msg;
	for (p = msg, argc = 1;
	     p < msg + off && argc < ARRAY_SIZE(argv);
	     p++) {
		if (*p)
			continue;
		p++;

		argv[argc] = p;
		if (*p == '\0')
			break;

		argc++;
	}

	return server_execute_cmd(fd, argc, argv);

out_close:
	close(fd);
	return 0;
}


static int usage_server(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl server <UNIX socket> [STORAGE ROOT]\n");
	return -1;
}

#define LISTEN_BACKLOG 1
static int
server_bind_socket(const char *path)
{
	int sfd = -1, rv, sockaddr_len;
	struct sockaddr_un sockaddr;

	/* Handle invocation by libcare.service */
	if (path[0] == '&') {
		if (sscanf(path, "&%d", &sfd) == 0)
			return -1;
		return sfd;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = AF_UNIX;
	sockaddr_len = strlen(path) + 1;
	if (sockaddr_len >= sizeof(sockaddr.sun_path)) {
		kperr("sockaddr is too long\n");
		return -1;
	}

	strncpy(sockaddr.sun_path, path, sizeof(sockaddr.sun_path));
	if (path[0] == '@')
		sockaddr.sun_path[0] = '\0';

	sockaddr_len += sizeof(sockaddr.sun_family);

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1)
		goto err_close;

	rv = bind(sfd, (struct sockaddr *)&sockaddr,
		  sockaddr_len);
	if (rv == -1)
		goto err_close;

	rv = listen(sfd, LISTEN_BACKLOG);
	if (rv == -1)
		goto err_close;

	return sfd;

err_close:
	if (rv < 0)
		kplogerror("can't listen on unix socket %s\n", path);
	if (sfd != -1)
		close(sfd);
	return rv;
}

static void
kill_child(int signum)
{
	/* Hello Bulba my old friend... */
	(void) signum;
	if (childpid)
		kill_and_wait(childpid);
	exit(0x80 | signum);
}

static int
cmd_server(int argc, char *argv[])
{
	int sfd = -1, cfd, rv;
	struct sigaction act;

	if (argc < 2)
		return usage_server("UNIX socket argument is missing");

	memset(&act, 0, sizeof(act));
	act.sa_handler = kill_child;
	act.sa_flags = SA_RESTART;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0) {
		kplogerror("can't install signal handler\n");
		return -1;
	}

	sfd = server_bind_socket(argv[1]);
	if (sfd < 0)
		return sfd;

	if (argc >= 3)
		strcpy(storage_dir, argv[2]);

	setlinebuf(stdout);

	while ((cfd = accept4(sfd, NULL, 0, SOCK_CLOEXEC)) >= 0) {
		rv = handle_client(cfd);
		if (rv < 0)
			kplogerror("server error\n");

		(void) close(cfd);
		if (rv == SERVER_STOP)
			break;
	}

	if (childpid)
		kill_and_wait(childpid);

	close(sfd);
	return 0;
}


/*****************************************************************************
 * Utilities.
 ****************************************************************************/
static int
processes_do(int pid, callback_t callback, void *data)
{
	DIR *dir;
	struct dirent *de;
	int ret = 0, rv;
	char *tmp, buf[64];

	if (pid != -1)
		return callback(pid, data);

	dir = opendir("/proc");
	if (!dir) {
		kplogerror("can't open '/proc' directory\n");
		return -1;
	}

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;

		pid = strtoul(de->d_name, &tmp, 10);
		if (pid == 0 || *tmp != '\0')
			continue;

		if (pid == 1 || pid == getpid())
			continue;

		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		rv = readlink(buf, buf, sizeof(buf));
		if (rv == -1) {
			if (errno == ENOENT)
				kpdebug("skipping kernel thread %d\n", pid);
			else
				kpdebug("can't get exec for %d: %s\n", pid,
					strerror(errno));
			continue;
		}

		rv = callback(pid, data);
		if (rv < 0)
			ret = -1;
		if (rv == -2)
			break;
	}

	closedir(dir);

	return ret;
}

static int usage(const char *err)
{
	if (err)
		fprintf(stderr, "err: %s\n", err);
	fprintf(stderr, "usage: libcare-ctl [options] <cmd> [args]\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -v          - verbose mode\n");
	fprintf(stderr, "  -h          - this message\n");
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  patch  - apply patch to a user-space process\n");
	fprintf(stderr, "  unpatch- unapply patch from a user-space process\n");
	fprintf(stderr, "  info   - show info on applied patches\n");
	fprintf(stderr, "  server - listen on a unix socket for commands\n");
	return -1;
}

static int
execute_cmd(int argc, char *argv[])
{
	char *cmd = argv[0];
	optind = 1;

	if (!strcmp(cmd, "patch") || !strcmp(cmd, "patch-user"))
		return cmd_patch_user(argc, argv);
	else if (!strcmp(cmd, "unpatch") || !strcmp(cmd, "unpatch-user"))
		return cmd_unpatch_user(argc, argv);
	else if (!strcmp(cmd, "info") || !strcmp(cmd, "info-user"))
		return cmd_info_user(argc, argv);
	else
		return usage("unknown command");
}

/* entry point */
int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "+vh")) != EOF) {
		switch (opt) {
			case 'v':
				log_level += 1;
				break;
			case 'h':
				return usage(NULL);
			default:
				return usage("unknown option");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		return usage("not enough arguments.");

	if (!strcmp(argv[0], "server"))
		return cmd_server(argc, argv);
	else
		return execute_cmd(argc, argv);
}

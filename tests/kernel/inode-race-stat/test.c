/*
 * Author: Colin King <colin.king@canonical.com>
 *
 * Copyright (C) 2012 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 *  Regression test for commit 3b06b3ebf44170c90c893c6c80916db6e922b9f2,
 *  bug https://bugzilla.kernel.org/show_bug.cgi?id=36002
 *
 *  "Only unlock and d_add() new inodes after the plaintext inode size has
 *   been read from the lower filesystem. This fixes a race condition that
 *   was sometimes seen during a multi-job kernel build in an eCryptfs mount."
 *
 *  Create file, drop inode cache, and stat file in multiple child processes to
 *  try and catch the inode size race.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define TEST_PASSED		(0)
#define TEST_FAILED		(1)
#define TEST_ERROR		(2)

#define THREADS_PER_CPU		(16)

#define MAX_CHILD		(512)	/* Maximum child processes */
#define MIN_DURATION		(10)	/* Minimum time to run a test */
#define TEST_DURATION		(20)	/* Default test duration in seconds */

#define CHECK_SIZE_FAILED	(-2)	/* stat failed */
#define CHECK_SIZE_ERROR	(-1)	/* stat error */
#define CHECK_SIZE_PASSED	(0)	/* stat passed */

#define CMD_QUIT		'q'
#define CMD_TEST		't'
#define CMD_PASSED		'p'
#define CMD_FAILED		'f'
#define CMD_READ_ERROR		'R'
#define CMD_STAT_ERROR		'S'
#define CMD_UNKNOWN_ERROR	'U'

#define WARN_ON_FILE_SIZE_ERROR	0	/* true to report failures to stderr */

static volatile bool keep_running = true;

static int drop_cache(const int val)
{
	FILE *fp;

	if ((fp = fopen("/proc/sys/vm/drop_caches", "w")) != NULL) {
		fprintf(fp, "%d\n", val);
		fclose(fp);
		return 0;
	}
	return -1;
}

static int check_size(const char *filename, const off_t size)
{
	struct stat statbuf;

	if (stat(filename, &statbuf) < 0) {
		fprintf(stderr, "stat failed on %s: %s\n",
			filename, strerror(errno));
		return CHECK_SIZE_ERROR;
	}
	if (statbuf.st_size != size) {
#if WARN_ON_FILE_SIZE_ERROR
		fprintf(stderr, "Got incorrect file size: %zd vs %zd\n",
			statbuf.st_size, size);
#endif
		return CHECK_SIZE_FAILED;
	}
	return CHECK_SIZE_PASSED;
}

static void do_test(const int fdin, const int fdout, const char *filename)
{
	for (;;) {
		int n;
		int ret;
		char cmd[32];

		if ((n = read(fdin, cmd, sizeof(cmd))) < 1) {
			cmd[0] = CMD_READ_ERROR;
			if (write(fdout, cmd, 1) < 0)
				fprintf(stderr, "write to pipe failed: %s\n",
					strerror(errno));
			exit(0);
		}
		if (cmd[0] == CMD_QUIT) {
			exit(0);
		}
		if (cmd[0] == CMD_TEST) {
			int ret;
			off_t sz;
			sscanf(cmd+1, "%jd", (intmax_t *)&sz);

			ret = check_size(filename, sz);
			switch (ret) {
			case CHECK_SIZE_PASSED:
				cmd[0] = CMD_PASSED;
				if (write(fdout, cmd, 1) < 0)
					fprintf(stderr, "write to pipe failed: %s\n",
						strerror(errno));
				break;
			case CHECK_SIZE_ERROR:
				cmd[0] = CMD_STAT_ERROR;
				ret = write(fdout, cmd, 1);
				exit(ret);
				break;
			case CHECK_SIZE_FAILED:
				cmd[0] = CMD_FAILED;
				ret = write(fdout, cmd, 1);
				exit(ret);
			default:
				cmd[0] = CMD_UNKNOWN_ERROR;
				ret = write(fdout, cmd, 1);
				exit(ret);
			}
		}
	}
}

void sigint_handler(int dummy)
{
	keep_running = false;
}

void show_usage(const char *name)
{
	fprintf(stderr, "Syntax: %s [-d duration] filename\n", name);
	fprintf(stderr, "\t-d duration of test (in seconds)\n");
	exit(TEST_ERROR);
}

int main(int argc, char **argv)
{
	int	fd;
	int	ret = TEST_PASSED;
	pid_t	pids[MAX_CHILD];
	int	pipe_to[MAX_CHILD][2];
	int	pipe_from[MAX_CHILD][2];
	char	cmd[32];
	char	*filename;
	int	i;
	off_t 	j;
	long	threads;
	int 	duration = TEST_DURATION;
	int	opt;
	time_t	t1, t2;
	int	max_fd;
	int	opened_fd;
	int	max_threads;

	if (geteuid() != 0) {
		fprintf(stderr, "Need to run with root privilege\n");
		exit(TEST_ERROR);
	}

	while ((opt = getopt(argc, argv, "d:")) != -1) {
		switch (opt) {
		case 'd':
			duration = atoi(optarg);
			break;
		default:
			show_usage(argv[0]);
			break;
		}
	}

	if (optind >= argc)
		show_usage(argv[0]);

	if (duration < MIN_DURATION) {
		fprintf(stderr,
			"Test duration must be %d or more seconds long.\n",
			MIN_DURATION);
		exit(TEST_ERROR);
	}

	filename = argv[optind];

	/* Determine how many used file descriptors we have */
	max_fd = (int)sysconf(_SC_OPEN_MAX);
	for (i = 0, opened_fd = 0; i < max_fd; i++)
		if (!fcntl(i, F_GETFD, 0))
			opened_fd++;
	/*
	 * Each process takes initially an extra 4 file descriptors
	 * on 2 pipe calls, but after the process has been successfully
	 * forked it closes two file descriptors. So we need 2*N + 2
	 * free file descriptors for N children which limits the
	 * maximum number of processes we can fork.
	 */
	max_threads = (max_fd - (opened_fd + 2)) / 2;
	max_threads = max_threads > MAX_CHILD ? MAX_CHILD : max_threads;

	threads = (int)sysconf(_SC_NPROCESSORS_CONF) * THREADS_PER_CPU;
	threads = threads > max_threads ? max_threads : threads;

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	for (i = 0; i < threads; i++) {
		pid_t	pid;

		if (pipe(pipe_to[i]) < 0) {
			fprintf(stderr, "pipe failed: %s\n", strerror(errno));
			exit(TEST_ERROR);
		}
		if (pipe(pipe_from[i]) < 0) {
			fprintf(stderr, "pipe failed: %s\n", strerror(errno));
			exit(TEST_ERROR);
		}

		pid = fork();
		switch (pid) {
		case -1:
			fprintf(stderr, "fork failed\n");
			break;
		case 0:
			/* child */
			(void)close(pipe_to[i][1]);
			(void)close(pipe_from[i][0]);

			do_test(pipe_to[i][0], pipe_from[i][1], filename);
			_exit(0);
		default:
			/* parent */
			(void)close(pipe_to[i][0]);
			(void)close(pipe_from[i][1]);

			pids[i] = pid;
			break;
		}
	}

	(void)time(&t1);

	for (j = 0; keep_running; j++) {
		off_t sz = j & 0xff;

		/* Create a file, of a given size, sync it, drop caches */
		if ((fd = creat(filename, S_IRUSR | S_IWUSR)) < 0) {
			fprintf(stderr, "create failed: %s\n", strerror(errno));
			ret = TEST_ERROR;
			break;
		}
		if (ftruncate(fd, sz) < 0) {
			fprintf(stderr, "ftruncate failed: %s\n",
				strerror(errno));
			ret = TEST_ERROR;
			break;
		}
		if (fdatasync(fd) < 0) {
			fprintf(stderr, "fdatasync failed: %s\n",
				strerror(errno));
			ret = TEST_ERROR;
			break;
		}
		(void)close(fd);

		if (drop_cache(1) < 0) {
			fprintf(stderr, "could not free pagecache\n");
			ret = TEST_ERROR;
			break;
		}
		if (drop_cache(2) < 0) {
			fprintf(stderr, "could free inodes and dentries\n");
			ret = TEST_ERROR;
			break;
		}
		if (drop_cache(3) < 0) {
			fprintf(stderr, "could not free page cache, "
				"inodes and dentries\n");
			ret = TEST_ERROR;
			break;
		}

		/* Now tell children to stat the file */
		snprintf(cmd, sizeof(cmd), "%c%jd", CMD_TEST, (intmax_t)sz);
		for (i = 0; i < threads; i++) {
			if (write(pipe_to[i][1], cmd, strlen(cmd)+1) < 0) {
				fprintf(stderr, "write to pipe failed: %s\n",
					strerror(errno));
				ret = TEST_ERROR;
				break;
			}
		}

		/* And check if it was OK */
		for (i = 0; i < threads; i++) {
			int n;

			memset(cmd, 0, sizeof(cmd));
			if ((n = read(pipe_from[i][0], cmd, 1)) < 0) {
				fprintf(stderr, "read from pipe failed: %s\n",
					strerror(errno));
				ret = TEST_ERROR;
				break;
			}
			if (n < 1) {
				fprintf(stderr, "expecting data from pipe\n");
				ret = TEST_ERROR;
				break;
			}

			switch (cmd[0]) {
			case CMD_PASSED:
				break;
			case CMD_FAILED:
				ret = TEST_FAILED;
				goto abort;
			default:
				ret = TEST_ERROR;
				goto abort;
			}
		}

		(void)time(&t2);

		if (difftime(t2, t1) > (double)duration)
			break;
	}

abort:
	(void)unlink(filename);

	if (!keep_running)
		ret = TEST_ERROR; /* User aborted! */

	cmd[0] = CMD_QUIT;
	for (i = 0; i < threads; i++) {
		int status;
		int ret;

		ret = write(pipe_to[i][1], cmd, 1);
		(void)waitpid(pids[i], &status, 0);

		(void)close(pipe_to[i][1]);
		(void)close(pipe_from[i][0]);
	}

	exit(ret);
}

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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

#define MAX_FILES	(16)	/* number of files to create per iteration */
#define MAX_ITERATIONS	(150)	/* number of mkdir/rmdir iterations */
#define THREADS_PER_CPU	(8)	/* number of child processes per CPU */

#define TIMEOUT		(30)	/* system hang timeout in seconds */

#define CREAT		(0)
#define TRUNCATE	(1)
#define UNLINK		(2)
#define UNKNOWN		(3)

static volatile bool die = false;

static char *options[] = { 
	"creat()",
	"unlink()",
	"truncate()",
	"<unknown>"
};

/*
 *  Create many threads that try and create mkdir and rmdir races
 *  Aim to load each CPU and create mkdir/rmdir collisions.
 */

/*
 *  Run mkdir/rmdir as a child and detect any timeouts.  This
 *  is a little heavy handed, but allows us to detect kernel
 *  hangs on the mkdir/rmdir syscalls if we lock up.
 *
 */
int hang_check(int option, const char *filename)
{
	pid_t pid;
	struct timeval tv;
	int ret;
	int status;
	int pipefd[2];
	int fd;
	fd_set readfds;

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;

	if (pipe(pipefd) < 0) {
		fprintf(stderr, "pipe error\n");
		return TEST_ERROR;
	}

	pid = fork();
	switch (pid) {
	case -1:
		fprintf(stderr, "failed to fork child\n");
		return TEST_ERROR;

	case 0:
		/* Child */
		close(pipefd[0]);

		
		switch (option) {
		case CREAT:
			fd = creat(filename, 0700);
			if (fd >= 0)
				close(fd);
			break;

		case TRUNCATE:
			/*
			 * We want to try and force a lock up -
			 * we don't care about the return since
			 * the file may not exit, but we assign
			 * ret to keep gcc happy
			 */
			ret = truncate(filename, 64 * 1024);
			ret = truncate(filename, 128 * 1024);
			ret = truncate(filename, 64 * 1024);
			ret = truncate(filename, 0);
			ret = truncate(filename, 64 * 1024);
			break;

		case UNLINK:
			unlink(filename);
			break;
			
		default:
			break;
		}
		if (write(pipefd[1], "EXIT", 4) < 0) 
			fprintf(stderr, "pipe write failed\n");

		close(pipefd[1]);
		_exit(0);
		break;

	default:
		/* Parent */
		close(pipefd[1]);

		FD_ZERO(&readfds);
		FD_SET(pipefd[0], &readfds);

		/* parent, sleep until we get a message from the child */
		ret = select(pipefd[0]+1, &readfds, NULL, NULL, &tv);
		close(pipefd[0]);

		switch (ret) {
		case 0:
			/* Timed out on select, no signal from child! */
			fprintf(stderr, "Timed out after %d seconds doing %s - possible eCryptfs hang\n",
				TIMEOUT, options[option > TRUNCATE ? UNKNOWN : option]);
			/* Vainly attempt to kill child */
			kill(pid, SIGINT);
			return TEST_FAILED;
		case -1:
			/* fprintf(stderr, "Unexpected return from select()\n"); */
			waitpid(pid, &status, 0);
			return TEST_ERROR;
		default:
			/* Child completed the required operation and wrote down the pipe, lets reap */
			waitpid(pid, &status, 0);
			return TEST_PASSED;
		}
	}
}

int test_dirs(const char *path, const int iterations, const int max_files)
{
	int i, j;
	char *filename;
	size_t len = strlen(path) + 32;
	int ret = TEST_PASSED;

	if ((filename = malloc(len)) == NULL) {
		fprintf(stderr, "failed to malloc filename\n");
		return TEST_ERROR;
	}

	for (j = 0; j < iterations; j++) {
		for (i = 0; i < max_files; i++) {
			snprintf(filename, len, "%s/%d", path, i);
			if ((ret = hang_check(CREAT, filename)) != TEST_PASSED) {
				free(filename);
				return ret;
			}
		}

		for (i = 0; i < max_files; i++) {
			snprintf(filename, len, "%s/%d", path, i);
			if ((ret = hang_check(TRUNCATE, filename)) != TEST_PASSED) {
				free(filename);
				return ret;
			}
		}

		for (i = 0; i < max_files; i++) {
			snprintf(filename, len, "%s/%d", path, i);
			if ((ret = hang_check(UNLINK, filename)) != TEST_PASSED) {
				free(filename);
				return ret;
			}
		}

		if (die) {
			ret = TEST_ERROR;
			break;
		}
	}

	free(filename);

	return ret;
}

void sighandler(int dummy)
{
	die = true;
}

int test_exercise(const char *path, const int iterations, const int max_files)
{
	int i;
	long threads = sysconf(_SC_NPROCESSORS_CONF) * THREADS_PER_CPU;
	pid_t *pids;
	int ret = TEST_PASSED;

	if ((pids = calloc(threads, sizeof(pid_t))) == NULL) {
		fprintf(stderr, "failed to calloc pids\n");
		return TEST_ERROR;
	}

	/* Go forth and multiply.. */
	for (i = 0; i < threads; i++) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case -1:
			fprintf(stderr, "failed to fork child %d of %ld\n", i+1, threads);
			break;
		case 0:
			exit(test_dirs(path, iterations, max_files));
		default:
			pids[i] = pid;
			break;
		}
	}

	for (i = 0; i < threads; i++) {
		int status;
		waitpid(pids[i], &status, 0);

		if (WEXITSTATUS(status) != TEST_PASSED)
			ret = WEXITSTATUS(status);
	}

	free(pids);

	return ret;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Syntax: pathname\n");
		exit(TEST_ERROR);
	}

	signal(SIGINT, sighandler);

	if (access(argv[1], R_OK | W_OK) < 0) {
		fprintf(stderr, "Cannot access %s\n", argv[1]);
		exit(TEST_ERROR);
	}

	exit(test_exercise(argv[1], MAX_ITERATIONS, MAX_FILES));
}

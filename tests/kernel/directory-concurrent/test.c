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

#define MAX_DIRS	(16)	/* number of directories to create per iteration */
#define THREADS_PER_CPU	(8)	/* number of child processes per CPU */

#define TIMEOUT		(30)	/* system hang timeout in seconds */

#define TEST_DURATION	(60)	/* duration of test (seconds) */
#define MIN_DURATION	(1)	/* minimum test duration (seconds) */

#define MKDIR		(0)
#define RMDIR		(1)

#define DIE_SIGINT	(1)	/* Kill test threads because of SIGINT */
#define DIE_COMPLETE	(2)	/* Kill test threads because end of test duration */

static volatile int die = 0;

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
		case MKDIR:
			mkdir(filename, 0700);
			break;
		case RMDIR:
			rmdir(filename);
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
				TIMEOUT, option == MKDIR ? "mkdir()" : "rmdir()");
			/* Vainly attempt to kill child */
			kill(pid, SIGINT);
			return TEST_FAILED;
		case -1:
			if (errno != EINTR) {
				fprintf(stderr, "Unexpected return from select(): %d %s\n", errno, strerror(errno));
				waitpid(pid, &status, 0);
				return TEST_ERROR;
			} else {
				/*
				 * We got sent a signal from controlling process to
				 * tell us to stop, so return TEST_PASSED since we have
				 * not detected any failures from our child
				 */
				waitpid(pid, &status, 0);
				return TEST_PASSED;
			}
		default:
			/* Child completed the required operation and wrote down the pipe, lets reap */
			waitpid(pid, &status, 0);
			return TEST_PASSED;
		}
	}
}

int test_dirs(const char *path, const int max_dirs)
{
	int i, j;
	char *filename;
	size_t len = strlen(path) + 32;
	int ret = TEST_PASSED;

	if ((filename = malloc(len)) == NULL) {
		fprintf(stderr, "failed to malloc filename\n");
		return TEST_ERROR;
	}

	while (!die) {
		for (i = 0; i < max_dirs; i++) {
			snprintf(filename, len, "%s/%d", path, i);
			if ((ret = hang_check(MKDIR, filename)) != TEST_PASSED) {
				free(filename);
				return ret;
			}
		}

		for (i = 0; i < max_dirs; i++) {
			snprintf(filename, len, "%s/%d", path, i);
			if ((ret = hang_check(RMDIR, filename)) != TEST_PASSED) {
				free(filename);
				return ret;
			}
		}
	}

	free(filename);

	if (die & DIE_SIGINT)
		ret = TEST_ERROR;	/* Got aborted */

	return ret;
}

void sigint_handler(int dummy)
{
	die = DIE_SIGINT;
}

void sigusr1_handler(int dummy)
{
	die = DIE_COMPLETE;
}

int test_exercise(const char *path, const int max_dirs, const int duration)
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
			exit(test_dirs(path, max_dirs));
		default:
			pids[i] = pid;
			break;
		}
	}

	sleep(duration);

	for (i = 0; i < threads; i++)
		kill(pids[i], SIGUSR1);

	for (i = 0; i < threads; i++) {
		int status;
		waitpid(pids[i], &status, 0);

		if (WEXITSTATUS(status) != TEST_PASSED)
			ret = WEXITSTATUS(status);
	}

	free(pids);

	return ret;
}

void show_usage(char *name)
{
	fprintf(stderr, "Syntax: %s [-d duration] pathname\n", name);
	fprintf(stderr, "\t-d duration of test (in seconds)\n");
	exit(TEST_ERROR);
}

int main(int argc, char **argv)
{
	int opt;
	int duration = TEST_DURATION;

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

	if (access(argv[optind], R_OK | W_OK) < 0) {
		fprintf(stderr, "Cannot access %s\n", argv[1]);
		exit(TEST_ERROR);
	}

	signal(SIGINT, sigint_handler);
	signal(SIGUSR1, sigusr1_handler);

	exit(test_exercise(argv[optind], MAX_DIRS, duration));
}

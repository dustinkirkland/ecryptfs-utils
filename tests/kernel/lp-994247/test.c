/**
 * test.c: C-based test for https://launchpad.net/bugs/994247
 *         This should result in a kernel BUG().
 * Author: Tyler Hicks <tyhicks@canonical.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int miscdev;

void sigusr1_handler(int ignored)
{
	exit(close(miscdev));
}

int main(void)
{
	struct sigaction sa;
	pid_t pid;
	int status, rc;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;

	miscdev = open("/dev/ecryptfs", O_RDWR);
	if (miscdev < 0)
		return 1;

	rc = sigaction(SIGUSR1, &sa, NULL);
	if (rc < 0)
		return 1;

	pid = fork();
	if (pid < 0)
		return 1;
	else if (!pid) {
		pause();
		exit(1);
	}

	/* The parent must close the file before the child */
	close(miscdev);

	rc = kill(pid, SIGUSR1);
	if (rc < 0)
		return 1;
	
	rc = waitpid(pid, &status, 0);
	if (rc < 0 || !WIFEXITED(status))
		return 1;

	return WEXITSTATUS(status);
}

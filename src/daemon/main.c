/**
 * Userspace daemon which responds to the eCryptfs kernel module's requests
 *
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/resource.h>
#include "config.h"
#include "../include/ecryptfs.h"

static int ecryptfs_socket = 0;
static char *pidfile = NULL;
static char *prompt_prog = NULL;

static
int
prompt_callback(char *prompt_type, char *prompt, char *input, int input_size) {
	int status;
	pid_t pid = -1;
	int fds[2] = {-1, -1};
	int r = 0;
	int rc;

	/*
	 * Make sure we don't reuse input
	 */
	if (input) {
		memset (input, 0, input_size);
	}

	if (prompt_prog == NULL) {
		rc = -EINVAL;
		goto out;
	}

	if (pipe (fds) == -1) {
		rc = -errno;
		goto out;
	}

	if ((pid = fork ()) == -1) {
		rc = -errno;
		goto out;
	}

	if (pid == 0) {
		close (fds[0]);
		fds[0] = -1;

		if (dup2 (fds[1], 1) == -1) {
			exit (1);
		}

		close (fds[1]);
		fds[1] = -1;

		execl (
			prompt_prog,
			prompt_prog,
			"-t",
			prompt_type,
			prompt,
			NULL
		);

		exit (1);
	}

	close (fds[1]);
	fds[1] = -1;

	while (
		(r=waitpid (pid, &status, __WNOTHREAD)) == 0 ||
		(r == -1 && errno == EINTR)
	);

	if (r == -1) {
		rc = -errno;
		goto out;
	}

	if (!WIFEXITED (status)) {
		rc = -EFAULT;
		goto out;
	}

	if (WEXITSTATUS (status) != 0) {
		rc = -EIO;
		goto out;
	}
	
	if (!strcmp (prompt_type, "password")) {
		if ((r = read (fds[0], input, input_size)) == -1) {
			rc = -errno;
			goto out;
		}
	
		input[r] = '\0';

		if (strlen (input) > 0 && input[strlen (input)-1] == '\n') {
			input[strlen (input)-1] = '\0';
		}
	}

	rc = 0;

out:
	if (rc != 0) {
		if (input) {
			memset (input, 0, input_size);
		}
	}

	if (fds[0] != -1) {
		close (fds[0]);
		fds[0] = -1;
	}

	if (fds[1] != -1) {
		close (fds[1]);
		fds[1] = -1;
	}

	return rc;
}


static void ecryptfsd_exit(int retval)
{
	if (pidfile != NULL) {
		unlink(pidfile);
		free(pidfile);
 		pidfile = NULL;
	}
	if (!ecryptfs_socket)
		goto out;
	if (ecryptfs_send_netlink(ecryptfs_socket, NULL,
				  ECRYPTFS_NLMSG_QUIT, 0, 0) < 0) {
		ecryptfs_syslog(LOG_ERR, "Failed to unregister netlink "
				"daemon with the eCryptfs kernel module\n");
	}
	ecryptfs_release_netlink(ecryptfs_socket);
out:
	ecryptfs_syslog(LOG_INFO, "Closing eCryptfs userspace netlink "
			"daemon [%u]\n", getpid());
	exit(retval);
}

void daemonize(void)
{
	pid_t pid;
	int fd;
	int null;

	if(getppid() == 1)
		return; /* Already a daemon */
	if ((pid=fork()) == -1) {
		fprintf(stderr, "Failed to create daemon process: %s\n",
			strerror(errno));
		exit(1);
	}
	if (pid != 0)
		exit(0);
	setsid();
	umask(027);
	chdir("/");
	if ((pid=fork()) == -1) { /* Fork in new session */
		syslog(LOG_ERR, "Failed to create daemon process: %s",
		       strerror(errno));
		exit(1);
	}
	if (pid != 0)
		exit(0);
	/* Make std handles write to null; close all others. */
	if ((null = open("/dev/null", O_RDWR)) == -1) {
		syslog(LOG_ERR, "Cannot open /dev/null");
		exit(1);
	}
	for (fd=0; fd < 3; fd++) {
		if (dup2(null, 0) == -1) {
			syslog(LOG_ERR, "Failed to dup null: %s",
			       strerror(errno));
			exit(1);
		}
	}
	for (fd = (getdtablesize() - 1); fd > 2; fd--)
		close(fd);
	/* Ignore major signals */
 	if (signal(SIGHUP, SIG_IGN) == SIG_ERR
	    || signal(SIGTERM, SIG_IGN) == SIG_ERR
	    || signal(SIGINT, SIG_IGN) == SIG_ERR) {
 		syslog(LOG_ERR, "Failed to setup initial signals");
 		exit(1);
 	}
}

void sigterm_handler(int sig)
{
	ecryptfsd_exit(0);
}

void usage(const char * const me, const struct option * const options,
	   const char * const short_options)
{
	const struct option *opt;

	printf("Usage: %s [options]", me);
	for (opt = options; opt->name; opt++) {
		const char *descr = opt->name + strlen(opt->name) + 1;

		if (strchr(short_options, opt->val))
			printf("\n  -%c, --%s", opt->val, opt->name);
		else
			printf("\n  --%s", opt->name);
		if (opt->has_arg)
			printf(" <%s>", opt->name);
		if (strlen(descr))
			printf("\t%s",descr);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	static struct option long_options[] = {
		{ "pidfile\0\tSet pid file name", required_argument, NULL, 'p' },
		{ "foreground\0\t\tDon't fork into background", no_argument, NULL, 'f' },
		{ "chroot\0\t\tChroot to directory", required_argument, NULL, 'C' },
   		{ "prompt-prog\0Program to execute for user prompt", required_argument, NULL, 'R' },
		{ "version\0\t\t\tShow version information", no_argument, NULL, 'V' },
		{ "help\0\t\t\tShow usage information", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	static char *short_options = "p:f:C:R:Vh";
	int long_options_ret;
	struct rlimit core = { 0, 0 };
	int foreground = 0;
	char *chrootdir = NULL;
	char *tty = NULL;
	int rc = 0;

	while ((long_options_ret = getopt_long (argc, argv, short_options,
						long_options, NULL)) != -1) {
		switch (long_options_ret) {
			case 'p':
				pidfile = strdup(optarg);
			break;
			case 'f':
				foreground = 1;
			break;
			case 'C':
				chrootdir = strdup(optarg);
			break;
 			case 'R':
 				prompt_prog = strdup(optarg);
  			break;
			case 'V':
				printf(("%s (%s) %s\n"
					"\n"
					"This is free software.  You may redistribute copies of it under the terms of\n"
					"the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n"
					"There is NO WARRANTY, to the extent permitted by law.\n"
					),
					basename(argv[0]),
					PACKAGE_NAME,
					PACKAGE_VERSION
				);
			break;
			case 'h':
			default:
				usage(basename(argv[0]), long_options,
				      short_options);
				exit(1);
			break;
		}
	}
	tty = ttyname(0); /* We may need the tty name later */
	if (tty != NULL)
		setenv ("TERM_DEVICE", tty, 0);
	if (!foreground)
		daemonize(); /* This will exit if cannot be completed */
	/* Disallow core file; secret values may be in it */
	if (setrlimit(RLIMIT_CORE, &core) == -1) {
		rc = -errno;
		syslog(LOG_ERR, "Cannot setrlimit: %s", strerror (errno));
		goto daemon_out;
	}
	if (chrootdir != NULL) {
		if (chroot(chrootdir) == -1) {
			rc = -errno;
			syslog(LOG_ERR, "Failed to chroot to '%s': %s",
			       chrootdir, strerror(errno));
			goto daemon_out;
		}
		free(chrootdir);
		chrootdir = NULL;
	}
	if (pidfile != NULL) {
		FILE *fp = fopen(pidfile, "w");

		if (fp == NULL) {
			rc = -errno;
			syslog(LOG_ERR, "Failed to open pid file '%s': %s",
			       pidfile, strerror(errno));
			goto daemon_out;
		}
		fprintf(fp, "%d", (int)getpid());
		fclose(fp);
	}
	if (signal(SIGTERM, sigterm_handler) == SIG_ERR) {
		rc = -ENOTSUP;
		syslog(LOG_ERR, "Failed to attach handler to SIGTERM");
		goto daemon_out;
	}
	if (signal(SIGINT, sigterm_handler) == SIG_ERR) {
		rc = -ENOTSUP;
		syslog(LOG_ERR, "Failed to attach handler to SIGINT");
		goto daemon_out;
	}
 	/* TODO: eCryptfs context via daemon */
 	cryptfs_get_ctx_opts()->prompt = prompt_callback;
	rc = init_netlink_daemon();
	if (rc) {
		syslog(LOG_ERR,
		       "Error initializing netlink daemon; rc = [%d]\n", rc);
		goto daemon_out;
	}
	rc = ecryptfs_init_netlink(&ecryptfs_socket);
	if (rc) {
		syslog(LOG_ERR, "Failed to run netlink daemon\n");
		goto daemon_out;
	}
	rc = ecryptfs_send_netlink(ecryptfs_socket, NULL,
				   ECRYPTFS_NLMSG_HELO, 0, 0);
	if (rc < 0) {
		syslog(LOG_ERR, "Failed to register netlink daemon with the "
		       "eCryptfs kernel module\n");
		goto daemon_out;
	}
	rc = ecryptfs_run_netlink_daemon(ecryptfs_socket);
daemon_out:
	ecryptfsd_exit(rc);
	return rc;
}

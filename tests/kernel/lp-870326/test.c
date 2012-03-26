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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <limits.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

#define MMAP_LEN	(8192)

/* read kernel log */
char *klog_read(void)
{
	int len;
	char *klog;

	if ((len = klogctl(10, NULL, 0)) < 0)
		return NULL;
	
	if ((klog = calloc(1, len)) == NULL)
		return NULL;

	if (klogctl(3, klog, len) < 0) {
		free(klog);
		return NULL;
	}
	return klog;
}

/*
 *  https://bugs.launchpad.net/ubuntu/+bug/870326
 *	open(), mmap(), close() and write to mapping causes
 * 	an error.
 */
int main(int argc, char **argv)
{
	int fd;
	int rc = TEST_PASSED;
	unsigned int *ptr;
	char buffer[MMAP_LEN];
	char *klog_before;
	char *klog_after, *klog_new_text;
	size_t n, lastline_len = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: file\n");
		exit(TEST_ERROR);
	}

	if ((fd = open(argv[1], O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) < 0) {
		fprintf(stderr, "Cannot create %s : %s\n",
			argv[1], strerror(errno));
		exit(TEST_ERROR);
	}

	memset(buffer, 'X', sizeof(buffer));
	if (write(fd, buffer, sizeof(buffer)) < 0) {
		fprintf(stderr, "Failed to write to %s : %s\n",
			argv[1], strerror(errno));
		close(fd);
		rc = TEST_ERROR;
		goto tidy;
	}

	ptr = mmap(NULL, MMAP_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "Cannot mmap file %s : %s\n",
			argv[1], strerror(errno));
		close(fd);
		rc = TEST_ERROR;
		goto tidy;
	}
	
	if (close(fd) < 0) {
		fprintf(stderr, "Failed to close : %s\n", strerror(errno));
		munmap(ptr, MMAP_LEN);
		rc = TEST_ERROR;
		goto tidy;
	}

	if ((klog_before = klog_read()) == NULL) {
		fprintf(stderr, "Failed to read kernel log\n");
		munmap(ptr, MMAP_LEN);
		rc = TEST_ERROR;
		goto tidy;
	}

	/* Seek back to start of last line */
	if ((n = strlen(klog_before)) > 0) {
		n--;
		lastline_len++;
		while (n > 0 && klog_before[n-1] != '\n') {
			n--;
			lastline_len++;
		}
	}

	/* Modify pages, this caused bug LP#870326 */
	memset(ptr, ' ', MMAP_LEN);

	if (munmap(ptr, MMAP_LEN) < 0) {
		fprintf(stderr, "munmap failed : %s\n", strerror(errno));
		free(klog_before);
		rc = TEST_ERROR;
		goto tidy;
	}
	
	/*
	 * Get klog again, find previous klog last line
	 * and offset to end of this
	 */
	if ((klog_after = klog_read()) == NULL) {
		fprintf(stderr, "Failed to read kernel log\n");
		free(klog_before);
		rc = TEST_ERROR;
		goto tidy;
	}
	klog_new_text = strstr(klog_after, klog_before + n);

	/* Any new kernel log lines contain the error message? */
	if (klog_new_text &&
	    strstr(klog_new_text + lastline_len,
		  "Error attempting to write lower page"))
		rc = TEST_FAILED;

	free(klog_before);
	free(klog_after);
tidy:
	unlink(argv[1]);

	exit(rc);
}

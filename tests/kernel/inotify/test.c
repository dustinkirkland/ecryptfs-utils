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
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/inotify.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

#define DIR_FLAGS	(S_IRWXU | S_IRWXG)
#define FILE_FLAGS	(S_IRUSR | S_IWUSR)

#define TIME_OUT	(15)	/* Duration in secs for inotify to report something */
#define BUF_SIZE	(4096)
#define MOVE_PATH	"/tmp/test_file"

typedef int (*test_helper)(char *path, void *private);
typedef int (*test_func)(char *path);

#define flags_check(buf, flags, flag)	\
	if (flags & flag)		\
		flags_add(buf, #flag)

void flags_add(char *buff, char *flagstr)
{
	if (*buff == '\0') {
		strcpy(buff, flagstr);
	} else {
		strcat(buff, " ");
		strcat(buff, flagstr);
	}
}

/*
 *  flags_to_str()
 *	convert inotify flags to human readable form
 */
char *flags_to_str(int flags)
{
	static char buf[4096];

	*buf = '\0';

	flags_check(buf, flags, IN_ACCESS);
	flags_check(buf, flags, IN_MODIFY);
	flags_check(buf, flags, IN_ATTRIB);
	flags_check(buf, flags, IN_CLOSE_WRITE);
	flags_check(buf, flags, IN_CLOSE_NOWRITE);
	flags_check(buf, flags, IN_OPEN);
	flags_check(buf, flags, IN_MOVED_FROM);
	flags_check(buf, flags, IN_MOVED_TO);
	flags_check(buf, flags, IN_CREATE);
	flags_check(buf, flags, IN_DELETE);
	flags_check(buf, flags, IN_DELETE_SELF);
	flags_check(buf, flags, IN_MOVE_SELF);
	flags_check(buf, flags, IN_UNMOUNT);

	return buf;
}


/*
 *  test_inotify()
 *	run a given test helper function 'func' and see if this triggers the
 *	required inotify event flags 'flags'.  Return TEST_FAILED if inotify()
 *	fails to work or match the require flags, TEST_ERROR if something went
 *	horribly wrong, or TEST_PASSED if it worked as expected
 */
int test_inotify(char *filename,/* Filename in test */
	char *watchname,	/* File or directory to watch using inotify */
	char *matchname,	/* Filename we expect inotify event to report */
	test_helper func,	/* Helper func */
	int flags,		/* IN_* flags to watch for */
	void *private)		/* Helper func private data */
{
	int len;
	int fd;
	int wd;
	int ret = 0;
	char buffer[1024];
	int check_flags = flags;
	int ignored = 0;

	if ((fd = inotify_init()) < 0) {
    		fprintf(stderr, "inotify_init failed: %s", strerror(errno));
		return TEST_FAILED;
	}

  	if ((wd = inotify_add_watch(fd, watchname, flags)) < 0) {
		close(fd);
    		fprintf(stderr, "inotify_add_watch failed: %s", strerror(errno));
		return TEST_FAILED;
	}

	if (func(filename, private) < 0) {
		close(fd);
		return TEST_ERROR;
	}

	while (check_flags) {
		int i = 0;
		struct timeval tv;
		fd_set rfds;
		int err;

		/* We give inotify TIME_OUT seconds to report back */
		tv.tv_sec = TIME_OUT;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		/* Wait for an inotify event ... */
		err = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (err == -1) {
			fprintf(stderr, "Select error: %s\n", strerror(errno));
			ret = TEST_FAILED;
			break;
		} else if (err == 0) {
			fprintf(stderr, "Timeout waiting for event flags 0x%x (%s)\n", flags, flags_to_str(flags));
			ret = TEST_FAILED;
			break;
		}

		if ((len = read(fd, buffer, sizeof(buffer))) < 0) {
			fprintf(stderr, "Error reading inotify fd: %s\n", strerror(errno));
			ret = TEST_FAILED;
			break;
		}

		/* Scan through inotify events */
		while (i < len) {
			int f;
			struct inotify_event *event = (struct inotify_event *)&buffer[i];

			/*
 			 * IN_IGNORED indicates the watch file/dir was removed and
			 * a side effect is that the kernel removes the watch so
			 * we shouldn't use inotify_rm_watch to reap this later
			 */
			if (event->mask & IN_IGNORED)
				ignored = 1;

			f = event->mask & (IN_DELETE_SELF | IN_MOVE_SELF |
					   IN_MOVED_TO | IN_MOVED_FROM | IN_ATTRIB);

			if (event->len &&
			    strcmp(event->name, matchname) == 0 &&
			    flags & event->mask)
				check_flags &= ~(flags & event->mask);
			else if (flags & f)
				check_flags &= ~(flags & event->mask);

			i += sizeof(struct inotify_event) + event->len;
		}
	}

	/* Note: EINVAL happens if the watched file itself is deleted */
	if (!ignored)
		inotify_rm_watch(fd, wd);
	close(fd);

	return ret;
}


/*
 *  mk_filename()
 *	simple helper to create a filename
 */
void inline mk_filename(char *filename, size_t len, const char *path, const char *name)
{
	snprintf(filename, len, "%s/%s", path, name);
}

/*
 *  mk_file()
 * 	create file of length sz bytes
 */
int mk_file(char *filename, size_t sz)
{
	int fd;

	char buffer[BUF_SIZE];

	(void)unlink(filename);

	if ((fd = open(filename, O_CREAT | O_RDWR, FILE_FLAGS)) < 0) {
		fprintf(stderr, "Cannot create %s: %s\n", filename, strerror(errno));
		return -1;
	}

	memset(buffer, 'x', BUF_SIZE);

	while (sz > 0) {
		size_t n = (sz > BUF_SIZE) ? BUF_SIZE : sz;
		int ret;

		if ((ret = write(fd, buffer, n)) < 0) {
			fprintf(stderr, "Error writing to file %s: %s\n",
				filename, strerror(errno));
			close(fd);
			return -1;
		}
		sz -= ret;
	}

	if (close(fd) < 0) {
		fprintf(stderr, "Cannot close %s: %s\n", filename, strerror(errno));
		return -1;
	}

	return 0;
}


int test_attrib_helper(char *path, void *dummy)
{
	if (chmod(path, S_IRUSR | S_IWUSR) < 0) {
		fprintf(stderr, "Cannot chmod %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int test_attrib_file(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return TEST_ERROR;

	ret = test_inotify(filepath, path, "test_file", test_attrib_helper, IN_ATTRIB, NULL);
	unlink(filepath);

	return ret;
}

int test_access_helper(char *path, void *dummy)
{
	int fd;
	char buffer[1];

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	/* Just want to force an access */
	if (read(fd, buffer, 1) < 0) {
		fprintf(stderr, "Cannot read %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int test_access_file(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return TEST_ERROR;

	ret = test_inotify(filepath, path, "test_file", test_access_helper, IN_ACCESS, NULL);
	(void)unlink(filepath);

	return ret;
}

int test_modify_helper(char *path, void *dummy)
{
	int fd;
	char buffer[1];

	if (mk_file(path, 4096) < 0)
		return -1;

	if ((fd = open(path, O_RDWR)) < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (write(fd, buffer, 1) < 0) {
		fprintf(stderr, "Cannot read %s: %s\n", path, strerror(errno));
		(void)unlink(path);
		return -1;
	}
	(void)unlink(path);
	return 0;
}

int test_modify_file(char *path)
{
	char filepath[PATH_MAX];

	mk_filename(filepath, PATH_MAX, path, "test_file");

	return test_inotify(filepath, path, "test_file", test_modify_helper, IN_MODIFY, NULL);
}

int test_creat_helper(char *path, void *dummy)
{
	if (creat(path, FILE_FLAGS) < 0) {
		fprintf(stderr, "Cannot creat %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int test_creat_file(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");

	ret = test_inotify(filepath, path, "test_file", test_creat_helper, IN_CREATE, NULL);
	unlink(filepath);
	return ret;
}

int test_open_helper(char *path, void *dummy)
{
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}
	close(fd);
	return 0;
}

int test_open_file(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return TEST_ERROR;

	ret = test_inotify(filepath, path, "test_file", test_open_helper, IN_OPEN, NULL);
	(void)unlink(filepath);
	return ret;
}


int test_delete_helper(char *path, void *dummy)
{
	if (unlink(path) < 0) {
		fprintf(stderr, "Cannot unlink %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int test_delete_file(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return TEST_ERROR;

	ret = test_inotify(filepath, path, "test_file", test_delete_helper, IN_DELETE, NULL);

	/* We remove (again) it just in case the test failed */
	(void)unlink(filepath);
	return ret;
}

int test_delete_self_helper(char *path, void *dummy)
{
	if (rmdir(path) < 0) {
		fprintf(stderr, "Cannot rmdir %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int test_delete_self(char *path)
{
	char filepath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_dir");
	if (mkdir(filepath, DIR_FLAGS) < 0)
		return TEST_ERROR;

	ret = test_inotify(filepath, filepath, "test_dir", test_delete_self_helper, IN_DELETE_SELF, NULL);
	/* We remove (again) in case the test failed */
	(void)rmdir(filepath);

	return ret;
}

int test_move_self_helper(char *oldpath, void *private)
{
	char *newpath = (char*)private;

	if (rename(oldpath, newpath) < 0) {
		fprintf(stderr, "Cannot rename %s to %s: %s\n",
			oldpath, newpath, strerror(errno));
		return -1;
	}
	return 0;
}

int test_move_self(char *path)
{
	char filepath[PATH_MAX];
	char newpath[PATH_MAX];
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_dir");
	if (mkdir(filepath, DIR_FLAGS) < 0) {
		fprintf(stderr, "Cannot mkdir %s: %s\n", filepath, strerror(errno));
		return TEST_ERROR;
	}
	mk_filename(newpath, PATH_MAX, path, "renamed_dir");

	ret = test_inotify(filepath, filepath, "test_dir", test_move_self_helper, IN_MOVE_SELF, newpath);
	(void)rmdir(newpath);

	return ret;
}

int test_moved_to_helper(char *newpath, void *private)
{
	char *oldpath = (char*)private;

	if (rename(oldpath, newpath) < 0) {
		fprintf(stderr, "Cannot rename %s to %s: %s\n",
			oldpath, newpath, strerror(errno));
		return -1;
	}
	return 0;
}

int test_moved_to(char *path)
{
	char olddir[PATH_MAX];
	char oldfile[PATH_MAX];
	char newfile[PATH_MAX];
	int ret;

	mk_filename(olddir, PATH_MAX, path, "new_dir");
	(void)rmdir(olddir);
	if (mkdir(olddir, DIR_FLAGS) < 0) {
		fprintf(stderr, "Cannot create directory %s: %s\n", olddir, strerror(errno));
		return TEST_ERROR;
	}
	mk_filename(oldfile, PATH_MAX, olddir, "test_file");
	if (mk_file(oldfile, 4096) < 0)
		return TEST_ERROR;

	mk_filename(newfile, PATH_MAX, path, "test_file");

	ret = test_inotify(newfile, path, "test_dir", test_moved_to_helper, IN_MOVED_TO, oldfile);
	(void)rmdir(olddir);
	(void)unlink(newfile);

	return ret;
}

int test_moved_from_helper(char *oldpath, void *private)
{
	char *newpath = (char*)private;

	if (rename(oldpath, newpath) < 0) {
		fprintf(stderr, "Cannot rename %s to %s: %s\n",
			oldpath, MOVE_PATH, strerror(errno));
		return -1;
	}
	return 0;
}

int test_moved_from(char *path)
{
	char oldfile[PATH_MAX];
	char newdir[PATH_MAX];
	char newfile[PATH_MAX];
	int ret;

	mk_filename(oldfile, PATH_MAX, path, "test_file");
	if (mk_file(oldfile, 4096) < 0)
		return TEST_ERROR;
	mk_filename(newdir, PATH_MAX, path, "new_dir");
	(void)rmdir(newdir);
	if (mkdir(newdir, DIR_FLAGS) < 0) {
		fprintf(stderr, "Cannot create directory %s: %s\n", newdir, strerror(errno));
		return TEST_ERROR;
	}
	mk_filename(newfile, PATH_MAX, newdir, "test_file");

	ret = test_inotify(oldfile, path, "test_dir", test_moved_from_helper, IN_MOVED_FROM, newfile);
	unlink(newfile);
	(void)rmdir(newdir);

	return ret;
}

int test_close_write_helper(char *path, void *fdptr)
{
	int fd = *(int*)fdptr;

	(void)close(fd);

	return 0;
}

int test_close_write_file(char *path)
{
	char filepath[PATH_MAX];
	int fd;
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return -1;

	if ((fd = open(filepath, O_RDWR)) < 0) {
		fprintf(stderr, "Cannot re-open %s: %s\n", filepath, strerror(errno));
		return -1;
	}

	ret = test_inotify(filepath, path, "test_file", test_close_write_helper, IN_CLOSE_WRITE, (void*)&fd);
	(void)unlink(filepath);

	return ret;
}

int test_close_nowrite_helper(char *path, void *fdptr)
{
	int fd = *(int*)fdptr;

	(void)close(fd);

	return 0;
}

int test_close_nowrite_file(char *path)
{
	char filepath[PATH_MAX];
	int fd;
	int ret;

	mk_filename(filepath, PATH_MAX, path, "test_file");
	if (mk_file(filepath, 4096) < 0)
		return TEST_ERROR;

	if ((fd = open(filepath, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot re-open %s: %s\n", filepath, strerror(errno));
		(void)unlink(filepath);
		return TEST_ERROR;
	}

	ret = test_inotify(filepath, path, "test_file", test_close_nowrite_helper, IN_CLOSE_NOWRITE, (void*)&fd);
	(void)unlink(filepath);

	return ret;
}

struct {
	test_func 	func;
	char*		description;
} inotify_test[] = {
	{ test_access_file, 		"IN_ACCESS" },
	{ test_modify_file,		"IN_MODIFY" },
	{ test_attrib_file,		"IN_ATTRIB" },
	{ test_close_write_file,	"IN_CLOSE_WRITE" },
	{ test_close_nowrite_file,	"IN_CLOSE_NOWRITE" },
	{ test_open_file,		"IN_OPEN" },
	{ test_moved_from,		"IN_MOVED_FROM" },
	{ test_moved_to,		"IN_MOVED_TO" },
	{ test_creat_file,		"IN_CREATE" },
	{ test_delete_file,		"IN_DELETE" },
	{ test_delete_self,		"IN_DELETE_SELF" },
	{ test_move_self,		"IN_MOVE_SELF" },
	{ NULL,				NULL }
};

int main(int argc, char **argv)
{
	int i;
	int test_failed = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s path\n", argv[0]);
		fprintf(stderr, "\twhere path is the path to run the inotify file tests in\n");
		exit(TEST_ERROR);
	}

	if (mkdir(argv[1], DIR_FLAGS) < 0) {
		if (errno != EEXIST) {
			fprintf(stderr, "Cannot create directory %s\n", argv[1]);
			exit(TEST_ERROR);
		}
	}

	for (i=0; inotify_test[i].func; i++) {
		int ret = inotify_test[i].func(argv[1]);
		/* Something went horribly wrong, bail out early */
		if (ret == TEST_ERROR) {
			printf("%s test encounted an error\n", inotify_test[i].description);
			exit(TEST_ERROR);
		}

		if (ret == TEST_FAILED) {
			test_failed++;
		}
		
	}

	(void)rmdir(argv[1]);

	exit(test_failed ? TEST_FAILED : TEST_PASSED);
}

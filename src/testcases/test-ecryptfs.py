#! /usr/bin/env python

import os
import sys
import getopt
import re

distro_str_dict = {"rh": "Red Hat-based",
		   "gentoo": "Gentoo",
		   "deb": "Debian-based"}

def process_args(ctx, opts, args):
	for o, a in opts:
		if o in ("-d", "--distro="):
			ctx.distro = a
		if o is "--dir":
			ctx.mount_dir = a
		if o in ("-h", "--help"):
			print "Usage:"
			print
			print "test-ecryptfs.py [-d|--distro=][rh|gentoo|deb]"
	if ctx.distro is None:
		print "No distro given; defaulting to Red Hat-based"
		ctx.distro = 'rh'
	if ctx.mount_dir is None:
		print "No mount directory given; defaulting to /secret"
		ctx.mount_dir = '/secret'
	ctx.orig_pwd = os.getcwd()
	
class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

chdir_after_tests = ["passphrase-mount-good"]

# base_test_descriptors are basic tests run under a single mount
# session
base_test_descriptors = [
	["Perform basic passphrase mount", # alias
	 "passphrase-mount-good",          # name
	 "keyutils",                       # rh_base_package_name
	 None,                             # gentoo_base_package_name
	 None,                             # deb_base_package_name
	 None,                             # source_base_package_name
	 "keyctl show",                    # check_command
	 None,                             # source_url
	 None,                             # setup_command
	 "mount -t ecryptfs -o key=passphrase:passwd=test,cipher=aes," \
	 "ecryptfs_key_bytes=16,passthrough=n,no_sig_cache [MOUNTDIR] " \
	 "[MOUNTDIR]",
	 0,                                # expected_rc
	 None,                             # post_command
	 "umount [MOUNTDIR]; keyctl unlink " \
	 "`keyctl search @u user d395309aaad4de06` @u"], # cleanup_command
	["List directory contents",
	 "listdir",
	 None,
	 None,
	 None,
	 None,
	 None,                             # check_command
	 None,
	 None,
	 "ls",
	 0,
	 None,
	 None],
	["Create new file",
	 "createfile",
	 None,
	 None,
	 None,
	 None,
	 None,                             # check_command
	 None,
	 None,
	 "echo 'test' > test.txt",
	 0,
	 None,
	 "rm -f test.txt"],
	["Stat new file",
	 "statfile",
	 None,
	 None,
	 None,
	 None,
	 None,                             # check_command
	 None,
	 None,
	 "stat test.txt | grep 'Size' | awk '{print $2;}'| egrep '^5$'",
	 0,
	 None,
	 None],
	["Read new file",
	 "readfile",
	 None,
	 None,
	 None,
	 None,
	 None,                             # check_command
	 None,
	 None,
	 "egrep '^test$' test.txt",
	 0,
	 None,
	 None],
	["Connectathon basic",
	 "connectathon-basic",
	 None,
	 None,
	 None,
	 None,
	 "ls cthon04",                     # check_command
	 "http://www.connectathon.org/nfstests.tar.gz",
	 "cp time-tmp.sh /usr/local/bin; tar xzf nfstests.tar.gz; cd cthon04; " \
	 "cp ../tests.init .; make",
	 "cd [ORIGPWD]/cthon04; ./runtests -b -f [MOUNTDIR]/1; cd -",
	 0,
	 "cd [MOUNTDIR]",
	 "rm -f /usr/local/bin/time-tmp.sh"],
	["Connectathon general",
	 "connectathon-general",
	 None,
	 None,
	 None,
	 None,
	 None,                             # check_command
	 None,
	 "cd cthon04/general; cp ../../runtests.wrk .",
	 "cd [ORIGPWD]/cthon04; ./runtests -g -f [MOUNTDIR]/1; cd -",
	 0,
	 "cd [MOUNTDIR]",
	 None]
	]

mount_umount_test_descriptors = [
	["Mount, write, umount, mount, read", # alias
	 "mount-umount-mount-1",           # name
	 None,                             # rh_base_package_name
	 None,                             # gentoo_base_package_name
	 None,                             # deb_base_package_name
	 None,                             # source_base_package_name
	 None,                             # check_command
	 None,                             # source_url
	 None,                             # setup_command
	 "mount -t ecryptfs -o key=passphrase:passwd=test,cipher=aes," \
	 "ecryptfs_key_bytes=16,passthrough=n,no_sig_cache [MOUNTDIR] " \
	 "[MOUNTDIR] && " \
	 "echo \"test\" > [MOUNTDIR]/test1.txt " \
	 "&& umount [MOUNTDIR] && " \
	 "mount -t ecryptfs -o key=passphrase:passwd=test,cipher=aes," \
	 "ecryptfs_key_bytes=16,passthrough=n,no_sig_cache [MOUNTDIR] " \
	 "[MOUNTDIR] &&" \
	 "grep \"^test$\" [MOUNTDIR]/test1.txt " \
	 "&& echo \"Success\" && rm -f [MOUNTDIR]/test1.txt && " \
	 "umount [MOUNTDIR]",
	 0,                                # expected_rc
	 None,                             # post_command
	 "keyctl unlink " \
	 "`keyctl search @u user d395309aaad4de06` @u"], # cleanup_command
	["Mount, write, mkdir, write, umount, mount, read", # alias
	 "mount-umount-mount-2",           # name
	 None,                             # rh_base_package_name
	 None,                             # gentoo_base_package_name
	 None,                             # deb_base_package_name
	 None,                             # source_base_package_name
	 None,                             # check_command
	 None,                             # source_url
	 None,                             # setup_command
	 "mount -t ecryptfs -o key=passphrase:passwd=test,cipher=aes," \
	 "ecryptfs_key_bytes=16,passthrough=n,no_sig_cache [MOUNTDIR] " \
	 "[MOUNTDIR] && " \
	 "echo \"test\" > [MOUNTDIR]/test1.txt " \
	 "&& mkdir [MOUNTDIR]/test2 " \
	 "&& echo \"test\" > [MOUNTDIR]/test2/test3.txt " \
	 "&& echo \"test\" > [MOUNTDIR]/test4.txt " \
	 "&& umount [MOUNTDIR] && " \
	 "mount -t ecryptfs -o key=passphrase:passwd=test,cipher=aes," \
	 "ecryptfs_key_bytes=16,passthrough=n,no_sig_cache [MOUNTDIR] " \
	 "[MOUNTDIR] &&" \
	 "grep \"^test$\" [MOUNTDIR]/test1.txt " \
	 "&& grep \"^test$\" [MOUNTDIR]/test2/test3.txt " \
	 "&& grep \"^test$\" [MOUNTDIR]/test4.txt " \
	 "&& echo \"Success\" && rm -rf [MOUNTDIR]/test* && " \
	 "umount [MOUNTDIR]",
	 0,                                # expected_rc
	 None,                             # post_command
	 None]                             # cleanup_command
	]

class test:
	alias = None
	name = None
	rh_base_package_name = None
	gentoo_base_package_name = None
	deb_base_package_name = None
	source_base_package_name = None
	source_url = None
	check_command = None
	setup_command = None
	exec_command = None
	expected_rc = 0
	post_command = None
	cleanup_command = None
	status = None

	def __init__(self, descriptor):
		(self.alias,
		 self.name,
		 self.rh_base_package_name,
		 self.gentoo_base_package_name,
		 self.deb_base_package_name,
		 self.source_base_package_name,
		 self.check_command,
		 self.source_url,
		 self.setup_command,
		 self.exec_command,
		 self.expected_rc,
		 self.post_command,
		 self.cleanup_command) = descriptor

	def __str__(self):
		str =   "Test\n"
		str = "%s----\n" % str
		str = "%s *  alias: [%s]\n" % (str, self.alias)
		str = "%s *   name: [%s]\n" % (str, self.name)
#		str = "%s * status: [%s]\n" % (str, self.status)
		return str

	def distro_install(self, ctx):
		print "ctx.distro = [%s]; self.rh_base_package_name = [%s]" \
		      % (ctx.distro, self.rh_base_package_name)
		if ctx.distro == "rh":
			if self.rh_base_package_name != None:
				print "Attempting to install distro package " \
				      "[%s]" % self.rh_base_package_name
				rc = os.system("yum install -y %s" % \
					       self.rh_base_package_name)
				if rc != 0:
					print "Trouble installing [%s] package" \
					      % self.rh_base_package_name
					raise test_init_exception
			else:
				raise test_init_exception

	def init(self, ctx):
		if self.exec_command != None:
			self.exec_command = self.exec_command.replace( \
				'[MOUNTDIR]', ctx.mount_dir)
			self.exec_command = self.exec_command.replace( \
				'[ORIGPWD]', ctx.orig_pwd)
		if self.post_command != None:
			self.post_command = self.post_command.replace( \
				'[MOUNTDIR]', ctx.mount_dir)
		if self.cleanup_command != None:
			self.cleanup_command = self.cleanup_command.replace( \
				'[MOUNTDIR]', ctx.mount_dir)
		if self.check_command != None:
			try:
				print "Checking command: [%s]" \
				      % self.check_command
				rc = os.system(self.check_command)
				if rc != 0:
					print "Error executing [%s]; " \
					      "attempting distro install" \
					      % self.check_command
					try:
						self.distro_install(ctx)
					except:
						cmd = "wget %s" % self.source_url
						os.system(cmd)
			except:
				status = "failed"
				print "[%s]: Test check failed" % self.name
				raise test_init_exception
		if self.setup_command is None:
			status = "setup"
			return
		try:
			rc = os.system(self.setup_command)
		except:
			status = "failed"
			print "[%s]: Test set up failed" % self.name
			raise test_init_exception
		if rc == 0:
			status = "setup"
			print "[%s]: Test set up" % self.name
		else:
			status = "failed"
			print "[%s]: Test set up failed" % self.name
			raise test_init_exception

	def run(self, ctx):
		if self.exec_command is None:
			raise "No exec_command"
		rc = os.system(self.exec_command)
		if rc == self.expected_rc:
			status = "passed"
			print "%s: Test passed" % self.name
		else:
			status = "failed"
			print "%s: Test failed; expected rc = [%d]; actual " \
			      "rc = [%d]" % (self.alias, self.expected_rc, rc)
		return rc
	def cleanup(self, ctx):
		if self.cleanup_command is None:
			status="clean"
			return
		rc = os.system(self.cleanup_command)
		if rc != 0:
			status="failed"
			print "%s: Test failed to clean up" % self.name
			return
		status="clean"

class test_context:
	distro = None
	mount_dir = None
	orig_pwd = None
	tests = []
	def __init__(self):
		None
	def __str__(self):
		str =   "Test Context\n"
		str = "%s------------\n" % str
		str = "%s *    distro: [%s]\n" % (str, self.distro)
		str = "%s * mount_dir: [%s]\n" % (str, self.mount_dir)
		str = "%s *  orig_pwd: [%s]\n" % (str, self.orig_pwd)
		return str

class test_init_exception(Exception):
	def __init__(self):
		None
	def __str__(self):
		return "Test init error"

def install_tests(ctx, test_descriptors):
	ctx.tests = []
	for td in test_descriptors:
		t = test(td)
		print "Registering test:"
		print t
		try:
			t.init(ctx)
		except test_init_exception:
			print "Error initializing test:"
			print t
		else:
			ctx.tests.append(t)

def run_tests(ctx):
	for t in ctx.tests:
		try:
			t.run(ctx)
		except:
			print "Error running test [%s]" % t.name
			raise
		if t.name in chdir_after_tests:
			os.chdir(ctx.mount_dir)

def run_test(ctx, name):
	for t in ctx.tests:
		if t.name == name:
			try:
				t.run(ctx)
			except:
				print "Error running test [%s]" % t.name
				raise
			if t.name in chdir_after_tests:
				os.chdir(ctx.mount_dir)

def cleanup_tests(ctx):
	for t in reversed(ctx.tests):
		if t.name in chdir_after_tests:
			os.chdir("/")
		t.cleanup(ctx)

def general_setup(ctx):
	uid = os.getuid()
	if uid != 0:
		raise "This test script must be run under uid 0 (root)"
	os.mkdir(ctx.mount_dir)
	print "This program assumes that you have inserted all the " \
	      "requisite kernel modules or that the environment is properly " \
	      "set up to auto-load the modules as needed."

def general_teardown(ctx):
	os.rmdir(ctx.mount_dir)

def main(argv=None):
	ctx = test_context()
	if argv is None:
		argv = sys.argv
	try:
		try:
			opts, args = getopt.getopt(argv[1:],
						   "hd:",
						   ["help", "distro=", "dir="])
		except getopt.error, msg:
			raise Usage(msg)
		process_args(ctx, opts, args)
	except Usage, err:
		print >> sys.stderr, err.msg
		print >> sys.stderr, "for help use --help"
		return 2
	print
	print ctx
	print "General setup."
	try:
		general_setup(ctx)
	except:
		print "Fatal exception whilst attempting to perform general " \
		      "setup"
		raise
	
	print "Registering base tests."
	try:
		install_tests(ctx, base_test_descriptors)
	except:
		print "Fatal exception whilst attempting to install testcases"
		raise
	print "Running tests."
	try:
		run_tests(ctx)
	except:
		print "Fatal exception whilst attempting to run testcases"
		raise
	print "Cleaning up."
	try:
		cleanup_tests(ctx)
	except:
		print "Fatal exception whilst attempting to clean up testcases"
		raise

	print "Registering mount-umount-mount tests."
	try:
		install_tests(ctx, mount_umount_test_descriptors)
	except:
		print "Fatal exception whilst attempting to install testcases"
		raise
	print "Running tests."
	try:
		run_tests(ctx)
	except:
		print "Fatal exception whilst attempting to run testcases"
		raise
	print "Cleaning up."
	try:
		cleanup_tests(ctx)
	except:
		print "Fatal exception whilst attempting to clean up testcases"
		raise

	print "General teardown."
	general_teardown(ctx)
	print "All tests passed."

if __name__ == "__main__":
	sys.exit(main())

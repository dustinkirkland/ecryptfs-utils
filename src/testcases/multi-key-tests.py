#!/usr/bin/python

import os
import sys

lower_path = sys.argv[1]
mount_point = sys.argv[2]
print "Lower path = [%s]" % lower_path
print "Mount point = [%s]" % mount_point
print "Clearing keyring"
cmd = "keyctl clear @u"
os.system(cmd)
print "Killing ecryptfsd"
cmd = "killall ecryptfsd"
os.system(cmd)
# 'a' + default salt -> a216278e6e397a04
# 'b' + default salt -> 97d42abf9fd3395c
# 'c' + default salt -> ccf6ee8211b7e3ad
cmd = "ecryptfs-add-passphrase a"
os.system(cmd)
cmd = "ecryptfs-add-passphrase b"
os.system(cmd)
cmd = "umount %s" % mount_point
os.system(cmd)
cmd = "mount -i -t ecryptfs %s %s -o rw,ecryptfs_key_bytes=16,ecryptfs_cipher=aes,ecryptfs_sig=a216278e6e397a04,ecryptfs_sig=97d42abf9fd3395c" % (lower_path, mount_point)
os.system(cmd)

cmd = "echo test > %s/test.txt" % mount_point
os.system(cmd)

cmd = "umount %s" % mount_point
os.system(cmd)

cmd = "keyctl clear @u"
os.system(cmd)

cmd = "ecryptfs-add-passphrase c"
os.system(cmd)

cmd = "mount -i -t ecryptfs %s %s -o rw,ecryptfs_key_bytes=16,ecryptfs_cipher=aes,ecryptfs_sig=ccf6ee8211b7e3ad" % (lower_path, mount_point)
os.system(cmd)

cmd = "cat %s/test.txt" % mount_point
rc = os.system(cmd)
if rc == 0:
    print "rc == 0; expected error"
    sys.exit(1)

cmd = "umount %s" % mount_point
os.system(cmd)

cmd = "ecryptfs-add-passphrase b"
os.system(cmd)

cmd = "mount -i -t ecryptfs %s %s -o rw,ecryptfs_key_bytes=16,ecryptfs_cipher=aes,ecryptfs_sig=ccf6ee8211b7e3ad" % (lower_path, mount_point)
os.system(cmd)

cmd = "cat %s/test.txt" % mount_point
rc = os.system(cmd)
if rc != 0:
    print "rc != 0; expected success"
    sys.exit(1)

cmd = "umount %s" % mount_point
os.system(cmd)

cmd = "keyctl clear @u"
os.system(cmd)


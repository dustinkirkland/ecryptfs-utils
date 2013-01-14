#!/bin/bash
#
# etl_funcs.sh: eCryptfs test library (etl) helper functions
# Author: Tyler Hicks <tyhicks@canonical.com>
#
# Copyright (C) 2012 Canonical Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

etl=$(dirname $BASH_SOURCE[0])

default_fekek_pass="foo"
default_fekek_salt_hex="0011223344556677"

default_fnek_pass="$default_fekek_pass"
default_fnek_salt_hex="9988776655443322"

default_lfs="ext4"
default_lmount_opts="rw,relatime"
default_ext2_opts="user_xattr,acl"
default_ext3_opts="user_xattr,acl,commit=600,barrier=1,data=ordered"
default_btrfs_opts="nodatacow"
default_mount_opts="rw,relatime,ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_sig=\${ETL_FEKEK_SIG}"
default_fne_mount_opts="${default_mount_opts},ecryptfs_fnek_sig=\${ETL_FNEK_SIG}"


#
# etl_add_fekek_passphrase [PASS] [SALT_HEX]
#
# Adds a passphrase-based file encryption key to the kernel keyring. A default
# PASS and SALT_HEX will be used if they are not specified. The key signature
# is exported into ETL_FEKEK_SIG upon success.
#
# Only call this directly if your test needs to add a specific fekek.
#
etl_add_fekek_passphrase()
{
	if [ -z "$1" ]; then
		pass=$default_fekek_pass
	else
		pass=$1
	fi
	if [ -z "$2" ]; then
		salt_hex=$default_fekek_salt_hex
	else
		salt_hex=$2
	fi

	sig=$(${etl}/etl-add-passphrase-key-to-keyring $pass $salt_hex)
	if [ $? -ne 0 ]; then
		return 1
	fi

	export ETL_FEKEK_SIG=$sig
	return 0
}

#
# etl_add_fnek_passphrase [PASS] [SALT_HEX]
#
# Adds a passphrase-based filename encryption key to the kernel keyring. A
# default PASS and SALT_HEX will be used if they are not specified. The key
# signature is exported into ETL_FNEK_SIG upon success.
#
# Only call this directly if your test needs to add a specific fnek.
#
etl_add_fnek_passphrase()
{
	if [ -z "$1" ]; then
		pass=$default_fnek_pass
	else
		pass=$1
	fi
	if [ -z "$2" ]; then
		salt_hex=$default_fnek_salt_hex
	else
		salt_hex=$2
	fi

	sig=$(${etl}/etl-add-passphrase-key-to-keyring $pass $salt_hex)
	if [ $? -ne 0 ]; then
		return 1
	fi

	export ETL_FNEK_SIG=$sig
	return 0
}

#
# etl_add_keys
#
# Adds a fekek and, if appropriate, a fnek to the kernel keyring using the
# default values defined above. Most test cases requiring a generic mount will
# use this rather than the lower level functions that this calls.
#
# Set ETL_TEST_FNE to true if you want filename encryption enabled (it is best
# to lest the test harness handle that). ETL_FEKEK_SIG and, if appropriate,
# ETL_FNEK_SIG will contain the key signatures upon success.
#
etl_add_keys()
{
	# TODO: This should support non-passphrase based keys, too

	etl_add_fekek_passphrase
	if [ $? -ne 0 ]; then
		return 1
	fi

	if $ETL_TEST_FNE ; then
		etl_add_fnek_passphrase
		return $?
	fi

	return 0
}

#
# etl_unlink_key_sig SIGNATURE
#
# Unlinks the key corresponding to the specified signature.
#
etl_unlink_key_sig()
{
	if [ -z "$1" ]; then
		return 1
	fi

	show_line=$(keyctl list @u | grep -s $1)
	if [ $? -ne 0 ]; then
		return 1
	fi

	key=$(printf $show_line | awk -F ':' '{ print $1 }')
	keyctl unlink $key &>/dev/null
}

#
# etl_unlink_fekek
#
# Unlinks the key corresponding to the value of ETL_FEKEK_SIG. Unsets
# that variable upon success.
#
etl_unlink_fekek()
{
	if [ -z "$ETL_FEKEK_SIG" ]; then
	       return 1
	fi

	etl_unlink_key_sig $ETL_FEKEK_SIG
	if [ $? -ne 0 ]; then
		return 1
	fi

	unset ETL_FEKEK_SIG
}

#
# etl_unlink_fnek
#
# Unlinks the key corresponding to the value of ETL_FNEK_SIG. Unsets
# that variable upon success.
#
etl_unlink_fnek()
{
	if [ -z "$ETL_FNEK_SIG" ]; then
		return 1
	fi

	etl_unlink_key_sig $ETL_FNEK_SIG
	if [ $? -ne 0 ]; then
		return 1
	fi

	unset ETL_FNEK_SIG
}

#
# etl_unlink_keys
#
# Unlinks the fekek and, if appropriate, the fnek from the kernel keyring. See
# the functions called by etl_unlink_keys() for more information.
#
# Most test cases requiring a generic mount will use this rather than the lower
# level functions that this calls.
#
etl_unlink_keys()
{
	etl_unlink_fekek
	if [ $? -ne 0 ]; then
		return 1
	fi

	if $ETL_TEST_FNE ; then
		etl_unlink_fnek
		return $?
	fi

	return 0
}

#
# etl_create_disk DISK_SIZE [DIR_PATH]
#
# Creates a disk image for testing. This disk image will be formatted and ready
# for mounting as the lower filesystem.
#
# DISK_SIZE must be specified in 1K block sizes. DIR_PATH can be specified so
# that the image file is stored somewhere other than the /tmp/ directory.
#
etl_create_disk()
{
	if [ -z "$1" ]; then
		return 1
	fi
	if [ -z "$2" ]; then
		dir_path="/tmp"
	else
		dir_path="$2"
	fi
	if [ -z "$ETL_LFS" ]; then
		lfs=$default_lfs
	else
		lfs=$ETL_LFS
	fi

	img=$(mktemp -q /${dir_path}/etl-img-XXXXXXXXXX)
	if [ $? -ne 0 ]; then
		return 1
	fi

	dd if=/dev/zero of=$img bs=1024 count=$1 &>/dev/null
	if [ $? -ne 0 ]; then
		rm $img &>/dev/null
		return 1
	fi

	case $lfs in
	ext2|ext3|ext4)
		mkfs_force='-F'
		;;
	xfs)
		mkfs_force='-f'
		;;
	*)
		mkfs_force=''
		;;
	esac

	mkfs -t $lfs $mkfs_force $img &>/dev/null
	if [ $? -ne 0 ]; then
		rm $img &>/dev/null
		return 1
	fi

	export ETL_DISK=$img
	export ETL_LMOUNT_SRC=$img
	export ETL_LFS=$lfs
}

#
# etl_remove_disk
#
# Removes any lower test disk created by etl_create_disk().
#
etl_remove_disk()
{
	if [ -z "$ETL_DISK" ] || [ ! -f "$ETL_DISK" ]; then
		return 1
	fi
	if grep -q $ETL_DISK /proc/mounts; then
		return 1
	fi

	rm -f $ETL_DISK &>/dev/null
	unset ETL_DISK
}

#
# etl_load_ecryptfs
#
# Ensures that the eCryptfs kernel code is either loaded, if a module, or
# compiled in.
#
# If your test only needs an eCryptfs mount, don't call this function. The mount
# process will autoload the module for you. If you need access to something like
# /dev/ecryptfs, but don't need an eCryptfs mount, this function is for you.
#
etl_load_ecryptfs()
{
	if ! grep -q ecryptfs /proc/filesystems; then
		modprobe ecryptfs
		return $?
	fi

	return 0
}

#
# etl_construct_lmount_opts
#
# Construct the lower filesystem mount options. If mount options are already
# set, nothing is done. Otherwise, the default mount options for the lower
# filesystem are set.
#
# If you need specific options, you should probably construct them yourself and
# simply export them as ETL_LMOUNT_OPTS. This function is mostly a helper for
# other etl functions.
#
etl_construct_lmount_opts()
{
	if [ -n "$ETL_LMOUNT_OPTS" ]; then
		return 0
	fi
	if [ -z "$ETL_LFS" ]; then
		export ETL_LFS=$default_lfs
	fi

	# TODO: Add support for more filesystems
	case $ETL_LFS in
	ext2)
		lmount_opts=${default_lmount_opts},${default_ext2_opts}
		;;
	ext3|ext4)
		lmount_opts=${default_lmount_opts},${default_ext3_opts}
		;;
	btrfs)
		lmount_opts=${default_lmount_opts},${default_btrfs_opts}
		;;
	*)
		lmount_opts=$default_lmount_opts
		;;
	esac

	if [ -f "$ETL_LMOUNT_SRC" ]; then
		lmount_opts="${lmount_opts},loop"
	fi

	export ETL_LMOUNT_OPTS=$lmount_opts
	return 0
}

#
# etl_lmount
#
# Mounts the lower filesystem based upon the various env variables.
#
etl_lmount()
{
	if [ -z "$ETL_LMOUNT_SRC" ] || [ -z "$ETL_LMOUNT_DST" ]; then
		return 1
	fi
	if ! etl_construct_lmount_opts; then
		return 1
	fi

	mount -t "$ETL_LFS" -o "$ETL_LMOUNT_OPTS" \
		"$ETL_LMOUNT_SRC" "$ETL_LMOUNT_DST" &>/dev/null
}

#
# etl_lumount
#
# Unmounts the lower filesystem.
#
etl_lumount()
{
	if [ -z "$ETL_LMOUNT_SRC" ]; then
		return 1
	fi

	sync
	umount "$ETL_LMOUNT_DST" &>/dev/null
}

#
# etl_lmax_filesize
#
# Estimate on largest file that one can
# create in the lower filesystem.
#
etl_lmax_filesize()
{
	blks=$(df --total $ETL_LMOUNT_DST | tail -1 | awk '{print $4}')

	case $ETL_LFS in
	btrfs)
		# btrfs is a pain, since there is a big difference between the
		# amount of free space it reports and the maximum size of a file
		# one can produce before filling up the partition, especially
		# with small partitions. So instead we divide by 4 to ensure
		# we have more than enough free space. 
		#
		blks=$((blks / 4))
		;;
	xfs)
		# xfs misbehaves on small file systems when we truncate, according to
		# david@fromorbit.com:
		#
		# "The space is considered "busy" and won't be reused until the
		# truncate transaction hits the log and the space is free on disk. See
		# xfs_busy_extent.c
		# 
		# Basically, testing XFS performance on tiny filesystems is going to
		# show false behaviours. XFS is optimised for large filesystems and
		# will typically shows low space artifacts on small filesystems,
		# especially when you are doing things like filling most of the free
		# filesystem space with 1 file.
		# 
		# e.g.  1GB free on at 100TB filesystem will throttle behaviours (say
		# speculative preallocation) much more effectively because itis within
		# 1% of ENOSPC. That same 1GB free on a 1GB filesystem won't throttle
		# preallocation at all, and so that one file when it reaches a little
		# over 500MB will try to preallocate half the remaining space in the
		# filesystem because the filesystem is only 50% full...."
		#
		# So lets limit ourselves generously by using just 33% for 'small'
		# xfs file systems to leave plenty of slop and 50% for larger xfs
		# file systems.
		#
		if [ $blks -lt 5000000 ]; then
			blks=$((blks / 3))
		else
			blks=$((blks / 2))
		fi
		;;
	*)
		#
		# for other file systems we take off ~5% for some slop
		#
		slop=$((blks / 20))
		blks=$((blks - $slop))
		;;
	esac

	echo $blks
}

#
# etl_mount_i
#
# Performs an eCryptfs mount, bypassing the eCryptfs mount helper.
#
# If you're fine with the default eCryptfs mount options, or have constructed
# your own mount options, and have already added the appropriate keys to the
# kernel keyring, this is the easiest way to do an eCryptfs mount.
#
etl_mount_i()
{
	if [ -z "$ETL_MOUNT_SRC" ] || [ -z "$ETL_MOUNT_DST" ]; then
		return 1
	fi
	if [ -z "$ETL_MOUNT_OPTS" ]; then
		if [ -n "ETL_FNEK_SIG" ]; then
			export ETL_MOUNT_OPTS=$(eval \
						"echo $default_fne_mount_opts")
		else
			export ETL_MOUNT_OPTS=$(eval "echo $default_mount_opts")
		fi
	fi
	
	mount -it ecryptfs -o "$ETL_MOUNT_OPTS" \
		"$ETL_MOUNT_SRC" "$ETL_MOUNT_DST"
}

#
# etl_umount_i
#
# Unmounts the eCryptfs mount point specified by ETL_MOUNT_DST. Note that the
# eCryptfs umount helper will not be called.
#
etl_umount_i()
{
	if [ -z "$ETL_MOUNT_DST" ]; then
		return 1
	fi

	if ! grep -q $ETL_MOUNT_DST /proc/mounts; then
		return 1
	fi

	sync
	umount -i "$ETL_MOUNT_DST" &>/dev/null
}

#
# etl_umount
#
# Unmounts the eCryptfs mount point specified by ETL_MOUNT_DST. Note that the
# eCryptfs umount helper will be called.
#
etl_umount()
{
	if [ -z "$ETL_MOUNT_DST" ]; then
		return 1
	fi

	if ! grep -q $ETL_MOUNT_DST /proc/mounts; then
		return 1
	fi

	sync
	umount "$ETL_MOUNT_DST" &>/dev/null
}

#
# etl_create_test_dir
#
# Creates a directory for carrying out tests inside of the eCryptfs mount point
# (ETL_MOUNT_DST).
#
# Upon success, the newly created directory's name is echoed to stdout.
#
etl_create_test_dir()
{
	parent=

	if [ -z "$ETL_MOUNT_DST" ] && [ -z "$1" ]; then
		return 1
	fi

	if [ -z "$1" ]; then
		parent=$ETL_MOUNT_DST
	else
		parent=$1
	fi
	test_basename=$(basename $0)
	test_dir=$(mktemp -qd ${parent}/etl-${test_basename}-XXXXXXXXXX)
	if [ $? -ne 0 ]; then
		return 1;
	fi

	echo $test_dir
	return 0
}

#
# etl_remove_test_dir TEST_DIR
#
# Removes the specified test directory.
#
# For now, it is nothing much more than a wrapper around rm -rf, but it may
# gain more functionality and/or safety checks in the future, so please use it.
#
etl_remove_test_dir()
{
	if [ -z "$1" ]; then
		return 0
	elif [ ! -d "$1" ]; then
		return 1
	elif [ "$1" = "/" ]; then
		return 1
	fi

	rm -rf $1 &>/dev/null
}

#
# etl_find_lower_path UPPER_PATH [LOWER_MOUNT]
#
# Given a path to an eCryptfs inode, finds a path to the lower inode. Searches
# for the lower inode in $ETL_LMOUNT_DST, unless LOWER_MOUNT is specified. Be
# careful using this with an inode with multiple hard links, as only one lower
# path will be returned.
#
# Upon success, the lower path is echoed to stdout and zero is returned.
#
etl_find_lower_path()
{
	lmount=$ETL_LMOUNT_DST
	if [ -n "$2" ]; then
		lmount=$2
	fi
	if [ -z "lmount" ]; then
		return 1
	fi

	inum=$(stat --printf=%i $1)
	if [ $? -ne 0 ]; then
		return 1
	fi

	lower_path=$(find $lmount -inum $inum -print -quit 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$lower_path" ]; then
		return 1
	fi

	echo $lower_path
	return 0
}

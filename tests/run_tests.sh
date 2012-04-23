#!/bin/bash
#
# eCryptfs test suite harness
# Author: Tyler Hicks <tyhicks@canonical.com>
#
# Copyright (C) 2012 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
#
# Example usage:
#
# # ./tests/run_tests.sh -K -c destructive -d /dev/vdb -l /lower -u /upper
#
# This would run kernel tests in the destructive category, as defined in
# kernel/tests.rc. /dev/vdb would be the block device containing the lower
# filesystem, which would be mounted at /lower. The eCryptfs mount point would
# be /upper.
#

run_tests_dir=$(dirname $0)
rc=1

. ${run_tests_dir}/lib/etl_funcs.sh

blocks=0
categories=""
cleanup_lower_mnt=0
cleanup_upper_mnt=0
default_lower_fses="ext4"
device=""
disk_dir=""
failed=0
kernel=false
ktests=""
lower_fses=""
lower_mnt=""
passed=0
tests=""
upper_mnt=""
userspace=false
utests=""

run_tests_cleanup()
{
	if [ $cleanup_upper_mnt -ne 0 ] && [ -n "$upper_mnt" ]; then
		rm -rf "$upper_mnt"
	fi
	if [ $cleanup_lower_mnt -ne 0 ] && [ -n "$lower_mnt" ]; then
		rm -rf "$lower_mnt"
	fi
	etl_remove_disk
	exit $rc
}
trap run_tests_cleanup 0 1 2 3 15

run_tests()
{
	test_dir=$1
	tests=$2

	for etest in $tests; do
		printf "%-16s\t" $(basename "$etest" .sh)

		${test_dir}/${etest}
		if [ $? -ne 0 ]; then
			((failed++))
			printf "FAIL\n"
		else
			((passed++))
			printf "pass\n"
		fi
	done
}

run_kernel_tests_on_existing_device()
{
	echo "Running eCryptfs filesystem tests"

	run_tests "${run_tests_dir}/kernel" "$ktests"
	if [ $? -ne 0 ]; then
		echo "Failed to run eCryptfs filesystem tests" 1>&2
		rc=1
		exit
	fi

	if [ -n "$ETL_DISK" ]; then
		etl_remove_disk
	fi
}

run_kernel_tests_on_created_disk_image()
{
	lower_fses=$(echo $lower_fses | tr ',' ' ')
	for lower_fs in $lower_fses; do
		echo "Running eCryptfs filesystem tests on $lower_fs"

		if [ "$blocks" -gt 0 ]; then
			export ETL_LFS=$lower_fs
			etl_create_disk $blocks $disk_dir
			if [ $? -ne 0 ]; then
				echo "Failed to create disk for $lower_fs"\
				     "(skipping all tests on $lower_fs)" 1>&2
				continue
			fi
			export ETL_LMOUNT_SRC=$ETL_DISK
		fi

		run_tests "${run_tests_dir}/kernel" "$ktests"
		if [ $? -ne 0 ]; then
			echo "Failed to run eCryptfs filesystem tests on"\
			     "$lower_fs" 1>&2
			rc=1
			exit
		fi

		if [ -n "$ETL_DISK" ]; then
			etl_remove_disk
		fi
	done
}

usage()
{
	echo "Usage: $(basename $0) [options] -K -c categories -b blocks"
	echo "  or:  $(basename $0) [options] -K -c categories -d device"
	echo "  or:  $(basename $0) [options] -U -c categories"
	echo "  or:  $(basename $0) [options] -K -U -c categories -b blocks"
	echo
	echo "eCryptfs test harness"
	echo
	echo "  -b blocks	number of 1K blocks used when creating backing "
	echo "		disk for lower filesystem (not compatible "
	echo "		with -d)"
	echo "  -c categories	comma-separated test categories" \
				"(e.g., -c safe,destructive)"
	echo "  -D disk_dir	directory used to store created backing disk "
	echo "		when using -b (not compatible with -d)"
	echo "  -d device	backing device to mount lower filesystem, such "
	echo "		as /dev/sdd3 (not compatible with -b)"
	echo "  -f lower_fses	comma-separated lower filesystem types" \
				"(e.g., -f ext4,btrfs)"
	echo "		defaults to $default_lower_fses" \
			"(not compatible with -d)"
	echo "  -h		display this help and exit"
	echo "  -K		run tests relating to the kernel module"
	echo "  -l lower_mnt	destination path to mount lower filesystem"
	echo "  -t tests	comma-separated list of tests to run"
	echo "  -U		run tests relating to the userspace utilities"
	echo "  -u upper_mnt	destination path to mount upper filesystem"
}

while getopts "b:c:D:d:f:hKl:t:Uu:" opt; do
	case $opt in
	b)
		blocks=$OPTARG
		;;
	c)
		categories=$OPTARG
		;;
	d)
		device=$OPTARG
		;;
	D)
		disk_dir=$OPTARG
		;;
	f)
		lower_fses=$OPTARG
		;;
	h)
		usage
		rc=0
		exit
		;;
	K)
		kernel=true
		;;
	l)
		lower_mnt=$OPTARG
		;;
	t)
		tests=$OPTARG
		;;
	U)
		userspace=true
		;;
	u)
		upper_mnt=$OPTARG
		;;
	\?)
		usage 1>&2
		exit
		;;
	:)
		usage 1>&2
		exit
		;;
	esac
done

if ! $kernel && ! $userspace ; then
	# Must specify at least one of these
	echo "Must specify one of -U or -K" 1>&2
	usage 1>&2
	exit
elif [ -z "$categories" ] && [ -z "$tests" ]; then
	# Must either specify test categories or specific tests
	echo "Must specify a list of test categories or a list of tests" 1>&2
	usage 1>&2
	exit
fi

if $kernel ; then
	if [ "$blocks" -lt 1 ] && [ -z "$device" ]; then
		# Must specify blocks for disk creation *or* an existing device
		echo "Blocks for disk creation or an existing device must be" \
		     "specified" 1>&2
		usage 1>&2
		exit
	elif [ "$blocks" -gt 0 ] && [ -n "$device" ]; then
		# Can't specify blocks for disk *and* an existing device 
		echo "Cannot specify blocks for disk creation *and* also an" \
		     "existing device" 1>&2
		usage 1>&2
		exit
	elif [ -n "$disk_dir" ] && [ -n "$device" ]; then
		# Can't specify a dir for disk creation and an existing device
		echo "Cannot specify a directory for disk creation *and* also" \
		     "an existing device" 1>&2
		usage 1>&2
		exit
	elif [ -n "$device" ] && [ ! -b "$device" ]; then
		# A small attempt at making sure we're dealing with a block dev
		echo "Backing device must be a valid block device" 1>&2
		usage 1>&2
		exit
	elif [ -n "$device" ] && [ -n "$lower_fses" ]; then
		# We currently don't reformat block devices so we shouldn't
		# accept a list of lower filesystems to test on
		echo "Lower filesystems cannot be specified when using" \
		     "existing block devices" 1>&2
		usage 1>&2
		exit
	elif [ -n "$lower_mnt" ] && [ ! -d "$lower_mnt" ]; then
		# A small attempt at making sure we're dealing with directories
		echo "Lower mount point must exist" 1>&2
		usage 1>&2
		exit
	elif [ -n "$upper_mnt" ] && [ ! -d "$upper_mnt" ]; then
		# A small attempt at making sure we're dealing with directories
		echo "Upper mount point must exist" 1>&2
		usage 1>&2
		exit
	elif [ -n "$disk_dir" ] && [ ! -d "$disk_dir" ]; then
		# A small attempt at making sure we're dealing with a directory
		echo "Directory used to store created backing disk must" \
		     "exist" 1>&2
		usage 1>&2
		exit
	fi
fi

if [ -n "$device" ]; then
	export ETL_LMOUNT_SRC=$device
elif [ -z "$lower_fses" ]; then
	lower_fses=$default_lower_fses
fi

if [ -z "$lower_mnt" ]; then
	cleanup_lower_mnt=1
	lower_mnt=$(mktemp -dq /tmp/etl-lower-XXXXXXXXXX)
	if [ $? -ne 0 ]; then
		cleanup_lower_mnt=0
		rc=1
		exit
	fi
fi
export ETL_LMOUNT_DST=$lower_mnt
export ETL_MOUNT_SRC=$lower_mnt

if [ -z "$upper_mnt" ]; then
	cleanup_upper_mnt=1
	upper_mnt=$(mktemp -dq /tmp/etl-upper-XXXXXXXXXX)
	if [ $? -ne 0 ]; then
		cleanup_upper_mnt=0
		rc=1
		exit
	fi
fi
export ETL_MOUNT_DST=$upper_mnt

# Source in the kernel and/or userspace tests.rc files to build the test lists
categories=$(echo $categories | tr ',' ' ')
if $kernel ; then
	if [ -n "$tests" ]; then
		ktests=$(echo $tests | tr ',' ' ')
	else
		. ${run_tests_dir}/kernel/tests.rc
		for cat in $categories ; do
			eval cat_tests=\$$cat
			ktests="$ktests $cat_tests"
		done
	fi

	if [ -n "$device" ]; then
		run_kernel_tests_on_existing_device
	else
		run_kernel_tests_on_created_disk_image
	fi
fi
if $userspace ; then
	if [ -n "$tests" ]; then
		utests=$(echo $tests | tr ',' ' ')
	else
		. ${run_tests_dir}/userspace/tests.rc
		for cat in $categories ; do
			eval cat_tests=\$$cat
			utests="$utests $cat_tests"
		done
	fi

	echo "Running eCryptfs userspace tests"

	run_tests "${run_tests_dir}/userspace" "$utests"
	if [ $? -ne 0 ]; then
		rc=1
		exit
	fi
fi

echo ""
echo "Test Summary:"
echo "$passed passed"
echo "$failed failed"

rc=$failed
exit

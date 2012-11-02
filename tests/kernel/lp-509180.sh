#!/bin/bash
#
# lp-509180.sh: Test for https://launchpad.net/bugs/509180
# Author: Colin Ian King <colin.king@canonical.com>
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

test_script_dir=$(dirname $0)
rc=1
test_dir=""

. ${test_script_dir}/../lib/etl_funcs.sh

test_cleanup()
{
	etl_remove_test_dir $test_dir
	etl_umount
	etl_lumount
	etl_unlink_keys
	exit $rc
}
trap test_cleanup 0 1 2 3 15

# This test is mainly for the filename encryption case, but it is also valid for
# plaintext filename support
etl_add_keys || exit
etl_lmount || exit
etl_mount_i || exit
test_dir=$(etl_create_test_dir) || exit

# Test method: https://bugs.launchpad.net/ecryptfs/+bug/509180/comments/50
# Create 1 byte test file
echo "testing 1 2 3" > $test_dir/test_file
old_sum=`md5sum $test_dir/test_file | cut -d ' ' -f 1`
lower_file=`ls $ETL_MOUNT_SRC/ECRYPTFS*/*`

# Increment 9th byte so that eCryptfs marker fails validation
${test_script_dir}/lp-509180/test -i $lower_file || exit
etl_umount

etl_mount_i || exit
cat $test_dir/test_file &> /dev/null
# Decrement 9th byte so that eCryptfs marker passes validation
${test_script_dir}/lp-509180/test -d $lower_file || exit
new_sum=`md5sum $test_dir/test_file | cut -d ' ' -f 1`

# md5sums should be the same
if [ $old_sum = $new_sum ]; then
	rc=0
fi

exit

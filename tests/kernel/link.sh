#!/bin/bash
#
# link.sh : Simple hard link sanity check
#
# Author: Colin Ian King <colin.king@canonical.com>
#
# Copyright (C) 2013 Canonical Ltd.
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

test_script_dir=$(dirname $0)
rc=1
test_dir=0

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

# TEST
etl_add_keys || exit
etl_lmount || exit
etl_mount_i || exit
test_dir=$(etl_create_test_dir) || exit
test_file1="${test_dir}/test1"
test_file2="${test_dir}/test2"

echo "Testing 1 2 3" > $test_file1

ln $test_file1 $test_file2

rc=0
#
#  Contents should be the same
#
diff $test_file1 $test_file2 > /dev/null 2>&1
if [ $? -ne 0 ]; then
	rc=1
fi

#
#  Size should be the same
#
test_file1_size=$(stat -c%s $test_file1)
test_file2_size=$(stat -c%s $test_file2)
if [ $test_file1_size -ne $test_file2_size ]; then
	rc=1
fi
	
#
#  Link count should be 2 for both
#
test_file1_links=$(stat -c%h $test_file1)
test_file2_links=$(stat -c%h $test_file2)
if [ $test_file1_links -ne 2 -a $test_file2_links -ne 2 ]; then
	rc=1
fi

rm -f $test_file1 $test_file2

etl_umount || exit
etl_mount_i || exit

exit

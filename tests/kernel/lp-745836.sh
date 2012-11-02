#!/bin/bash
#
# lp-74586.sh: Test for https://launchpad.net/bugs/745836
# Author: Colin Ian King <colin.king@canonical.com>
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

test_script_dir=$(dirname $0)
rc=1

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

etl_add_keys || exit
etl_lmount || exit
etl_mount_i || exit
test_dir=$(etl_create_test_dir) || exit
test_file="${test_dir}/foo"

touch $test_file || exit
truncate -s 4096 $test_file || exit
sync || exit
echo 1 > /proc/sys/vm/drop_caches || exit
#
#  File should be all full of zeros and hence have the
#  following md5sum:
#
sum=$(md5sum $test_file | cut -f1 -d ' ')
if [ $sum == "620f0b67a91f7f74151bc5be745b7110" ]; then
	rc=0
fi
rm $test_file

exit

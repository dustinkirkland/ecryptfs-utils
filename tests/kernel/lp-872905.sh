#!/bin/bash
#
# lp-872905: Test for https://launchpad.net/bugs/872905
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

etl_add_keys || exit
etl_lmount || exit
etl_mount_i || exit
test_dir=$(etl_create_test_dir `basename $0`) || exit


#
# Fill the lower
#
dd if=/dev/zero of=$ETL_LMOUNT_DST/filler bs=4K > /dev/null 2>&1

#
# Now attempt to create an upper and see how big it is
#
touch $test_dir/testfile >& /dev/null

#
# We shouldn't have a lower file created of zero bytes size if
# the bug is fixed
# 
rc=0
for f in $ETL_LMOUNT_DST/ECRYPTFS*/ECRYPTFS*
do
	if [ -f $f ]; then
		sz=$(stat -c%s $f)
		if [ $sz -eq 0 ]; then
			rc=1
		fi
	fi
done

rm -f $ETL_LMOUNT_DST/filler $test_dir/testfile 

exit

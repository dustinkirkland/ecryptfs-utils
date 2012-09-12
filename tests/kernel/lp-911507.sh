#!/bin/bash
#
# lp-911507.sh: Test for https://launchpad.net/bugs/911507
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

touch $test_dir/testfile

#
# Drop caches
#
echo 1 > /proc/sys/vm/drop_caches

#
# Truncate lower, this will force bug LP#911507 when reading the file
#
for f in $ETL_LMOUNT_DST/*/*
do
	if [ -f $f ]; then
		truncate -s 0 $f
	fi
done

#
# Now read the file, eCryptfs should fix the lower file
# and append the text without failing
#
cat $test_dir/testfile > /dev/null 2>&1 
rc=$?
if [ $rc -eq 0 ]; then
	#
	# Is the file contents correct?
	#
	sum=$(md5sum $test_dir/testfile | cut -d' ' -f1)
	if [ x$sum != xd41d8cd98f00b204e9800998ecf8427e ]; then
		rc=1
	fi
fi

exit

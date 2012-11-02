#!/bin/bash
#
# lp-613873.sh: Test for https://launchpad.net/bugs/613873
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
test_dir=$(etl_create_test_dir) || exit

#
# Test that modify time does not change
#
date > $test_dir/testfile
stat_before=`stat -c%Y $test_dir/testfile`
#
# Wait a little
#
sleep 0.25
chmod 0600 $test_dir/testfile
stat_after=`stat -c%Y $test_dir/testfile`
#
# Modify time should be the same
#
if [ $stat_before -eq $stat_after ]; then
	rc=0
fi

rm $test_dir/testfile

exit

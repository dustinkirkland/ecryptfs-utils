#!/bin/bash
#
# lp-561129.sh: Test for https://launchpad.net/bugs/561129
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
src="${test_dir}/src"
dst="${test_dir}/dst"

touch "$dst" || exit
# IMPORTANT: This test gives false positives on filesystems that do not
# report free inodes (btrfs, for example) in statfs(). On those
# filesystems, we're testing [ 0 -eq 0 ]. Until this test framework has
# the notion of skipped tests, we'll have to let it slide.
expected_inodes=$(stat -fc %d "$dst") || exit
# TODO: Mark test as skipped if [ $expected_inodes -eq 0 ]

touch "$src" || exit
mv "$src" "$dst" || exit
free_inodes=$(stat -fc %d "$dst") || exit

if [ $free_inodes -eq $expected_inodes ]; then
	rc=0
fi

exit

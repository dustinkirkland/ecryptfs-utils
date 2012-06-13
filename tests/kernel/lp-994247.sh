#!/bin/bash
#
# lp-994247.sh: Test for https://launchpad.net/bugs/994247
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

. ${test_script_dir}/../lib/etl_funcs.sh

test_cleanup()
{
	exit $rc
}
trap test_cleanup 0 1 2 3 15

etl_load_ecryptfs || exit
${test_script_dir}/lp-994247/test

rc=$?
exit

#!/bin/bash
#
# verify_passphrase_sig.sh: Check for regressions in libecryptfs'
# 			    generate_passphrase_sig()
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

pass="foo"
salt="0011223344556677"
# Expected values come from testing ecryptfs-utils version 30
expected_sig="253ca7e88811d184"
expected_fekek="3f0cffa9389d2c396ad887c6ec657898e2e9e74cbb3cb1d25d410f58de2aa6b70dd81ccedaf8fad725346d8f751b8fc2c50ad69fba27d1d4fb735f207e76c6e9"

${test_script_dir}/verify-passphrase-sig/test "$pass" "$salt" \
						"$expected_sig" \
						"$expected_fekek"
rc=$?
if [ $rc -ne 0 ]; then
	exit $rc
fi


pass="a"
salt="aaaaaaaaaaaaaaaa"
expected_sig="c42ec75301dc1674"
expected_fekek="27f2ff49bfc520109f2579b36377a29955585cee6e8e5210b474a7ef7e5c4e9cf499075ace62d03b78d718d0e311726bb35b6699061f12d0731dd6a3efe9b3f2"

${test_script_dir}/verify-passphrase-sig/test "$pass" "$salt" \
						"$expected_sig" \
						"$expected_fekek"
rc=$?
if [ $rc -ne 0 ]; then
	exit $rc
fi


pass="ef2fa983a4ecc87b6f48821bd9b36940220345624949e6bf826efd692678d78b"
salt="fa1507f9913d915b"
expected_sig="09582907da54851e"
expected_fekek="bdc9089cb08554ac6039c64345a82f49e175c1427104bb1906fed9f3ad703c4f3745b2ef9a2f4210b24c973fe17370ae39def8af31d7b3f304d1209ed4313f4d"

${test_script_dir}/verify-passphrase-sig/test "$pass" "$salt" \
						"$expected_sig" \
						"$expected_fekek"
rc=$?
exit $rc

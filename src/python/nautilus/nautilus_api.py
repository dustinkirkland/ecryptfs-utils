# ecryptfs.nautilus.nautilus_api - provide Nautilus API
#
# Copyright 2009 Michael Rooney <mrooney@ubuntu.com>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
"""A wrapper module to conditionally import the Nautilus extension API
when it is available; otherwise, import stubs for it.

"""

try:
    from nautilus import LocationWidgetProvider, InfoProvider, MenuProvider, MenuItem
except ImportError:
    from dummy_nautilus import LocationWidgetProvider, InfoProvider, MenuProvider, MenuItem

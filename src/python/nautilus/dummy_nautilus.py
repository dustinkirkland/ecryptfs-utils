# ecryptfs.nautilus.dummy_nautilus - stub Nautilus API
#
# Author: Tim Cole <tim.cole@canonical.com>
#
# Copyright 2009 Canonical Ltd.
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
"""Replacement stubs for the Nautilus extension API."""

class LocationWidgetProvider(object):
    """Stub base class for location widget providers."""
    pass


class InfoProvider(object):
    """Stub base class for file info providers."""
    pass

class MenuProvider(object):
    """Stub base class for menu providers."""
    pass


class MenuItem(object):
    """Stub base class for menu items."""
    pass

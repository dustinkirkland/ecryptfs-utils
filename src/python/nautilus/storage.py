# ecryptfs.nautilus.storage - storage extension for Nautilus
#
# Authors: Tim Cole <tim.cole@canonical.com>
#          Rodney Dawes <rodney.dawes@canonical.com>
#          Michael Rooney <mrooney@ubuntu.com>
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
"""Storage extension for Nautilus."""

from __future__ import with_statement

import os
import gtk
import gnomekeyring
from urlparse import urlparse
from urllib import url2pathname, urlencode
from urllib2 import urlopen, Request, HTTPError
from twisted.internet import defer
from twisted.python import failure
from threading import Thread
import nautilus_api as nautilus

from ecryptfs import ecryptapi

class StorageBar(gtk.HBox):
    """The storage bar widget."""

    def __init__(self, path, *args, **kw):
        """Initialize the widget."""
        super(StorageBar, self).__init__(*args, **kw)
        self.__label = gtk.Label()
        self.__label.set_markup("These are files in an encrypted directory")
        self.__label.set_alignment(0.0, 0.5)
        self.__label.show()
        self.add(self.__label)
        self.__button = gtk.Button()
        self.__button.connect("clicked", self.__toggle_state)
        self.__button.show()
        self.pack_end(self.__button, expand=False, fill=False)
        self.__path = path
        self.__mounted = None
        self.__update_status()

    def __toggle_state(self, button):
        """Toggle the connectivity state."""
        if self.__mounted:
            ecryptapi.setMounted(False)
        else:
            ecryptapi.setMounted(True)

        self.__update_status()

    def __update_status(self):
        """Update the label, and button when connection status changes."""
        self.__mounted = ecryptapi.getMounted()
        if self.__mounted:
            self.__button.set_label("Lock directory")
        else:
            self.__button.set_label("Unlock directory")


def is_storagefs(path):
    """Returns True if the given path is a directory in a mounted
    storagefs filesystem.

    @param path: the path to test
    @return: True if the path is a directory in storagefs
    """
    # pylint: disable-msg=W0602
    if ecryptapi.PRIVATE_LOCATION:
        return path == ecryptapi.PRIVATE_LOCATION or path.startswith(ecryptapi.PRIVATE_LOCATION + "/")
    else:
        return False

class StorageBarProvider(nautilus.LocationWidgetProvider):
    """An extension class providing a location widget for storage
    directories.

    """
    # pylint: disable-msg=W0231
    def __init__(self, widget_class=StorageBar,
                 is_storagefs=is_storagefs):
        """Initializes a new instance of the extension class."""
        self.__widget_class = widget_class
        self.__storagefs_test = is_storagefs

    def _get_storage_dir_path(self, url):
        """Gets the local filesystem path corresponding to the given URL,
        or otherwise None if it does not refer to a storage directory.

        @param url: the directory URL
        @return: the local filesystem path, or else None

        """
        parsed_url = urlparse(url)
        if parsed_url.scheme == "file" and parsed_url.path:
            path = url2pathname(parsed_url.path)
            if self.__storagefs_test(path):
                return path
            else:
                return None
        else:
            return None

    def get_widget(self, url, window):
        """Returns either None or a Gtk widget to decorate the Nautilus
        window with, based on whether the current directory is a storage
        directory.

        @param url: the URL of the currently viewed directory
        @param window: the Nautilus window
        @return: a Gtk widget or None

        """
        path = self._get_storage_dir_path(url)
        if path is not None:
            widget = self.__widget_class(path=path)
            widget.show()
            return widget
        else:
            return None

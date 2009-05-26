#!/usr/bin/env python
#
#    ecryptapi.py, Copyright 2008 Mike Rooney (https://launchpad.net/~mrooney)
#    Date: 2008-12-12
#    Version: 0.3
#
#    This is a graphical GTK utility to manage an encrypted ~/Private
#    directory, allowing the user to mount and unmount, as well as enable
#    auto-mounting at login.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import commands, os

AUTOMOUNT_FILE = os.path.expanduser("~/.ecryptfs/auto-mount")
AUTOUMOUNT_FILE = os.path.expanduser("~/.ecryptfs/auto-umount")
PRIVATE_LOCATION_FILE = os.path.expanduser("~/.ecryptfs/Private.mnt")
PRIVATE_LOCATION = os.path.exists(PRIVATE_LOCATION_FILE) and open(PRIVATE_LOCATION_FILE).read().strip()

def setAutoMount(doAuto):
    """Enable or disable automounting for this user."""
    if doAuto:
        command = "touch %s" % AUTOMOUNT_FILE
        #open(AUTOMOUNT_FILE, "w")
    else:
        command = "rm %s" % AUTOMOUNT_FILE
        #os.remove(AUTOMOUNT_FILE)

    return commands.getstatusoutput(command)

def getAutoMount():
    """Return whether or not automounting is enabled for this user."""
    return os.path.exists(AUTOMOUNT_FILE)

def setAutoUnmount(doAuto):
    """Enable or disable automounting for this user."""
    if doAuto:
        command = "touch %s" % AUTOUMOUNT_FILE
    else:
        command = "rm %s" % AUTOUMOUNT_FILE

    return commands.getstatusoutput(command)

def getAutoUnmount():
    """Return whether or not automounting is enabled for this user."""
    return os.path.exists(AUTOUMOUNT_FILE)

def setMounted(doMount):
    """Set the mounted (unencrypted) state of ~/Private."""
    if doMount:
        command = "mount.ecryptfs_private"
    else:
        command = "umount.ecryptfs_private"

    return commands.getstatusoutput(command)

def getMounted():
    """Return whether or not ~/Private is mounted (unencrypted)."""
    if PRIVATE_LOCATION:
        mounts = open("/proc/mounts").read()
        return PRIVATE_LOCATION in mounts
    else:
        return False

def needsSetup():
    encryptedHome = False #TODO: implement
    encryptedPrivate = PRIVATE_LOCATION
    return not (encryptedHome or encryptedPrivate)

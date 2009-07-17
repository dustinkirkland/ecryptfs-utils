#!/usr/bin/env python
#
#    ecryptfsapi.py, Copyright 2008, 2009 Michael Rooney <mrooney@ubuntu.com>
#    Date: 2009-05-28
#    Version: 0.4
#
#    This is a python API for interacting with ecryptfs-utils and its
#    encrypted directories.
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

def set_automount(doAuto):
    """Enable or disable automounting for this user."""
    if doAuto:
        command = "touch %s" % AUTOMOUNT_FILE
        #open(AUTOMOUNT_FILE, "w")
    else:
        command = "rm %s" % AUTOMOUNT_FILE
        #os.remove(AUTOMOUNT_FILE)

    return commands.getstatusoutput(command)

def get_automount():
    """Return whether or not automounting is enabled for this user."""
    return os.path.exists(AUTOMOUNT_FILE)

def set_autounmount(doAuto):
    """Enable or disable automounting for this user."""
    if doAuto:
        command = "touch %s" % AUTOUMOUNT_FILE
    else:
        command = "rm %s" % AUTOUMOUNT_FILE

    return commands.getstatusoutput(command)

def get_autounmount():
    """Return whether or not autounmounting is enabled for this user."""
    return os.path.exists(AUTOUMOUNT_FILE)

def set_mounted(doMount):
    """Set the mounted (unencrypted) state of ~/Private."""
    if doMount:
        command = "/sbin/mount.ecryptfs_private"
    else:
        command = "/sbin/umount.ecryptfs_private"

    return commands.getstatusoutput(command)

def get_mounted():
    """Return whether or not ~/Private is mounted (unencrypted)."""
    if PRIVATE_LOCATION:
        mounts = open("/proc/mounts").read()
        return PRIVATE_LOCATION in mounts
    else:
        return False

def needs_setup():
    """
    Return whether or not an encrypted directory has been set up by ecryptfs
    for this user, either Home or Private.
    """
    encryptedHome = False #TODO: implement
    encryptedPrivate = PRIVATE_LOCATION
    return not (encryptedHome or encryptedPrivate)

#!/bin/sh

whoami | grep "^root$" &> /dev/null
if test $? == 1; then
  echo "Please run this script as root"
  echo
  exit
fi

echo "USAGE:"
echo " # ecryptfs-undo-pam.sh [username]"
echo

if test "x$1" == "x"; then
    echo "Must provide a username"
    echo
    exit
fi

mv -f /etc/pam.d/.system-auth-before-pam_ecryptfs /etc/pam.d/system-auth
mv -f /home/$1/.bash_profile-before-pam_ecryptfs /home/$1/.bash_profile
chown $1:$1 /home/$1/.bash_profile
grep -v "/home/$1/Confidential ecryptfs" /etc/fstab > /tmp/fstab
mv -f /tmp/fstab /etc/fstab

echo "Undone."
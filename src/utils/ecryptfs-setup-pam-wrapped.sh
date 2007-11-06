#!/bin/sh

echo
echo "You must run this script as root. Do not use sudo; either log in"
echo "as root or use 'su -'"
echo
echo "This script applies to Open Client systems only with the IBM-security-compliance RPM installed"
echo

whoami | grep "^root$" &> /dev/null
if test $? == 1; then
  echo "Please run this script as root"
  echo
  exit
fi

echo "USAGE:"
echo " # ecryptfs-setup-pam-wrapped.sh [username] [mount passphrase] [wrapping passphrase]"
echo
echo "Be sure to properly escape your parameters according to your shell's special character nuances, and also surround the parameters by double quotes, if need be."
echo
echo "No special characters allowed in the username."
echo

if test "x$1" == "x"; then
    echo "Must provide a username"
    echo
    exit
fi

if test "x$2" == "x"; then
    echo "Must provide a mount passphrase"
    echo
    exit
fi

if test "x$3" == "x"; then
    echo "Must provide a wrapping passphrase"
    echo
    exit
fi

echo "Using username [$1]"
echo "Using mount passphrase [$2]"
echo "Using wrapping passphrase [$3]"
echo
echo "This script will attempt to set up your system to mount eCryptfs"
echo "automatically on login, using your login passphrase."
echo

modprobe ecryptfs
mkdir /home/$1/Confidential
chown $1:$1 /home/$1/Confidential
chmod 700 /home/$1/Confidential
grep -v "ecryptfs_sig" /etc/fstab > /tmp/fstab
mv -f /tmp/fstab /etc/fstab
umount /home/$1/Confidential
mount | grep "/home/$1/Confidential type ecryptfs"
if test $? == 0; then
 echo "ERROR: /home/$1/Confidential still mounted after umount; cannot continue with setup"
 exit 1
fi
mount -t ecryptfs /home/$1/Confidential /home/$1/Confidential -o key=passphrase:passwd="$2",cipher=aes,ecryptfs_key_bytes=16,passthrough=n,no_sig_cache
grep ecryptfs_sig /etc/mtab | sed 's/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16,user,noauto,/' >> /etc/fstab
umount /home/$1/Confidential
cp -f /etc/pam.d/system-auth /etc/pam.d/.system-auth-before-pam_ecryptfs
grep -v "pam_ecryptfs" /etc/pam.d/system-auth > /tmp/system-auth
mv -f /tmp/system-auth /etc/pam.d/system-auth
grep -v "auth.*pam_deny" /etc/pam.d/system-auth > /tmp/system-auth
mv -f /tmp/system-auth /etc/pam.d/system-auth
cat /etc/pam.d/system-auth | sed 's/auth.*pam_unix\.so\(.*\)/auth required pam_unix.so\1\nauth required pam_ecryptfs.so unwrap/' > /tmp/system-auth
mv -f /tmp/system-auth /etc/pam.d/system-auth
cat /etc/pam.d/system-auth | sed 's/password\s*sufficient\s*pam_unix\.so\(.*\)/password required pam_ecryptfs.so\npassword sufficient pam_unix.so\1/' > /tmp/system-auth
mv -f /tmp/system-auth /etc/pam.d/system-auth
grep "Confidential type ecryptfs" /home/$1/.bash_profile
if test $? != 0; then
    cp -f /home/$1/.bash_profile /home/$1/.bash_profile-before-pam_ecryptfs
    echo "if test -e \$HOME/.ecryptfs/auto-mount; then" >> /home/$1/.bash_profile
    echo "  mount | grep \"\$HOME/Confidential type ecryptfs\"" >> /home/$1/.bash_profile
    echo "  if test \$? != 0; then" >> /home/$1/.bash_profile
    echo "    mount -i \$HOME/Confidential" >> /home/$1/.bash_profile
    echo "  fi" >> /home/$1/.bash_profile
    echo "fi" >> /home/$1/.bash_profile
    echo "ecryptfs-zombie-kill" >> /home/$1/.bash_profile
fi
mkdir -p /home/$1/.ecryptfs
chown $1:$1 /home/$1/.ecryptfs
touch /home/$1/.ecryptfs/auto-mount
chown $1:$1 /home/$1/.ecryptfs/auto-mount
rm -f /home/$1/.ecryptfs/wrapped-passphrase
/usr/bin/ecryptfs-wrap-passphrase /home/$1/.ecryptfs/wrapped-passphrase "$2" "$3"
chown $1:$1 /home/$1/.ecryptfs/wrapped-passphrase

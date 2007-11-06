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
echo " # ecryptfs-setup-pam.sh [username] [passphrase] <noninteractive>"
echo

if test "x$1" == "x"; then
    echo "Must provide a username"
    echo
    exit
fi

if test "x$2" == "x"; then
    echo "Must provide a login passphrase"
    echo
    exit
fi

if test "x$3" == "xnoninteractive"; then
    echo "Running in non-interactive mode"
    INTERACTIVE=0
else
    echo "Running in interactive mode"
    INTERACTIVE=1
fi


echo $2 | grep "[;\"\\]"
if test $? == 0; then
    echo "Warning: Using backslashes, quotes, or semicolons in your passphrase"
    echo "may cause problems."
    echo
    if test $INTERACTIVE == 1; then
        echo "Hit ENTER to continue, CTRL-C to abort..."
        read
    fi
fi

echo "Using username [$1]"
echo "Using login passphrase [$2]"
echo
echo "This script will attempt to set up your system to mount eCryptfs"
echo "automatically on login, using your login passphrase."
echo
if test $INTERACTIVE == 1; then
    echo "Hit ENTER to continue, CTRL-C to abort..."
    read
fi
echo
echo "This script will now attempt to take the following steps:"
echo " * Insert the ecryptfs kernel module"
echo "  # modprobe ecryptfs"
echo " * Create a Confidential directory in the user's home directory"
echo "  # mkdir /home/$1/Confidential"
echo "  # chown $1:$1 /home/$1/Confidential"
echo "  # chmod 700 /home/$1/Confidential"
echo " * Perform an eCryptfs mount"
echo "  # mount -t ecryptfs /home/$1/Confidential /home/$1/Confidential -o key=passphrase:passwd=\"$2\",cipher=aes,ecryptfs_key_bytes=16,passthrough=n,no_sig_cache"
echo " * Add an entry to /etc/fstab with the the mount parameters" 
echo "  # grep ecryptfs_sig /etc/mtab | sed 's/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16,user,noauto,/' >> /etc/fstab"
echo " * Unmount eCryptfs"
echo "  # umount ecryptfs"
echo " * Add pam_ecryptfs to PAM stack"
echo "  # cat /etc/pam.d/system-auth | sed 's/auth\s*required\s*pam_unix\.so likeauth nullok/auth       required     pam_unix.so likeauth nullok\nauth       required     pam_ecryptfs.so/' > /tmp/system-auth"
echo "  # cp -f /etc/pam.d/system-auth /etc/pam.d/.system-auth-before-pam_ecryptfs"
echo "  # mv -f /tmp/system-auth /etc/pam.d/system-auth"
echo " * Add eCryptfs mount commands to /home/$1/.bash_profile"
echo "  # cp -f /home/$1/.bash_profile /home/$1/.bash_profile-before-pam_ecryptfs"
echo "  # echo \"if test -e \$HOME/.ecryptfs/auto-mount; then\" >> /home/$1/.bash_profile"
echo "  # echo \"  mount | grep \\\"\$HOME/Confidential type ecryptfs\\\"\" >> /home/$1/.bash_profile"
echo "  # echo \"  if test \$? != 0; then\" >> /home/$1/.bash_profile"
echo "  # echo \"    mount -i \$HOME/Confidential\" >> /home/$1/.bash_profile"
echo "  # echo \"  fi\" >> /home/$1/.bash_profile"
echo "  # echo \"fi\" >> /home/$1/.bash_profile"
echo " * Turn on automount for the user"
echo "  # mkdir -p /home/$1/.ecryptfs"
echo "  # chown $1:$1 /home/$1/.ecryptfs"
echo "  # touch /home/$1/.ecryptfs/auto-mount"
echo "  # chown $1:$1 /home/$1/.ecryptfs/auto-mount"
echo
echo "If something goes wrong, or if you notice that an operation "
echo "listed above will not work on your system, than you will need "
echo "to take these steps manually."
echo
if test $INTERACTIVE == 1; then
    echo "Hit ENTER to continue, CTRL-C to abort..."
    read
fi
modprobe ecryptfs
mkdir /home/$1/Confidential
chown $1:$1 /home/$1/Confidential
chmod 700 /home/$1/Confidential
mount -t ecryptfs /home/$1/Confidential /home/$1/Confidential -o key=passphrase:passwd="$2",cipher=aes,ecryptfs_key_bytes=16,passthrough=n,no_sig_cache
grep ecryptfs_sig /etc/mtab | sed 's/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16/ecryptfs_cipher\=aes,ecryptfs_key_bytes\=16,user,noauto,/' >> /etc/fstab
umount /home/$1/Confidential
cat /etc/pam.d/system-auth | sed 's/auth\s*required\s*pam_unix\.so likeauth nullok/auth       required     pam_unix.so likeauth nullok\nauth       required     pam_ecryptfs.so/' > /tmp/system-auth
cp -f /etc/pam.d/system-auth /etc/pam.d/.system-auth-before-pam_ecryptfs
mv -f /tmp/system-auth /etc/pam.d/system-auth
cp -f /home/$1/.bash_profile /home/$1/.bash_profile-before-pam_ecryptfs
echo "if test -e \$HOME/.ecryptfs/auto-mount; then" >> /home/$1/.bash_profile
echo "  mount | grep \"\$HOME/Confidential type ecryptfs\"" >> /home/$1/.bash_profile
echo "  if test \$? != 0; then" >> /home/$1/.bash_profile
echo "    mount -i \$HOME/Confidential" >> /home/$1/.bash_profile
echo "  fi" >> /home/$1/.bash_profile
echo "fi" >> /home/$1/.bash_profile
mkdir -p /home/$1/.ecryptfs
chown $1:$1 /home/$1/.ecryptfs
touch /home/$1/.ecryptfs/auto-mount
chown $1:$1 /home/$1/.ecryptfs/auto-mount

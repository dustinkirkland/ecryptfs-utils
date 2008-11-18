#!/bin/sh

echo
echo "This script will try to build and install the kernel and userspace"
echo "components of eCryptfs. On a 32-bit platform, it will install the "
echo "following files:"
echo
echo "/sbin/mount.ecryptfs"
echo "/usr/lib/libecryptfs.so.0.0.0"
echo "/usr/lib/libecryptfs.so.0"
echo "/usr/lib/libecryptfs.so"
echo "/usr/lib/ecryptfs/libecryptfs_pki_openssl.so"
echo "/usr/bin/ecryptfsd"
defaultmodulesdir=/lib/modules/`uname -r`
echo "$defaultmodulesdir/kernel/fs/ecryptfs/ecryptfs.ko"
echo
echo "If you want to install to different locations, then you will need to"
echo "go into the ecryptfs-util/ and ecryptfs-kernel/ directories and build"
echo "them according to the instructions in the README files."
echo
echo "Once the build and install is successfully completed, you can mount "
echo "eCryptfs with these steps:"
echo
echo "# modprobe ecryptfs"
echo "# ecryptfsd"
echo "# mkdir -p /var/ecryptfs_encrypted_files"
echo "# mkdir -p /mnt/ecryptfs"
echo "# mount -t ecryptfs /var/ecryptfs_encrypted_files /mnt/ecryptfs"
echo
echo "If this script aborts, you will need to try to build the kernel"
echo "module and/or the userspace tools by hand. You can always get help from"
echo "the eCryptfs mailing list:"
echo "<https://launchpad.net/~ecryptfs-devel>"
whoami | grep "^root$" &> /dev/null
if test $? == 1; then
  echo
  echo "You should be running this script as root so that the script has"
  echo "permission to write into the above listed directories. If you do not"
  echo "want to run the script as root, make sure that the user running this"
  echo "script has permission to write into the given locations."
fi
echo
echo "Press ENTER to continue, CTRL-C to abort..."
read
cd ecryptfs-kernel
./configure || { echo "Error configuring kernel module" && exit 1; }
make || { echo "Error building kernel module" && exit 1; }
make install || { echo "Error installing kernel module" && exit 1; }
cd ../ecryptfs-util
./configure --prefix=/usr || { echo "Error configuring user space" &&
exit 1; }
make || { echo "Error building user space" && exit 1; }
make install || { echo "Error installing user space" && exit 1; }
echo
echo "Build/install complete. You can mount eCryptfs with these steps:"
echo
echo "# modprobe ecryptfs"
echo "# ecryptfsd"
echo "# mkdir -p /var/ecryptfs_encrypted_files"
echo "# mkdir -p /mnt/ecryptfs"
echo "# mount -t ecryptfs /var/ecryptfs_encrypted_files /mnt/ecryptfs"
echo

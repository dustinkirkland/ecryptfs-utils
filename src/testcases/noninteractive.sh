#!/bin/sh

# Run this script as root

SRC_DIR="/tmp/crypt"
DST_DIR="/mnt/crypt"
HOME_DIR="/root"
PASSWD_DIR="$HOME_DIR/.ecryptfs/pki"
PASSWD_PATH="$PASSWD_DIR/passwd"

function mkdirs {
    mkdir -p $SRC_DIR
    mkdir -p $DST_DIR
    mkdir -p $PASSWD_DIR
}

function write_tmp_files {
    echo "passwd=t" > $PASSWD_PATH
}

function clean_src {
    if [ "x$SRC_DIR" == "x" ]; then
	echo "SRC_DIR is empty"
	exit 1
    else
	if [ "x$SRC_DIR" == "x/" ]; then
	    echo "SRC_DIR is root; probably not what you want"
	    exit 1
	else
	    rm -rf $SRC_DIR/*
	fi
    fi
}

function mount_passphrase {
    mount -t ecryptfs $SRC_DIR $DST_DIR -o key=passphrase,cipher=aes,verbosity=0
}

function remount_ro {
    mount -i -o remount,ro $DST_DIR
}

function umount_ecryptfs {
    umount $DST_DIR
}

function mkdir_clean_mount_passphrase {
    for i in "passwd=t" "passfile=$HOME_DIR/.ecryptfs/pki/passwd"; do
	    echo "Performing mount with passphrase option [$i]"
	    /sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o key=passphrase:$i,cipher=aes,verbosity=0 > /dev/null
	    if [ $? -eq 0 ]
	    then
		echo "ok"
	    else
		echo "Error mounting ecryptfs with passphrase option [$i] [$?]"
		exit 1
	    fi
	    umount_ecryptfs
    done
}

#we should return errno from calls to libecryptfs functions.
function mkdir_clean_mount_bad_passphrase {
    for i in "passwd=" "passfile="; do
	    echo "Performing mount with passphrase option [$i]"
	    /sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o key=passphrase:$i,cipher=aes,verbosity=0 > /dev/null
	    if [ $? -eq 234 ]
	    then
		echo "ok"
	    else
		echo "Return code differed from what was expected [$i]"
	        umount_ecryptfs
		exit 1
	    fi
    done
}

function mkdir_clean_mount_ciphers {
    for i in "aes" "des" "cast5" "cast6" "blowfish" "twofish" "des3_ede" ""; do
	    echo "Performing mount with cipher [$i]"
	    /sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o key=passphrase:passwd=t,cipher=$i,verbosity=0 > /dev/null
	    if [ $? -eq 0 ]
	    then
		echo "ok"
	    else
		echo "Error mounting ecryptfs with cipher [$i]"
		exit 1
	    fi
	    umount_ecryptfs
    done
}

function mkdir_clean_mount_bad_ciphers {
    for i in "aesaaaaaaa" "bbbaes" "xxxaesyyy"; do
	    echo "Performing mount with incorrect cipher [$i]"
	    /sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o key=passphrase:passwd=t,cipher=$i,verbosity=0 > /dev/null
	    if [ $? -eq 234 ]
	    then
		echo "ok"
	    else
		echo "Mount should have failed with cipher [$i]"
	        umount_ecryptfs
		exit
	    fi
    done
}

#Salts need to be hex values if a non hex value is specified 0 is used
#we should probably clarify that we are requesting a hex value
function mkdir_clean_mount_salt {
    for i in "" "a" "12345678" "0xdeadbeefdeadbeefdeadbeef" "ghijklmn" "sdflajsdflksjdaflsdjk" ""; do
	    echo "Performing mount with salt [$i]"
	    /sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o key=passphrase:passwd=t:salt=$i,cipher=aes,verbosity=0 > /dev/null
	    if [ $? -eq 0 ]
	    then
		echo "ok"
	    else
		echo "Error mounting ecryptfs with salt [$i]"
		exit 1
	    fi
	    umount_ecryptfs
    done
}

function clean_up_tests {
    rm -f $PASSWD_PATH
}

echo "Running non-interactive mount tests"
echo "Passphrase mount"

echo "Making directories"
mkdirs
echo "Writing temporary files"
write_tmp_files
echo "Cleaning out source directory"
clean_src
echo "Testing Passphrase Modes"
mkdir_clean_mount_passphrase
mkdir_clean_mount_bad_passphrase
echo ""
echo "Testing Cipher Modes"
mkdir_clean_mount_ciphers
mkdir_clean_mount_bad_ciphers
echo ""
echo "Testing Salts"
mkdir_clean_mount_salt
echo ""
echo "Cleaning up"
clean_up_tests

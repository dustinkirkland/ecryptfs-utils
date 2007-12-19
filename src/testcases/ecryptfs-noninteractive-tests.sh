#!/bin/sh

# Run this script as root

SRC_DIR="/tmp/crypt"
DST_DIR="/mnt/crypt"
HOME_DIR="/root"
PASSWD_DIR="$HOME_DIR/.ecryptfs/pki"
PASSWD_PATH="$PASSWD_DIR/passwd"
ERROR=0

function usage {
    echo "Usage:"
    echo "    `basename $0` [-v/--verbose | -s/--silent]"
    echo ""
    echo "Verbose and Silent modes are mutually exclusive"
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
        -v|--verbose)
            VERBOSE=yes
            shift
            ;;
        -s|--silent)
            SILENT=yes
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [ -n "$VERBOSE" -a -n "$SILENT" ]; then
    usage
fi

function vecho {
    NONL=""
    if [ "$1" == "-n" ]; then
        NONL="-n"
        shift
    fi
    [ -z "$SILENT" ] && echo $NONL "$@"
    return 0
}

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
    mount -t ecryptfs $SRC_DIR $DST_DIR -o key=passphrase,verbosity=0,ecryptfs_cipher=aes
}

function remount_ro {
    mount -i -o remount,ro $DST_DIR
}

function umount_ecryptfs {
    umount $DST_DIR
}

function do_mount {
    mount_opts="$1"
    expected_retval="$2"
    mount_cmd="/sbin/mount.ecryptfs $SRC_DIR $DST_DIR -o $mount_opts"
    if [ -z "$VERBOSE" ]; then
        $mount_cmd > /dev/null
    else
        $mount_cmd
    fi
    retval=$?
    if [ "$retval" -eq "$expected_retval" ]; then
        vecho "ok"
        return 0
    fi
    return $retval
}

function write_file {
    string="$@"
    echo "$string" > $DST_DIR/temp.txt
    if [ $? -ne 0 ]; then
        echo "Error writing to temp file"
        exit 1
    fi
}

function read_file {
    string="$@"
    grep "$string" $DST_DIR/temp.txt > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error reading from temp file"
        exit 1
    fi
    rm -f $DST_DIR/temp.txt
}

function mount_passphrase {
    for i in "passwd=t" "passfile=$HOME_DIR/.ecryptfs/pki/passwd"; do
        vecho "--"
        vecho -n "Performing mount with passphrase option [$i]: "
        mount_opts="key=passphrase:$i:verbosity=0,ecryptfs_key_bytes=16,ecryptfs_cipher=aes"
        expected_retval=0
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error mounting ecryptfs with passphrase option [$i] [$?]"
            exit 1
        fi
        vecho -n "Writing file to ecryptfs..... "
        write_file $i
        [ $? -eq 0 ] && vecho "ok" || (echo "FAILED: write error" && exit 1)
        vecho -n "Remounting ecryptfs.......... "
        umount_ecryptfs
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error remounting ecryptfs with passphrase option [$i] [$?]"
            exit 1
        fi
        vecho -n "Reading file from ecrytpfs... "
        read_file $i
        [ $? -eq 0 ] && vecho "ok"  || (echo "FAILED: read error" && exit 1)
        umount_ecryptfs
    done
    vecho "--"
    echo "done"
}

# We should return errno from calls to libecryptfs functions.
function mount_bad_passphrase {
    for i in "passwd=" "passfile="; do
        vecho -n "Performing mount with bad passphrase option [$i]: "
        mount_opts="key=passphrase:$i:verbosity=0,ecryptfs_key_bytes=16,ecryptfs_cipher=aes"
        expected_retval=234
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Return code differed from what was expected [$i]"
            umount_ecryptfs
            exit 1
        fi
    done
    echo "done"
}

function mount_ciphers {
    for i in "aes" "cast5" "cast6" "blowfish" "twofish" "des3_ede" ""; do
        vecho "--"
        vecho -n "Performing mount with cipher [$i]: "
        if [ "$i" == "des3_ede" ]; then
            keysize=24
        else
            keysize=16
        fi
        mount_opts="key=passphrase:passwd=t:verbosity=0,ecryptfs_key_bytes=$keysize,ecryptfs_cipher=$i"
        expected_retval=0
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error mounting ecryptfs with cipher [$i]"
            exit 1
        fi
        vecho -n "Writing file to ecryptfs..... "
        write_file $i
        [ $? -eq 0 ] && vecho "ok" || (echo "FAILED: write error" && exit 1)
        vecho -n "Remounting ecryptfs.......... "
        umount_ecryptfs
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error remounting ecryptfs with cipher [$i]"
            exit 1
        fi
        vecho -n "Reading file from ecrytpfs... "
        read_file $i
        [ $? -eq 0 ] && vecho "ok"  || (echo "FAILED: read error" && exit 1)
        umount_ecryptfs
    done
    vecho "--"
    echo "done"
}

function mount_bad_ciphers {
    for i in "aesaaaaaaa" "bbbaes" "xxxaesyyy" "abcdefghijklmnopqrstuvwxyzabcdefghijkl"; do
        vecho -n "Performing mount with incorrect cipher [$i]: "
        mount_opts="key=passphrase:passwd=t:verbosity=0,ecryptfs_key_bytes=16,ecryptfs_cipher=$i"
        expected_retval=234
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Mount should have failed with cipher [$i]"
            umount_ecryptfs
            exit 1
        fi
    done
    echo "done"
}

# Salts need to be hex values if a non hex value is specified 0 is used
# we should probably clarify that we are requesting a hex value
function mount_salt {
    for i in "" "a" "12345678" "0xdeadbeefdeadbeefdeadbeef" "ghijklmn" "sdflajsdflksjdaflsdjk" ""; do
        vecho "--"
        vecho "Performing mount with salt [$i]"
        mount_opts="key=passphrase:passwd=t:salt=$i:verbosity=0,ecryptfs_key_bytes=16,ecryptfs_cipher=aes"
        expected_retval=0
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
	    echo "FAILED"
            echo "Error mounting ecryptfs with salt [$i]"
            exit 1
        fi
        vecho -n "Writing file to ecryptfs..... "
        write_file $i
        [ $? -eq 0 ] && vecho "ok" || (echo "FAILED: write error" && exit 1)
        vecho -n "Remounting ecryptfs.......... "
        umount_ecryptfs
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error remounting ecryptfs with salt [$i]"
            exit 1
        fi
        vecho -n "Reading file from ecrytpfs... "
        read_file $i
        [ $? -eq 0 ] && vecho "ok"  || (echo "FAILED: read error" && exit 1)
        umount_ecryptfs
    done
    vecho "--"
    echo "done"
}

# SSL keyfile mounts
function mount_keyfile {
    for i in "openssl" "openssl" "openssl"; do
        vecho "--"
        vecho -n "Performing mount with key file [$i]: "
        keyfile=$PASSWD_DIR/$i/key.pem
        if [ ! -e $keyfile ]; then
	    echo "FAILED"
            echo "Error: no $i key file found. Please create $keyfile with password = t, by running ecryptfs-manager"
            exit 1
        fi
        mount_opts="key=openssl:passwd=t:keyfile=$keyfile:verbosity=0,ecryptfs_key_bytes=16,ecryptfs_cipher=aes"
        expected_retval=0
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error mounting ecryptfs with key file [$i]"
            exit 1
        fi
        vecho -n "Writing file to ecryptfs..... "
        write_file $i
        [ $? -eq 0 ] && vecho "ok" || (echo "FAILED: write error" && exit 1)
        vecho -n "Remounting ecryptfs.......... "
        umount_ecryptfs
        do_mount $mount_opts $expected_retval
        if [ "$?" -ne 0 ]; then
            echo "FAILED"
            echo "Error remounting ecryptfs with key file [$i]"
            exit 1
        fi
        vecho -n "Reading file from ecrytpfs... "
        read_file $i
        [ $? -eq 0 ] && vecho "ok"  || (echo "FAILED: read error" && exit 1)
        umount_ecryptfs
    done
    vecho "--"
    echo "done"
}

function clean_up_tests {
    rm -f $PASSWD_PATH
}

echo "Running non-interactive mount tests"

vecho "Making directories"
mkdirs
vecho "Writing temporary files"
write_tmp_files
vecho "Cleaning out source directory"
clean_src
echo -n "Testing Passphrase Modes....... "
vecho ""
mount_passphrase
vecho ""
echo -n "Testing Invalid Passphrases.... "
vecho ""
mount_bad_passphrase
vecho ""
echo -n "Testing Cipher Modes........... "
vecho ""
mount_ciphers
vecho ""
echo -n "Testing Invalid Ciphers........ "
vecho ""
mount_bad_ciphers
vecho ""
echo -n "Testing Salts.................. "
vecho ""
mount_salt
vecho ""
echo -n "Testing Keyfile Modes.......... "
vecho ""
mount_keyfile
vecho ""
vecho "Cleaning up"
clean_up_tests
echo "All tests completed successfully"
echo ""

#!/usr/bin/env python

import sys
import getopt
import base64
from ZSI.client import Binding
import libecryptfs

__doc__ = '''
Usage: escrow-passphrase.py <-v|--verbose> <[salt]> [passphrase]
'''

def main():
    verbosity = 0
    default_salt_hex = "0011223344556677"
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hv", ["help", "verbose"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)
        elif o in ("-v", "--verbose"):
            verbosity = 1
    salt_bytes = []
    if len(args) < 1 or len(args) > 2:
        print "invalid number of arguments"
        print "for help use --help"
        sys.exit(2)        
    if len(args) == 1:
        salt_hex = default_salt_hex
        passphrase_charstr = args[0]
    if len(args) == 2:
        salt_hex = args[0]
        passphrase_charstr = args[1]
    if len(salt_hex) != 16:
            print "Salt value provided is [%s], which is [%d] characters long. The salt must be comprised of [%d] hexidecimal characters." % (salt_hex, len(salt_hex), 16)
    for i in range(0, 16, 2):
        salt_bytes.append(chr(int(salt_hex[i:i+2], 16)))
    salt_charstr = ""
    for sb in salt_bytes:
        salt_charstr = "%s%c" % (salt_charstr, sb)
    blob = libecryptfs.ecryptfs_passphrase_blob(salt_charstr, \
                                                    passphrase_charstr)
    sig = libecryptfs.ecryptfs_passphrase_sig_from_blob(blob)
    b = Binding(url="http://127.0.0.1:8080")
    b64sig = base64.b64encode(sig)
    b64blob = base64.b64encode(blob)
    b.store_key_blob([b64sig, b64blob])

if __name__ == "__main__":
    main()

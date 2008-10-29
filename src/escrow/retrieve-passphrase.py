#!/usr/bin/env python

import sys
import getopt
from ZSI.client import Binding
import base64
import libecryptfs

__doc__ = '''
Usage: escrow-passphrase.py <-v|--verbose> [sig]
'''

def main():
    verbosity = 0
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
    if len(args) != 1:
        print "invalid number of arguments"
        print "for help use --help"
        sys.exit(2)        
    sig = args[0]
    b = Binding(url="http://127.0.0.1:8080")
    b64sig = base64.b64encode(sig)
    b64blob = b.fetch_key_blob(b64sig)
    blob = base64.b64decode(b64blob)
    libecryptfs.ecryptfs_add_blob_to_keyring(blob, sig)

if __name__ == "__main__":
    main()

#!/bin/sh


if scripts/validate-dir.sh; then
        echo "Validated directory; proceeding to delete files"
else
        echo "Directory not validated; aborting"
	exit 1
fi

rm -rf .git/
rm -rf .to_fold/
rm -rf rpm/
rm -f src/pki/Makefile
rm -f src/include/Makefile
rm -f src/libecryptfs/Makefile
rm -f src/utils/Makefile
rm -f src/daemon/Makefile
rm -f src/Makefile
rm -f Makefile
rm -rf debian/ecryptfs-util
rm -rf debian/ecryptfs-util-doc
find . -name ".libs" -exec rm -rf {} \;
find . -name ".deps" -exec rm -rf {} \;
find . -name ".tmp_versions" -exec rm -rf {} \;
find . -name ".test*" -exec rm -rf {} \;
find . -name "*.ko" -exec rm -rf {} \;
find . -name "*.o" -exec rm -rf {} \;
find . -name "*.lo" -exec rm -rf {} \;
find . -name "*.la" -exec rm -rf {} \;
find . -name "*.orig" -exec rm -rf {} \;
find . -name "*.mod.c" -exec rm -rf {} \;
find . -name "*.symvers" -exec rm -rf {} \;
find . -name "*~" -exec rm -rf {} \;
find . -name ".[a-z]*~" -exec rm -rf {} \;
find . -name "*.rej" -exec rm -rf {} \;
find . -name "out.txt" -exec rm -rf {} \;
find . -name ".dotest" -exec rm -rf {} \;
find . -name "patches-*" -exec rm -rf {} \;
find . -name "nohup.out" -exec rm -rf {} \;
find . -name "cscope.out" -exec rm -rf {} \;
find . -type d -name "gui" -exec rm -rf {} \;

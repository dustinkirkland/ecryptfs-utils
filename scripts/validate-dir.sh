#!/bin/sh

FILES="AUTHORS COPYING ChangeLog INSTALL Makefile.am NEWS README THANKS configure"

for file in $FILES; do
        if [ -e $file ]; then
                echo "$file found"
        else
	        echo "$file not found; returning 1"
                exit 1
        fi
done

echo "Directory check successful; returning 0"

exit 0

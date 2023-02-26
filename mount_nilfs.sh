#!/bin/bash

set -euo pipefail

FILESYSTEM_FILE=nilfs.bin
DESTINATION=/tmp/mnt

umount $DESTINATION || true
rm -fv $FILESYSTEM_FILE
fallocate -l 1GiB $FILESYSTEM_FILE
mkfs -t nilfs2 $FILESYSTEM_FILE
rm -rfv /tmp/mnt
mkdir -pv $DESTINATION

mount -i -v -t nilfs2 $FILESYSTEM_FILE $DESTINATION

echo "123456789" > $DESTINATION/f1
echo "123456789" > $DESTINATION/f2
echo "123456789" > $DESTINATION/f3

## in case of failure, run script again

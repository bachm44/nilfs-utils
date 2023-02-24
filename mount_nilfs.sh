#!/bin/bash

set -euo pipefail

FILESYSTEM_FILE=nilfs.bin
DESTINATION=/tmp/mnt

fallocate -l 1GiB $FILESYSTEM_FILE
mkfs -t nilfs2 $FILESYSTEM_FILE
mkdir -pv $DESTINATION
umount $DESTINATION || true

mount -i -v -t nilfs2 $FILESYSTEM_FILE $DESTINATION

## in case of failure, run script again

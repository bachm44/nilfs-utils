#!/bin/sh

set -euo pipefail # fail on error
set -x # logging
IFS=$'\n\t'

MNT_DIR=/mnt/nilfs2
FS_FILE_SIZE=1G
FS_BIN_FILE=nilfs2.bin
LOOP_INTERFACE=/dev/loop6

umount $LOOP_INTERFACE || true
losetup -d $LOOP_INTERFACE || true
rm -f $FS_BIN_FILE

fallocate -l $FS_FILE_SIZE $FS_BIN_FILE
losetup -P $LOOP_INTERFACE $FS_BIN_FILE
mkfs.nilfs2 $LOOP_INTERFACE
nilfs-tune -i 1 $LOOP_INTERFACE

mkdir -p $MNT_DIR
mount -t nilfs2 $LOOP_INTERFACE $MNT_DIR

genfile --size=10M --type=0 --seed=420 $MNT_DIR/f1
genfile --size=10M --type=0 --seed=420 $MNT_DIR/f2

umount $LOOP_INTERFACE || true
losetup -d $LOOP_INTERFACE || true
losetup -P $LOOP_INTERFACE $FS_BIN_FILE
mount -t nilfs2 $LOOP_INTERFACE $MNT_DIR

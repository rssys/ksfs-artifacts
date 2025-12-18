#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4

RESULT_DIR=`realpath ../results/pjdfstest`
CURR_DIR=`pwd`
PJDFSTEST_DIR=`realpath ../../pjdfstest/tests`
mkdir -p $CURR_DIR

sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs

cd $MNT
sudo prove --nocolor -rv $PJDFSTEST_DIR > $RESULT_DIR/$FS-$TYPE.txt
cd $CURR_DIR
sudo umount $MNT
#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
N=$5
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs
OLDDIR=`pwd`
PREFIX=$OLDDIR/../results/tar/$N-$FS-$TYPE
cd $MNT
sudo wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.5.9.tar.xz
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
(time bash -c "sudo tar xf linux-6.5.9.tar.xz &> /dev/null; sync") &> $PREFIX-untar.txt
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
(time bash -c "sudo cp -r linux-6.5.9 linux-6.5.9-2 &> /dev/null; sync") &> $PREFIX-copy.txt
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
(time bash -c "sudo tar cf linux-6.5.9-2.tar linux-6.5.9-2 &> /dev/null; sync") &> $PREFIX-tar.txt
cd $OLDDIR

#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
N=$5
PREFIX=../results/filebench/$N-$FS-$TYPE
sed "s|KSFS_MNT|$MNT|g" webserver.f.in > webserver.f
sed "s|KSFS_MNT|$MNT|g" varmail.f.in > varmail.f
sed "s|KSFS_MNT|$MNT|g" fileserver.f.in > fileserver.f
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs
sudo filebench -f webserver.f &> $PREFIX-webserver.txt
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs
sudo filebench -f varmail.f &> $PREFIX-varmail.txt
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs
sudo filebench -f fileserver.f &> $PREFIX-fileserver.txt
sudo umount /mnt


#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
MKFS=$5

SCRIPT=`readlink -f "$0"`
DIR=`dirname $SCRIPT`

if [ "$MKFS" == "--mkfs" ]; then
    if [ "$FS" == "ntfs" ]; then
        umount $MNT
        blkdiscard -f $DEV
        mkfs.ntfs -f $DEV
    elif [ "$FS" == "exfat" ]; then
        umount $MNT
        blkdiscard -f $DEV
        mkfs.exfat $DEV
    elif [ "$FS" == "ext4" ]; then
        umount $MNT
        blkdiscard -f $DEV
        mkfs.ext4 $DEV
    fi
fi

if [ "$TYPE" == "native" ]; then
    if [ "$FS" == "ntfs" ]; then
        mount -t ntfs3 $DEV $MNT
    elif [ "$FS" == "exfat" ]; then
        mount -t exfat -o noatime $DEV $MNT
    elif [ "$FS" == "ext4" ]; then
        mount -t ext4 $DEV $MNT
    fi
elif [ "$TYPE" == "fuse" ]; then
    if [ "$FS" == "ntfs" ]; then
        $DIR/bin/lowntfs-3g -o default_permissions,permissions,allow_other,delay_mtime=1 $DEV $MNT
    elif [ "$FS" == "exfat" ]; then
        $DIR/bin/mount.exfat-lowfuse -o default_permissions,allow_other,noatime $DEV $MNT
    fi
elif [ "$TYPE" == "ksfs" ]; then
    if [ "$FS" == "ntfs" ]; then
        $DIR/bin/mount_ksfs_ntfs $DEV $MNT $DIR/ntfs.aot
    elif [ "$FS" == "exfat" ]; then
        $DIR/bin/mount_ksfs_exfat $DEV $MNT $DIR/exfat.aot
    fi
elif [ "$TYPE" == "fuse-opt" ]; then
    if [ "$FS" == "ntfs" ]; then
        $DIR/bin/lowntfs-3g-opt -o default_permissions,permissions,allow_other,delay_mtime=1 $DEV $MNT
    elif [ "$FS" == "exfat" ]; then
        $DIR/bin/mount.exfat-lowfuse-opt -o default_permissions,allow_other,noatime $DEV $MNT
    fi
elif [ "$TYPE" == "bento" ]; then
    if [ "$FS" == "exfat" ]; then
        insmod $DIR/bentofs.ko
        insmod $DIR/bento_exfat.ko
        sudo umount $MNT
        sudo mount -t bentoblk -o rootmode=0040000,user_id=0,group_id=0,allow_other,default_permissions,blksize=4096,name=bento_exfat $DEV $MNT
    fi
fi

#!/bin/bash
source ../env.sh
mkdir -p ../results/fault-injection
OUTPUT_FILE=../results/fault-injection/stack_overflow
sudo dmesg -C
$(sudo ../../drivers/bin/mount_ksfs_fault $KSFS_MNT ../../ksfs/fault-injection/stack_overflow.aot -1 &> $OUTPUT_FILE)
sudo dmesg >> $OUTPUT_FILE
if grep -qE "wasm exception: Exception: native stack overflow" $OUTPUT_FILE; then
    echo "fault caught" | tee -a $OUTPUT_FILE
fi
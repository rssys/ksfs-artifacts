#!/bin/bash
TYPE=$1
FS=$2
DEV=$3
MNT=$4
N=$5
sudo ../../drivers/mount.sh $TYPE $FS $DEV $MNT --mkfs
PREFIX=../results/rocksdb/$N-$FS-$TYPE
export NUM_KEYS=100000000
export CACHE_SIZE=536870912
export DB_DIR=$MNT/db
export WAL_DIR=$MNT/wal
sudo mkdir -p $DB_DIR $WAL_DIR
OUTPUT_DIR_bulkload=$PREFIX/bulkload
OUTPUT_DIR_readrandom=$PREFIX/readrandom
OUTPUT_DIR_overwrite=$PREFIX/overwrite
OUTPUT_DIR_readwhilewriting=$PREFIX/readwhilewriting
mkdir -p $OUTPUT_DIR_bulkload $OUTPUT_DIR_readrandom \
    $OUTPUT_DIR_overwrite $OUTPUT_DIR_readwhilewriting
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
OUTPUT_DIR=$OUTPUT_DIR_bulkload sudo -E \
    ./benchmark.sh bulkload &> $OUTPUT_DIR_bulkload/output.txt
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
DURATION=60 OUTPUT_DIR=$OUTPUT_DIR_readrandom sudo -E \
    ./benchmark.sh readrandom &> $OUTPUT_DIR_readrandom/output.txt
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
DURATION=60 OUTPUT_DIR=$OUTPUT_DIR_overwrite sudo -E \
    ./benchmark.sh overwrite &> $OUTPUT_DIR_overwrite/output.txt
sleep 10
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches
KB_WRITE_PER_SEC=100 DURATION=60 OUTPUT_DIR=$OUTPUT_DIR_readwhilewriting sudo -E \
    ./benchmark.sh readwhilewriting &> $OUTPUT_DIR_readwhilewriting/output.txt

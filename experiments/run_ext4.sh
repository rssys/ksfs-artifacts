#!/bin/bash
echo 50|sudo tee /proc/sys/vm/dirty_ratio
cd fio-sequential && ./run_ext4.sh && cd ..
cd fio-rand && ./run_ext4.sh && cd ..
cd tar && ./run_ext4.sh && cd ..
cd filebench && ./run_ext4.sh && cd ..
cd rocksdb && ./run_ext4.sh && cd ..


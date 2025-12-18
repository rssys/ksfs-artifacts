#!/bin/bash
cd bentofs && make -j && cd ..
cd exfat && make && cd ..
cp bentofs/bentofs.ko exfat/bento_exfat.ko ../drivers/
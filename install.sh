#!/bin/bash
sudo apt update
sudo apt install -y ./linux-image-6.1.38_6.1.38-13_amd64.deb ./linux-headers-6.1.38_6.1.38-13_amd64.deb ./librocksdb7.8_7.8.3-2_amd64.deb
sudo apt install -y build-essential libfuse3-dev meson ninja-build fio clang autoconf automake \
    libtool bison flex yacc pkg-config exfatprogs ntfs-3g
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
  --default-toolchain nightly-2025-08-23 \
  --target x86_64-unknown-linux-gnu
. "$HOME/.cargo/env"
rustup component add rust-src --toolchain nightly-2025-08-23
git clone https://github.com/filebench/filebench.git
cd filebench
git checkout 22620e602cbbebad90c0bd041896ebccf70dbf5f
git apply < ../filebench.patch
libtoolize
aclocal
autoheader
automake --add-missing
libtoolize
automake --add-missing
autoconf
./configure
make -j
sudo make install
cd ..
git clone https://github.com/pjd/pjdfstest.git
cd pjdfstest
autoreconf -ifs
./configure
make -j

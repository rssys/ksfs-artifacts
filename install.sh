#!/bin/bash
sudo apt update
sudo apt install -y ./linux-image-6.1.38_6.1.38-13_amd64.deb ./linux-headers-6.1.38_6.1.38-13_amd64.deb
sudo apt install -y build-essential libfuse3-dev meson ninja-build fio clang autoconf automake \
    libtool bison flex yacc pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
. "$HOME/.cargo/env"
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
wget https://github.com/filebench/filebench/archive/refs/tags/1.4.9.1.tar.gz
tar xzf 1.4.9.1.tar.gz
cd filebench-1.4.9.1
libtoolize
aclocal
autoheader
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
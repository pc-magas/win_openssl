#!/usr/bin/env bash

wget https://www.openssl.org/source/openssl-3.0.5.tar.gz 
tar -xvf openssl-3.0.5.tar.gz

echo "Makle library Path"
mkdir -p ./lib/{32,64}

echo "Install 64 bit openssl"
cd ./openssl-3.0.5
./Configure enable-tls1_3 enable-tls1_2 --prefix=$(pwd)/../lib/64 --cross-compile-prefix=x86_64-w64-mingw32- mingw64
make -j16
make install
make clean

echo "Install 32 bit openssl"
./openssl-3.0.5/Configure enable-tls1_3 enable-tls1_2 --prefix=$(pwd)/../lib/32 --cross-compile-prefix=i686-w64-mingw32- mingw
make -j16
make install

cd ../
rm -rf openssl-3.0.5.tar.gz
rm -rf openssl-openssl-3.0.5
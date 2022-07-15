#Install Compiler

```
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
sudo apt-get install g++-mingw-w64-i686 g++-mingw-w64-i686
```

# Build OpenSSL

```
wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz
tar -xvf openssl-1.1.1q.tar.gz
cd ./openssl-1.1.1q
./Configure enable-tls1_3 enable-tls1_2 no-async no-shared --cross-compile-prefix=i686-w64-mingw32- mingw
make -j 16 # j can ommited it is used to specify the build threads
make install
```

# Build APP

```
LANG=C i686-w64-mingw32-gcc main.c -lws2_32 -I"openssl-1.1.1q/C:/Program Files (x86)/OpenSSL/include" -L"openssl-1.1.1q/C:/Program Files (x86)/OpenSSL/lib" -fpermissive -o main.exe -lcrypto -lssl
```

# Run the app

```
mkdir ./release
cp -r ./openssl-1.1.1q/C\:/Program\ Files\ \(x86\)/OpenSSL/bin/*.dll ./release/
cp main.exe ./release/
```

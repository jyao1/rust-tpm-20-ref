
## Run ```process_openssl.pl```

when update opensslversion

mkdir -p conf-include/openssl;
mkdir -p conf-include/crypto;
CC=clang-12 AR=llvm-ar-12 CFLAGS="-Werror -Wall -target x86_64-unknown-windows-gnu -nostdlib -nostdlibinc -ffreestanding -Istd-include -Iconf-include -Iarch/x86_64 -include CrtLibSupport.h -UWIN32 -U_WIN32 -U_WIN64" ./process_openssl.pl

make -j$(nproc) libcrypto.a
cp libcrypto.a crypto.lib

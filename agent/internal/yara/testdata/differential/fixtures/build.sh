#!/bin/sh
# Rebuilds the binary fixtures. Needs gcc, clang and mingw-w64
# (x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc). The outputs are
# committed so the tests do not need these tools.
set -eu
cd "$(dirname "$0")"

x86_64-w64-mingw32-gcc -Os -s -nostdlib -Wl,-e,start -o pe64.exe src/pe64.c -lkernel32 -luser32
i686-w64-mingw32-gcc -Os -s -shared -nostdlib -Wl,-e,_DllMain@12 -o dll32.dll src/dll32.c -lkernel32
gcc -Os -s -nostdlib -static -no-pie -o elf_exec src/elf.c
gcc -Os -s -nostdlib -static-pie -o elf_dyn src/elf.c
gcc -O1 -o elf_hello src/hello.c
clang --target=aarch64-linux-gnu -ffreestanding -O1 -c -o elf_aarch64.o src/aarch64.c
ls -l pe64.exe dll32.dll elf_exec elf_dyn elf_hello elf_aarch64.o

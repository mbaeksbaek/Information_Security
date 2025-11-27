// AES_백승민_2020253045
#include "app.h"

/*
[11.15] TODO - File Name 공백 처리 - [11.16] 안하기로 결정, 일관성 해침

Build: Generated at : /build/app
gcc -Wall -Wextra -O2 \
  -Iinclude \
  -o build/app \
  src/main.c \
  src/app.c \
  src/aes/aes_tables.c \
  src/aes/aes_key_schedule.c \
  src/aes/aes_block.c \
  src/aes/aes_modes.c \
  src/aes/aes_ops.c \
  src/crypto_ops.c \
  src/file_io.c \
  src/codec_hex.c \
  src/runner.c

Exec:
./build/app enc line \
"res/input/Plain Text 1.txt" \
"res/output/Plain Text 1.enc" \
00112233445566778899AABBCCDDEEFF \
hex

./build/app dec line \
"res/output/Plain Text 1.enc" \
"res/output/Plain Text 1.dec" \
00112233445566778899AABBCCDDEEFF \
hex

./build/app enc whole \
"res/input/Plain Text 2.txt" \
"res/output/Plain Text 2.enc" \
00112233445566778899AABBCCDDEEFF \
hex

./build/app dec whole \
"res/output/Plain Text 2.enc" \
"res/output/Plain Text 2.dec" \
00112233445566778899AABBCCDDEEFF \
hex
*/

int main(int argc, char **argv) {
    return aes_cli_run(argc, argv);
}

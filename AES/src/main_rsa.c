// src/main_rsa.c
#include "rsa/rsa_app.h"

/*
gcc -Wall -Wextra -O2 \
  -Iinclude \
  src/main_rsa.c \
  src/rsa/rsa_app.c \
  src/rsa/rsa_ops.c \
  src/bigint/bigint.c \
  src/runner.c \
  src/file_io.c \
  src/codec_hex.c \
  src/crypto_ops.c \
  -o build/app_rsa

  # enc line
./build/app_rsa enc line \
  "res/input/Plain Text 1.txt" \
  "res/output/Plain Text 1.rsa.enc" \
  0CA10011 \
  hex

# dec line
./build/app_rsa dec line \
  "res/output/Plain Text 1.rsa.enc" \
  "res/output/Plain Text 1.rsa.dec" \
  0CA10AC1 \
  hex

  ./build/app_rsa enc whole \
  "res/input/Plain Text 2.txt" \
  "res/output/Plain Text 2.rsa.enc" \
  0CA10011 \
  hex

./build/app_rsa dec whole \
  "res/output/Plain Text 2.rsa.enc" \
  "res/output/Plain Text 2.rsa.dec" \
  0CA10AC1 \
  hex

*/

int main(int argc, char **argv) {
    return rsa_cli_run(argc, argv);
}

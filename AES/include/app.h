#ifndef ___APP_H___
#define ___APP_H___
/*
[11.15]
AES App Facade Header
added cli entry point
- main.c : aes_cli_run(argc, argv)

usage:
app enc line res/input/PlainText1.txt res/output/PlainText1.enc <KEYHEX> [hex|bin]
app dec line " " ...
*/

#include "aes/aes.h"
#include "aes/aes_ops.h"
#include "crypto_ops.h"
#include "runner.h"
#include "codec_hex.h"
#include "file_io.h"

// cli entry point of main function
int aes_cli_run(int argc, char **argv);
#endif  // app.h
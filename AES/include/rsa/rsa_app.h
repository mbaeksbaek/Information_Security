// include/rsa/rsa_app.h
/*
- [12.07] App Exception Handling Added
*/
#ifndef __RSA_APP_H__
#define __RSA_APP_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "crypto_ops.h"
#include "runner.h"
#include "codec_hex.h"
#include "file_io.h"

// RSA CLI entry point
// usage:
//   rsa_app enc line  <in> <out> <KEYHEX> [hex|raw]
//   rsa_app dec whole <in> <out> <KEYHEX> [hex|raw]
int rsa_cli_run(int argc, char **argv);

#endif // __RSA_APP_H__

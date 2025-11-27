// ... reused module from des, but minor patches
#ifndef __RUNNER_H__
#define __RUNNER_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h> // int->bool
#include "file_io.h"
//#include "des.h"    // minor patch - [11.12] Deleted - Revision to AES
#include "crypto_ops.h"

/*
// [11.12] - Deleted : Integrated to Config parameter: int is_encrypt...
typedef enum {
    RUN_MODE_ENC = 0,
    RUN_MODE_DEC = 1
} RunnerMode;
*/
/*
// [11.12] - Deleted
typedef enum {
    RUN_LINE = 0,
    RUN_FILE = 1
} RunnerPT;
*/


// [11.12] - 얘는 어떻게하지 .. key를 고정해버렸는데.
typedef struct {
    //RunnerMode mode;
    //RunnerPT pt_mode;
    // [11.12] - CryptoOps Abstraction
    const CryptoOps* ops;
    const uint8_t* key;
    size_t key_len;
    const char* input_path;
    const char* output_path;
    //uint8_t key[8]; // des keys : including parity bits
    int use_hex;    // [11.12] - 0: binary mode, 1: hex text
    bool is_encrypt; // [11.12] - 0: decrypt, 1: encrypt
} RunnerConfig;
 

// [11.12] - Deleted : Mode에 따른 함수 선언이 Open/Close Principle에 대해 낫다고 판단
// main Runner Function : user call funnction
//FHStatus runner(const RunnerConfig *config);

FHStatus runner_exec_line(const RunnerConfig* cfg);
FHStatus runner_exec_whole(const RunnerConfig* cfg);

#endif // runner.h

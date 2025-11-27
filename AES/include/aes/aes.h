#ifndef ___AES_H___
#define ___AES_H___

#include <stdint.h>
#include <stddef.h>
/*  
AES Hiearchy Structure
- Application Layer -> AES_Runner(FILE_IO) -> CRYPTO OPS(Adapter) -> AES_MODES -> AES_BLOCK -> AES_KEY_SCHEDULE -> AES_TABLES
aes_tables : only const values (closed)
aes_key_schedule : for generating round keys (closed)
aes_block : single 16B block encrypt/decrypt (closed)

aes_modes : blocks encrypt/decrypt (open)
aes_ops (Crypto Ops) : Runner Adapter (open)
aes : for api header, const&structure open (open)

Entry Point : AES_MODES

-> aes.h : open type const (header)
-> aes_modes : open api (to check functions, go to :aes_modes.h)
-> aes_block : engine
-> aes_ops : adapter
*/
enum {
    AES_BLOCK_BYTES = 16,
    AES128_KEY_BYTES = 16,
    AES192_KEY_BYTES = 24,
    AES256_KEY_BYTES = 32
};

// error code : 0 : OK, else : failure
typedef enum {
    AES_OK = 0,
    AES_ERR_INVALID_ARG,
    AES_ERR_OOM,
    AES_ERR_INTERNAL,
    AES_ERR_TEST = -999 // for debug
} AES_Status;

// key length -> Round Number Mapping -> KeySchedule
typedef struct {
    // round key memory : Max val of 60 for AES-256 case
    uint32_t rk[60];
    int Nr; // number of Rounds
} AES_KeySchedule;

#endif  // aes.h
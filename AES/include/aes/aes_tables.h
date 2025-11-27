#ifndef ___AES_TABLES_H___
#define ___AES_TABLES_H___
#include <stdint.h>
#include <stddef.h>
// test passed
// [11.14] Typo fixed
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];
extern const uint8_t AES_RCON[11];
// [11.15] Table Added : GF Mul (AES Block)
extern const uint8_t AES_MUL2[256];
extern const uint8_t AES_MUL3[256];
// Decrypt Table
extern const uint8_t AES_MUL9[256];
extern const uint8_t AES_MUL11[256];
extern const uint8_t AES_MUL13[256];
extern const uint8_t AES_MUL14[256];
#endif  // aes_tables.h
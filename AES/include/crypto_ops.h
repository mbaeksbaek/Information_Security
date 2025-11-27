#ifndef ___CRYPTO_OPS_H___
#define ___CRYPTO_OPS_H___
/*
[11.12] - Abstraction Layer Added
CryptoOps : Runner(Ocasterator) - Algorithm Adapter : Runner Abstraction Purpose
- Adapter Layer of Runner
*/
#include <stddef.h>
#include <stdint.h>

typedef struct {
    /* Key Schedule Life Cyc (0: OK, else: error) */
    int (*ks_init)(void* ks_mem, const uint8_t* key, size_t key_len);
    void (*ks_clear)(void* kes_mem);

    /* ECB + Zero Padding */
    int (*encrypt_ecb_zeropad)(const void* ks_mem, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
    int (*decrypt_ecb_strip)(const void* ks_mem, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);

    /* Runner : KS buffer malloc/free size variable */
    size_t ks_size;
} CryptoOps;

#endif  // CRYPTO_OPS_H
// RSA KAT vectors (converted from rsa_vectors.json)
#ifndef RSA_KAT_VECTORS_H
#define RSA_KAT_VECTORS_H

#include <stddef.h>

typedef struct {
    const char *name;
    const char *pt_hex;
    const char *ct_hex;
} RSAKATCase;

typedef struct {
    int bits;
    size_t k_bytes;
    const char *N_hex;
    const char *e_hex;
    const char *d_hex;
    const RSAKATCase *cases;
    size_t num_cases;
} RSAKATVector;

extern const RSAKATVector RSA_KAT_VECTORS[];
extern const size_t RSA_KAT_VECTORS_LEN;

#endif // RSA_KAT_VECTORS_H

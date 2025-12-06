// tests/unit/test_rsa_ops.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto_ops.h"
#include "rsa/rsa_ops.h"
/*
gcc -Wall -Wextra -O2 \
  -Iinclude \
  src/bigint/bigint.c \
  src/rsa/rsa_ops.c \
  tests/unit/test_rsa_ops.c \
  -o build/unit/test_rsa_ops

./build/unit/test_rsa_ops
*/
static void test_rsa_ops_small(void) {
    // p = 61, q = 53
    // n   = 3233 = 0x0CA1
    // e   = 17   = 0x0011
    // d   = 2753 = 0x0AC1

    uint8_t n_be[2] = { 0x0C, 0xA1 };
    uint8_t e_be[2] = { 0x00, 0x11 };
    uint8_t d_be[2] = { 0x0A, 0xC1 };

    uint8_t key_enc[4];
    uint8_t key_dec[4];

    memcpy(key_enc,     n_be, 2);
    memcpy(key_enc + 2, e_be, 2);

    memcpy(key_dec,     n_be, 2);
    memcpy(key_dec + 2, d_be, 2);

    // 🔥 여기! ks_size 사용해서 동적 할당
    uint8_t *ks_enc_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    uint8_t *ks_dec_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_enc_buf && ks_dec_buf);

    int ret;
    ret = RSA_OPS.ks_init(ks_enc_buf, key_enc, sizeof(key_enc));
    assert(ret == 0);
    ret = RSA_OPS.ks_init(ks_dec_buf, key_dec, sizeof(key_dec));
    assert(ret == 0);

    uint8_t pt[3] = { 'A', 'B', 'C' };
    uint8_t *ct = NULL;
    size_t ct_len = 0;

    ret = RSA_OPS.encrypt_ecb_zeropad(ks_enc_buf, pt, sizeof(pt), &ct, &ct_len);
    assert(ret == 0);
    assert(ct != NULL);
    // k_bytes = 2, pt_block_bytes = 1 → 3블록 → 3*2 = 6
    assert(ct_len == 6);

    uint8_t *pt2 = NULL;
    size_t pt2_len = 0;

    ret = RSA_OPS.decrypt_ecb_strip(ks_dec_buf, ct, ct_len, &pt2, &pt2_len);
    assert(ret == 0);
    assert(pt2 != NULL);
    assert(pt2_len == sizeof(pt));
    assert(memcmp(pt, pt2, sizeof(pt)) == 0);

    free(ct);
    free(pt2);

    RSA_OPS.ks_clear(ks_enc_buf);
    RSA_OPS.ks_clear(ks_dec_buf);
    free(ks_enc_buf);
    free(ks_dec_buf);
}

int main(void) {
    test_rsa_ops_small();
    printf("RSA OPS basic tests: OK\n");
    return 0;
}

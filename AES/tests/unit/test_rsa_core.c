// tests/unit/test_rsa_core.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "bigint/bigint.h"
#include "rsa/rsa_core.h"
/*
gcc -Wall -Wextra -O2 \
  -Iinclude \
  src/bigint/bigint.c \
  src/rsa/rsa_core.c \
  tests/unit/test_rsa_core.c \
  -o build/unit/test_rsa_core
*/

static void test_rsa_small_sample(void)
{
    // p = 61, q = 53
    // n   = 3233
    // phi = 3120
    // e   = 17
    // d   = 2753
    // message m = 65 ("A")
    // c = 65^17 mod 3233 = 2790
    // m' = 2790^2753 mod 3233 = 65

    BigInt n, e, d;
    bi_from_u64(&n, 3233u);
    bi_from_u64(&e, 17u);
    bi_from_u64(&d, 2753u);

    RSAContext ctx_enc;
    RSAContext ctx_dec;
    rsa_ctx_init(&ctx_enc, &n, &e);
    rsa_ctx_init(&ctx_dec, &n, &d);

    assert(ctx_enc.modulus_bytes == 2);
    assert(ctx_dec.modulus_bytes == 2);

    // 평문: 65 = 0x0041 (2바이트, big-endian)
    uint8_t m[2] = { 0x00, 0x41 };
    uint8_t c[2] = { 0, 0 };
    uint8_t m2[2] = { 0, 0 };

    int ret;

    ret = rsa_encrypt_block(&ctx_enc, m, sizeof(m), c, sizeof(c));
    assert(ret == 0);

    // 암호문이 0x0A, 0xE6 인지 확인 (2790 = 0x0AE6)
    assert(c[0] == 0x0A);
    assert(c[1] == 0xE6);

    ret = rsa_decrypt_block(&ctx_dec, c, sizeof(c), m2, sizeof(m2));
    assert(ret == 0);

    // 복호 결과가 원래 평문과 동일해야 함
    assert(m2[0] == m[0]);
    assert(m2[1] == m[1]);

    // 추가: m >= n 이면 실패하는지 간단 체크
    BigInt n_plus_one;
    bi_from_u64(&n_plus_one, 4000u); // 4000 > 3233

    uint8_t bad_m[2] = { 0x0F, 0xA0 }; // 4000 (0x0FA0)
    uint8_t out_bad[2];

    // ctx_enc.n은 그대로 3233이므로, 이 입력은 m >= n 이라서 실패해야 함
    ret = rsa_encrypt_block(&ctx_enc, bad_m, sizeof(bad_m), out_bad, sizeof(out_bad));
    assert(ret != 0);
}

int main(void)
{
    test_rsa_small_sample();
    printf("RSA core basic tests: OK\n");
    return 0;
}

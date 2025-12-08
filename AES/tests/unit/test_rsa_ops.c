// tests/unit/test_rsa_ops.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto_ops.h"
#include "rsa/rsa_ops.h"

/*
- gcc -Wall -Wextra -O2 \
-   -Iinclude \
-   src/bigint/bigint.c \
-   src/rsa/rsa_ops.c \
-   tests/unit/test_rsa_ops.c \
-   -o build/unit/test_rsa_ops
-
- ./build/unit/test_rsa_ops
-
- 1. 작은키(3233, 17, 2753) 기본 roundtrip
- 2. 빈 입력 처리
- 3. ciphertext 길이 불일치 에러
- 4. ks_init 잘못된 인자/올-제로 키 에러
- 5. ZeroPadding strip 정책 확인
*/

/* - 공통 키: n = 3233 (0x0CA1), e = 17 (0x0011), d = 2753 (0x0AC1) */
static void make_small_keys(uint8_t *key_enc, uint8_t *key_dec, size_t *key_len) {
    uint8_t n_be[2] = { 0x0C, 0xA1 };
    uint8_t e_be[2] = { 0x00, 0x11 };
    uint8_t d_be[2] = { 0x0A, 0xC1 };

    memcpy(key_enc,     n_be, 2);
    memcpy(key_enc + 2, e_be, 2);

    memcpy(key_dec,     n_be, 2);
    memcpy(key_dec + 2, d_be, 2);

    if (key_len) {
        *key_len = 4;
    }
}

/* - [TC1] CryptoOps 기본 round-trip ("ABC") */
static void test_rsa_ops_small_basic(void) {
    uint8_t key_enc[4];
    uint8_t key_dec[4];
    size_t  key_len = 0;
    make_small_keys(key_enc, key_dec, &key_len);

    uint8_t *ks_enc_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    uint8_t *ks_dec_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_enc_buf && ks_dec_buf);

    int ret;
    ret = RSA_OPS.ks_init(ks_enc_buf, key_enc, key_len);
    assert(ret == 0);
    ret = RSA_OPS.ks_init(ks_dec_buf, key_dec, key_len);
    assert(ret == 0);

    uint8_t pt[3] = { 'A', 'B', 'C' };
    uint8_t *ct   = NULL;
    size_t   ct_len = 0;

    ret = RSA_OPS.encrypt_ecb_zeropad(ks_enc_buf,
                                      pt, sizeof(pt),
                                      &ct, &ct_len);
    assert(ret == 0);
    assert(ct != NULL);

    /* k_bytes = 2, pt_block_bytes = 1 → 3바이트 평문 → 3블록 → 3*2 = 6 */
    assert(ct_len == 6);

    uint8_t *pt2    = NULL;
    size_t   pt2_len = 0;

    ret = RSA_OPS.decrypt_ecb_strip(ks_dec_buf,
                                    ct, ct_len,
                                    &pt2, &pt2_len);
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

/* - [TC2] 빈 입력 처리: enc/dec 모두 out_len == 0 */
static void test_rsa_ops_empty_io(void) {
    uint8_t key_enc[4];
    uint8_t key_dec[4];
    size_t  key_len = 0;
    make_small_keys(key_enc, key_dec, &key_len);

    uint8_t *ks_enc_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    uint8_t *ks_dec_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_enc_buf && ks_dec_buf);

    int ret;
    ret = RSA_OPS.ks_init(ks_enc_buf, key_enc, key_len);
    assert(ret == 0);
    ret = RSA_OPS.ks_init(ks_dec_buf, key_dec, key_len);
    assert(ret == 0);

    /* encrypt: in == NULL, n == 0 → 허용 (out_len = 0) */
    uint8_t *ct = NULL;
    size_t   ct_len = 1234; /* sentinel */
    ret = RSA_OPS.encrypt_ecb_zeropad(ks_enc_buf,
                                      NULL, 0,
                                      &ct, &ct_len);
    assert(ret == 0);
    assert(ct != NULL);
    assert(ct_len == 0);
    free(ct);

    /* decrypt: in == NULL, n == 0 → 허용 (out_len = 0) */
    uint8_t *pt = NULL;
    size_t   pt_len = 777; /* sentinel */
    ret = RSA_OPS.decrypt_ecb_strip(ks_dec_buf,
                                    NULL, 0,
                                    &pt, &pt_len);
    assert(ret == 0);
    assert(pt != NULL);
    assert(pt_len == 0);
    free(pt);

    RSA_OPS.ks_clear(ks_enc_buf);
    RSA_OPS.ks_clear(ks_dec_buf);
    free(ks_enc_buf);
    free(ks_dec_buf);
}

/* - [TC3] decrypt_ecb_strip: ciphertext 길이 불일치 에러 */
static void test_rsa_ops_bad_ct_length(void) {
    uint8_t key_enc[4];
    uint8_t key_dec[4];
    size_t  key_len = 0;
    make_small_keys(key_enc, key_dec, &key_len);

    uint8_t *ks_enc_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    uint8_t *ks_dec_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_enc_buf && ks_dec_buf);

    int ret;
    ret = RSA_OPS.ks_init(ks_enc_buf, key_enc, key_len);
    assert(ret == 0);
    ret = RSA_OPS.ks_init(ks_dec_buf, key_dec, key_len);
    assert(ret == 0);

    uint8_t pt[3] = { 'X', 'Y', 'Z' };
    uint8_t *ct   = NULL;
    size_t   ct_len = 0;

    ret = RSA_OPS.encrypt_ecb_zeropad(ks_enc_buf,
                                      pt, sizeof(pt),
                                      &ct, &ct_len);
    assert(ret == 0);
    assert(ct != NULL);
    assert(ct_len == 6); /* k_bytes = 2 */

    uint8_t *pt_bad = NULL;
    size_t   pt_bad_len = 0;

    /* 일부러 길이를 1 줄여서 n % k_bytes != 0 이 되게 한다. */
    ret = RSA_OPS.decrypt_ecb_strip(ks_dec_buf,
                                    ct, ct_len - 1,
                                    &pt_bad, &pt_bad_len);
    assert(ret != 0);
    /* 실패 시 구현상 out 포인터를 건드리지 않으므로 NULL 유지 기대 */
    assert(pt_bad == NULL);

    free(ct);

    RSA_OPS.ks_clear(ks_enc_buf);
    RSA_OPS.ks_clear(ks_dec_buf);
    free(ks_enc_buf);
    free(ks_dec_buf);
}

/* - [TC4] ks_init: 잘못된 파라미터/키 길이/올-제로 키 에러 처리 */
static void test_rsa_ops_ks_init_invalid(void) {
    uint8_t dummy_key[4] = { 0x01, 0x02, 0x03, 0x04 };

    /* ks_mem == NULL */
    int ret = RSA_OPS.ks_init(NULL, dummy_key, sizeof(dummy_key));
    assert(ret != 0);

    /* key_bytes == NULL */
    uint8_t *ks_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_buf);
    ret = RSA_OPS.ks_init(ks_buf, NULL, sizeof(dummy_key));
    assert(ret != 0);

    /* key_len == 0 */
    ret = RSA_OPS.ks_init(ks_buf, dummy_key, 0);
    assert(ret != 0);

    /* key_len 이 홀수 (3) 인 경우 */
    ret = RSA_OPS.ks_init(ks_buf, dummy_key, 3);
    assert(ret != 0);

    /* 모두 0 인 키: N 또는 EXP 가 0 으로 들어가므로 실패해야 함 */
    uint8_t zero_key[4] = { 0, 0, 0, 0 };
    ret = RSA_OPS.ks_init(ks_buf, zero_key, sizeof(zero_key));
    assert(ret != 0);

    free(ks_buf);
}

/* - [TC5] ZeroPadding + strip: "A00" encrypt/decrypt 후 'A'만 남는지 확인 */
static void test_rsa_ops_zero_padding_strip(void) {
    uint8_t key_enc[4];
    uint8_t key_dec[4];
    size_t  key_len = 0;
    make_small_keys(key_enc, key_dec, &key_len);

    uint8_t *ks_enc_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    uint8_t *ks_dec_buf = (uint8_t *)malloc(RSA_OPS.ks_size);
    assert(ks_enc_buf && ks_dec_buf);

    int ret;
    ret = RSA_OPS.ks_init(ks_enc_buf, key_enc, key_len);
    assert(ret == 0);
    ret = RSA_OPS.ks_init(ks_dec_buf, key_dec, key_len);
    assert(ret == 0);

    /* "A" + padding 2바이트를 평문으로 넣어본다. */
    uint8_t pt[3] = { 'A', 0x00, 0x00 };
    uint8_t *ct   = NULL;
    size_t   ct_len = 0;

    ret = RSA_OPS.encrypt_ecb_zeropad(ks_enc_buf,
                                      pt, sizeof(pt),
                                      &ct, &ct_len);
    assert(ret == 0);
    assert(ct != NULL);

    uint8_t *pt2    = NULL;
    size_t   pt2_len = 0;

    ret = RSA_OPS.decrypt_ecb_strip(ks_dec_buf,
                                    ct, ct_len,
                                    &pt2, &pt2_len);
    assert(ret == 0);
    assert(pt2 != NULL);

    /* 뒤쪽 ZeroPadding 이 잘 strip 되어 길이는 1, 내용은 'A' 만 남아야 한다. */
    assert(pt2_len == 1);
    assert(pt2[0] == 'A');

    free(ct);
    free(pt2);

    RSA_OPS.ks_clear(ks_enc_buf);
    RSA_OPS.ks_clear(ks_dec_buf);
    free(ks_enc_buf);
    free(ks_dec_buf);
}

/* - 엔트리포인트: rsa_ops 확장 테스트 */
int main(void) {
    test_rsa_ops_small_basic();
    test_rsa_ops_empty_io();
    test_rsa_ops_bad_ct_length();
    test_rsa_ops_ks_init_invalid();
    test_rsa_ops_zero_padding_strip();

    printf("RSA OPS extended tests: OK\n");
    return 0;
}

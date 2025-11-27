// AES_백승민_2020253045
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"
#include "aes/aes_key_schedule.h"
#include "aes/aes_block.h"
              
/*
   예외/에러 케이스 의도 (NEG-ARGS / NEG-HELPER)
    - aes_encrypt_block / aes_decrypt_block
         * ks == NULL → AES_ERR_INVALID_ARG
         * in == NULL, out == NULL → AES_ERR_INVALID_ARG
         * ks.Nr 가 9처럼 잘못된 라운드 수를 가진 경우 → AES_ERR_INVALID_ARG
     - SubBytes / ShiftRows / MixColumns / AddRoundKey helper 들
         * in == NULL 또는 out == NULL → AES_ERR_INVALID_ARG
         * AddRoundKey 에서 rk == NULL → AES_ERR_INVALID_ARG
 
 
     - 이 파일은 AES 한 블록(16바이트)에 대한
       "정상적인 라운드 동작" + "잘못된 인자 전달 시 방어 로직"까지 함께 검증한다.
 */

/*
 * AES Block Unit Tests
 *
 *  - SubBytes / ShiftRows / MixColumns (단일 연산)
 *  - 한 라운드 흐름 (Figure 7.21)
 *  - AES-128 KAT (FIPS-197 + 강의자료 예제 7.12~7.14)
 *  - Negative / Edge 케이스
  gcc -Wall -Wextra -O2 \
  -Iinclude \
  -o build/unit/test_unit_block \
  tests/unit/test_unit_block.c \
  src/aes/aes_tables.c \
  src/aes/aes_key_schedule.c \
  src/aes/aes_block.c

  [Coverage Test]
  gcc -Wall -Wextra -O0 --coverage \
  -Iinclude \
  -o build/unit/test_unit_block \
  tests/unit/test_unit_block.c \
  src/aes/aes_tables.c \
  src/aes/aes_key_schedule.c \
  src/aes/aes_block.c
 */

static void dump_hex16(const char *label, const uint8_t v[16])
{
    printf("%s", label);
    for (int i = 0; i < 16; ++i) {
        printf("%02X", v[i]);
        if (i != 15) printf(" ");
    }
    printf("\n");
}


static int test_subbytes_basic(void)
{
    const uint8_t in[16] = {
        0x00,0x12,0x0C,0x08,
        0x04,0x04,0x00,0x23,
        0x12,0x12,0x13,0x19,
        0x14,0x00,0x11,0x19
    };

    const uint8_t expect[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0xF2,0x63,0x26,
        0xC9,0xC9,0x7D,0xD4,
        0xFA,0x63,0x82,0xD4
    };

    uint8_t out[16];
    AES_Status st = aes_block_test_subbytes(in, out);
    if (st != AES_OK) {
        printf("[SubBytes] FAIL: status=%d\n", st);
        return 1;
    }
    if (memcmp(out, expect, 16) != 0) {
        printf("[SubBytes] FAIL: state mismatch\n");
        dump_hex16("  in     : ", in);
        dump_hex16("  expect : ", expect);
        dump_hex16("  actual : ", out);
        return 1;
    }
    printf("[SubBytes] OK\n");
    return 0;
}

static int test_shiftrows_basic(void)
{
    const uint8_t in[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0xF2,0x63,0x26,
        0xC9,0xC9,0x7D,0xD4,
        0xFA,0x63,0x82,0xD4
    };

    const uint8_t expect[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0x63,0x26,0xF2,
        0x7D,0xD4,0xC9,0xC9,
        0xD4,0xFA,0x63,0x82
    };

    uint8_t out[16];
    AES_Status st = aes_block_test_shiftrows(in, out);
    if (st != AES_OK) {
        printf("[ShiftRows] FAIL: status=%d\n", st);
        return 1;
    }
    if (memcmp(out, expect, 16) != 0) {
        printf("[ShiftRows] FAIL: state mismatch\n");
        dump_hex16("  in     : ", in);
        dump_hex16("  expect : ", expect);
        dump_hex16("  actual : ", out);
        return 1;
    }
    printf("[ShiftRows] OK\n");
    return 0;
}

static int test_mixcolumns_basic(void)
{
    const uint8_t in[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0x63,0x26,0xF2,
        0x7D,0xD4,0xC9,0xC9,
        0xD4,0xFA,0x63,0x82
    };

    const uint8_t expect[16] = {
        0x62,0x02,0x27,0x26,
        0xCF,0x92,0x91,0x0D,
        0x0C,0x0C,0xF4,0xD6,
        0x99,0x18,0x30,0x74
    };

    uint8_t out[16];
    AES_Status st = aes_block_test_mixcolumns(in, out);
    if (st != AES_OK) {
        printf("[MixColumns] FAIL: status=%d\n", st);
        return 1;
    }
    if (memcmp(out, expect, 16) != 0) {
        printf("[MixColumns] FAIL: state mismatch\n");
        dump_hex16("  in     : ", in);
        dump_hex16("  expect : ", expect);
        dump_hex16("  actual : ", out);
        return 1;
    }
    printf("[MixColumns] OK\n");
    return 0;
}

/*
 *  AES-128 KAT : FIPS-197 Appendix C.1
*/
static int test_encrypt_block_kat128_fips(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    };

    const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,
        0xCC,0xDD,0xEE,0xFF
    };

    const uint8_t expect_ct[16] = {
        0x69,0xC4,0xE0,0xD8,
        0x6A,0x7B,0x04,0x30,
        0xD8,0xCD,0xB7,0x80,
        0x70,0xB4,0xC5,0x5A
    };

    AES_KeySchedule ks;
    uint8_t out[16];

    AES_Status st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[KAT-FIPS] FAIL: key_schedule_init status=%d\n", st);
        return 1;
    }

    st = aes_encrypt_block(&ks, pt, out);
    if (st != AES_OK) {
        printf("[KAT-FIPS] FAIL: aes_encrypt_block status=%d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    if (memcmp(out, expect_ct, 16) != 0) {
        printf("[KAT-FIPS] FAIL: ciphertext mismatch\n");
        dump_hex16("  expect : ", expect_ct);
        dump_hex16("  actual : ", out);
        aes_key_schedule_clear(&ks);
        return 1;
    }
        /* decrypt: CT -> PT */
    {
        uint8_t dec[16];
        st = aes_decrypt_block(&ks, expect_ct, dec);
        if (st != AES_OK || memcmp(dec, pt, 16) != 0) {
            printf("[KAT-FIPS] FAIL: decrypt mismatch\n");
            dump_hex16("  expect_pt : ", pt);
            dump_hex16("  actual_pt : ", dec);
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }

    aes_key_schedule_clear(&ks);
    printf("[KAT-FIPS] OK\n");
    return 0;
}

/* 
 *  AES-128 KAT : 강의자료 Example 7.12, 7.13, 7.14 */

static int test_encrypt_block_lecture_712_713(void)
{
    /* Example 7.12 & 7.13 공통 키 */
    const uint8_t key[16] = {
        0x24,0x75,0xA2,0xB3,
        0x34,0x75,0x56,0x88,
        0x31,0xE2,0x12,0x00,
        0x13,0xAA,0x54,0x87
    };

    const uint8_t pt1[16] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };

    const uint8_t pt2[16] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x01
    };

    const uint8_t ct1[16] = {
        0x63,0x2C,0xD4,0x5E,
        0x5D,0x56,0xED,0xB5,
        0x62,0x04,0x01,0xA0,
        0xAA,0x9C,0x2D,0x8D
    };

    const uint8_t ct2[16] = {
        0x26,0xF3,0x9B,0xBC,
        0xA1,0x9C,0x0F,0xB7,
        0xC7,0x2E,0x7E,0x30,
        0x63,0x92,0x73,0x13
    };

    AES_KeySchedule ks;
    uint8_t out[16];
    AES_Status st;

    st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[KAT-LEC-712/713] FAIL: key_schedule_init status=%d\n", st);
        return 1;
    }

    /* Example 7.12 / Ciphertext1 */
    st = aes_encrypt_block(&ks, pt1, out);
    if (st != AES_OK || memcmp(out, ct1, 16) != 0) {
        printf("[KAT-712] FAIL\n");
        dump_hex16("  expect : ", ct1);
        dump_hex16("  actual : ", out);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    /* decrypt ct1 -> pt1 */
    {
        uint8_t dec[16];
        st = aes_decrypt_block(&ks, ct1, dec);
        if (st != AES_OK || memcmp(dec, pt1, 16) != 0) {
            printf("[KAT-712] FAIL: decrypt mismatch\n");
            dump_hex16("  expect_pt : ", pt1);
            dump_hex16("  actual_pt : ", dec);
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }

    /* Example 7.13 / Ciphertext2 */
    st = aes_encrypt_block(&ks, pt2, out);
    if (st != AES_OK || memcmp(out, ct2, 16) != 0) {
        printf("[KAT-713] FAIL\n");
        dump_hex16("  expect : ", ct2);
        dump_hex16("  actual : ", out);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    {
        uint8_t dec[16];
        st = aes_decrypt_block(&ks, ct2, dec);
        if (st != AES_OK || memcmp(dec, pt2, 16) != 0) {
            printf("[KAT-713] FAIL: decrypt mismatch\n");
            dump_hex16("  expect_pt : ", pt2);
            dump_hex16("  actual_pt : ", dec);
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }

    aes_key_schedule_clear(&ks);
    printf("[KAT-LEC-712/713] OK\n");
    return 0;
}

static int test_encrypt_block_lecture_714(void)
{
    /* Example 7.14 : all-zero key */
    const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };

    const uint8_t pt[16] = {
        0x00,0x04,0x12,0x14,
        0x12,0x04,0x12,0x00,
        0x0C,0x00,0x13,0x11,
        0x08,0x23,0x19,0x19
    };

    const uint8_t expect_ct[16] = {
        0x5A,0x6F,0x4B,0x67,
        0x57,0xB7,0xA5,0xD2,
        0xC4,0x30,0x91,0xED,
        0x64,0x9A,0x42,0x72
    };

    AES_KeySchedule ks;
    uint8_t out[16];
    AES_Status st;

    st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[KAT-714] FAIL: key_schedule_init status=%d\n", st);
        return 1;
    }


    st = aes_encrypt_block(&ks, pt, out);
    if (st != AES_OK || memcmp(out, expect_ct, 16) != 0) {
        printf("[KAT-714] FAIL\n");
        dump_hex16("  expect : ", expect_ct);
        dump_hex16("  actual : ", out);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    /* decrypt: ct -> pt */
    {
        uint8_t dec[16];
        st = aes_decrypt_block(&ks, expect_ct, dec);
        if (st != AES_OK || memcmp(dec, pt, 16) != 0) {
            printf("[KAT-714] FAIL: decrypt mismatch\n");
            dump_hex16("  expect_pt : ", pt);
            dump_hex16("  actual_pt : ", dec);
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }

    aes_key_schedule_clear(&ks);
    printf("[KAT-714] OK\n");
    return 0;
}

/* 
 *  Edge: all-zero key & block 
 */

static int test_encrypt_block_all_zero(void)
{
    AES_KeySchedule ks;
    uint8_t key[16] = {0};
    uint8_t pt[16]  = {0};
    uint8_t out1[16];
    uint8_t out2[16];

    AES_Status st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[AllZero] FAIL: key_schedule_init status=%d\n", st);
        return 1;
    }

    st = aes_encrypt_block(&ks, pt, out1);
    if (st != AES_OK) {
        printf("[AllZero] FAIL: first encrypt status=%d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    st = aes_encrypt_block(&ks, pt, out2);
    if (st != AES_OK) {
        printf("[AllZero] FAIL: second encrypt status=%d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    if (memcmp(out1, out2, 16) != 0) {
        printf("[AllZero] FAIL: out1 != out2\n");
        dump_hex16("  out1 : ", out1);
        dump_hex16("  out2 : ", out2);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    /* decrypt: ct -> pt (all zero) */
    {
        uint8_t dec[16];
        st = aes_decrypt_block(&ks, out1, dec);
        if (st != AES_OK || memcmp(dec, pt, 16) != 0) {
            printf("[AllZero] FAIL: decrypt mismatch\n");
            dump_hex16("  expect_pt : ", pt);
            dump_hex16("  actual_pt : ", dec);
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }
    aes_key_schedule_clear(&ks);
    printf("[AllZero] OK\n");
    return 0;
}

/*
 *  Negative: aes_encrypt_block 인자 / Nr 체크
 */

static int test_encrypt_block_negative_args(void)
{
    AES_KeySchedule ks;
    uint8_t key[16] = {0};
    uint8_t pt[16]  = {0};
    uint8_t ct[16]  = {0};
    AES_Status st;

    st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[NEG-ARGS] FAIL: key_schedule_init status=%d\n", st);
        return 1;
    }

    st = aes_encrypt_block(NULL, pt, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: ks=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    st = aes_encrypt_block(&ks, NULL, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: in=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    st = aes_encrypt_block(&ks, pt, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: out=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    AES_KeySchedule bad_ks;
    memset(&bad_ks, 0, sizeof(bad_ks));
    bad_ks.Nr = 9; /* invalid */

    st = aes_encrypt_block(&bad_ks, pt, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: invalid Nr -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }
        /* decrypt 쪽도 동일한 인자 검증 */
    st = aes_decrypt_block(NULL, pt, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: dec ks=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    st = aes_decrypt_block(&ks, NULL, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: dec in=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    st = aes_decrypt_block(&ks, pt, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: dec out=NULL -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    //AES_KeySchedule bad_ks;
    memset(&bad_ks, 0, sizeof(bad_ks));
    bad_ks.Nr = 9; /* invalid */

    st = aes_decrypt_block(&bad_ks, pt, ct);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] FAIL: dec invalid Nr -> %d\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    aes_key_schedule_clear(&ks);
    printf("[NEG-ARGS] OK\n");
    return 0;
}

// negative
static int test_internal_helpers_negative(void)
{
    uint8_t in[16]  = {0};
    uint8_t out[16] = {0};
    uint32_t rw[4]  = {0};
    AES_Status st;
    int fail = 0;

    st = aes_block_test_subbytes(NULL, out);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] SubBytes in=NULL -> %d\n", st);
        fail++;
    }
    st = aes_block_test_subbytes(in, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] SubBytes out=NULL -> %d\n", st);
        fail++;
    }

    st = aes_block_test_shiftrows(NULL, out);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] ShiftRows in=NULL -> %d\n", st);
        fail++;
    }
    st = aes_block_test_shiftrows(in, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] ShiftRows out=NULL -> %d\n", st);
        fail++;
    }

    st = aes_block_test_mixcolumns(NULL, out);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] MixColumns in=NULL -> %d\n", st);
        fail++;
    }
    st = aes_block_test_mixcolumns(in, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] MixColumns out=NULL -> %d\n", st);
        fail++;
    }

    st = aes_block_test_addroundkey(NULL, out, rw);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] AddRK in=NULL -> %d\n", st);
        fail++;
    }
    st = aes_block_test_addroundkey(in, NULL, rw);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] AddRK out=NULL -> %d\n", st);
        fail++;
    }
    st = aes_block_test_addroundkey(in, out, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-HELPER] AddRK rk=NULL -> %d\n", st);
        fail++;
    }

    if (fail == 0) {
        printf("[NEG-HELPER] OK\n");
        return 0;
    } else {
        printf("[NEG-HELPER] FAIL count=%d\n", fail);
        return 1;
    }
}


// inverse rt
static int test_subbytes_inverse_roundtrip(void)
{
    const uint8_t src[16] = {
        0x00,0x12,0x0C,0x08,
        0x04,0x04,0x00,0x23,
        0x12,0x12,0x13,0x19,
        0x14,0x00,0x11,0x19
    };

    uint8_t tmp[16];
    uint8_t out[16];

    AES_Status st = aes_block_test_subbytes(src, tmp);
    if (st != AES_OK) {
        printf("[InvSubBytes] FAIL: forward status=%d\n", st);
        return 1;
    }

    st = aes_block_test_inv_subbytes(tmp, out);
    if (st != AES_OK) {
        printf("[InvSubBytes] FAIL: inverse status=%d\n", st);
        return 1;
    }

    if (memcmp(out, src, 16) != 0) {
        printf("[InvSubBytes] FAIL: round-trip mismatch\n");
        dump_hex16("  src    : ", src);
        dump_hex16("  afterS : ", tmp);
        dump_hex16("  back   : ", out);
        return 1;
    }

    printf("[InvSubBytes] OK\n");
    return 0;
}

static int test_shiftrows_inverse_roundtrip(void)
{
    const uint8_t src[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0xF2,0x63,0x26,
        0xC9,0xC9,0x7D,0xD4,
        0xFA,0x63,0x82,0xD4
    };

    uint8_t tmp[16];
    uint8_t out[16];

    AES_Status st = aes_block_test_shiftrows(src, tmp);
    if (st != AES_OK) {
        printf("[InvShiftRows] FAIL: forward status=%d\n", st);
        return 1;
    }

    st = aes_block_test_inv_shiftrows(tmp, out);
    if (st != AES_OK) {
        printf("[InvShiftRows] FAIL: inverse status=%d\n", st);
        return 1;
    }

    if (memcmp(out, src, 16) != 0) {
        printf("[InvShiftRows] FAIL: round-trip mismatch\n");
        dump_hex16("  src    : ", src);
        dump_hex16("  afterR : ", tmp);
        dump_hex16("  back   : ", out);
        return 1;
    }

    printf("[InvShiftRows] OK\n");
    return 0;
}

static int test_mixcolumns_inverse_roundtrip(void)
{
    const uint8_t src[16] = {
        0x63,0xC9,0xFE,0x30,
        0xF2,0x63,0x26,0xF2,
        0x7D,0xD4,0xC9,0xC9,
        0xD4,0xFA,0x63,0x82
    };

    uint8_t tmp[16];
    uint8_t out[16];

    AES_Status st = aes_block_test_mixcolumns(src, tmp);
    if (st != AES_OK) {
        printf("[InvMixColumns] FAIL: forward status=%d\n", st);
        return 1;
    }

    st = aes_block_test_inv_mixcolumns(tmp, out);
    if (st != AES_OK) {
        printf("[InvMixColumns] FAIL: inverse status=%d\n", st);
        return 1;
    }

    if (memcmp(out, src, 16) != 0) {
        printf("[InvMixColumns] FAIL: round-trip mismatch\n");
        dump_hex16("  src    : ", src);
        dump_hex16("  afterM : ", tmp);
        dump_hex16("  back   : ", out);
        return 1;
    }

    printf("[InvMixColumns] OK\n");
    return 0;
}



int main(void)
{
    int fails = 0;

    fails += test_subbytes_basic();
    fails += test_shiftrows_basic();
    fails += test_mixcolumns_basic();

    //fails += test_single_round_flow_fig_7_21();
    fails += test_subbytes_inverse_roundtrip();
    fails += test_shiftrows_inverse_roundtrip();
    fails += test_mixcolumns_inverse_roundtrip();

    fails += test_encrypt_block_kat128_fips();
    fails += test_encrypt_block_lecture_712_713();
    fails += test_encrypt_block_lecture_714();

    fails += test_encrypt_block_all_zero();
    fails += test_encrypt_block_negative_args();
    fails += test_internal_helpers_negative();

    if (fails == 0) {
        printf("== AES Block UNIT TESTS: PASSED ==\n");
        return 0;
    } else {
        printf("== AES Block UNIT TESTS: FAILED (count=%d) ==\n", fails);
        return 1;
    }
}

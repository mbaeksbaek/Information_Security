// AES_백승민_2020253045
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes/aes.h"
#include "aes/aes_key_schedule.h"
#include "aes/aes_block.h"
#include "aes/aes_modes.h"
/*
  [Unit Test] AES ECB 모드 (aes_modes.c)
 
   대상
     - aes_encrypt_ecb_zeropad()
     - aes_decrypt_ecb_strip()
     - 내부적으로 aes_encrypt_block / aes_decrypt_block + 패딩 정책
 
   주요 테스트
     - 다양한 길이에 대한 round-trip:
          len = 0, 1, 15, 16, 17, 31, 32 ... 경계 길이
          ZeroPadding 규칙에 맞춰 암호문 길이(ct_len)가
           16바이트 배수인지, 복호 후 원문 길이와 일치하는지 확인
     - 랜덤 평문 100회 반복 round-trip 으로 모드 단위 안정성 확인
 
   예외/에러 케이스 의도
     - NULL 인자 / 버퍼 크기 부족에 대한 방어 코드 검증
          ctx == NULL, in == NULL, out == NULL
          out_len == NULL
          out 버퍼가 필요한 길이보다 작은 경우
         → 모두 AES_ERR_INVALID_ARG 또는 관련 에러 코드 기대
     - encrypt/decrypt 호출 전에 key schedule 이 제대로 초기화되지 않은 경우
       (Nr, rk 등이 이상한 값)도 음성 케이스에서 다룰 수 있도록 준비.
*/
/*
  gcc -Wall -Wextra -O2 \
   -Iinclude \
   -o build/unit/test_modes_ecb \
   tests/unit/test_modes_ecb.c \
   src/aes/aes_tables.c \
   src/aes/aes_key_schedule.c \
   src/aes/aes_block.c \
   src/aes/aes_modes.c
*/
/*
[Coverage Test]
gcc -Wall -Wextra -O0 --coverage \
   -Iinclude \
   -o build/unit/test_modes_ecb \
   tests/unit/test_modes_ecb.c \
   src/aes/aes_tables.c \
   src/aes/aes_key_schedule.c \
   src/aes/aes_block.c \
   src/aes/aes_modes.c

gcov test_key_schedule-aes_key_schedule.gcno
gcov test_key_schedule-aes_tables.gcno
gcov 
*/

static void dump_hex(const char* label, const uint8_t* buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if (i + 1 != len) printf(" ");
    }
    printf("\n");
}

// key sscheduler helper
static AES_Status ks128_init(AES_KeySchedule* ks)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    };
    return aes_key_schedule_init(ks, key, AES128_KEY_BYTES);
}

/*  1) Roundtrip 경계 테스트: 0,1,15,16,17,31,32 바이트 */
static int test_roundtrip_boundaries(void)
{
    size_t lengths[] = {0, 1, 15, 16, 17, 31, 32};
    int num = (int)(sizeof(lengths) / sizeof(lengths[0]));
    int fails = 0;

    for (int i = 0; i < num; ++i) {
        size_t len = lengths[i];
        AES_KeySchedule ks;
        AES_Status st;

        st = ks128_init(&ks);
        if (st != AES_OK) {
            printf("[RT-Boundary] len=%zu: ks_init FAIL (%d)\n", len, st);
            return 1;
        }

        uint8_t* pt = NULL;
        if (len > 0) {
            pt = (uint8_t*)malloc(len);
            if (!pt) {
                printf("[RT-Boundary] len=%zu: OOM (pt)\n", len);
                aes_key_schedule_clear(&ks);
                return 1;
            }
            for (size_t j = 0; j < len; ++j) {
                pt[j] = (uint8_t)(j + 1); // ★ 항상 non-zero 패턴
            }
        }

        uint8_t* ct = NULL;
        size_t ct_len = 0;

        st = aes_encrypt_zeropad(&ks, pt, len, &ct, &ct_len);
        if (st != AES_OK) {
            printf("[RT-Boundary] len=%zu: encrypt FAIL (%d)\n", len, st);
            free(pt);
            aes_key_schedule_clear(&ks);
            return 1;
        }

        if (!ct || (ct_len % AES_BLOCK_BYTES) != 0) {
            printf("[RT-Boundary] len=%zu: encrypt out invalid (ct=%p, len=%zu)\n",
                   len, (void*)ct, ct_len);
            free(pt);
            free(ct);
            aes_key_schedule_clear(&ks);
            return 1;
        }

        size_t expected_ct_len =
            (len == 0) ? AES_BLOCK_BYTES
                       : ((len + AES_BLOCK_BYTES - 1) / AES_BLOCK_BYTES) * AES_BLOCK_BYTES;
        if (ct_len != expected_ct_len) {
            printf("[RT-Boundary] len=%zu: ct_len mismatch (exp=%zu, got=%zu)\n",
                   len, expected_ct_len, ct_len);
            free(pt);
            free(ct);
            aes_key_schedule_clear(&ks);
            return 1;
        }

        uint8_t* dec = NULL;
        size_t dec_len = 0;

        st = aes_ecb_decrypt_stripzero(&ks, ct, ct_len, &dec, &dec_len);
        if (st != AES_OK) {
            printf("[RT-Boundary] len=%zu: decrypt FAIL (%d)\n", len, st);
            free(pt);
            free(ct);
            aes_key_schedule_clear(&ks);
            return 1;
        }

        if (len == 0) {
            if (dec_len != 0) {
                printf("[RT-Boundary] len=0: dec_len!=0 (%zu)\n", dec_len);
                free(pt);
                free(ct);
                free(dec);
                aes_key_schedule_clear(&ks);
                return 1;
            }
        } else {
            if (!dec || dec_len != len) {
                printf("[RT-Boundary] len=%zu: dec_len mismatch (exp=%zu, got=%zu)\n",
                       len, len, dec_len);
                dump_hex("  ct   : ", ct, ct_len);
                if (dec) dump_hex("  dec  : ", dec, dec_len);
                free(pt);
                free(ct);
                free(dec);
                aes_key_schedule_clear(&ks);
                return 1;
            }
            if (memcmp(pt, dec, len) != 0) {
                printf("[RT-Boundary] len=%zu: PT != DEC\n", len);
                dump_hex("  pt   : ", pt, len);
                dump_hex("  dec  : ", dec, dec_len);
                free(pt);
                free(ct);
                free(dec);
                aes_key_schedule_clear(&ks);
                return 1;
            }
        }

        free(pt);
        free(ct);
        free(dec);
        aes_key_schedule_clear(&ks);
    }

    printf("[RT-Boundary] OK\n");
    return fails;
}


/*
   2) 패딩/제로 스트립 동작 테스트
      - 중간 0x00 은 유지
      - 끝의 0x00 들은 잘려나감
*/

static int test_zero_strip_behavior(void)
{
    AES_KeySchedule ks;
    AES_Status st = ks128_init(&ks);
    if (st != AES_OK) {
        printf("[ZeroStrip] ks_init FAIL (%d)\n", st);
        return 1;
    }

    /* (A) 중간에 0x00 이 포함된 경우: 원본 그대로 복원되어야 함 */
    const uint8_t pt_mid[] = {
        0x11, 0x22, 0x00, 0x33, 0x00, 0x44, 0x55
    };
    const size_t len_mid = sizeof(pt_mid);

    uint8_t *ct = NULL, *dec = NULL;
    size_t ct_len = 0, dec_len = 0;

    st = aes_encrypt_zeropad(&ks, pt_mid, len_mid, &ct, &ct_len);
    if (st != AES_OK) {
        printf("[ZeroStrip] mid: encrypt FAIL (%d)\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    st = aes_ecb_decrypt_stripzero(&ks, ct, ct_len, &dec, &dec_len);
    if (st != AES_OK || dec_len != len_mid || memcmp(pt_mid, dec, len_mid) != 0) {
        printf("[ZeroStrip] mid: roundtrip FAIL\n");
        dump_hex("  pt  : ", pt_mid, len_mid);
        if (dec) dump_hex("  dec : ", dec, dec_len);
        free(ct);
        free(dec);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    free(ct);
    free(dec);

    /* (B) 끝에 0x00 이 붙어있는 경우: 끝의 연속된 0x00 은 제거됨 */
    const uint8_t pt_tail[] = {
        0xAA, 0xBB, 0xCC, 0x00, 0x00
    };
    const size_t len_tail = sizeof(pt_tail);

    st = aes_encrypt_zeropad(&ks, pt_tail, len_tail, &ct, &ct_len);
    if (st != AES_OK) {
        printf("[ZeroStrip] tail: encrypt FAIL (%d)\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }
    st = aes_ecb_decrypt_stripzero(&ks, ct, ct_len, &dec, &dec_len);
    if (st != AES_OK) {
        printf("[ZeroStrip] tail: decrypt FAIL (%d)\n", st);
        free(ct);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    /* 예상: 끝의 0x00,0x00 제거 > [AA,BB,CC] 만 남음 */
    if (dec_len != 3 ||
        dec[0] != 0xAA || dec[1] != 0xBB || dec[2] != 0xCC) {
        printf("[ZeroStrip] tail: strip result unexpected\n");
        dump_hex("  dec : ", dec, dec_len);
        free(ct);
        free(dec);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    free(ct);
    free(dec);
    aes_key_schedule_clear(&ks);

    printf("[ZeroStrip] OK\n");
    return 0;
}

/* 
 *  3) KAT 기반 모드 동작 검증
 *     - 한 블록짜리 KAT 를 모드로 암/복호
 */

static int test_modes_with_fips_kat_block(void)
{
    /* FIPS-197 AES-128 Appendix C.1 */
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
    AES_Status st = aes_key_schedule_init(&ks, key, AES128_KEY_BYTES);
    if (st != AES_OK) {
        printf("[Modes-KAT] ks_init FAIL (%d)\n", st);
        return 1;
    }

    uint8_t* ct = NULL;
    size_t ct_len = 0;

    /* 길이 16 → 패딩 없이 딱 1블록 암호화 되는지 확인 */
    st = aes_encrypt_zeropad(&ks, pt, sizeof(pt), &ct, &ct_len);
    if (st != AES_OK) {
        printf("[Modes-KAT] encrypt FAIL (%d)\n", st);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    if (ct_len != 16 || memcmp(ct, expect_ct, 16) != 0) {
        printf("[Modes-KAT] encrypt mismatch\n");
        dump_hex("  expect : ", expect_ct, 16);
        dump_hex("  actual : ", ct, ct_len);
        free(ct);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    uint8_t* dec = NULL;
    size_t dec_len = 0;

    st = aes_ecb_decrypt_stripzero(&ks, ct, ct_len, &dec, &dec_len);
    if (st != AES_OK || dec_len != 16 || memcmp(dec, pt, 16) != 0) {
        printf("[Modes-KAT] decrypt mismatch\n");
        dump_hex("  dec : ", dec, dec_len);
        free(ct);
        free(dec);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    free(ct);
    free(dec);
    aes_key_schedule_clear(&ks);

    printf("[Modes-KAT] OK\n");
    return 0;
}

/* 
 *  4) Negative 테스트 (인자 검증, Nr 검증)
 */

static int test_modes_negative_args(void)
{
    AES_KeySchedule ks;
    uint8_t dummy[32] = {0x11,0x22,0x33,0x44};
    uint8_t* out = NULL;
    size_t out_len = 0;
    AES_Status st;
    int fail = 0;

    if (ks128_init(&ks) != AES_OK) {
        printf("[NEG-ARGS] ks_init FAIL\n");
        return 1;
    }

    /* encrypt 쪽 */
    st = aes_encrypt_zeropad(NULL, dummy, sizeof(dummy), &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] encrypt ks=NULL -> %d\n", st);
        fail++;
    }

    st = aes_encrypt_zeropad(&ks, NULL, 10, &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] encrypt in=NULL, len>0 -> %d\n", st);
        fail++;
    }

    st = aes_encrypt_zeropad(&ks, dummy, sizeof(dummy), NULL, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] encrypt out=NULL -> %d\n", st);
        fail++;
    }

    st = aes_encrypt_zeropad(&ks, dummy, sizeof(dummy), &out, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] encrypt out_len=NULL -> %d\n", st);
        fail++;
    }

    /* decrypt 쪽: 길이 16배수 아니면 에러 */
    st = aes_ecb_decrypt_stripzero(&ks, dummy, 15, &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt len not multiple of 16 -> %d\n", st);
        fail++;
    }

    st = aes_ecb_decrypt_stripzero(NULL, dummy, 16, &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt ks=NULL -> %d\n", st);
        fail++;
    }

    st = aes_ecb_decrypt_stripzero(&ks, NULL, 16, &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt in=NULL -> %d\n", st);
        fail++;
    }

    st = aes_ecb_decrypt_stripzero(&ks, dummy, 16, NULL, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt out=NULL -> %d\n", st);
        fail++;
    }

    st = aes_ecb_decrypt_stripzero(&ks, dummy, 16, &out, NULL);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt out_len=NULL -> %d\n", st);
        fail++;
    }

    /* 잘못된 Nr */
    AES_KeySchedule bad_ks;
    memset(&bad_ks, 0, sizeof(bad_ks));
    bad_ks.Nr = 9; /* 유효: 10/12/14 만 허용 */

    st = aes_encrypt_zeropad(&bad_ks, dummy, sizeof(dummy), &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] encrypt bad Nr -> %d\n", st);
        fail++;
    }

    st = aes_ecb_decrypt_stripzero(&bad_ks, dummy, 16, &out, &out_len);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG-ARGS] decrypt bad Nr -> %d\n", st);
        fail++;
    }

    aes_key_schedule_clear(&ks);

    if (fail == 0) {
        printf("[NEG-ARGS] OK\n");
        return 0;
    } else {
        printf("[NEG-ARGS] FAIL count=%d\n", fail);
        return 1;
    }
}

int main(void)
{
    int fails = 0;

    fails += test_roundtrip_boundaries();
    fails += test_zero_strip_behavior();
    fails += test_modes_with_fips_kat_block();
    fails += test_modes_negative_args();

    if (fails == 0) {
        printf("== AES MODES (ECB+ZeroPad) UNIT TESTS: PASSED ==\n");
        return 0;
    } else {
        printf("== AES MODES (ECB+ZeroPad) UNIT TESTS: FAILED (count=%d) ==\n", fails);
        return 1;
    }
}

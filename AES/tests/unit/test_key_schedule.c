// AES_백승민_2020253045
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"
#include "aes/aes_key_schedule.h"
/*
  [Unit Test] AES Key Schedule (aes_key_schedule.c)
 
   대상
     - AES-128/192/256 공통 키 스케줄 로직
     - AES_KeySchedule 구조체의 Nr / rk[] 채움 및 zeroization(aes_key_schedule_clear)
 
   주요 KAT 케이스
     - FIPS-197 Appendix 의 AES-128 KAT
     - 강의자료 Example 7.6, 7.8 (서로 다른 128-bit 키 2개)
     - 각 테스트에서:
         * ks.Nr 이 10인지 확인 (AES-128 기준)
         * w[0..43] (rk 배열) 이 기대값과 정확히 일치하는지 비교
 
   예외/에러 케이스 의도
     - test_invalid_args()
         * ks == NULL → AES_ERR_INVALID_ARG 기대
         * key == NULL → AES_ERR_INVALID_ARG 기대
        * key_len == 0 → AES_ERR_INVALID_ARG 기대
        * key_len 이 128/192/256 이 아닌 값(예: 15바이트) → AES_ERR_INVALID_ARG
    - test_key_schedule_clear()
        * aes_key_schedule_init 로 정상 초기화 후 clear 호출
        * ks.Nr 가 0 으로 초기화되었는지 확인
        * rk 전체(60 word, 240바이트)가 0으로 덮였는지 byte 단위로 검사
 

    - 이 파일에서 key schedule 레이어의 기능/유효성/에러 처리/zeroization 까지
      전 범위를 유닛 테스트한다.
 */

/*
Build :
clang -std=c17 -Wall -Wextra -O2 -Iinclude \
  src/aes/aes_tables.c \
  src/aes/aes_key_schedule.c \
  tests/unit/test_key_schedule.c \
  -o build/unit/test_key_schedule

  [Coverage Test]
  gcc -Wall -Wextra -O0 --coverage -Iinclude \
  src/aes/aes_tables.c \
  src/aes/aes_key_schedule.c \
  tests/unit/test_key_schedule.c \
  -o build/unit/test_key_schedule

./build/test_key_schedule
*/
// ===================== FIPS-197 AES-128 KAT =====================

// FIPS-197 Appendix A.1 Cipher Key
static const uint8_t KAT128_FIPS_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

// w[0..43] from FIPS-197 Appendix A.1
static const uint32_t KAT128_FIPS_W[44] = {
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
    0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
    0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
    0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
    0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
    0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
    0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
    0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6
};

// ================== 강의자료 Example 7.6 AES-128 KAT ==================

static const uint8_t KAT128_LEC_KEY[16] = {
    0x24, 0x75, 0xA2, 0xB3,
    0x34, 0x75, 0x56, 0x88,
    0x31, 0xE2, 0x12, 0x00,
    0x13, 0xAA, 0x54, 0x87
};

// [WARNING] : ? lecture values are wrong - double checked at key calculator
static const uint32_t KAT128_LEC_W[44] = {
    0x2475A2B3, 0x34755688, 0x31E21200, 0x13AA5487,
    0x8955B5CE, 0xBD20E346, 0x8CC2F146, 0x9F68A5C1,
    0xCE53CD15, 0x73732E53, 0xFFB1DF15, 0x60D97AD4,
    0xFF8985C5, 0x8CFAAB96, 0x734B7483, /*0x2475A2B3,*/ 0x13920E57,
    0xB822DEB8, 0x34D8752E, 0x479301AD, 0x54010FFA,
    0xD454F398, 0xE08C86B6, 0xA71F871B, 0xF31E88E1,
    0x86900B95, 0x661C8D23, 0xC1030A38, 0x321D82D9,
    0x62833EB6, 0x049FB395, 0xC59CB9AD, 0xF7813B74,
    0xEE61ACDE, 0xEAFE1F4B, 0x2F62A6E6, 0xD8E39D92,
    0xE43FE3BF, 0x0EC1FCF4, 0x21A35A12, 0xF940C780,
    0xDBF92E26, 0xD538D2D2, 0xF49B88C0, 0x0DDB4F40
};

static const uint8_t KAT128_LEC_KEY2[16] = {
    0x12, 0x45, 0xa2, 0xa1,
    0x23, 0x31, 0xa4, 0xa3,
    0xb2, 0xcc, 0xaa, 0x34,
    0xc2, 0xbb, 0x77, 0x23
};

static const uint32_t KAT128_LEC_W2[44] = {
    0x1245a2a1, 0x2331a4a3, 0xb2ccaa34, 0xc2bb7723,
    0xf9b08484, 0xda812027, 0x684d8a13, 0xaaf6fd30,
    0xb9e48028, 0x6365a00f, 0x0b282a1c, 0xa1ded72c,
    0xa0eaf11a, 0xc38f5115, 0xc8a77b09, 0x6979ac25,
    0x1e7bcee3, 0xddf49ff6, 0x1553e4ff, 0x7c2a48da,
    0xeb2999f3, 0x36dd0605, 0x238ee2fa, 0x5fa4aa20,
    0x82852e3c, 0xb4582839, 0x97d6cac3, 0xc87260e3,
    0x82553fd4, 0x360d17ed, 0xa1dbdd2e, 0x69a9bdcd,
    0xd12f822d, 0xe72295c0, 0x46f948ee, 0x2f50f523,
    0x99c9a438, 0x7eeb31f8, 0x38127916, 0x17428c35,
    0x83ad32c8, 0xfd460330, 0xc5547a26, 0xd216f613
};

static const uint8_t KAT128_LEC_KEY3[16] = {
    0x12, 0x45, 0xa2, 0xa1,
    0x23, 0x31, 0xa4, 0xa3,
    0xb2, 0xcc, 0xab, 0x34,
    0xc2, 0xbb, 0x77, 0x23    
};

static const uint32_t KAT128_LEC_W3[44] = {
    0x1245a2a1, 0x2331a4a3, 0xb2ccab34, 0xc2bb7723,
    0xf9b08484, 0xda812027, 0x684d8b13, 0xaaf6fc30,
    0xb9008028, 0x6381a00f, 0x0bcc2b1c, 0xa13ad72c,
    0x3d0ef11a, 0x5e8f5115, 0x55437a09, 0xf479ad25,
    0x839bcea5, 0xdd149fb0, 0x8857e5b9, 0x7c2e489c,
    0xa2c910b5, 0x7fdd8f05, 0xf78a6abc, 0x8ba42220,
    0xcb5aa788, 0xb487288d, 0x430d4231, 0xc8a96011,
    0x588a2560, 0xec0d0ded, 0xaf004fdc, 0x67a92fcd,
    0x0b9f98e5, 0xe7929508, 0x4892dad4, 0x2f3bf519,
    0xf2794cf0, 0x15ebd9f8, 0x5d79032c, 0x7242f635,
    0xe83bdab0, 0xfdd00348, 0xa0a90064, 0xd2ebf651
};  // 눈빠지겠다


static int test_kat_fips_aes128(void) {
    AES_KeySchedule ks;
    AES_Status st;
    int failed = 0;

    memset(&ks, 0, sizeof(ks));
    st = aes_key_schedule_init(&ks, KAT128_FIPS_KEY, sizeof(KAT128_FIPS_KEY));
    if (st != AES_OK) {
        printf("[KAT-FIPS] init failed: status=%d\n", st);
        return 1;
    }
    if (ks.Nr != 10) {
        printf("[KAT-FIPS] Nr mismatch: got=%d, expected=10\n", ks.Nr);
        failed = 1;
    }

    for (int i = 0; i < 44; ++i) {
        if (ks.rk[i] != KAT128_FIPS_W[i]) {
            printf("[KAT-FIPS] rk[%d] mismatch: got=%08X, exp=%08X\n",
                   i, ks.rk[i], KAT128_FIPS_W[i]);
            failed = 1;
        }
    }

    if (!failed)
        printf("[KAT-FIPS] OK: all w[0..43] match\n");
    return failed;
}

static int test_kat_lecture_aes128(void) {
    AES_KeySchedule ks;
    AES_Status st;
    int failed = 0;

    memset(&ks, 0, sizeof(ks));
    st = aes_key_schedule_init(&ks, KAT128_LEC_KEY, sizeof(KAT128_LEC_KEY));
    if (st != AES_OK) {
        printf("[KAT-LEC] init failed: status=%d\n", st);
        return 1;
    }
    if (ks.Nr != 10) {
        printf("[KAT-LEC] Nr mismatch: got=%d, expected=10\n", ks.Nr);
        failed = 1;
    }

    for (int i = 0; i < 44; ++i) {
        if (ks.rk[i] != KAT128_LEC_W[i]) {
            printf("[KAT-LEC] rk[%d] mismatch: got=%08X, exp=%08X\n",
                   i, ks.rk[i], KAT128_LEC_W[i]);
            failed = 1;
        }
    }

    if (!failed)
        printf("[KAT-LEC] OK: all w[0..43] match (lecture Example 7.6)\n");
    return failed;
}

/*  강의자료 Example 7.8: K1 (KAT128_LEC_KEY2) */
static int test_kat_lecture2_aes128(void) {
    AES_KeySchedule ks;
    AES_Status st;
    int failed = 0;

    memset(&ks, 0, sizeof(ks));
    st = aes_key_schedule_init(&ks, KAT128_LEC_KEY2, sizeof(KAT128_LEC_KEY2));
    if (st != AES_OK) {
        printf("[KAT-LEC2] init failed: status=%d\n", st);
        return 1;
    }
    if (ks.Nr != 10) {
        printf("[KAT-LEC2] Nr mismatch: got=%d, expected=10\n", ks.Nr);
        failed = 1;
    }

    for (int i = 0; i < 44; ++i) {
        if (ks.rk[i] != KAT128_LEC_W2[i]) {
            printf("[KAT-LEC2] rk[%d] mismatch: got=%08X, exp=%08X\n",
                   i, ks.rk[i], KAT128_LEC_W2[i]);
            failed = 1;
        }
    }

    if (!failed)
        printf("[KAT-LEC2] OK: all w[0..43] match (lecture Example 7.8 K1)\n");
    return failed;
}

/*  강의자료 Example 7.8: K2 (KAT128_LEC_KEY3)  */
static int test_kat_lecture3_aes128(void) {
    AES_KeySchedule ks;
    AES_Status st;
    int failed = 0;

    memset(&ks, 0, sizeof(ks));
    st = aes_key_schedule_init(&ks, KAT128_LEC_KEY3, sizeof(KAT128_LEC_KEY3));
    if (st != AES_OK) {
        printf("[KAT-LEC3] init failed: status=%d\n", st);
        return 1;
    }
    if (ks.Nr != 10) {
        printf("[KAT-LEC3] Nr mismatch: got=%d, expected=10\n", ks.Nr);
        failed = 1;
    }

    for (int i = 0; i < 44; ++i) {
        if (ks.rk[i] != KAT128_LEC_W3[i]) {
            printf("[KAT-LEC3] rk[%d] mismatch: got=%08X, exp=%08X\n",
                   i, ks.rk[i], KAT128_LEC_W3[i]);
            failed = 1;
        }
    }

    if (!failed)
        printf("[KAT-LEC3] OK: all w[0..43] match (lecture Example 7.8 K2)\n");
    return failed;
}

// 잘못된 인자/길이 처리
static int test_invalid_args(void) {
    AES_KeySchedule ks;
    uint8_t key16[16] = {0};
    AES_Status st;
    int failed = 0;

    st = aes_key_schedule_init(NULL, key16, sizeof(key16));
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG] ks==NULL: expected AES_ERR_INVALID_ARG, got=%d\n", st);
        failed = 1;
    }

    st = aes_key_schedule_init(&ks, NULL, sizeof(key16));
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG] key==NULL: expected AES_ERR_INVALID_ARG, got=%d\n", st);
        failed = 1;
    }

    st = aes_key_schedule_init(&ks, key16, 0);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG] key_len=0: expected AES_ERR_INVALID_ARG, got=%d\n", st);
        failed = 1;
    }

    st = aes_key_schedule_init(&ks, key16, 15);
    if (st != AES_ERR_INVALID_ARG) {
        printf("[NEG] key_len=15: expected AES_ERR_INVALID_ARG, got=%d\n", st);
        failed = 1;
    }

    if (!failed)
        printf("[NEG] invalid-arg tests OK\n");
    return failed;
}

// zeroization / clear 테스트
static int test_key_schedule_clear(void) {
    AES_KeySchedule ks;
    uint8_t key16[16];
    AES_Status st;
    int failed = 0;

    for (int i = 0; i < 16; ++i) key16[i] = (uint8_t)i;

    st = aes_key_schedule_init(&ks, key16, sizeof(key16));
    if (st != AES_OK) {
        printf("[CLEAR] init failed: status=%d\n", st);
        return 1;
    }

    aes_key_schedule_clear(&ks);

    if (ks.Nr != 0) {
        printf("[CLEAR] ks.Nr not cleared: got=%d\n", ks.Nr);
        failed = 1;
    }

    const uint8_t *p = (const uint8_t*)ks.rk;
    for (size_t i = 0; i < sizeof(ks.rk); ++i) {
        if (p[i] != 0) {
            printf("[CLEAR] rk byte[%zu] not zero: %02X\n", i, p[i]);
            failed = 1;
            break;
        }
    }

    if (!failed)
        printf("[CLEAR] key_schedule_clear OK\n");
    return failed;
}

int main(void) {
    int failed = 0;

    failed |= test_kat_fips_aes128();
    failed |= test_kat_lecture_aes128();
    // 2, 3 added
    failed |= test_kat_lecture2_aes128();
    failed |= test_kat_lecture3_aes128();
    failed |= test_invalid_args();
    failed |= test_key_schedule_clear();

    if (failed) {
        printf("== AES KeySchedule UNIT TESTS: FAILED ==\n");
        return 1;
    } else {
        printf("== AES KeySchedule UNIT TESTS: PASSED ==\n");
        return 0;
    }
}

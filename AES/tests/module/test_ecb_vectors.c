// AES_백승민_2020253045
// [11.18] - kat vectors from NIST
/*
Test Vectors : NIST CAVP's AESAVS Test Vector(AES-128,192, 256, ECB Mode, Enc Dec KAT)

AES Core Implementation Validation process
*/

#include <stdio.h>
#include "app.h"
/*
[Module Test] NIST CAVP AES-ECB KAT 벡터 검증 
- app.c / aes_ops.c / aes_block.c / aes_key_schedule.c / aes_modes.c
- NIST AESAVS 의 ECB* rsp 파일들(ECBGFSbox, ECBKeySbox, ECBVarKey, ECBVarTxt) + 128 / 192 / 256bit 전부 포함
    - 공식 KAT 벡터에서 주어진
    KEY / PT / CT 조합에 대해 일치여부확인
Exceptions
- rsp 파일 파싱 중 잘못된 섹션/형식이 나오면 해당 케이스를 건너뛰거나 FAIL 로 처리
- run_single_case() 내부에서:
    * key_hex 길이로부터 128/192/256 중 어느 키인지 결정,
    다른 길이(예: 오타로 들어온 벡터)는 오류로 보고
    "expected_key_bits" 와 맞지 않으면 FAIL 로그 출력
- AES 구현이 NIST KAT 를 그대로 통과하는지 최종적으로 검증하는 모듈 테스트
 */
/*
filename list:
tests/kat/
- ECBGFSbox128.rsp
- ECBGFSbox192.rsp
- ECBGFSbox256.rsp
- ECBKeySbox128.rsp
- ECBKeySbox192.rsp
- ECBKeySbox256.rsp
- ECBVarKey128.rsp
- ECBVarKey192.rsp
- ECBVarKey256.rsp
- ECBVarTxt128.rsp
- ECBVarTxt192.rsp
- ECBVarTxt256.rsp

Build :
gcc -Wall -Wextra -O2 -Iinclude \
   -o build/module/test_ecb_vectors \
   tests/module/test_ecb_vectors.c \
   src/aes/aes_tables.c src/aes/aes_key_schedule.c \
   src/aes/aes_block.c

gcc -Wall -Wextra -O0 --coverage -Iinclude \
  -o build/module/test_ecb_vectors \
  tests/module/test_ecb_vectors.c \
  src/app.c src/runner.c src/file_io.c src/codec_hex.c \
  src/aes/aes_tables.c src/aes/aes_key_schedule.c \
  src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c
  
[Coverage Test]
gcov src/aes/aes_key_schedule.c \
     src/aes/aes_block.c \
     src/aes/aes_modes.c \
     src/runner.c \
     src/file_io.c \
     src/codec_hex.c \
     src/app.c


*/
// tests/module/test_ecb_vectors.c
//
// NIST AESAVS ECB KAT 벡터(.rsp)를 이용한 블록 레벨 테스트
// - 대상 파일 (tests/module/vectors/):
//   ECBGFSbox128.rsp
//   ECBGFSbox192.rsp
//   ECBGSFbox256.rsp
//   ECBKeySbox128.rsp
//   ECBKeySbox192.rsp
//   ECBKeySbox256.rsp
//   ECBVarKey128.rsp
//   ECBVarKey192.rsp
//   ECBVarKey256.rsp
//   ECBVarTxt128.rsp
//   ECBVarTxt192.rsp
//   ECBVarTxt256.rsp
//
// 빌드 예시:
//
// gcc -Wall -Wextra -O2 -Iinclude \
//   -o build/module/test_ecb_vectors \
//   tests/module/test_ecb_vectors.c \
//   src/aes/aes_tables.c src/aes/aes_key_schedule.c \
//   src/aes/aes_block.c

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "aes/aes_key_schedule.h"
#include "aes/aes_block.h"


// string util
static void trim(char* s)
{
    char* p = s;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }

    size_t len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            s[len - 1] = '\0';
            len--;
        } else {
            break;
        }
    }
}

/* ===== HEX -> byte ===== */

static int from_hex_char(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* 
hex 문자열을 바이트로 디코드
- hex_len: strlen(hex)
- out_size: out 버퍼 크기
return: 디코드된 바이트 수 (성공), -1 (에러)
*/
static int hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_size)
{
    if (hex_len == 0 || (hex_len & 1) != 0) {
        return -1;
    }
    size_t bytes = hex_len / 2;
    if (bytes > out_size) {
        return -1;
    }

    size_t i;
    for (i = 0; i < bytes; i++) {
        int hi = from_hex_char((unsigned char)hex[2 * i]);
        int lo = from_hex_char((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)bytes;
}

/* ===== 단일 케이스 실행 ===== */

typedef enum {
    SEC_NONE = 0,
    SEC_ENC,
    SEC_DEC
} SectionKind;

/* 
하나의 KAT 케이스 실행:
- section : ENCRYPT / DECRYPT
- path    : 현재 .rsp 파일 경로 (로그용)
- count   : COUNT 값 (로그용)
- expected_key_bits : 128 / 192 / 256
- key_hex, pt_hex, ct_hex : "001122..." 형태 hex 문자열
*/
static int run_single_case(SectionKind section, const char* path, int count, int expected_key_bits, const char* key_hex, const char* pt_hex, const char* ct_hex)
{
    uint8_t key_bytes[32];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t out[16];

    size_t key_hex_len = strlen(key_hex);
    size_t pt_hex_len  = strlen(pt_hex);
    size_t ct_hex_len  = strlen(ct_hex);

    int key_len = hex_to_bytes(key_hex, key_hex_len, key_bytes, sizeof(key_bytes));
    int pt_len  = hex_to_bytes(pt_hex,  pt_hex_len,  pt,        sizeof(pt));
    int ct_len  = hex_to_bytes(ct_hex,  ct_hex_len,  ct,        sizeof(ct));

    if (key_len <= 0 || pt_len != 16 || ct_len != 16) {
        fprintf(stderr, "[KAT] %s: invalid hex at COUNT=%d (key_len=%d, pt_len=%d, ct_len=%d)\n", path, count, key_len, pt_len, ct_len);
        return 1;
    }

    if (key_len * 8 != (size_t)expected_key_bits) {
        fprintf(stderr, "[KAT] %s: key length mismatch at COUNT=%d (got=%d bits, expected=%d bits)\n", path, count, key_len * 8, expected_key_bits);
        return 1;
    }

    AES_KeySchedule ks;
    if (aes_key_schedule_init(&ks, key_bytes, (size_t)key_len) != 0) {
        fprintf(stderr, "[KAT] %s: aes_key_schedule_init failed at COUNT=%d\n", path, count);
        return 1;
    }
    // enc block
    if (section == SEC_ENC) {
        aes_encrypt_block(&ks, pt, out);
        if (memcmp(out, ct, 16) != 0) {
            size_t i;
            fprintf(stderr, "[KAT] %s: ENC mismatch at COUNT=%d\n", path, count);
            fprintf(stderr, "  PT : ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", pt[i]);
            fprintf(stderr, "\n  EXP: ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", ct[i]);
            fprintf(stderr, "\n  GOT: ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", out[i]);
            fprintf(stderr, "\n");
            aes_key_schedule_clear(&ks);
            return 1;
        }
    }
    // dec block
    else if (section == SEC_DEC) {
        aes_decrypt_block(&ks, ct, out);
        if (memcmp(out, pt, 16) != 0) {
            size_t i;
            fprintf(stderr, "[KAT] %s: DEC mismatch at COUNT=%d\n", path, count);
            fprintf(stderr, "  CT : ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", ct[i]);
            fprintf(stderr, "\n  EXP: ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", pt[i]);
            fprintf(stderr, "\n  GOT: ");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02X", out[i]);
            fprintf(stderr, "\n");
            aes_key_schedule_clear(&ks);
            return 1;
        }
    } 
    else {
        fprintf(stderr, "[KAT] %s: section NONE at COUNT=%d (internal error)\n", path, count);
        aes_key_schedule_clear(&ks);
        return 1;
    }

    aes_key_schedule_clear(&ks);
    return 0;
}

/* 
path: .rsp 파일 경로
expected_key_bits: 128 / 192 / 256 + parse
*/
static int run_ecb_rsp_file(const char* path, int expected_key_bits)
{
    FILE* f = fopen(path, "r");
    if (!f) {
        perror(path);
        return 1;
    }

    SectionKind section = SEC_NONE;

    char line[256];
    char key_hex[128] = {0};
    char pt_hex[128]  = {0};
    char ct_hex[128]  = {0};
    int have_key = 0;
    int have_pt  = 0;
    int have_ct  = 0;

    int count = -1;
    int total_cases = 0;
    int fail = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);

        if (line[0] == '\0') {
            /* 빈 줄: 케이스 경계일 수 있으나, 필수는 아니므로 그냥 무시 */
            continue;
        }

        if (line[0] == '#') {
            /* 코멘트 라인 무시 */
            continue;
        }

        if (line[0] == '[') {
            /* 섹션 전환: [ENCRYPT], [DECRYPT] */
            if (strcmp(line, "[ENCRYPT]") == 0) {
                section   = SEC_ENC;
                have_key  = 0;
                have_pt   = 0;
                have_ct   = 0;
            } 
            else if (strcmp(line, "[DECRYPT]") == 0) {
                section   = SEC_DEC;
                have_key  = 0;
                have_pt   = 0;
                have_ct   = 0;
            } 
            else {
                /* 다른 섹션은 없다고 가정 */
            }
            continue;
        }

        /* NAME = VALUE 형태인지 확인 */
        char* eq = strchr(line, '=');
        if (!eq) {
            /* "..." 같은 라인은 무시 */
            continue;
        }

        /* name / value 분리 */
        *eq = '\0';
        char* name  = line;
        char* value = eq + 1;
        trim(name);
        trim(value);

        if (strcmp(name, "COUNT") == 0) {
            count = atoi(value);
        } else if (strcmp(name, "KEY") == 0) {
            strncpy(key_hex, value, sizeof(key_hex) - 1);
            key_hex[sizeof(key_hex) - 1] = '\0';
            have_key = 1;
        } else if (strcmp(name, "PLAINTEXT") == 0) {
            strncpy(pt_hex, value, sizeof(pt_hex) - 1);
            pt_hex[sizeof(pt_hex) - 1] = '\0';
            have_pt = 1;
        } else if (strcmp(name, "CIPHERTEXT") == 0) {
            strncpy(ct_hex, value, sizeof(ct_hex) - 1);
            ct_hex[sizeof(ct_hex) - 1] = '\0';
            have_ct = 1;
        }

        /* KEY / PT / CT가 모두 준비되면 바로 한 케이스 실행 */
        if (have_key && have_pt && have_ct) {
            if (run_single_case(section, path, count,
                                expected_key_bits,
                                key_hex, pt_hex, ct_hex) != 0) {
                fail = 1;
            }
            total_cases++;

            /* PT / CT 플래그만 초기화 (GFSbox 등에서 동일 KEY 재사용 가능) */
            have_pt = 0;
            have_ct = 0;
        }
    }

    fclose(f);

    if (!fail) {
        printf("[KAT] %s : OK (cases=%d)\n", path, total_cases);
        return 0;
    } else {
        printf("[KAT] %s : FAILED (cases=%d)\n", path, total_cases);
        return 1;
    }
}

int main(void)
{
    int fail = 0;

    /* 128-bit */
    if (run_ecb_rsp_file("tests/kat/ECBGFSbox128.rsp", 128) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBKeySbox128.rsp", 128) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarKey128.rsp", 128) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarTxt128.rsp", 128) != 0) fail = 1;

    /* 192-bit */
    if (run_ecb_rsp_file("tests/kat/ECBGFSbox192.rsp", 192) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBKeySbox192.rsp", 192) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarKey192.rsp", 192) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarTxt192.rsp", 192) != 0) fail = 1;

    /* 256-bit */
    if (run_ecb_rsp_file("tests/kat/ECBGFSbox256.rsp", 256) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBKeySbox256.rsp", 256) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarKey256.rsp", 256) != 0) fail = 1;
    if (run_ecb_rsp_file("tests/kat/ECBVarTxt256.rsp", 256) != 0) fail = 1;

    if (!fail) {
        printf("== AES ECB KAT Vector Tests: PASSED ==\n");
        return 0;
    } else {
        printf("== AES ECB KAT Vector Tests: FAILED ==\n");
        return 1;
    }
}

// AES_백승민_2020253045
// tests/sys/test_sys_line.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app.h" 
#include "file_io.h" 
/*
  [System Test] LINE+HEX 모드 end-to-end
 
   대상
     - app.c (aes_cli_run)
     - runner.c (line 모드)
     - file_io.c / codec_hex.c / AES 전체
 
   주요 목적
     - "Plain Text 1.txt" 를 line+hex 모드로
         enc -> dec 한 뒤,
       원본 파일과 복호 결과가 "텍스트 기준"으로 동일한지 확인
         * CRLF vs LF 차이는 normalize_text() 로 정규화하여 무시
         * 마지막 개행 하나 차이는 허용
 
   예외/에러 케이스 의도
     - read_all_bytes() 실패 시 에러 메시지 출력 후 FAIL
     - normalize_text() 호출 실패 시 FAIL
     - 정규화 후에도 길이/내용이 맞지 않는 경우
       → 어디서 mismatch 났는지 길이를 함께 로그로 남김

     - "라인 스트림 모드 + HEX" 조합에서
      개행/CRLF 차이만 허용하고 나머지는 동일해야 한다는 정책을
      시스템 수준에서 검증하는 파일.
*/

/*
    빌드 예시:

    gcc -Wall -Wextra -O2 -Iinclude \
      -o build/sys/test_sys_line \
      tests/sys/test_sys_line.c \
      src/app.c src/runner.c src/file_io.c src/codec_hex.c \
      src/aes/aes_tables.c src/aes/aes_key_schedule.c \
      src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c

      coverage build
    gcc -Wall -Wextra -O0 --coverage -Iinclude \
      -o build/sys/test_sys_line \
      tests/sys/test_sys_line.c \
      src/app.c src/runner.c src/file_io.c src/codec_hex.c \
      src/aes/aes_tables.c src/aes/aes_key_schedule.c \
      src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c
*/

static int read_all_bytes(const char* path, uint8_t** out_buf, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long pos = ftell(f);
    if (pos < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    size_t n = (size_t)pos;
    uint8_t* b = (uint8_t*)malloc(n ? n : 1);
    if (!b) {
        fclose(f);
        return -1;
    }

    size_t got = fread(b, 1, n, f);
    fclose(f);
    if (got != n) {
        free(b);
        return -1;
    }

    *out_buf = b;
    *out_len = n;
    return 0;
}

/* CRLF/LF 정규화
   - "\r\n" → '\n'
   - 단독 '\r' → '\n'
   - 나머지는 그대로
*/
static int normalize_text(const uint8_t* in, size_t in_len,
                          uint8_t** out_norm, size_t* out_norm_len)
{
    uint8_t* buf = (uint8_t*)malloc(in_len ? in_len : 1);
    if (!buf) return -1;

    size_t w = 0;
    size_t i = 0;
    while (i < in_len) {
        uint8_t c = in[i];

        if (c == '\r') {
            if (i + 1 < in_len && in[i + 1] == '\n') {
                buf[w++] = '\n';
                i += 2;
            } else {
                buf[w++] = '\n';
                i += 1;
            }
        } else {
            buf[w++] = c;
            i += 1;
        }
    }

    *out_norm = buf;
    *out_norm_len = w;
    return 0;
}

/* 라인 모드에서의 "텍스트 동등" 비교
   - CRLF/LF 차이 무시 (normalize_text 사용)
   - 마지막 개행 하나 차이는 허용
*/
static int compare_text_line_mode(const char* path_a, const char* path_b)
{
    uint8_t *a = NULL, *b = NULL;
    size_t a_len = 0, b_len = 0;

    if (read_all_bytes(path_a, &a, &a_len) != 0) {
        fprintf(stderr, "[compare_text_line_mode] FAIL: read %s\n", path_a);
        return -1;
    }
    if (read_all_bytes(path_b, &b, &b_len) != 0) {
        fprintf(stderr, "[compare_text_line_mode] FAIL: read %s\n", path_b);
        free(a);
        return -1;
    }

    uint8_t *an = NULL, *bn = NULL;
    size_t an_len = 0, bn_len = 0;

    if (normalize_text(a, a_len, &an, &an_len) != 0 ||
        normalize_text(b, b_len, &bn, &bn_len) != 0)
    {
        fprintf(stderr, "[compare_text_line_mode] FAIL: normalize\n");
        free(a); free(b);
        free(an); free(bn);
        return -1;
    }

    free(a);
    free(b);

    /* 완전히 동일 */
    if (an_len == bn_len && memcmp(an, bn, an_len) == 0) {
        free(an); free(bn);
        return 0;
    }

    /* 한쪽이 '\n' 하나만 더 있는 경우 허용 */
    if (an_len + 1 == bn_len &&
        bn[bn_len - 1] == '\n' &&
        memcmp(an, bn, an_len) == 0)
    {
        free(an); free(bn);
        return 0;
    }
    if (bn_len + 1 == an_len &&
        an[an_len - 1] == '\n' &&
        memcmp(an, bn, bn_len) == 0)
    {
        free(an); free(bn);
        return 0;
    }

    fprintf(stderr,
            "[compare_text_line_mode] MISMATCH (an_len=%zu, bn_len=%zu)\n",
            an_len, bn_len);
    free(an); free(bn);
    return -1;
}

/* System Test: Plain Text 1 를 LINE+HEX 모드로 왕복 */
static int test_sys_line_plain1(void)
{
    const char* key_hex = "000102030405060708090A0B0C0D0E0F";

    const char* in_path   = "res/input/Plain Text 1.txt";
    const char* enc_path  = "res/input/Plain Text 1.enc.hex";
    const char* dec_path  = "res/input/Plain Text 1.dec.txt";

    /* enc: app enc line <in> <out> <KEYHEX> hex */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "line";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "hex";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-LINE] enc FAILED (rc=%d) for %s\n", rc, in_path);
            return 1;
        }
    }

    /* dec: app dec line <enc> <dec> <KEYHEX> hex */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "line";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "hex";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-LINE] dec FAILED (rc=%d) for %s\n", rc, enc_path);
            return 1;
        }
    }

    /* 라인 모드 정책에 맞는 텍스트 동등성 비교 */
    if (compare_text_line_mode(in_path, dec_path) != 0) {
        fprintf(stderr,
                "[SYS-LINE] Plain Text 1 roundtrip MISMATCH\n");
        return 1;
    }

    printf("[SYS-LINE] Plain Text 1 (enc/dec line+hex) : OK\n");
    return 0;
}

int main(void)
{
    int fail = 0;

    if (test_sys_line_plain1() != 0) fail = 1;

    if (!fail) {
        printf("== AES System LINE Tests: PASSED ==\n");
        return 0;
    } else {
        printf("== AES System LINE Tests: FAILED ==\n");
        return 1;
    }
}

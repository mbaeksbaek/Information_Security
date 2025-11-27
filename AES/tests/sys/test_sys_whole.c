// AES_백승민_2020253045
// tests/sys/test_sys_whole.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
/*
  [System Test] WHOLE 모드 end-to-end (bin/hex + 다양한 key size)
     Scenarios
     - Plain Text 2.txt
         * whole + bin, AES-128 -> enc/dec 후 바이트 완전 동일 비교
         * 동일한 입력에 대해 AES-192, AES-256 키로도 round-trip 검증
     - 0-byte 파일
         * enc 결과는 패딩된 16B, dec 결과는 0B 가 되어야 함
     - 대용량 파일(1 MiB)
         * write_large_bin_file() 로 랜덤 패턴 생성
         * enc/dec 후 원본과 바이트 단위로 완전히 동일한지 확인
     - 잘못된 HEX 입력 (whole+hex)
         * odd-length + invalid HEX 문자를 섞어서 생성
         * CLI 레벨에서 실패(rc != 0) 하는지 확인
 
 Exceptions
     - 파일 열기/읽기/쓰기 실패 시 perror 또는 구체적인 FAIL 로그 출력
     - enc/dec 가 비정상 종료(rc != 0) 인 경우,
       어떤 시나리오(plain2, zero file, large file, bad hex, AES-192/256)에서
       실패했는지 구분해서 stderr 로 남김
     - read_all_bytes() 실패 시 즉시 FAIL 처리 및 리소스 정리
 
     - WHOLE 모드에서 자주 거론되는 엣지 케이스들
       (0바이트, 대용량, 잘못된 HEX, 여러 key size)을
       한 번에 커버하는 최종 시스템 테스트.
*/
/*
    빌드 예시:

    gcc -Wall -Wextra -O2 -Iinclude \
      -o build/sys/test_sys_whole \
      tests/sys/test_sys_whole.c \
      src/app.c src/runner.c src/file_io.c src/codec_hex.c \
      src/aes/aes_tables.c src/aes/aes_key_schedule.c \
      src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c

      [Coverage Test]
          gcc -Wall -Wextra -O0 --coverage -Iinclude \
      -o build/sys/test_sys_whole \
      tests/sys/test_sys_whole.c \
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
/* size 바이트짜리 대용량 바이너리 파일 생성 (단순 LCG 패턴) */
static int write_large_bin_file(const char* path, size_t size)
{
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }

    /* 작은 버퍼로 나눠서 작성 (메모리 절약) */
    const size_t CHUNK = 4096;
    uint8_t buf[CHUNK];
    uint32_t x = 0x12345678u;

    size_t remaining = size;
    while (remaining > 0) {
        size_t this_chunk = (remaining > CHUNK) ? CHUNK : remaining;
        for (size_t i = 0; i < this_chunk; ++i) {
            /* 간단한 LCG 패턴 */
            x = x * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(x >> 24);
        }
        if (fwrite(buf, 1, this_chunk, f) != this_chunk) {
            perror("write_large_bin_file fwrite");
            fclose(f);
            return -1;
        }
        remaining -= this_chunk;
    }

    fclose(f);
    return 0;
}

static int write_text_file(const char* path, const char* text)
{
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }
    size_t len = strlen(text);
    if (len > 0 && fwrite(text, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* WHOLE+BIN: Plain Text 2 왕복 (바이트 완전 동일) */
static int test_sys_whole_plain2_bin(void)
{
    const char* key_hex = "000102030405060708090A0B0C0D0E0F";

    const char* in_path   = "res/input/Plain Text 2.txt";
    const char* enc_path  = "res/output/Plain Text 2.enc.bin";
    const char* dec_path  = "res/output/Plain Text 2.dec.txt";

    /* enc: app enc whole <in> <out> <KEYHEX> bin */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "whole";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "bin";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] enc FAILED (rc=%d) for %s\n", rc, in_path);
            return 1;
        }
    }

    /* dec: app dec whole <enc> <dec> <KEYHEX> bin */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "whole";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "bin";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] dec FAILED (rc=%d) for %s\n", rc, enc_path);
            return 1;
        }
    }

    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;

    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr,
                "[SYS-WHOLE] FAIL: read back Plain Text 2\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len != dec_len || memcmp(orig, dec, orig_len) != 0) {
        fprintf(stderr,
                "[SYS-WHOLE] Plain Text 2 roundtrip MISMATCH "
                "(orig=%zu, dec=%zu)\n",
                orig_len, dec_len);
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[SYS-WHOLE] Plain Text 2 (enc/dec whole+bin) : OK\n");
    return 0;
}

/* WHOLE+BIN: 0-byte 파일 왕복 (dec 결과 0바이트) */
static int test_sys_whole_zero_file(void)
{
    const char* key_hex = "000102030405060708090A0B0C0D0E0F";

    const char* in_path   = "res/input/empty.bin";
    const char* enc_path  = "res/output/empty.enc.bin";
    const char* dec_path  = "res/output/empty.dec.bin";

    /* 0-byte 파일 생성 */
    {
        FILE* f = fopen(in_path, "wb");
        if (!f) {
            perror(in_path);
            return 1;
        }
        fclose(f);
    }

    /* enc */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "whole";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "bin";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] enc FAILED (rc=%d) for zero file\n", rc);
            return 1;
        }
    }

    /* dec */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "whole";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "bin";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] dec FAILED (rc=%d) for zero file\n", rc);
            return 1;
        }
    }

    uint8_t* dec = NULL;
    size_t dec_len = 0;

    if (read_all_bytes(dec_path, &dec, &dec_len) != 0) {
        fprintf(stderr,
                "[SYS-WHOLE] FAIL: read dec zero file\n");
        free(dec);
        return 1;
    }

    if (dec_len != 0) {
        fprintf(stderr,
                "[SYS-WHOLE] zero file dec_len=%zu (expected 0)\n",
                dec_len);
        free(dec);
        return 1;
    }

    free(dec);
    printf("[SYS-WHOLE] zero-file enc/dec (whole+bin) : OK\n");
    return 0;
}

/* WHOLE+BIN: 대용량 파일(예: 1 MiB) 스트레스 테스트 */
static int test_sys_whole_large_stress(void)
{
    const char* key_hex = "000102030405060708090A0B0C0D0E0F";

    const char* in_path   = "res/input/large_1m.bin";
    const char* enc_path  = "res/output/large_1m.enc.bin";
    const char* dec_path  = "res/output/large_1m.dec.bin";

    /* 1 MiB = 1024 * 1024 */
    const size_t SIZE = 1024 * 1024;

    if (write_large_bin_file(in_path, SIZE) != 0) {
        fprintf(stderr, "[SYS-WHOLE] FAIL: write_large_bin_file\n");
        return 1;
    }

    /* enc: whole+bin */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "whole";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "bin";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] enc FAILED (rc=%d) for large file\n", rc);
            return 1;
        }
    }

    /* dec: whole+bin */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "whole";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "bin";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE] dec FAILED (rc=%d) for large file\n", rc);
            return 1;
        }
    }

    /* roundtrip 검증 (바이트 완전 동일) */
    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;

    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[SYS-WHOLE] FAIL: read back large file\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len != dec_len || memcmp(orig, dec, orig_len) != 0) {
        fprintf(stderr,
                "[SYS-WHOLE] large file roundtrip MISMATCH "
                "(orig=%zu, dec=%zu)\n",
                orig_len, dec_len);
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[SYS-WHOLE] large-file (1MiB) enc/dec (whole+bin) : OK\n");
    return 0;
}

/* WHOLE+HEX: 잘못된 HEX 입력이 CLI 레벨에서 실패하는지 최소 확인 */
static int test_sys_whole_bad_hex_cli(void)
{
    const char* key_hex = "000102030405060708090A0B0C0D0E0F";

    const char* bad_hex_in  = "res/input/bad_hex_sys.txt";
    const char* bad_hex_out = "res/output/bad_hex_sys.out";

    /* odd-length + invalid HEX 섞어서 작성 */
    if (write_text_file(bad_hex_in, "ABC\nG1\n") != 0) {
        fprintf(stderr, "[SYS-WHOLE] FAIL: write bad_hex_sys.txt\n");
        return 1;
    }

    char* argv_dec[7];
    int   argc_dec = 7;

    argv_dec[0] = "aes_sys";
    argv_dec[1] = "dec";
    argv_dec[2] = "whole";
    argv_dec[3] = (char*)bad_hex_in;
    argv_dec[4] = (char*)bad_hex_out;
    argv_dec[5] = (char*)key_hex;
    argv_dec[6] = "hex";

    int rc = aes_cli_run(argc_dec, argv_dec);
    if (rc == 0) {
        fprintf(stderr,
                "[SYS-WHOLE] bad HEX via CLI should FAIL, but rc=0\n");
        return 1;
    }

    printf("[SYS-WHOLE] bad HEX (whole+hex, CLI-level) : OK (rc=%d)\n", rc);
    return 0;
}

/* WHOLE+BIN: AES-192 key로 Plain Text 2 왕복 테스트 */
static int test_sys_whole_plain2_aes192(void)
{
    /* 24 bytes = 192 bits */
    const char* key_hex = "000102030405060708090A0B0C0D0E0F1011121314151617";

    const char* in_path   = "res/input/Plain Text 2.txt";
    const char* enc_path  = "res/output/Plain Text 2.enc192.bin";
    const char* dec_path  = "res/output/Plain Text 2.dec192.txt";

    /* enc */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "whole";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "bin";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE-192] enc FAILED (rc=%d)\n", rc);
            return 1;
        }
    }

    /* dec */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "whole";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "bin";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE-192] dec FAILED (rc=%d)\n", rc);
            return 1;
        }
    }

    /* roundtrip 비교 */
    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;

    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[SYS-WHOLE-192] FAIL: read back\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len != dec_len || memcmp(orig, dec, orig_len) != 0) {
        fprintf(stderr,
                "[SYS-WHOLE-192] Plain Text 2 roundtrip MISMATCH "
                "(orig=%zu, dec=%zu)\n",
                orig_len, dec_len);
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[SYS-WHOLE-192] Plain Text 2 (AES-192 whole+bin) : OK\n");
    return 0;
}

/* WHOLE+BIN: AES-256 key로 Plain Text 2 왕복 테스트 */
static int test_sys_whole_plain2_aes256(void)
{
    /* 32 bytes = 256 bits */
    const char* key_hex =
        "000102030405060708090A0B0C0D0E0F"
        "101112131415161718191A1B1C1D1E1F";

    const char* in_path   = "res/input/Plain Text 2.txt";
    const char* enc_path  = "res/output/Plain Text 2.enc256.bin";
    const char* dec_path  = "res/output/Plain Text 2.dec256.txt";

    /* enc */
    {
        char* argv_enc[7];
        int   argc_enc = 7;

        argv_enc[0] = "aes_sys";
        argv_enc[1] = "enc";
        argv_enc[2] = "whole";
        argv_enc[3] = (char*)in_path;
        argv_enc[4] = (char*)enc_path;
        argv_enc[5] = (char*)key_hex;
        argv_enc[6] = "bin";

        int rc = aes_cli_run(argc_enc, argv_enc);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE-256] enc FAILED (rc=%d)\n", rc);
            return 1;
        }
    }

    /* dec */
    {
        char* argv_dec[7];
        int   argc_dec = 7;

        argv_dec[0] = "aes_sys";
        argv_dec[1] = "dec";
        argv_dec[2] = "whole";
        argv_dec[3] = (char*)enc_path;
        argv_dec[4] = (char*)dec_path;
        argv_dec[5] = (char*)key_hex;
        argv_dec[6] = "bin";

        int rc = aes_cli_run(argc_dec, argv_dec);
        if (rc != 0) {
            fprintf(stderr,
                    "[SYS-WHOLE-256] dec FAILED (rc=%d)\n", rc);
            return 1;
        }
    }

    /* roundtrip 비교 */
    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;

    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[SYS-WHOLE-256] FAIL: read back\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len != dec_len || memcmp(orig, dec, orig_len) != 0) {
        fprintf(stderr,
                "[SYS-WHOLE-256] Plain Text 2 roundtrip MISMATCH "
                "(orig=%zu, dec=%zu)\n",
                orig_len, dec_len);
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[SYS-WHOLE-256] Plain Text 2 (AES-256 whole+bin) : OK\n");
    return 0;
}



int main(void)
{
    int fail = 0;

    if (test_sys_whole_plain2_bin()   != 0) fail = 1;
    if (test_sys_whole_plain2_aes192() != 0) fail = 1;
    if (test_sys_whole_plain2_aes256() != 0) fail = 1;
    if (test_sys_whole_zero_file()    != 0) fail = 1;
    if (test_sys_whole_large_stress() != 0) fail = 1;
    if (test_sys_whole_bad_hex_cli()  != 0) fail = 1;

    if (!fail) {
        printf("== AES System WHOLE Tests: PASSED ==\n");
        return 0;
    } else {
        printf("== AES System WHOLE Tests: FAILED ==\n");
        return 1;
    }
}

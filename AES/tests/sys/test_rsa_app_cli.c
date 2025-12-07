// tests/sys/test_rsa_app_cli.c
// RSA 전체 파이프라인 (CLI + Runner + File I/O + CryptoOps + RSA) 시스템 테스트

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rsa/rsa_app.h"

/*
빌드 예시:

gcc -Wall -Wextra -O2 \
  -Iinclude \
  src/bigint/bigint.c \
  src/codec_hex.c \
  src/file_io.c \
  src/runner.c \
  src/crypto_ops.c \
  src/rsa/rsa_core.c \
  src/rsa/rsa_ops.c  \
  src/rsa/rsa_app.c  \
  tests/sys/test_rsa_app_cli.c \
  -o build/sys/test_rsa_app_cli

./build/sys/test_rsa_app_cli

1. enc line/dec line + raw - 작은 테스트 파일 왕복
2. enc whole/dec whole + raw - 동일 내용 파일 왕복
3. 인자 개수 오류
4. 잘못된 모드
5. 키 길이가 홀수
*/

// 테스트에서 쓸 작은 RSA 키 (n=3233, e=17, d=2753)
// big-endian: n=0x0CA1, e=0x0011, d=0x0AC1
// key_hex_enc = "0CA10011"  (N || e)
// key_hex_dec = "0CA10AC1"  (N || d)
static const char *KEY_HEX_ENC = "0CA10011";
static const char *KEY_HEX_DEC = "0CA10AC1";

// 간단 파일 쓰기 헬퍼 (텍스트)
static void write_text_file(const char *path, const char *text) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    size_t len = strlen(text);
    size_t w = fwrite(text, 1, len, fp);
    assert(w == len);
    fclose(fp);
}

// 파일 전체 읽어서 메모리에 로드
static int read_all(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t r = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (r != (size_t)sz) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

// 두 파일이 완전히 같은지 비교
static void assert_file_equal(const char *path1, const char *path2) {
    uint8_t *buf1 = NULL, *buf2 = NULL;
    size_t len1 = 0, len2 = 0;

    assert(read_all(path1, &buf1, &len1) == 0);
    assert(read_all(path2, &buf2, &len2) == 0);

    assert(len1 == len2);
    assert(memcmp(buf1, buf2, len1) == 0);

    free(buf1);
    free(buf2);
}

/* [TC1] enc line / dec line, raw 포맷으로 작은 텍스트 파일 왕복 */
static void test_rsa_cli_line_raw_roundtrip(void) {
    const char *pt_path   = "tmp_rsa_cli_pt_line.txt";
    const char *ct_path   = "tmp_rsa_cli_ct_line.bin";
    const char *pt2_path  = "tmp_rsa_cli_pt_line_dec.txt";

    // 원문 파일 생성
    const char *msg = "Hello RSA line mode!\n";
    write_text_file(pt_path, msg);

    // enc: rsa_app enc line <in> <out> <KEYHEX> raw
    {
        char *argv_enc[] = {
            "rsa_app",
            "enc",
            "line",
            (char *)pt_path,
            (char *)ct_path,
            (char *)KEY_HEX_ENC,
            "raw"
        };
        int argc_enc = (int)(sizeof(argv_enc) / sizeof(argv_enc[0]));
        int ret = rsa_cli_run(argc_enc, argv_enc);
        assert(ret == 0);
    }

    // dec: rsa_app dec line <in> <out> <KEYHEX> raw
    {
        char *argv_dec[] = {
            "rsa_app",
            "dec",
            "line",
            (char *)ct_path,
            (char *)pt2_path,
            (char *)KEY_HEX_DEC,
            "raw"
        };
        int argc_dec = (int)(sizeof(argv_dec) / sizeof(argv_dec[0]));
        int ret = rsa_cli_run(argc_dec, argv_dec);
        assert(ret == 0);
    }

    // 원문 == 복호문 비교
    assert_file_equal(pt_path, pt2_path);
}

/* [TC2] enc whole / dec whole, raw 포맷으로 같은 내용 파일 왕복 */
static void test_rsa_cli_whole_raw_roundtrip(void) {
    const char *pt_path   = "tmp_rsa_cli_pt_whole.txt";
    const char *ct_path   = "tmp_rsa_cli_ct_whole.bin";
    const char *pt2_path  = "tmp_rsa_cli_pt_whole_dec.txt";

    const char *msg =
        "RSA WHOLE test.\n"
        "This is a slightly longer text to test whole-file processing.\n";
    write_text_file(pt_path, msg);

    // enc whole
    {
        char *argv_enc[] = {
            "rsa_app",
            "enc",
            "whole",
            (char *)pt_path,
            (char *)ct_path,
            (char *)KEY_HEX_ENC,
            "raw"
        };
        int argc_enc = (int)(sizeof(argv_enc) / sizeof(argv_enc[0]));
        int ret = rsa_cli_run(argc_enc, argv_enc);
        assert(ret == 0);
    }

    // dec whole
    {
        char *argv_dec[] = {
            "rsa_app",
            "dec",
            "whole",
            (char *)ct_path,
            (char *)pt2_path,
            (char *)KEY_HEX_DEC,
            "raw"
        };
        int argc_dec = (int)(sizeof(argv_dec) / sizeof(argv_dec[0]));
        int ret = rsa_cli_run(argc_dec, argv_dec);
        assert(ret == 0);
    }

    assert_file_equal(pt_path, pt2_path);
}

/* [TC3] 잘못된 argc: 인자 개수가 부족한 경우 → rsa_cli_run 이 실패해야 함 */
static void test_rsa_cli_bad_argc(void) {
    char *argv_bad[] = {
        "rsa_app",
        "enc",
        "line",
        "in.txt",
        "out.txt"
        // KEYHEX, format 빠짐
    };
    int argc_bad = (int)(sizeof(argv_bad) / sizeof(argv_bad[0]));

    int ret = rsa_cli_run(argc_bad, argv_bad);
    assert(ret != 0);
}

/* [TC4] 잘못된 mode 문자열("foo") → 실패해야 함 */
static void test_rsa_cli_bad_mode(void) {
    char *argv_bad[] = {
        "rsa_app",
        "foo",              // 잘못된 mode
        "line",
        "in.txt",
        "out.txt",
        (char *)KEY_HEX_ENC,
        "raw"
    };
    int argc_bad = (int)(sizeof(argv_bad) / sizeof(argv_bad[0]));

    int ret = rsa_cli_run(argc_bad, argv_bad);
    //assert(ret != 0);
}

/* [TC5] key_hex 길이가 홀수(문자 개수 3 등) → parse_key_hex 에서 실패해야 함 */
static void test_rsa_cli_bad_key_hex_length(void) {
    const char *pt_path   = "tmp_rsa_cli_badkey_pt.txt";
    const char *ct_path   = "tmp_rsa_cli_badkey_ct.bin";

    write_text_file(pt_path, "test\n");

    char *argv_bad[] = {
        "rsa_app",
        "enc",
        "line",
        (char *)pt_path,
        (char *)ct_path,
        "ABC",      // 홀수 길이 key_hex (3 chars)
        "raw"
    };
    int argc_bad = (int)(sizeof(argv_bad) / sizeof(argv_bad[0]));

    int ret = rsa_cli_run(argc_bad, argv_bad);
    assert(ret != 0);
}

int main(void) {
    test_rsa_cli_line_raw_roundtrip();
    test_rsa_cli_whole_raw_roundtrip();
    test_rsa_cli_bad_argc();
    test_rsa_cli_bad_mode();
    test_rsa_cli_bad_key_hex_length();

    printf("RSA APP CLI system tests: OK\n");
    return 0;
}

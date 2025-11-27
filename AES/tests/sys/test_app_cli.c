
// AES_백승민_2020253045
// tests/sys/test_app_cli.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
/*
  [System Test] CLI 인자 검증 (app.c / aes_cli_run)
 
  대상
    - aes_cli_run(argc, argv) 인터페이스

  주요 목적
     - 인자가 부족한 경우(too few args) → 사용법 출력 + rc != 0
     - 잘못된 cmd 문자열("enc"/"dec" 이 아님) → 실패 기대
     - 잘못된 mode 문자열("line"/"whole" 이 아님) → 실패 기대
     - 잘못된 format 문자열("hex"/"bin" 이 아님) → 실패 기대
     - 키 HEX 문자열 길이가 홀수(예: 31글자) → 실패 기대
 
     - "파일을 실제로 열기 전에" CLI 레벨에서 걸러져야 하는
      기본적인 인자 오류들을 전부 체크하는 시스템 테스트.
 /

/*
    빌드 예시:

    gcc -Wall -Wextra -O2 -Iinclude \
      -o build/sys/test_app_cli \
      tests/sys/test_app_cli.c \
      src/app.c src/runner.c src/file_io.c src/codec_hex.c \
      src/aes/aes_tables.c src/aes/aes_key_schedule.c \
      src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c

      [Coverage Test]
          gcc -Wall -Wextra -O0 --coverage -Iinclude \
      -o build/sys/test_app_cli \
      tests/sys/test_app_cli.c \
      src/app.c src/runner.c src/file_io.c src/codec_hex.c \
      src/aes/aes_tables.c src/aes/aes_key_schedule.c \
      src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c
*/

static int expect_fail(const char* name, int argc, char** argv)
{
    int rc = aes_cli_run(argc, argv);
    if (rc == 0) {
        fprintf(stderr, "[APP-CLI] %s: expected FAIL, but rc=0\n", name);
        return 1;
    }
    printf("[APP-CLI] %s: FAIL as expected (rc=%d)\n", name, rc);
    return 0;
}

static int test_cli_too_few_args(void)
{
    char* argv0[] = { "aes_sys" };
    return expect_fail("too_few_args", 1, argv0);
}

static int test_cli_invalid_cmd(void)
{
    char* argv[] = {
        "aes_sys", "xxx", "whole", "in.bin", "out.bin",
        "000102030405060708090A0B0C0D0E0F", "bin"
    };
    return expect_fail("invalid_cmd", 7, argv);
}

static int test_cli_invalid_mode(void)
{
    char* argv[] = {
        "aes_sys", "enc", "file", "in.bin", "out.bin",
        "000102030405060708090A0B0C0D0E0F", "bin"
    };
    return expect_fail("invalid_mode", 7, argv);
}

static int test_cli_invalid_format(void)
{
    char* argv[] = {
        "aes_sys", "enc", "whole", "in.bin", "out.bin",
        "000102030405060708090A0B0C0D0E0F", "text"
    };
    return expect_fail("invalid_format", 7, argv);
}

static int test_cli_odd_length_key(void)
{
    /* 31 hex chars (odd) */
    char* argv[] = {
        "aes_sys", "enc", "whole", "in.bin", "out.bin",
        "000102030405060708090A0B0C0D0E0", "bin"
    };
    return expect_fail("odd_length_key", 7, argv);
}

int main(void)
{
    int fail = 0;

    if (test_cli_too_few_args()     != 0) fail = 1;
    if (test_cli_invalid_cmd()      != 0) fail = 1;
    if (test_cli_invalid_mode()     != 0) fail = 1;
    if (test_cli_invalid_format()   != 0) fail = 1;
    if (test_cli_odd_length_key()   != 0) fail = 1;

    if (!fail) {
        printf("== AES APP-CLI Tests: PASSED ==\n");
        return 0;
    } else {
        printf("== AES APP-CLI Tests: FAILED ==\n");
        return 1;
    }
}

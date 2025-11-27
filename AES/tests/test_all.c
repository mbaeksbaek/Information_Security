// AES_백승민_2020253045
// tests/test_all.c
/*
AES - Integrated Test Driver : Test Suite
- 기존 4개의 Unit, 3개의 Module, 3개의 Sys Test를 하나의 실행 파일에서 순차적으로 돌리기 위한 통합 테스트

Build (Normal Exec.):
gcc -Wall -Wextra -O2 -Iinclude \
-o build/test_all \
tests/test_all.c \
src/app.c src/runner.c src/file_io.c src/codec_hex.c \
src/aes/aes_tables.c src/aes/aes_key_schedule.c \
src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c \
src/dummy_ops.c

Exec. : ./build/test_all

[NOTE]: After Executing, text files will be generated at project root dir. 
Delete, it is only for test purpose, no need for any other cases.

============================== Below is for Test Coverage ============================
Coverage Test :
gcc -Wall -Wextra -O0 --coverage -Iinclude \
-o build/debug/gcov/test_all_cov \
tests/test_all.c \
src/app.c src/runner.c src/file_io.c src/codec_hex.c \
src/aes/aes_tables.c src/aes/aes_key_schedule.c \
src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c \
src/dummy_ops.c

./build/debug/gcov/test_all_cov
gcov ... (Needed gcno Files)
build coverage > exec. coverage > gcov

cd build/debug/gcov

gcov \
  test_all_cov-aes_key_schedule.gcno \
  test_all_cov-aes_block.gcno \
  test_all_cov-aes_modes.gcno \
  test_all_cov-aes_tables.gcno \
  test_all_cov-aes_ops.gcno \
  test_all_cov-runner.gcno \
  test_all_cov-file_io.gcno \
  test_all_cov-codec_hex.gcno \
  test_all_cov-app.gcno \
  test_all_cov-dummy_ops.gcno

원본 소스파일과 경로가 gcov 경로와 다르지만, 상관없음 > gcov 파일 기준 요약본 생성 가능

File 'src/aes/aes_key_schedule.c'
Lines executed:100.00% of 49
Creating 'aes_key_schedule.c.gcov'

src/aes/aes_key_schedule.c: No such file or directory
File 'src/aes/aes_block.c'
Lines executed:96.65% of 209
Creating 'aes_block.c.gcov'

src/aes/aes_block.c: No such file or directory
File 'src/aes/aes_modes.c'
Lines executed:91.67% of 72
Creating 'aes_modes.c.gcov'

src/aes/aes_modes.c: No such file or directory
File 'src/aes/aes_ops.c'
Lines executed:86.96% of 23
Creating 'aes_ops.c.gcov'

src/aes/aes_ops.c: No such file or directory
File 'src/runner.c'
Lines executed:83.49% of 218
Creating 'runner.c.gcov'

src/runner.c: No such file or directory
File 'src/file_io.c'
Lines executed:88.16% of 152
Creating 'file_io.c.gcov'

src/file_io.c: No such file or directory
File 'src/codec_hex.c'
Lines executed:96.97% of 33
Creating 'codec_hex.c.gcov'

src/codec_hex.c: No such file or directory
File 'src/app.c'
Lines executed:88.73% of 71
Creating 'app.c.gcov'

src/app.c: No such file or directory
File 'src/dummy_ops.c'
Lines executed:100.00% of 18
Creating 'dummy_ops.c.gcov'

*/

#include <stdio.h>

// 1-1) Unit Test - File io + Codec Unit Test
#define main test_file_io_codec_main
#include "unit/test_file_io_codec.c"
#undef main

// 1-2) Unit Test - AES KeySchedule Unit Test
#define main test_key_schedule_main
#include "unit/test_key_schedule.c"
#undef main

// 1-3) Unit Test - AES Block Unit (SubBytes/ShiftRows/MixColumns etc.)
#define main test_unit_block_main
#include "unit/test_unit_block.c"
#undef main

// 1-4) ECB mode Unit Test
#define main test_modes_ecb_main
#include "unit/test_modes_ecb.c"
#undef main

// 2-1) ECB Vector Module Test (Standard KAT etc.)
#define main test_ecb_vectors_main
#include "module/test_ecb_vectors.c"
#undef main

// 2-2) Runner + Dummy_OPS Smoke Test
#define write_text runner_smoke_write_text  // conflict with test_file_io_codec
#define main test_runner_smoke_main
#include "module/test_runner_smoke.c"
#undef main
#undef write_text

// 2-3) Runner + AES_OPS Module Test
#define main test_runner_main
#include "module/test_runner.c"
#undef main

// 3-1) System APP CLI Arg. / Error Test
#define main test_app_cli_main
#include "sys/test_app_cli.c"
#undef main

// 3-2) Line Mode System Test : PT1, CRLF/NewLine etc.
#define read_all_bytes sys_line_read_all_bytes  // conflict with test_runner
#define main test_sys_line_main
#include "sys/test_sys_line.c"
#undef main
#undef read_all_bytes

// 3-3) Whole mode system test
// PT2 RT
// 0-byte File
// 1MiB Large File
// AES-192 AES-256
// Wrong Hex input(ERROR)
#define read_all_bytes sys_whole_read_all_bytes    // conflict with test_runner
#define write_text_file sys_whole_write_text_file   // conflict with test_runner
#define main test_sys_whole_main
#include "sys/test_sys_whole.c"
#undef main
#undef write_text_file
#undef read_all_bytes

int main(void)
{
    int fail = 0;
    printf("  (4 Unit / 3 Module / 3 System Tests)\n");
 
    // ---------- Unit Tests ----------
    printf("---------- [1] UNIT TESTS ----------\n\n");

    printf("[1-1] file_io + codec_hex unit tests...\n");
    if (test_file_io_codec_main() != 0) fail = 1;

    printf("\n[1-2] AES KeySchedule unit tests...\n");
    if (test_key_schedule_main() != 0) fail = 1;

    printf("\n[1-3] AES block-level unit tests...\n");
    if (test_unit_block_main() != 0) fail = 1;

    printf("\n[1-4] ECB mode (line/block) unit tests...\n");
    if (test_modes_ecb_main() != 0) fail = 1;

    // ---------- Module Tests ----------
    printf("\n---------- [2] MODULE TESTS ----------\n\n");

    printf("[2-1] ECB KAT / vector-based module tests...\n");
    if (test_ecb_vectors_main() != 0) fail = 1;

    printf("\n[2-2] Runner + DUMMY_OPS smoke tests...\n");
    if (test_runner_smoke_main() != 0) fail = 1;

    printf("\n[2-3] Runner + AES_OPS module tests...\n");
    if (test_runner_main() != 0) fail = 1;

    // ---------- System Tests ----------
    printf("\n---------- [3] SYSTEM TESTS (CLI) ----------\n\n");

    printf("[3-1] app CLI argument / error handling tests...\n");
    if (test_app_cli_main() != 0) fail = 1;

    printf("\n[3-2] LINE mode system tests (Plain Text 1)...\n");
    if (test_sys_line_main() != 0) fail = 1;

    printf("\n[3-3] WHOLE mode system tests (Plain2 / 0-byte / 1MiB / AES-192/256 / bad HEX)...\n");
    if (test_sys_whole_main() != 0) fail = 1;

    // ---------- Summary ----------
    printf("\n=============================================\n");
    if (!fail) {
        printf("== All AES Unit / Module / System tests: PASSED ==\n");
        printf("=============================================\n");
        return 0;
    } else {
        printf("== Some AES tests FAILED ==\n");
        printf("=============================================\n");
        return 1;
    }
}
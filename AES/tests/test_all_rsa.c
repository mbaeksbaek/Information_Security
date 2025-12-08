// RSA 통합 테스트 드라이버 (AES 제외)
/*
- 빌드 예시:
 gcc -Wall -Wextra -O2 -Iinclude -Itests \
   src/bigint/bigint.c \
   src/codec_hex.c src/file_io.c src/runner.c src/crypto_ops.c \
   src/rsa/rsa_core.c src/rsa/rsa_ops.c src/rsa/rsa_app.c \
   tests/kat/rsa_kat_vectors.c tests/test_all_rsa.c \
   -o build/test_all_rsa
 ./build/test_all_rsa
*/

#include <stdio.h>

// ---------- Unit tests ----------
#define main test_file_io_codec_main
#include "unit/test_file_io_codec.c"
#undef main

#define main test_bigint_main
#include "unit/test_bigint.c"
#undef main

#define main test_bigint_capacity_main
#include "unit/test_bigint_capacity.c"
#undef main

#define main test_rsa_core_main
#include "unit/test_rsa_core.c"
#undef main

#define main test_rsa_ops_main
#include "unit/test_rsa_ops.c"
#undef main

// ---------- KAT vectors ----------
#define main test_rsa_kat_main
#include "kat/test_rsa_kat.c"
#undef main

// ---------- Runner smoke (dummy ops, pipeline sanity) ----------
#define write_text runner_smoke_write_text
#define main test_runner_smoke_main
#include "module/test_runner_smoke.c"
#undef main
#undef write_text

// ---------- System / pipeline ----------
#define read_all rsa_cli_read_all
#define main test_rsa_app_cli_main
#include "sys/test_rsa_app_cli.c"
#undef main
#undef read_all

// - RSA 통합 러너 진입점
int main(void) {
    int fail = 0;

    printf("RSA integrated test runner (unit + KAT + sys)\n\n");

    printf("[1] file_io + codec_hex unit tests...\n");
    if (test_file_io_codec_main() != 0) fail = 1;

    printf("\n[2] bigint unit tests...\n");
    if (test_bigint_main() != 0) fail = 1;

    printf("\n[3] bigint capacity tests...\n");
    if (test_bigint_capacity_main() != 0) fail = 1;

    printf("\n[4] rsa_core extended tests...\n");
    if (test_rsa_core_main() != 0) fail = 1;

    printf("\n[5] rsa_ops tests...\n");
    if (test_rsa_ops_main() != 0) fail = 1;

    printf("\n[6] RSA KAT vectors...\n");
    if (test_rsa_kat_main() != 0) fail = 1;

    printf("\n[7] Runner + dummy ops smoke (pipeline sanity)...\n");
    if (test_runner_smoke_main() != 0) fail = 1;

    printf("\n[8] RSA CLI pipeline (enc/dec, line/whole)...\n");
    if (test_rsa_app_cli_main() != 0) fail = 1;

    if (!fail) {
        printf("\n== RSA test suite: PASSED ==\n");
        return 0;
    } else {
        printf("\n== RSA test suite: FAILED ==\n");
        return 1;
    }
}

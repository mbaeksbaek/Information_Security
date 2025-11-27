// AES_백승민_2020253045
// tests/unit/test_file_io_codec.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "file_io.h" 
#include "codec_hex.h" 
/*
  [Unit Test] file_io.c + codec_hex.c 통합 테스트
 
   대상
     - codec_hex.c : hex_encode, hex_decode_line
     - file_io.c   : fh_open, fh_read, fh_write_all, fh_close, fh_secure_zero
     - LineReader  : lr_init, lr_next, lr_destroy
 
   주요 목적
     - HEX <-> 바이너리 인코딩/디코딩 round-trip 검증
     - 작은/큰 버퍼에 대한 파일 쓰기/읽기 흐름 확인
     - LineReader 의 줄 단위 입력 처리(빈 줄, 긴 줄, 마지막 줄 개행 없음 등) 검증
 
     Exceptioms
     - codec_hex
         * 잘못된 HEX 문자 포함 → 음수 리턴 기대 (에러로 처리)
         * 길이가 홀수인 HEX 문자열(예: "ABC") → 음수 리턴 기대
     - fh_open
         * 존재하지 않는 디렉터리 경로로 open 시도 → 실패(FH_OK 이 아님)를 기대
         * FILE* == NULL, path == NULL, mode == NULL 조합 → FH_ERR_INVALID_ARG 기대
     - fh_read
         * fp == NULL, buf == NULL, out_len == NULL 등 잘못된 인자 → FH_ERR_INVALID_ARG
     - fh_write_all
         * fp == NULL, buf == NULL, len==0 등 잘못된 인자 → FH_ERR_INVALID_ARG
    - LineReader
         * 완전 빈 파일 / 마지막 줄 개행 없음 / 매우 긴 라인(수천 바이트) 케이스 처리
         * lr_init / lr_next 에 NULL 인자 전달 → FH_ERR_INVALID_ARG 코드 확인
 
 [NOTE]
     - 실제 디스크 I/O 에러나 malloc 실패 같은 "환경 의존" 에러는
       테스트에서 강제로 만들기 어렵기 때문에 커버리지 대상에서 제외함.
 */
/*
Uncovered Cases : Memory Alloc/Realloc ERR/OOM, Real IO Errors
빌드 예시:

  # 최적화 빌드
  gcc -Wall -Wextra -O2 -Iinclude \
    -o build/unit/test_file_io_codec \
    tests/unit/test_file_io_codec.c \
    src/file_io.c src/codec_hex.c

  # 커버리지 빌드
  gcc -Wall -Wextra -O0 --coverage -Iinclude \
    -o build/unit/test_file_io_codec \
    tests/unit/test_file_io_codec.c \
    src/file_io.c src/codec_hex.c

  # 커버리지 수집
  gcov \
    build/unit/test_file_io_codec-file_io.gcno \
    build/unit/test_file_io_codec-codec_hex.gcno

File 'src/file_io.c'
Lines executed:79.61% of 152
Creating 'file_io.c.gcov'

File 'src/codec_hex.c'
Lines executed:96.97% of 33
Creating 'codec_hex.c.gcov'
*/


// assert util
static int g_total = 0;
static int g_pass  = 0;

static void report_case(const char* name, int ok)
{
    g_total++;
    if (ok) {
        g_pass++;
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
    }
}

// file wrapper
static int write_bin(const char* path, const uint8_t* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[ERR] fopen(wb): %s\n", path);
        return 0;
    }
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    if (n != len) {
        fprintf(stderr, "[ERR] fwrite short: %zu/%zu (%s)\n", n, len, path);
        return 0;
    }
    return 1;
}

static int write_text(const char* path, const char* text)
{
    return write_bin(path, (const uint8_t*)text, strlen(text));
}

static int read_all(const char* path, uint8_t* buf, size_t cap, size_t* out_n)
{
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[ERR] fopen(rb): %s\n", path);
        return 0;
    }
    size_t n = fread(buf, 1, cap, f);
    if (ferror(f)) {
        fprintf(stderr, "[ERR] fread: %s\n", path);
        fclose(f);
        return 0;
    }
    fclose(f);
    *out_n = n;
    return 1;
}

// codec functions
static void test_unit_codec_hex(void)
{
    printf("\n[UNIT] codec_hex 테스트 시작\n");

    /* 1) encode/decode 왕복 */
    {
        uint8_t src[] = {0x00,0x01,0xAB,0xCD,0xEF,0x10,0x99};
        char    hex[64];
        uint8_t dst[64];
        size_t  n = sizeof(src);

        /* hex_encode: n 바이트 -> 2n 바이트 HEX (널 종료는 별도) */
        hex_encode(src, n, (uint8_t*)hex);

        long dec = hex_decode_line((const uint8_t*)hex, n * 2, dst);
        int  ok  = (dec == (long)n) && (memcmp(src, dst, n) == 0);

        report_case("codec_hex: roundtrip", ok);
    }

    /* 2) invalid char 처리 (에러 코드 < 0 이어야 함) */
    {
        const char* bad = "A0B1C2GG";  /* 'G' 는 유효하지 않은 HEX */
        uint8_t dst[64];
        long dec = hex_decode_line((const uint8_t*)bad, strlen(bad), dst);
        int  ok  = (dec < 0);
        report_case("codec_hex: invalid input", ok);
    }

    /* 3) odd-length HEX 문자열 (길이 홀수 → 실패 기대) */
    {
        const char* odd = "ABC";  /* 3글자 */
        uint8_t dst[64];
        long dec = hex_decode_line((const uint8_t*)odd, strlen(odd), dst);
        int  ok  = (dec < 0);
        report_case("codec_hex: odd-length input", ok);
    }
}

// fh functions
static void test_unit_fh_primitives(void)
{
    printf("\n[UNIT] file_io 기본 함수(fh_*) 테스트 시작\n");

    /* 경로 설정 (루트에 res/ 디렉터리가 있다고 가정) */
    const char* path_ok   = "res/test/unit/tmp_fh_basic.bin";
    const char* path_fail = "res/no_such_dir/tmp_fh_basic.bin";

    /* 1) 정상 흐름: open(wb) -> write_all -> close -> open(rb) -> read -> close */
    {
        uint8_t data[256];
        for (size_t i = 0; i < sizeof(data); i++) {
            data[i] = (uint8_t)(i ^ 0x5A);
        }

        FHStatus st;
        FILE* fp = NULL;
        int ok = 1;

        /* open for write */
        st = fh_open(&fp, path_ok, "wb");
        if (st.code != FH_OK || fp == NULL) ok = 0;
        report_case("fh_open(wb): success", ok);

        /* write_all */
        if (ok) {
            st = fh_write_all(fp, data, sizeof(data));
            if (st.code != FH_OK) ok = 0;
            report_case("fh_write_all: success", ok);
        }

        /* close */
        if (ok) {
            st = fh_close(&fp);
            if (st.code != FH_OK || fp != NULL) ok = 0;
            report_case("fh_close(wb): success", ok);
        }

        /* open for read */
        if (ok) {
            st = fh_open(&fp, path_ok, "rb");
            if (st.code != FH_OK || fp == NULL) ok = 0;
            report_case("fh_open(rb): success", ok);
        }

        /* read-all via fh_read 반복 */
        if (ok) {
            uint8_t buf[128];
            size_t total = 0;
            for (;;) {
                size_t got = 0;
                st = fh_read(fp, buf, sizeof(buf), &got);
                if (st.code != FH_OK) { ok = 0; break; }
                if (got == 0) break;  /* EOF */
                if (total + got <= sizeof(data)) {
                    if (memcmp(buf, data + total, got) != 0) {
                        ok = 0;
                        break;
                    }
                } else {
                    ok = 0;
                    break;
                }
                total += got;
            }
            if (ok && total != sizeof(data)) ok = 0;
            report_case("fh_read (loop): roundtrip match", ok);
        }

        /* close read */
        if (ok) {
            st = fh_close(&fp);
            if (st.code != FH_OK || fp != NULL) ok = 0;
            report_case("fh_close(rb): success", ok);
        }
    }

    /* 2) open 실패 케이스: 존재하지 않는 디렉터리 */
    {
        FILE* fp = NULL;
        FHStatus st = fh_open(&fp, path_fail, "wb");
        int ok = (st.code == FH_ERR_OPEN) && (fp == NULL);
        report_case("fh_open: invalid path should fail", ok);
    }

    /* 3) fh_open: 잘못된 인자 (fp == NULL / path == NULL / mode == NULL) */
    {
        FILE* fp_dummy = NULL;
        FHStatus s1 = fh_open(NULL, "res/tmp.bin", "wb");
        FHStatus s2 = fh_open(&fp_dummy, NULL, "wb");
        FHStatus s3 = fh_open(&fp_dummy, "res/tmp.bin", NULL);
        int ok = (s1.code == FH_ERR_INVALID_ARG &&
                  s2.code == FH_ERR_INVALID_ARG &&
                  s3.code == FH_ERR_INVALID_ARG);
        report_case("fh_open: invalid args", ok);
    }

    /* 4) fh_read: 잘못된 인자 (fp == NULL, buffer == NULL, buf_size == 0, nread == NULL) */
    {
        uint8_t buf[16];
        size_t out_len = 0;
        FHStatus st;

        st = fh_read(NULL, buf, sizeof(buf), &out_len);
        int ok1 = (st.code == FH_ERR_INVALID_ARG);

        st = fh_read((FILE*)1, NULL, sizeof(buf), &out_len);
        int ok2 = (st.code == FH_ERR_INVALID_ARG);

        st = fh_read((FILE*)1, buf, 0, &out_len);
        int ok3 = (st.code == FH_ERR_INVALID_ARG);

        st = fh_read((FILE*)1, buf, sizeof(buf), NULL);
        int ok4 = (st.code == FH_ERR_INVALID_ARG);

        report_case("fh_read: invalid args", ok1 && ok2 && ok3 && ok4);
    }

    /* 5) fh_read: 빈 파일에서 EOF 처리 (OK + nread=0) */
    {
        const char* path_empty = "res/test/unit/tmp_fh_empty.bin";
        FILE* f = fopen(path_empty, "wb");
        if (f) fclose(f);

        FILE* fp = NULL;
        FHStatus st = fh_open(&fp, path_empty, "rb");
        int ok = (st.code == FH_OK && fp != NULL);
        if (ok) {
            uint8_t buf[8];
            size_t got = 0;
            st = fh_read(fp, buf, sizeof(buf), &got);
            if (st.code != FH_OK || got != 0) ok = 0;
        }
        if (fp) {
            FHStatus st2 = fh_close(&fp);
            if (st2.code != FH_OK) ok = 0;
        }
        report_case("fh_read: empty file EOF", ok);
    }

    /* 6) fh_write_all: 잘못된 인자 (fp == NULL, buf == NULL, nbytes == 0) */
    {
        uint8_t dummy = 0xAA;

        FHStatus s1 = fh_write_all(NULL, &dummy, 1);
        FHStatus s2 = fh_write_all((FILE*)1, NULL, 1);
        FHStatus s3 = fh_write_all((FILE*)1, &dummy, 0);

        int ok = (s1.code == FH_ERR_INVALID_ARG &&
                  s2.code == FH_ERR_INVALID_ARG &&
                  s3.code == FH_ERR_INVALID_ARG);
        report_case("fh_write_all: invalid args", ok);
    }

    /* 7) fh_close: NULL 인자 처리 (모두 OK 취급) */
    {
        FILE* fp = NULL;
        FHStatus s1 = fh_close(NULL);    /* pfp == NULL */
        FHStatus s2 = fh_close(&fp);     /* *pfp == NULL */

        int ok = (s1.code == FH_OK && s2.code == FH_OK && fp == NULL);
        report_case("fh_close: NULL args treated as OK", ok);
    }

    /* 8) fh_secure_zero: wipe + NULL/0 케이스 */
    {
        uint8_t buf[32];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0xFF;

        fh_secure_zero(buf, sizeof(buf));
        int ok1 = 1;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] != 0x00) { ok1 = 0; break; }
        }

        /* 크래시 없으면 OK라고 본다 */
        fh_secure_zero(NULL, 16);
        fh_secure_zero(buf, 0);

        report_case("fh_secure_zero: wipe + harmless on NULL/0", ok1);
    }
}

// linereader
static void test_unit_line_reader_basic(void)
{
    printf("\n[UNIT] file_io LineReader 기본 테스트 시작\n");

    const char* path = "res/test/unit/tmp_line_reader_aes.txt";

    /* 입력 파일 준비:
       - 빈 줄
       - "short"
       - "hello world!"
       - 5000바이트 긴 줄
    */
    {
        char big[5000];
        for (size_t i = 0; i < sizeof(big); i++) {
            big[i] = 'A' + (char)(i % 26);
        }

        const char* head =
            "\n"
            "short\r\n"
            "hello world!\n";

        FILE* f = fopen(path, "wb");
        int ok = 0;
        if (f) {
            fwrite(head, 1, strlen(head), f);
            fwrite(big, 1, sizeof(big), f);
            fwrite("\n", 1, 1, f);
            fclose(f);
            ok = 1;
        }
        report_case("LineReader-basic: prepare file", ok);
        if (!ok) return;
    }

    /* LineReader 동작 확인 */
    {
        FILE* f = fopen(path, "rb");
        int ok_open = (f != NULL);
        report_case("LineReader-basic: fopen", ok_open);
        if (!ok_open) return;

        LineReader lr;
        FHStatus st;
        const uint8_t* line = NULL;
        size_t len = 0;

        st = lr_init(&lr, f, 0);
        report_case("LineReader-basic: init", (st.code == FH_OK));

        /* 1: 빈 줄 */
        st = lr_next(&lr, &line, &len);
        int ok1 = (st.code == FH_OK && len == 0);
        report_case("LineReader-basic: empty line", ok1);

        /* 2: "short" (CRLF) */
        st = lr_next(&lr, &line, &len);
        int ok2 = (st.code == FH_OK && len == strlen("short"));
        report_case("LineReader-basic: short line", ok2);

        /* 3: "hello world!" */
        st = lr_next(&lr, &line, &len);
        int ok3 = (st.code == FH_OK && len == strlen("hello world!"));
        report_case("LineReader-basic: hello line", ok3);

        /* 4: 5000바이트 긴 줄 (버퍼 grow 테스트) */
        st = lr_next(&lr, &line, &len);
        int ok4 = (st.code == FH_OK && len == 5000);
        report_case("LineReader-basic: big line", ok4);

        /* 5: EOF (line == NULL, len == 0) */
        st = lr_next(&lr, &line, &len);
        int ok5 = (st.code == FH_OK && line == NULL && len == 0);
        report_case("LineReader-basic: EOF", ok5);

        lr_destroy(&lr);
        fclose(f);
    }
}

/* ===== LineReader edge / negative 케이스 ===== */

static void test_unit_line_reader_edges(void)
{
    printf("\n[UNIT] file_io LineReader edge/negative 테스트 시작\n");

    /* 1) 빈 파일: 즉시 EOF 나오는지 */
    {
        const char* path = "res/test/unit/tmp_line_reader_empty.txt";

        FILE* f = fopen(path, "wb");
        if (f) fclose(f);

        f = fopen(path, "rb");
        int ok_open = (f != NULL);
        report_case("LineReader-empty: fopen", ok_open);
        if (!ok_open) return;

        LineReader lr;
        FHStatus st;
        const uint8_t* line = NULL;
        size_t len = 0;

        st = lr_init(&lr, f, 0);
        report_case("LineReader-empty: init", (st.code == FH_OK));

        st = lr_next(&lr, &line, &len);
        int ok1 = (st.code == FH_OK && line == NULL && len == 0);
        report_case("LineReader-empty: first call is EOF", ok1);

        /* EOF 이후 한 번 더 호출해도 계속 EOF 인지 */
        st = lr_next(&lr, &line, &len);
        int ok2 = (st.code == FH_OK && line == NULL && len == 0);
        report_case("LineReader-empty: repeated EOF", ok2);

        lr_destroy(&lr);
        fclose(f);
    }

    /* 2) 마지막 줄에 '\n' 이 없는 파일 */
    {
        const char* path = "res/test/unit/tmp_line_reader_no_nl.txt";
        const char* content = "last_line_without_newline";

        int ok_w = write_text(path, content);
        report_case("LineReader-no-nl: prepare file", ok_w);

        if (ok_w) {
            FILE* f = fopen(path, "rb");
            int ok_open = (f != NULL);
            report_case("LineReader-no-nl: fopen", ok_open);
            if (ok_open) {
                LineReader lr;
                FHStatus st;
                const uint8_t* line = NULL;
                size_t len = 0;

                st = lr_init(&lr, f, 0);
                report_case("LineReader-no-nl: init", (st.code == FH_OK));

                st = lr_next(&lr, &line, &len);
                int ok1 = (st.code == FH_OK &&
                           line != NULL &&
                           len == strlen(content));
                report_case("LineReader-no-nl: single line", ok1);

                st = lr_next(&lr, &line, &len);
                int ok2 = (st.code == FH_OK && line == NULL && len == 0);
                report_case("LineReader-no-nl: EOF after single line", ok2);

                lr_destroy(&lr);
                fclose(f);
            }
        }
    }

    /* 3) lr_init: invalid args (lr == NULL or fp == NULL) */
    {
        LineReader lr;
        FILE* dummy_fp = (FILE*)1;  /* 실제로 사용되기 전에 바로 리턴됨 */

        FHStatus s1 = lr_init(NULL, dummy_fp, 0);
        FHStatus s2 = lr_init(&lr, NULL, 0);

        int ok = (s1.code == FH_ERR_INVALID_ARG &&
                  s2.code == FH_ERR_INVALID_ARG);
        report_case("LineReader: lr_init invalid args", ok);
    }

    /* 4) lr_next: invalid args (lr == NULL, out_line == NULL, out_len == NULL) */
    {
        LineReader lr;
        lr.fp = (FILE*)1;  /* 실제로 사용되지 않고, 인자 체크에서 바로 리턴 */

        const uint8_t* line = NULL;
        size_t len = 0;

        FHStatus s1 = lr_next(NULL, &line, &len);
        FHStatus s2 = lr_next(&lr, NULL, &len);
        FHStatus s3 = lr_next(&lr, &line, NULL);

        int ok = (s1.code == FH_ERR_INVALID_ARG &&
                  s2.code == FH_ERR_INVALID_ARG &&
                  s3.code == FH_ERR_INVALID_ARG);
        report_case("LineReader: lr_next invalid args", ok);
    }
}


int main(void)
{
    printf("[AES] file_io + codec_hex 유닛 테스트 시작\n");

    test_unit_codec_hex();
    test_unit_fh_primitives();
    test_unit_line_reader_basic();
    test_unit_line_reader_edges();

    printf("\n[SUMMARY] %d / %d passed\n", g_pass, g_total);
    return (g_pass == g_total) ? 0 : 1;
}

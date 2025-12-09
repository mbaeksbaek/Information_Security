// AES_백승민_2020253045
// tests/module/test_runner_smoke.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "runner.h"
#include "file_io.h"
/*
[Module Test] runner.c + dummy_ops.c 연동 Smoke Test
 
 대상
     - runner.c : line 모드, whole 모드 I/O 파이프라인
     - dummy_ops.c : "암호 연산 = 입력 그대로 반환" 더미 연산
 
   주요 목적
     - 실제 AES 대신 dummy 연산을 사용해서
       파일 읽기 - 블록 처리 - 파일 쓰기 전체 흐름이 깨지지 않는지 확인
     - line+hex, whole+hex/whole+bin 등 기본 조합을 빠르게 점검
 
   예외/에러 케이스 의도
     - line 모드 결과 파일이 각 줄 끝에 '\n' 으로 끝나는지 확인
       → 줄 끝 처리 누락/버퍼링 문제를 조기에 잡기 위함
     - WHOLE-HEX-DEC 에서 기대 길이가
       제대로 유지되는지 확인
     - odd-length HEX 입력을 주었을 때
       runner 레벨에서 FORMAT 에러를 리턴하는지 확인
 
     - "암호 알고리즘을 빼고 runner 파이프라인만" 보는 연기(연기 테스트) 용도.
 */

/*
gcc -Wall -Wextra -O2 -Iinclude \
  -o build/module/test_runner_smoke \
  tests/module/test_runner_smoke.c \
  src/runner.c src/file_io.c \
  src/dummy_ops.c src/codec_hex.c

[Coverage Test]
gcc -Wall -Wextra -O0 --coverage -Iinclude \
  -o build/module/test_runner_smoke \
  tests/module/test_runner_smoke.c \
  src/runner.c src/file_io.c \
  src/dummy_ops.c src/codec_hex.c

  gcov \
  build/module/test_runner_smoke-file_io.gcno \
  build/module/test_runner_smoke-runner.gcno \
  build/module/test_runner_smoke-codec_hex.gcno
*/

// DUMMY_OPS는 src/dummy_ops.c에 존재해야 함
extern const CryptoOps DUMMY_OPS;

static void write_text(const char* path, const char* s) {
    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); exit(1); }
    fwrite(s, 1, strlen(s), f);
    fclose(f);
}

static long filesize(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fclose(f);
    return n;
}

static void read_all_text(const char* path, char** out, size_t* on) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc((size_t)n + 1);
    if (!buf) { perror("malloc"); exit(1); }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    *out = buf; *on = got;
}

static void print_status(const char* name, FHStatus st) {
    printf("[%s] status=%s stage=%s msg=%s\n",
        name, fh_status_to_str(st.code), fh_stage_to_str(st.stage),
        st.msg ? st.msg : "(null)");
}

int main(void) {
    (void)filesize;

    /* ---------- 1) LINE + binary (encrypt) ---------- */
    write_text("res/input/line_plain.txt",
               "ABC\n"
               "\n"          // 빈 줄
               "Hello, AES!\n"
               "끝줄개행없음");  // 마지막 줄 개행 없음

    RunnerConfig cfg1 = {
        .ops = &DUMMY_OPS,
        .key = (const uint8_t*)"0123456789ABCDEF", // dummy key
        .key_len = 16,
        .input_path = "res/input/line_plain.txt",
        .output_path = "res/output/line_enc.bin",
        .use_hex = false,
        .is_encrypt = true
    };
    FHStatus st = runner_exec_line(&cfg1);
    print_status("LINE-BIN-ENC", st);
    if (st.code != FH_OK) return 1;

    // 더미는 입력==출력이므로 줄단위로 그대로 쓰였는지(개행 보존) 확인
    char *out1 = NULL; size_t on1 = 0;
    read_all_text("res/output/line_enc.bin", &out1, &on1);
    char *in1 = NULL; size_t in1n = 0;
    read_all_text("res/input/line_plain.txt", &in1, &in1n);
    // runner는 각 라인 뒤에 개행을 보장 → 입력 마지막 줄에 개행 없었어도 출력은 개행 존재
    if (out1[on1-1] != '\n') { printf("FAIL: line mode should end lines with \\n\n"); return 2; }
    free(out1); free(in1);

    /* ---------- 2) LINE + HEX (encrypt) ---------- */
    RunnerConfig cfg2 = cfg1;
    cfg2.use_hex = true;
    cfg2.output_path = "res/output/line_enc_hex.txt";
    st = runner_exec_line(&cfg2);
    print_status("LINE-HEX-ENC", st);
    if (st.code != FH_OK) return 3;

    // 간단히 파일 사이즈만 체크(줄마다 길이가 2배 이상이어야 함)
    long sz_plain = filesize("res/input/line_plain.txt");
    long sz_hex   = filesize("res/output/line_enc_hex.txt");
    if (sz_hex <= sz_plain) { printf("WARN: hex output not bigger than input?\n"); }

    /* ---------- 3) WHOLE + HEX (decrypt) ---------- */
    // HEX 섞인 파일(공백/개행 포함): "ABC" → 41 42 43
    write_text("res/input/whole_hex.txt", "41 42\n43  \n");
    RunnerConfig cfg3 = {
        .ops = &DUMMY_OPS,
        .key = (const uint8_t*)"0123456789ABCDEF",
        .key_len = 16,
        .input_path = "res/input/whole_hex.txt",
        .output_path = "res/output/whole_dec.bin",
        .use_hex = true,
        .is_encrypt = false
    };
    st = runner_exec_whole(&cfg3);
    print_status("WHOLE-HEX-DEC", st);
    if (st.code != FH_OK) return 4;

    char *out3 = NULL; size_t on3 = 0;
    read_all_text("res/output/whole_dec.bin", &out3, &on3);
    if (!(on3 == 3 && memcmp(out3, "ABC", 3) == 0)) {
        printf("FAIL: WHOLE-HEX-DEC expected 'ABC' (3 bytes)\n");
        free(out3);
        return 5;
    }
    free(out3);

    /* ---------- 4) WHOLE + HEX (decrypt) - odd length error ---------- */
    write_text("res/input/whole_hex_odd.txt", "4 1 4 2 4"); // 홀수 HEX 수
    RunnerConfig cfg4 = cfg3;
    cfg4.input_path = "res/input/whole_hex_odd.txt";
    cfg4.output_path = "res/output/whole_dec_err.bin";
    st = runner_exec_whole(&cfg4);
    print_status("WHOLE-HEX-DEC-ODD", st);
    if (st.code == FH_OK) {
        printf("FAIL: expected FORMAT error on odd hex length\n");
        return 6;
    }

    /* ---------- 5) LINE mode: 존재하지 않는 입력 파일 ---------- */
    RunnerConfig cfg5 = cfg1;
    cfg5.input_path = "res/input/no_such_file.txt";
    cfg5.output_path = "res/output/should_not_create.bin";
    st = runner_exec_line(&cfg5);
    print_status("LINE-NOFILE", st);
    if (st.code == FH_OK) {
        printf("FAIL: expected OPEN/READ error on missing input\n");
        return 7;
    }

    /* ---------- 6) WHOLE + HEX (decrypt) - invalid hex char ---------- */
    write_text("res/input/whole_hex_badchar.txt", "GG");
    RunnerConfig cfg6 = cfg3;
    cfg6.input_path = "res/input/whole_hex_badchar.txt";
    cfg6.output_path = "res/output/whole_dec_badchar.bin";
    st = runner_exec_whole(&cfg6);
    print_status("WHOLE-HEX-DEC-BADCHAR", st);
    if (st.code == FH_OK) {
        printf("FAIL: expected FORMAT error on non-hex input\n");
        return 8;
    }

    puts("ALL SMOKE TESTS PASSED (with DUMMY_OPS).");
    return 0;
}

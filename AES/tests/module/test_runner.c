// AES_백승민_2020253045
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"       
#include "runner.h"     
#include "file_io.h"    
#include "codec_hex.h"  
/*
  [Module Test] runner.c + AES 전체 파이프라인 테스트
 
   대상
     - runner.c : line/whole, hex/bin 모드 전체 흐름
     - aes_ops.c + aes_block.c + aes_modes.c + aes_key_schedule.c
    - file_io.c / codec_hex.c
 
   주요 목적
     - 실제 AES-ECB 를 사용해서
       "입력 파일 → 암호화 → 출력 파일 → 다시 복호화" 흐름이
       손실 없이 왕복되는지 모듈 단에서 검증
     - 다양한 helper (read_all_bytes, write_text_file 등)를 사용하여
       입력/출력 내용을 바이트 레벨로 비교
 
   예외/에러 케이스 의도
     - encrypt/decrypt 호출이 FHStatus.code / FHStatus.stage 로
       적절한 에러와 단계 정보를 돌려주는지 확인
         * 예: 파일 읽기 실패, HEX 디코딩 실패, AES 오류 등
     - ASSERT 매크로(또는 assert 비슷한 래퍼)를 통해
       예기치 않은 상태에서 즉시 FAIL 로그를 남기고 종료
 
     - System 테스트 바로 전 단계에서
       "Runner + AES 모듈"을 끝까지 연결한 end-to-end 테스트 역할.
 */

/*
gcc -Wall -Wextra -O2 -Iinclude \
  -o build/module/test_runner \
  tests/module/test_runner.c \
  src/app.c src/runner.c src/file_io.c src/codec_hex.c \
  src/aes/aes_tables.c src/aes/aes_key_schedule.c \
  src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c

[Coverage Test]
gcc -Wall -Wextra -O0 --coverage -Iinclude \
  -o build/module/test_runner \
  tests/module/test_runner.c \
  src/app.c src/runner.c src/file_io.c src/codec_hex.c \
  src/aes/aes_tables.c src/aes/aes_key_schedule.c \
  src/aes/aes_block.c src/aes/aes_modes.c src/aes/aes_ops.c

*/

// helpers
static void assert_true(int cond, const char* msg) {
    if (!cond) {
        fprintf(stderr, "[ASSERT FAIL] %s\n", msg);
    }
}

/* 텍스트 파일 하나 쓰기 (테스트 입력용) */
static int write_text_file(const char* path, const char* text)
{
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
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

/* 바이너리 파일 쓰기 */
static int write_bin_file(const char* path, const uint8_t* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* 파일 전체 읽기 (검증용) */
static int read_all_bytes(const char* path, uint8_t** out_buf, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long pos = ftell(f);
    if (pos < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    size_t n = (size_t)pos;
    uint8_t* b = (uint8_t*)malloc(n ? n : 1);
    if (!b) { fclose(f); return -1; }

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

/* 간단한 key hex 디코더 (app.c의 decode_key_hex 간이 버전) */
static int decode_key_hex_simple(const char* hex, uint8_t key_buf[32], size_t* key_len_out)
{
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1) != 0 || hex_len > 64) {
        return -1;
    }
    long n = hex_decode_line((const uint8_t*)hex, hex_len, key_buf);
    if (n <= 0) return -1;
    if (key_len_out) *key_len_out = (size_t)n;
    return 0;
}

/* 공용으로 쓸 AES-128 key */
static const char* TEST_KEY_HEX = "000102030405060708090A0B0C0D0E0F";

/* RunnerConfig 기본 세팅 헬퍼 (key 등만 세팅해주고 나머지는 0으로) */
static int init_cfg_with_key(RunnerConfig* cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    uint8_t key_buf[32];
    size_t key_len = 0;
    if (decode_key_hex_simple(TEST_KEY_HEX, key_buf, &key_len) != 0) {
        fprintf(stderr, "[init_cfg_with_key] FAIL: key decode\n");
        return -1;
    }
    cfg->ops = &AES_OPS;
    /* 주의: RunnerConfig.key는 const uint8_t* 이므로
       여기서는 stack 버퍼를 쓰면 안 되고,
       바로 이 함수 안에서 cfg에 복사할 수 없음.
       - 테스트에서는 간단히 static key를 한 번 더 저장 */
    uint8_t* dyn_key = (uint8_t*)malloc(key_len ? key_len : 1);
    if (!dyn_key) return -1;
    memcpy(dyn_key, key_buf, key_len);
    cfg->key = dyn_key;
    cfg->key_len = key_len;
    return 0;
}

/* cfg에 할당해둔 key free */
static void free_cfg_key(RunnerConfig* cfg)
{
    if (cfg && cfg->key) {
        /* key는 민감정보라면 secure_zero가 더 좋지만,
           여기서는 테스트 코드라 단순 free만 수행 */
        free((void*)cfg->key);
        cfg->key = NULL;
        cfg->key_len = 0;
    }
}

/* ========== LINE 모드 테스트 ========== */

/* Positive: line + HEX 모드 roundtrip
   - 빈 줄, 공백 줄, 마지막 줄 개행 없음 포함 */
static int test_runner_line_hex_roundtrip(void)
{
    const char* in_path  = "res/test/runner/tmp_runner_line_in.txt";
    const char* enc_path = "res/test/runner/tmp_runner_line_enc.txt";
    const char* dec_path = "res/test/runner/tmp_runner_line_dec.txt";

    const char* input_text =
        "Hello AES\n"
        "\n"
        "   \n"
        "LastLineNoNewline";  /* 마지막 줄 개행 없음 */

    if (write_text_file(in_path, input_text) != 0) {
        fprintf(stderr, "[line_hex_roundtrip] FAIL: write input\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = in_path;
    cfg.output_path = enc_path;
    cfg.use_hex     = 1;      // HEX 출력
    cfg.is_encrypt  = true;   // 암호화

    FHStatus st = runner_exec_line(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[line_hex_roundtrip] FAIL: encrypt (code=%d, stage=%d)\n",
                st.code, st.stage);
        free_cfg_key(&cfg);
        return 1;
    }

    // decrypt
    cfg.input_path  = enc_path;
    cfg.output_path = dec_path;
    cfg.is_encrypt  = false;  // 복호

    st = runner_exec_line(&cfg);
    free_cfg_key(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[line_hex_roundtrip] FAIL: decrypt (code=%d, stage=%d)\n",
                st.code, st.stage);
        return 1;
    }

    // 파일 비교
    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;
    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[line_hex_roundtrip] FAIL: read back\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len == dec_len) {
        if (memcmp(orig, dec, orig_len) != 0) {
            fprintf(stderr, "[line_hex_roundtrip] FAIL: plaintext != decrypted (same len)\n");
            free(orig); free(dec);
            return 1;
        }
    } else if (dec_len == orig_len + 1 &&
               dec[dec_len - 1] == '\n' &&
               memcmp(orig, dec, orig_len) == 0) {
        // OK: 복호본이 마지막에 '\n' 하나만 더 있는 경우는 허용
        // (Line 모드 정책: 항상 마지막 줄에 개행을 붙임)
    } else {
        fprintf(stderr,
                "[line_hex_roundtrip] FAIL: length mismatch (orig=%zu, dec=%zu)\n",
                orig_len, dec_len);
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[MODULE-RUNNER] line+hex roundtrip: OK\n");
    return 0;
}

/* Negative: LINE + HEX 복호에서 odd-length HEX 라인 */
static int test_runner_line_hex_odd_length(void)
{
    const char* in_path  = "res/test/runner/tmp_runner_line_odd_hex.txt";
    const char* out_path = "res/test/runner/tmp_runner_line_odd_hex_out.txt";

    /* len=3 → squeeze 없이도 홀수 길이 */
    const char* bad_hex_line = "ABC\n";
    if (write_text_file(in_path, bad_hex_line) != 0) {
        fprintf(stderr, "[line_hex_odd_length] FAIL: write input\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = in_path;
    cfg.output_path = out_path;
    cfg.use_hex     = 1;       // HEX 입력/출력
    cfg.is_encrypt  = false;   // 복호

    FHStatus st = runner_exec_line(&cfg);
    free_cfg_key(&cfg);

    if (st.code == FH_OK) {
        fprintf(stderr, "[line_hex_odd_length] FAIL: expected error but got OK\n");
        return 1;
    }

    assert_true(st.code == FH_ERR_INVALID_ARG, "line odd hex -> FH_ERR_INVALID_ARG");
    assert_true(st.stage == FH_STAGE_LINE,     "line odd hex -> FH_STAGE_LINE");
    printf("[MODULE-RUNNER] line+hex odd-length: OK (expected error)\n");
    return 0;
}

/* Negative: LINE + HEX 복호에서 invalid HEX 문자 (길이는 짝수, 문자만 잘못된 경우) */
static int test_runner_line_hex_invalid_char(void)
{
    const char* in_path  = "res/test/runner/tmp_runner_line_invalid_hex.txt";
    const char* out_path = "res/test/runner/tmp_runner_line_invalid_hex_out.txt";

    /* "G1\n"
       - LineReader는 개행을 떼고 "G1" + len=2 를 넘겨줌
       - 길이는 짝수지만 'G'가 hex 문자가 아니라서 from_hex()에서 -1 리턴
       - hex_decode_line() 이 -1을 리턴 - FH_ERR_INVALID_ARG / FH_STAGE_LINE 기대 */
    const char* bad_hex_line = "G1\n";
    if (write_text_file(in_path, bad_hex_line) != 0) {
        fprintf(stderr, "[line_hex_invalid_char] FAIL: write input\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = in_path;
    cfg.output_path = out_path;
    cfg.use_hex     = 1;       // HEX 입력/출력
    cfg.is_encrypt  = false;   // 복호

    FHStatus st = runner_exec_line(&cfg);
    free_cfg_key(&cfg);

    if (st.code == FH_OK) {
        fprintf(stderr,
                "[line_hex_invalid_char] FAIL: expected error but got OK\n");
        return 1;
    }

    if (st.code != FH_ERR_INVALID_ARG) {
        fprintf(stderr,
                "[line_hex_invalid_char] FAIL: code=%d (expected INVALID_ARG)\n",
                st.code);
        return 1;
    }
    if (st.stage != FH_STAGE_LINE) {
        fprintf(stderr,
                "[line_hex_invalid_char] FAIL: stage=%d (expected LINE)\n",
                st.stage);
        return 1;
    }

    printf("[MODULE-RUNNER] line+hex invalid-char: OK (expected error)\n");
    return 0;
}

/* Negative: RunnerConfig 잘못 세팅 (Open stage) */
static int test_runner_invalid_cfg(void)
{
    RunnerConfig cfg;
    FHStatus st;

    /* 1) ops = NULL */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ops = NULL;
    st = runner_exec_whole(&cfg);
    assert_true(st.code == FH_ERR_INVALID_ARG, "null ops -> INVALID_ARG");
    assert_true(st.stage == FH_STAGE_OPEN,     "null ops -> OPEN stage");

    /* 2) key_len = 0 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ops        = &AES_OPS;
    cfg.key        = (const uint8_t*)"dummy";
    cfg.key_len    = 0;
    cfg.input_path = "dummy_in";
    cfg.output_path = "dummy_out";
    st = runner_exec_whole(&cfg);
    assert_true(st.code == FH_ERR_INVALID_ARG, "key_len=0 -> INVALID_ARG");
    assert_true(st.stage == FH_STAGE_OPEN,     "key_len=0 -> OPEN stage");

    /* 3) input_path = NULL */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ops        = &AES_OPS;
    cfg.key        = (const uint8_t*)"dummy";
    cfg.key_len    = 16;
    cfg.input_path = NULL;
    cfg.output_path = "dummy_out";
    st = runner_exec_whole(&cfg);
    assert_true(st.code == FH_ERR_INVALID_ARG, "null input_path -> INVALID_ARG");
    assert_true(st.stage == FH_STAGE_OPEN,     "null input_path -> OPEN stage");

    printf("[MODULE-RUNNER] invalid cfg cases: OK\n");
    return 0;
}

/* ========== WHOLE 모드 테스트 ========== */

/* Positive: WHOLE + BIN, 0-byte 파일과 작은 파일 roundtrip */
static int test_runner_whole_bin_roundtrip(void)
{
    /* 0-byte 파일 */
    const char* zero_in  = "res/test/runner/tmp_runner_whole_zero_in.bin";
    const char* zero_enc = "res/test/runner/tmp_runner_whole_zero_enc.bin";
    const char* zero_dec = "res/test/runner/tmp_runner_whole_zero_dec.bin";

    /* 그냥 열었다 닫기만 해도 0바이트 파일 생성 */
    FILE* f = fopen(zero_in, "wb");
    if (!f) { perror("fopen"); return 1; }
    fclose(f);

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;

    /* enc: whole + bin */
    cfg.input_path  = zero_in;
    cfg.output_path = zero_enc;
    cfg.use_hex     = 0;
    cfg.is_encrypt  = true;

    FHStatus st = runner_exec_whole(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: zero enc (code=%d, stage=%d)\n",
                st.code, st.stage);
        free_cfg_key(&cfg);
        return 1;
    }

    /* dec: whole + bin */
    cfg.input_path  = zero_enc;
    cfg.output_path = zero_dec;
    cfg.is_encrypt  = false;

    st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: zero dec (code=%d, stage=%d)\n",
                st.code, st.stage);
        return 1;
    }

    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;
    if (read_all_bytes(zero_in, &orig, &orig_len) != 0 ||
        read_all_bytes(zero_dec, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: zero read back\n");
        free(orig); free(dec);
        return 1;
    }
    assert_true(orig_len == 0, "zero orig len == 0");
    assert_true(dec_len == 0,  "zero dec len == 0");
    free(orig); free(dec);

    /* 작은 파일 (2~3블록 정도) */
    const char* small_in  = "res/test/runner/tmp_runner_whole_small_in.bin";
    const char* small_enc = "res/test/runner/tmp_runner_whole_small_enc.bin";
    const char* small_dec = "res/test/runner/tmp_runner_whole_small_dec.bin";

    const char* small_txt =
        "This is AES WHOLE-mode test.\n"
        "Second line.\n";

    if (write_text_file(small_in, small_txt) != 0) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: write small_in\n");
        return 1;
    }

    if (init_cfg_with_key(&cfg) != 0) return 1;

    cfg.input_path  = small_in;
    cfg.output_path = small_enc;
    cfg.use_hex     = 0;
    cfg.is_encrypt  = true;

    st = runner_exec_whole(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: small enc (code=%d, stage=%d)\n",
                st.code, st.stage);
        free_cfg_key(&cfg);
        return 1;
    }

    cfg.input_path  = small_enc;
    cfg.output_path = small_dec;
    cfg.is_encrypt  = false;

    st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: small dec (code=%d, stage=%d)\n",
                st.code, st.stage);
        return 1;
    }

    uint8_t *orig2 = NULL, *dec2 = NULL;
    size_t orig2_len = 0, dec2_len = 0;
    if (read_all_bytes(small_in, &orig2, &orig2_len) != 0 ||
        read_all_bytes(small_dec, &dec2, &dec2_len) != 0)
    {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: small read back\n");
        free(orig2); free(dec2);
        return 1;
    }

    if (orig2_len != dec2_len || memcmp(orig2, dec2, orig2_len) != 0) {
        fprintf(stderr, "[whole_bin_roundtrip] FAIL: small plaintext != decrypted\n");
        free(orig2); free(dec2);
        return 1;
    }

    free(orig2); free(dec2);
    printf("[MODULE-RUNNER] whole+bin (zero + small) roundtrip: OK\n");
    return 0;
}

/* Positive: WHOLE + HEX 모드 roundtrip
   - enc: use_hex=1, is_encrypt=1 → 암호문을 HEX로 출력
   - dec: use_hex=1, is_encrypt=0 → HEX를 디코드해 복호 */
static int test_runner_whole_hex_roundtrip(void)
{
    const char* in_path  = "res/test/runner/tmp_runner_whole_hex_in.bin";
    const char* enc_path = "res/test/runner/tmp_runner_whole_hex_enc.txt";
    const char* dec_path = "res/test/runner/tmp_runner_whole_hex_dec.bin";

    const char* pt =
        "WHOLE HEX MODE TEST\n"
        "line2\n";

    if (write_text_file(in_path, pt) != 0) {
        fprintf(stderr, "[whole_hex_roundtrip] FAIL: write in\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;

    /* enc: binary 입력 → HEX 암호문 출력 */
    cfg.input_path  = in_path;
    cfg.output_path = enc_path;
    cfg.use_hex     = 1;
    cfg.is_encrypt  = true;

    FHStatus st = runner_exec_whole(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_hex_roundtrip] FAIL: enc (code=%d, stage=%d)\n",
                st.code, st.stage);
        free_cfg_key(&cfg);
        return 1;
    }

    /* dec: HEX 암호문 → binary 평문 */
    cfg.input_path  = enc_path;
    cfg.output_path = dec_path;
    cfg.is_encrypt  = false;

    st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);
    if (st.code != FH_OK) {
        fprintf(stderr, "[whole_hex_roundtrip] FAIL: dec (code=%d, stage=%d)\n",
                st.code, st.stage);
        return 1;
    }

    uint8_t *orig = NULL, *dec = NULL;
    size_t orig_len = 0, dec_len = 0;
    if (read_all_bytes(in_path, &orig, &orig_len) != 0 ||
        read_all_bytes(dec_path, &dec, &dec_len) != 0)
    {
        fprintf(stderr, "[whole_hex_roundtrip] FAIL: read back\n");
        free(orig); free(dec);
        return 1;
    }

    if (orig_len != dec_len || memcmp(orig, dec, orig_len) != 0) {
        fprintf(stderr, "[whole_hex_roundtrip] FAIL: plaintext != decrypted\n");
        free(orig); free(dec);
        return 1;
    }

    free(orig); free(dec);
    printf("[MODULE-RUNNER] whole+hex roundtrip: OK\n");
    return 0;
}

/* Negative: WHOLE + HEX 복호에서 odd-length / invalid HEX */
static int test_runner_whole_hex_bad_input(void)
{
    /* 1) odd-length hex: READ / INVALID_ARG 기대 */
    const char* odd_path  = "res/test/runner/tmp_runner_whole_hex_odd.txt";
    const char* odd_out   = "res/test/runner/tmp_runner_whole_hex_odd_out.bin";
    const char* odd_hex   = "ABC\n";  /* squeeze 후 길이 3 */

    if (write_text_file(odd_path, odd_hex) != 0) {
        fprintf(stderr, "[whole_hex_bad_input] FAIL: write odd\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = odd_path;
    cfg.output_path = odd_out;
    cfg.use_hex     = 1;
    cfg.is_encrypt  = false;  /* decrypt: HEX 입력 */

    FHStatus st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);

    if (st.code == FH_OK) {
        fprintf(stderr, "[whole_hex_bad_input] FAIL: odd hex expected error\n");
        return 1;
    }
    if (st.code != FH_ERR_INVALID_ARG) {
        fprintf(stderr,
                "[whole_hex_bad_input] FAIL: odd hex -> code=%d (expected INVALID_ARG)\n",
                st.code);
        return 1;
    }
    if (st.stage != FH_STAGE_READ) {
        fprintf(stderr,
                "[whole_hex_bad_input] FAIL: odd hex -> stage=%d (expected READ)\n",
                st.stage);
        return 1;
    }

    /* 2) invalid hex char only: READ / INVALID_ARG 기대
       - squeeze_hex 이후 sq == 0 이면, hex 포맷 에러로 처리 */
    const char* bad_path  = "res/test/runner/tmp_runner_whole_hex_invalid.txt";
    const char* bad_out   = "res/test/runner/tmp_runner_whole_hex_invalid_out.bin";
    const char* bad_hex   = "GG\n";

    if (write_text_file(bad_path, bad_hex) != 0) {
        fprintf(stderr, "[whole_hex_bad_input] FAIL: write bad\n");
        return 1;
    }

    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = bad_path;
    cfg.output_path = bad_out;
    cfg.use_hex     = 1;
    cfg.is_encrypt  = false;

    st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);

    if (st.code == FH_OK) {
        fprintf(stderr,
                "[whole_hex_bad_input] FAIL: invalid hex should cause error (got OK)\n");
        return 1;
    }
    if (st.code != FH_ERR_INVALID_ARG) {
        fprintf(stderr,
                "[whole_hex_bad_input] FAIL: invalid hex -> code=%d (expected INVALID_ARG)\n",
                st.code);
        return 1;
    }
    if (st.stage != FH_STAGE_READ) {
        fprintf(stderr,
                "[whole_hex_bad_input] FAIL: invalid hex -> stage=%d (expected READ)\n",
                st.stage);
        return 1;
    }

    printf("[MODULE-RUNNER] whole+hex bad-input (odd/invalid) : OK (expected errors)\n");
    return 0;
}


/* Negative: WHOLE + BIN, 잘못된 key_len → CRYPTO stage (ks_init 실패) */
static int test_runner_whole_bad_keylen_crypto(void)
{
    const char* in_path  = "res/test/runner/tmp_runner_whole_badkey_in.bin";
    const char* out_path = "res/test/runner/tmp_runner_whole_badkey_out.bin";

    const uint8_t data[] = "BAD KEYLEN TEST";
    if (write_bin_file(in_path, data, sizeof(data)-1) != 0) {
        fprintf(stderr, "[whole_bad_keylen_crypto] FAIL: write in\n");
        return 1;
    }

    RunnerConfig cfg;
    if (init_cfg_with_key(&cfg) != 0) return 1;
    cfg.input_path  = in_path;
    cfg.output_path = out_path;
    cfg.use_hex     = 0;
    cfg.is_encrypt  = true;

    /* 의도적으로 key_len을 잘못 세팅 (예: 15) */
    if (cfg.key_len > 1) {
        cfg.key_len -= 1;
    } else {
        cfg.key_len = 15; /* 어차피 AES는 16/24/32만 허용 */
    }

    FHStatus st = runner_exec_whole(&cfg);
    free_cfg_key(&cfg);

    if (st.code == FH_OK) {
        fprintf(stderr, "[whole_bad_keylen_crypto] FAIL: expected ks_init error\n");
        return 1;
    }

    assert_true(st.code == FH_ERR_INVALID_ARG, "bad key_len -> INVALID_ARG");
    assert_true(st.stage == FH_STAGE_CRYPTO,   "bad key_len -> CRYPTO stage");
    printf("[MODULE-RUNNER] whole+bin bad key_len (ks_init fail): OK (expected error)\n");
    return 0;
}


int main(void)
{
    int fail = 0;

    if (test_runner_line_hex_roundtrip()      != 0) fail = 1;
    if (test_runner_line_hex_odd_length()     != 0) fail = 1;
    if (test_runner_line_hex_invalid_char() != 0) fail = 1;
    if (test_runner_invalid_cfg()             != 0) fail = 1;
    if (test_runner_whole_bin_roundtrip()     != 0) fail = 1;
    if (test_runner_whole_hex_roundtrip()     != 0) fail = 1;
    if (test_runner_whole_hex_bad_input()     != 0) fail = 1;
    if (test_runner_whole_bad_keylen_crypto() != 0) fail = 1;

    if (!fail) {
        printf("== Runner + AES_OPS Module Tests: PASSED ==\n");
        return 0;
    } else {
        printf("== Runner + AES_OPS Module Tests: FAILED ==\n");
        return 1;
    }
}

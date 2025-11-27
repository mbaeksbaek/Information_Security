// AES_백승민_2020253045
#include "app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes/aes.h"
#include "aes/aes_ops.h"
#include "crypto_ops.h"
#include "runner.h"
#include "file_io.h"
#include "codec_hex.h"
/*
[AES KeySchedule]
gcov \
  build/unit/test_key_schedule-aes_key_schedule.gcno \
  build/unit/test_modes_ecb-aes_key_schedule.gcno \
  build/unit/test_unit_block-aes_key_schedule.gcno \
  build/module/test_ecb_vectors-aes_key_schedule.gcno \
  build/module/test_runner-aes_key_schedule.gcno \
  build/sys/test_app_cli-aes_key_schedule.gcno \
  build/sys/test_sys_line-aes_key_schedule.gcno \
  build/sys/test_sys_whole-aes_key_schedule.gcno

  File 'src/aes/aes_key_schedule.c'
Lines executed:91.84% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:89.80% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:89.80% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:97.96% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:91.84% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:0.00% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:89.80% of 49
Creating 'aes_key_schedule.c.gcov'

File 'src/aes/aes_key_schedule.c'
Lines executed:97.96% of 49
Creating 'aes_key_schedule.c.gcov'

[AES Block]
gcov \
  build/unit/test_modes_ecb-aes_block.gcno \
  build/unit/test_unit_block-aes_block.gcno \
  build/module/test_ecb_vectors-aes_block.gcno \
  build/module/test_runner-aes_block.gcno \
  build/sys/test_app_cli-aes_block.gcno \
  build/sys/test_sys_line-aes_block.gcno \
  build/sys/test_sys_whole-aes_block.gcno

File 'src/aes/aes_block.c'
Lines executed:64.59% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:96.65% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:64.59% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:64.59% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:0.00% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:64.59% of 209
Creating 'aes_block.c.gcov'

File 'src/aes/aes_block.c'
Lines executed:64.59% of 209
Creating 'aes_block.c.gcov'

[AES Modes]
gcov \
  build/unit/test_modes_ecb-aes_modes.gcno \
  build/module/test_runner-aes_modes.gcno \
  build/sys/test_app_cli-aes_modes.gcno \
  build/sys/test_sys_line-aes_modes.gcno \
  build/sys/test_sys_whole-aes_modes.gcno

File 'src/aes/aes_modes.c'
Lines executed:91.67% of 72
Creating 'aes_modes.c.gcov'

File 'src/aes/aes_modes.c'
Lines executed:87.50% of 72
Creating 'aes_modes.c.gcov'

File 'src/aes/aes_modes.c'
Lines executed:0.00% of 72
Creating 'aes_modes.c.gcov'

File 'src/aes/aes_modes.c'
Lines executed:83.33% of 72
Creating 'aes_modes.c.gcov'

File 'src/aes/aes_modes.c'
Lines executed:91.67% of 72
Creating 'aes_modes.c.gcov'  

[AES Tables]
gcov \
  build/unit/test_key_schedule-aes_tables.gcno \
  build/unit/test_modes_ecb-aes_tables.gcno \
  build/unit/test_unit_block-aes_tables.gcno \
  build/module/test_ecb_vectors-aes_tables.gcno \
  build/module/test_runner-aes_tables.gcno \
  build/sys/test_app_cli-aes_tables.gcno \
  build/sys/test_sys_line-aes_tables.gcno \
  build/sys/test_sys_whole-aes_tables.gcno

[AES Ops]
gcov \
  build/sys/test_app_cli-aes_ops.gcno \
  build/sys/test_sys_line-aes_ops.gcno \
  build/sys/test_sys_whole-aes_ops.gcno
File 'src/aes/aes_ops.c'
Lines executed:0.00% of 23
Creating 'aes_ops.c.gcov'

File 'src/aes/aes_ops.c'
Lines executed:86.96% of 23
Creating 'aes_ops.c.gcov'

File 'src/aes/aes_ops.c'
Lines executed:86.96% of 23
Creating 'aes_ops.c.gcov'

[Runner]
gcov \
  build/module/test_runner-runner.gcno \
  build/sys/test_app_cli-runner.gcno \
  build/sys/test_sys_line-runner.gcno \
  build/sys/test_sys_whole-runner.gcno

File 'src/runner.c'
Lines executed:76.15% of 218
Creating 'runner.c.gcov'

File 'src/runner.c'
Lines executed:7.80% of 218
Creating 'runner.c.gcov'

File 'src/runner.c'
Lines executed:36.70% of 218
Creating 'runner.c.gcov'

File 'src/runner.c'
Lines executed:41.28% of 218
Creating 'runner.c.gcov'

[File IO]
gcov \
  build/module/test_runner-file_io.gcno \
  build/sys/test_app_cli-file_io.gcno \
  build/sys/test_sys_line-file_io.gcno \
  build/sys/test_sys_whole-file_io.gcno

seungmin@Seugminui-MacBookPro AES % gcov \
  build/module/test_runner-file_io.gcno \
  build/sys/test_app_cli-file_io.gcno \
  build/sys/test_sys_line-file_io.gcno \
  build/sys/test_sys_whole-file_io.gcno

File 'src/file_io.c'
Lines executed:63.82% of 152
Creating 'file_io.c.gcov'

File 'src/file_io.c'
Lines executed:13.16% of 152
Creating 'file_io.c.gcov'

File 'src/file_io.c'
Lines executed:60.53% of 152
Creating 'file_io.c.gcov'

File 'src/file_io.c'
Lines executed:29.61% of 152
Creating 'file_io.c.gcov'

[HEX Codec]
gcov \
  build/module/test_runner-codec_hex.gcno \
  build/sys/test_app_cli-codec_hex.gcno \
  build/sys/test_sys_line-codec_hex.gcno \
  build/sys/test_sys_whole-codec_hex.gcno

  File 'src/codec_hex.c'
Lines executed:93.94% of 33
Creating 'codec_hex.c.gcov'

File 'src/codec_hex.c'
Lines executed:48.48% of 33
Creating 'codec_hex.c.gcov'

File 'src/codec_hex.c'
Lines executed:84.85% of 33
Creating 'codec_hex.c.gcov'

File 'src/codec_hex.c'
Lines executed:48.48% of 33
Creating 'codec_hex.c.gcov'

[APP CLI]

gcov \
  build/sys/test_app_cli-app.gcno \
  build/sys/test_sys_line-app.gcno \
  build/sys/test_sys_whole-app.gcno

  File 'src/app.c'
Lines executed:84.51% of 71
Creating 'app.c.gcov'

File 'src/app.c'
Lines executed:53.52% of 71
Creating 'app.c.gcov'

File 'src/app.c'
Lines executed:69.01% of 71
Creating 'app.c.gcov'

aes_key_schedule.c	48 / 49	≈ 98.0%
aes_block.c	135 / 209	≈ 64.6%
aes_modes.c	66 / 72	≈ 91.7%
aes_ops.c	20 / 23	≈ 87.0%
app.c	49 / 71	≈ 69.0%
codec_hex.c	16 / 33	≈ 48.5%
file_io.c	45 / 152	≈ 29.6%
runner.c	90 / 218	≈ 41.3%
*/


/*
- USER CLI Interface를 담당
- main() 에서 aes_cli_run()만 호출하게끔 파이프라인 동작 설계

1) 명령행 인자 파싱(end/dec line/whole in/out path, key_hex, hex|bin)
 2) key-hex 문자열을 실제 키 바이트 배열로 디코드
 3) runner config 채워서 Runner-exec-line / runner-exec-whole
 4) fhstatus 를 보고 에러 메세지 및 사용법 출력
*/

// Explanation of how to use
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s enc|dec line|whole <in_path> <out_path> <key_hex> [hex|bin]\n"
        "\n"
        "  enc|dec   : encrypt or decrypt\n"
        "  line      : line-by-line 모드 (Plain Text 1)\n"
        "  whole     : whole-file 모드 (Plain Text 2)\n"
        "  key_hex   : 128/192/256-bit key in HEX (32/48/64 hex chars)\n"
        "  [hex|bin] : I/O format (default=hex)\n",
        prog
    );
}

// decoding key hex : 16, 24, 32 (AES-128/192/256), key buf : max 32 byte
/*

- cli param: key_hex 문자열 실제 키 바이트 배열 디코딩

hex 문자열 길이:1~64글자, 짝수 길이
디코딩 결과 바이트: 16/24/32 만 허용

Exception:
- 길이가 0, 홀수, 64 초과 > invalid key hex length
- hex_decode_line fail: invalid key in key string
- 최종 키 길이가 16/24/32 가 아니면: unsupported key size

returns:
0 success (keybuf 에 키가 들어가고 *Key_len_out 설정)
-1: 실패.. stderr 에 출력
*/
static int decode_key_hex(const char *hex, uint8_t key_buf[32], size_t *key_len_out)
{
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1) != 0 || hex_len > 64) {
        fprintf(stderr, "[AES-CLI] invalid key hex length: %zu\n", hex_len);
        return -1;
    }

    int n = hex_decode_line((const uint8_t *)hex, hex_len, key_buf);
    if (n < 0) {
        fprintf(stderr, "[AES-CLI] invalid hex in key string\n");
        return -1;
    }

    size_t key_len = (size_t)n;
    if (key_len != AES128_KEY_BYTES &&
        key_len != AES192_KEY_BYTES &&
        key_len != AES256_KEY_BYTES)
    {
        fprintf(stderr,
                "[AES-CLI] unsupported key size: %zu bytes (need 16/24/32)\n",
                key_len);
        return -1;
    }

    if (key_len_out) {
        *key_len_out = key_len;
    }
    return 0;
}

// aes cli entry point : called at main
/*
argv[1]: enc/dec
argv[2]: line/whole
argv[3]: input path
argv[4]: output path
argv[5]: hex_hex(32/48/64 hex char)
argv[6]: (Optional) hex/bin (basis:hex)

Process
- 1) 인자 개수 검사(6~7만 허용)
- 2) 모드 문자열 검증:
  - mode: enc/dec
  - io mode: line/whole
  - fmt: hex/bin
- 3) key_hex decode: key_buf, key_len
- 4) RunnerConfig 구성 후, runner-exec-line/runner-exec-whole 호출
- 5) fh status 성공 0, 실패 1 반환

Exceptions
- 인자 이상/문자열 오타: 사용법 + 1 리턴
- key_hex 포맷 오류/지원하지 않는 키 길이: 1리턴
- runner 쪽에서 fh-ok 가 아닌 코드 : 스테이지/코드/메세지 출력 후 1리턴
*/
int aes_cli_run(int argc, char** argv) {
    if (argc < 6 || argc > 7) {
        print_usage(argv[0]);
        return 1;
    }

    const char* mode = argv[1];     // enc dec
    const char* io_mode = argv[2];  // line whole
    const char* in_path = argv[3]; 
    const char* out_path = argv[4];
    const char* key_hex = argv[5];
    const char* fmt = (argc>=7) ? argv[6] : "hex";

    // enc dec flag
    int is_encrypt;
    if (strcmp(mode, "enc") == 0) is_encrypt = 1;
    else if (strcmp(mode, "dec") == 0) is_encrypt = 0;
    else {
        fprintf(stderr, "[AES-CLI] first arg must be 'enc' or 'dec'\n");
        print_usage(argv[0]);
        return 1;
    }

    // line whole
    int use_line_mode;
    if (strcmp(io_mode, "line") == 0) use_line_mode = 1;
    else if (strcmp(io_mode, "whole") == 0 || strcmp(io_mode, "file") == 0) use_line_mode = 0;
    else {
        fprintf(stderr, "[AES-CLI] second arg must be 'line' or 'whole'\n");
        print_usage(argv[0]);
        return 1;
    }

    // io format : hex bin
    int use_hex_format;
    if (strcmp(fmt, "hex") == 0) use_hex_format = 1;
    else if (strcmp(fmt, "bin") == 0) use_hex_format = 0;
    else {
        fprintf(stderr, "[AES-CLI] format must be 'hex' or 'bin'\n");
        print_usage(argv[0]);
        return 1;
    }

    // key decode
    uint8_t key_buf[32];
    size_t key_len = 0;
    if (decode_key_hex(key_hex, key_buf, &key_len) != 0) return 1;

    // runner config
    RunnerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    // init
    cfg.ops = &AES_OPS;
    cfg.key = key_buf;
    cfg.key_len = key_len;
    cfg.input_path = in_path;
    cfg.output_path = out_path;
    cfg.is_encrypt = is_encrypt;
    cfg.use_hex = use_hex_format;

    // execute
    FHStatus st;
    if (use_line_mode) st = runner_exec_line(&cfg);
    else st = runner_exec_whole(&cfg);

    if (st.code != FH_OK) {
        fprintf(stderr,
        "[AES-CLI] Failed : %s (stage=%s)\n", fh_status_to_str(st.code), fh_status_to_str(st.stage));
        if (st.msg) {
            fprintf(stderr, "    msg:%s\n", st.msg);
        }
        return 1;
    }
    return 0;
}
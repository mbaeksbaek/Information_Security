// src/rsa/rsa_app.c
// RSA_백승민_2020253045
// RSA-ECB + ZeroPadding CLI (Runner + CryptoOps 기반)

#include "rsa/rsa_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa/rsa_ops.h"
#include "crypto_ops.h"
#include "runner.h"
#include "file_io.h"
#include "codec_hex.h"

// 간단한 usage 출력
static void rsa_print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s enc line  <in> <out> <key_hex> <hex|raw>\n"
        "  %s enc whole <in> <out> <key_hex> <hex|raw>\n"
        "  %s dec line  <in> <out> <key_hex> <hex|raw>\n"
        "  %s dec whole <in> <out> <key_hex> <hex|raw>\n",
        prog, prog, prog, prog);
    fprintf(stderr,
        "\n key_hex format: [N | EXP] in big-endian hex bytes\n"
        "   enc: EXP = e, dec: EXP = d\n");
}

// HEX 문자열을 바이트 배열로 디코딩하는 헬퍼
// 성공: out_buf 할당 + out_len 설정, 0 리턴
// 실패: -1 리턴
static int decode_key_hex(const char *hex_str, uint8_t **out_buf, size_t *out_len) {
    size_t len = strlen(hex_str);
    if (len == 0 || (len & 1u) != 0) {
        return -1; // empty or odd length
    }

    uint8_t *buf = (uint8_t *)malloc(len / 2 ? len / 2 : 1);
    if (!buf) return -1;

    long bl = hex_decode_line((const uint8_t *)hex_str, len, buf);
    if (bl < 0) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = (size_t)bl;
    return 0;
}

int rsa_cli_run(int argc, char **argv) {
    if (argc != 7) {
        rsa_print_usage(argv[0]);
        return 1;
    }

    const char *mode_str  = argv[1]; // "enc" or "dec"
    const char *unit_str  = argv[2]; // "line" or "whole"
    const char *in_path   = argv[3];
    const char *out_path  = argv[4];
    const char *key_hex   = argv[5];
    const char *fmt_str   = argv[6]; // "hex" or "raw"

    int is_encrypt = 0;
    int use_line_mode = 0;
    int use_hex = 0;

    // enc/dec 판단
    if (strcmp(mode_str, "enc") == 0) {
        is_encrypt = 1;
    } else if (strcmp(mode_str, "dec") == 0) {
        is_encrypt = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid mode: %s\n", mode_str);
        rsa_print_usage(argv[0]);
        return 1;
    }

    // line/whole 판단
    if (strcmp(unit_str, "line") == 0) {
        use_line_mode = 1;
    } else if (strcmp(unit_str, "whole") == 0) {
        use_line_mode = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid unit: %s\n", unit_str);
        rsa_print_usage(argv[0]);
        return 1;
    }

    // hex/raw 판단 → runner.c의 cfg->use_hex 와 연결
    if (strcmp(fmt_str, "hex") == 0) {
        use_hex = 1;
    } else if (strcmp(fmt_str, "raw") == 0) {
        use_hex = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid format: %s (use hex or raw)\n", fmt_str);
        rsa_print_usage(argv[0]);
        return 1;
    }

    // key_hex -> 바이트 배열
    uint8_t *key_bytes = NULL;
    size_t key_len = 0;
    if (decode_key_hex(key_hex, &key_bytes, &key_len) != 0) {
        fprintf(stderr, "[RSA-CLI] invalid key_hex (decode failed)\n");
        return 1;
    }

    // RunnerConfig 설정
    RunnerConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.ops         = &RSA_OPS;   // 🔥 여기서 AES가 아니라 RSA를 사용
    cfg.key         = key_bytes;
    cfg.key_len     = key_len;
    cfg.input_path  = in_path;
    cfg.output_path = out_path;
    cfg.is_encrypt  = is_encrypt;
    cfg.use_hex     = use_hex;

    // 실제 실행
    FHStatus st;
    if (use_line_mode)
        st = runner_exec_line(&cfg);
    else
        st = runner_exec_whole(&cfg);

    // key 버퍼는 RunnerConfig에서 참조만 하므로 여기서 free
    fh_secure_zero(key_bytes, key_len);
    free(key_bytes);

    if (st.code != FH_OK) {
        fprintf(stderr,
            "[RSA-CLI] Failed : %s (stage=%s)\n",
            fh_status_to_str(st.code),
            fh_stage_to_str(st.stage));
        if (st.msg) {
            fprintf(stderr, "    msg: %s\n", st.msg);
        }
        return 1;
    }

    return 0;
}

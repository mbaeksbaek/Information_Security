// src/rsa/rsa_app.c
// RSA-ECB + ZeroPadding CLI (Runner + CryptoOps 기반)

#include "rsa/rsa_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa/rsa_ops.h"   // extern const CryptoOps RSA_OPS;

static void print_usage(FILE *fp) {
    fprintf(fp,
        "Usage:\n"
        "  rsa_app enc line  <in> <out> <KEYHEX> [hex|raw]\n"
        "  rsa_app enc whole <in> <out> <KEYHEX> [hex|raw]\n"
        "  rsa_app dec line  <in> <out> <KEYHEX> [hex|raw]\n"
        "  rsa_app dec whole <in> <out> <KEYHEX> [hex|raw]\n"
        "\n"
        "  KEYHEX : big-endian hex of N||EXP (enc: EXP=e, dec: EXP=d)\n"
        "  [hex|raw] : plaintext/ciphertext file format\n"
    );
}

// 간단한 KEYHEX 파서: HEX 문자열 → 바이트 배열
static int parse_key_hex(const char *key_hex,
                         uint8_t **out_key,
                         size_t *out_key_len)
{
    if (!key_hex || !out_key || !out_key_len) {
        return -1;
    }

    size_t hex_len = strlen(key_hex);
    if (hex_len == 0 || (hex_len & 1u) != 0) {
        fprintf(stderr, "[RSA-CLI] key_hex length must be even and > 0\n");
        return -1;
    }

    size_t key_bytes = hex_len / 2;
    uint8_t *buf = (uint8_t *)malloc(key_bytes);
    if (!buf) {
        fprintf(stderr, "[RSA-CLI] OOM while allocating key buffer\n");
        return -1;
    }

    long dec_len = hex_decode_line((const uint8_t *)key_hex,
                                   hex_len,
                                   buf);
    if (dec_len <= 0) {
        fprintf(stderr, "[RSA-CLI] key_hex must be valid hexadecimal string\n");
        free(buf);
        return -1;
    }

    *out_key = buf;
    *out_key_len = (size_t)dec_len;
    return 0;
}

int rsa_cli_run(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "[RSA-CLI] invalid number of arguments\n");
        print_usage(stderr);
        return 1;
    }

    const char *mode_str = argv[1];  // "enc" / "dec"
    const char *ptmode_str = argv[2]; // "line" / "whole"
    const char *in_path   = argv[3];
    const char *out_path  = argv[4];
    const char *key_hex   = argv[5];
    const char *fmt_str   = argv[6]; // "hex" / "raw"

    int is_encrypt = 0;
    int use_line_mode = 0;
    int use_hex = 0;

    // enc/dec 판단
    if (strcmp(mode_str, "enc") == 0) {
        is_encrypt = 1;
    } else if (strcmp(mode_str, "dec") == 0) {
        is_encrypt = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid mode: %s (use enc|dec)\n", mode_str);
        print_usage(stderr);
        return 1;
    }

    // line/whole 판단
    if (strcmp(ptmode_str, "line") == 0) {
        use_line_mode = 1;
    } else if (strcmp(ptmode_str, "whole") == 0) {
        use_line_mode = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid ptmode: %s (use line|whole)\n", ptmode_str);
        print_usage(stderr);
        return 1;
    }

    // hex/raw 판단
    if (strcmp(fmt_str, "hex") == 0) {
        use_hex = 1;
    } else if (strcmp(fmt_str, "raw") == 0) {
        use_hex = 0;
    } else {
        fprintf(stderr, "[RSA-CLI] invalid format: %s (use hex|raw)\n", fmt_str);
        print_usage(stderr);
        return 1;
    }

    // KEYHEX → key bytes 파싱 (형식적 검증은 CLI에서 담당)
    uint8_t *key_bytes = NULL;
    size_t   key_len   = 0;
    if (parse_key_hex(key_hex, &key_bytes, &key_len) != 0) {
        // parse_key_hex 가 이미 에러 메시지 출력
        print_usage(stderr);
        return 1;
    }

    // RunnerConfig 설정 (Runner는 CryptoOps만 알고, 내부 RSA는 모름)
    RunnerConfig cfg;
    cfg.ops         = &RSA_OPS;     // RSA용 CryptoOps 어댑터
    cfg.key         = key_bytes;
    cfg.key_len     = key_len;
    cfg.input_path  = in_path;
    cfg.output_path = out_path;
    cfg.use_hex     = use_hex;
    cfg.is_encrypt  = is_encrypt ? true : false;

    FHStatus st;
    if (use_line_mode) {
        st = runner_exec_line(&cfg);
    } else {
        st = runner_exec_whole(&cfg);
    }

    // key buffer 정리
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

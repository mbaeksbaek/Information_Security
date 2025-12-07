// NIST-style RSA KAT verification (textbook RSA) against rsa_vectors.json
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bigint/bigint.h"
#include "rsa/rsa_core.h"
#include "kat/rsa_kat_vectors.h"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int decode_hex(const char *hex, uint8_t **out, size_t *out_len) {
    size_t len = strlen(hex);
    if ((len & 1u) != 0) return -1;
    size_t bytes = len / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes ? bytes : 1);
    if (!buf) return -1;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = bytes;
    return 0;
}

static void zero_and_free(uint8_t *p, size_t n) {
    if (!p) return;
    memset(p, 0, n);
    free(p);
}

static void kat_run_one(const RSAKATVector *v) {
    uint8_t *n_bytes = NULL, *e_bytes = NULL, *d_bytes = NULL;
    size_t n_len = 0, e_len = 0, d_len = 0;

    assert(decode_hex(v->N_hex, &n_bytes, &n_len) == 0);
    assert(decode_hex(v->e_hex, &e_bytes, &e_len) == 0);
    assert(decode_hex(v->d_hex, &d_bytes, &d_len) == 0);
    assert(n_len == v->k_bytes);
    assert(e_len == v->k_bytes);
    assert(d_len == v->k_bytes);

    BigInt N, E, D;
    bi_from_be_bytes(&N, n_bytes, n_len);
    bi_from_be_bytes(&E, e_bytes, e_len);
    bi_from_be_bytes(&D, d_bytes, d_len);

    RSAContext ctx_enc, ctx_dec;
    rsa_ctx_init(&ctx_enc, &N, &E);
    rsa_ctx_init(&ctx_dec, &N, &D);
    assert(ctx_enc.modulus_bytes == v->k_bytes);
    assert(ctx_dec.modulus_bytes == v->k_bytes);

    for (size_t i = 0; i < v->num_cases; i++) {
        const RSAKATCase *c = &v->cases[i];
        uint8_t *pt = NULL, *ct = NULL;
        size_t pt_len = 0, ct_len = 0;
        assert(decode_hex(c->pt_hex, &pt, &pt_len) == 0);
        assert(decode_hex(c->ct_hex, &ct, &ct_len) == 0);
        assert(ct_len == v->k_bytes);
        assert(pt_len <= v->k_bytes);

        // left-pad plaintext to modulus size
        uint8_t *pt_block = (uint8_t *)calloc(v->k_bytes, 1);
        assert(pt_block != NULL);
        if (pt_len > 0) {
            memcpy(pt_block + (v->k_bytes - pt_len), pt, pt_len);
        }

        uint8_t *got_ct = (uint8_t *)calloc(v->k_bytes, 1);
        uint8_t *got_pt = (uint8_t *)calloc(v->k_bytes, 1);
        assert(got_ct && got_pt);

        int rc_enc = rsa_encrypt_block(&ctx_enc,
                                       pt_block, v->k_bytes,
                                       got_ct, v->k_bytes);
        if (rc_enc != 0 || memcmp(got_ct, ct, v->k_bytes) != 0) {
            fprintf(stderr, "[KAT][%s] encrypt mismatch (rc=%d)\n", c->name, rc_enc);
            assert(0);
        }

        int rc_dec = rsa_decrypt_block(&ctx_dec,
                                       ct, v->k_bytes,
                                       got_pt, v->k_bytes);
        if (rc_dec != 0 || memcmp(got_pt, pt_block, v->k_bytes) != 0) {
            fprintf(stderr, "[KAT][%s] decrypt mismatch (rc=%d)\n", c->name, rc_dec);
            assert(0);
        }

        zero_and_free(pt, pt_len);
        zero_and_free(ct, ct_len);
        zero_and_free(pt_block, v->k_bytes);
        zero_and_free(got_ct, v->k_bytes);
        zero_and_free(got_pt, v->k_bytes);
    }

    zero_and_free(n_bytes, n_len);
    zero_and_free(e_bytes, e_len);
    zero_and_free(d_bytes, d_len);
}

int main(void) {
    for (size_t i = 0; i < RSA_KAT_VECTORS_LEN; i++) {
        const RSAKATVector *v = &RSA_KAT_VECTORS[i];
        printf("[KAT] RSA-%d (%zu bytes) ...\n", v->bits, v->k_bytes);
        kat_run_one(v);
    }
    printf("RSA KAT vectors: OK\n");
    return 0;
}

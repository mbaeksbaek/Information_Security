// AES_백승민_2020253045
#include "runner.h"
//#include "des.h" [11.12] - Module Refactorization Process
#include "codec_hex.h"
#include "file_io.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
Runner
- 파일 단위 암복호 파이프라인 오케스트레이션
- Line / Whole Mode
        * 입력 파일 열기 -> 읽기 (LineReader / read_all) -> CryptoOps (AES/Dummy) 호출 -> 출력 파일 쓰기
- 모든 에러는 FHStatus/FHStage 로 래핑해서 상위계층(app.c)에 전달


- CryptoOps 추상화로 알고리즘(AES/Dummy)교체 가능하도록 설계
- runner_validate_cfg 에서 Config을 선제적 검증, 이후 함수들에서는 정상 cfg를 전제로 동작
*/

/* check validation of Config */
static FHStatus runner_validate_cfg(const RunnerConfig* c) {
    /*
    Exception List
    - RunnerConfig Null
    - CryptoOps vtable Null
    - cryptoOps 구현ㅊ가 인터페이스 모두 안채움
    - 키 버퍼가 없거나 null
    - file path 인자가 비어잇는 경우
    */
    if (!c) return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "null cfg");
    if (!c->ops) return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "null ops");

    if (!c->ops->ks_init || !c->ops->ks_clear ||
        !c->ops->encrypt_ecb_zeropad || !c->ops->decrypt_ecb_strip ||
        (c->ops->ks_size == 0))
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "bad ops");

    if (!c->key || c->key_len == 0)
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "bad key");

    if (!c->input_path || !c->output_path)
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "bad path");

    return fh_status_ok();
}

/* CryptoOps : in-out */
/*
run-bytes-with-ops
- 이미 메모리로 읽어온 in/in_len 을 CryptoOps 에 넘겨서 암복호화 결과를 out/out_len 으로 받아오는 헬퍼

1) ks_size 만큼 key schedule malloc
2) ks_init -> round key 준비
3) encrypt/decrypt 함수 호출
4) ks_clear로 key zeroization 후 ks free
5) CryptoOps가 0이 아닌 값을 리턴하면 FH_ERR_CRYPTO로 매핑

Exception
- malloc err: FH_ERR_OOM/FH_STAGE_CRYPTO
- ks_init fail(rc!=0): FH_ERR_INVALID_ARG/FH_STAGE_CRYPTO
- enc/dec fail(rc!=0): FH_ERR_CRYPTO/FH_STAGE_CRYPTO
*/
static FHStatus run_bytes_with_ops(const RunnerConfig* cfg, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len) {
    void* ks = malloc(cfg->ops->ks_size);
    // mem error
    if (!ks) return fh_status_make(FH_ERR_OOM, FH_STAGE_CRYPTO, "malloc ks");

    int rc = cfg->ops->ks_init(ks, cfg->key, cfg->key_len);
    if (rc!=0) {
        free(ks);
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_CRYPTO, "ks_init");
    }

    if (cfg->is_encrypt)
        rc = cfg->ops->encrypt_ecb_zeropad(ks, in, in_len, out, out_len);
    else
        rc = cfg->ops->decrypt_ecb_strip(ks, in, in_len, out, out_len);
    
    cfg->ops->ks_clear(ks);
    free(ks);

    if (rc != 0) return fh_status_make(FH_ERR_CRYPTO, FH_STAGE_CRYPTO, "crypto fail");
    return fh_status_ok();
}

// file mode "FILE TO MEMORY"
/*
read all
파일 전체를 한번에 메모리로 불러옴.. Whole 모드에서 사용.. 터질가능성 존재
- fseek*(SEEK_END) / ftell 로 파일 길이 구한 뒤, 처음으로 돌아가서 
    n 만큼 malloc 후 fread
- n==0 인 경우 mlloc(1)처리로 포인터는 항상 유효

예외처리:
- fseek/ftell 실패: FH_ERR_READ/FH_STAGE_READ
- malloc 실패: FH_ERR_OOM/FH_STAGE_READ
- fread n bytes read fail: FH_ERR_READ/FH_STAGE_READ
*/
static FHStatus read_all(FILE* f, uint8_t** buf, size_t* len) {
    long pos;
    if (fseek(f, 0, SEEK_END) != 0) return fh_status_make(FH_ERR_READ, FH_STAGE_READ, "fseek end");
    pos = ftell(f);
    if (pos < 0) return fh_status_make(FH_ERR_READ, FH_STAGE_READ, "ftell");
    if (fseek(f, 0, SEEK_SET) != 0) return fh_status_make(FH_ERR_READ, FH_STAGE_READ, "fseek set");
    size_t n = (size_t)pos;
    uint8_t* b = (uint8_t*)malloc(n?n:1);
    if(!b) return fh_status_make(FH_ERR_OOM, FH_STAGE_READ, "malloc");
    size_t got = fread(b,1,n,f);
    if (got!=n) {
        free(b); return fh_status_make(FH_ERR_READ, FH_STAGE_READ, "fread");
    }
    *buf=b;
    *len=n;
    return fh_status_ok();
}

// HEX TEXT ('\n',' ' include) to only HEX
/*
hex txt 에서 문자만 뽑아서 hex 문자열로 압축, 공백 개행 기타 문자는 무시

Whole Decrypt+hex 모드에서 파일 전체를 hex문자열로 보고 실제 hex decode line을 적용하기 전에 불필요한 문자를 제거할때 사용

[NOTE]
- 유효한 HEX 문자가 하나도 없으면 *on == 0 으로 리턴, 호출부에서 HEX Format Error 로 판단할지 여부ㅠ 결정해야함
*/
static void squeeze_hex(const uint8_t* in, size_t n, uint8_t** out, size_t* on) {
    uint8_t* b = (uint8_t*)malloc(n?n:1);
    size_t w=0;
    for (size_t i=0; i<n; i++) {
        int c = in[i];
        // hex
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            b[w++] = (uint8_t)c;
    }
    *out = b;
    *on = w;
}

/*
Line Mode: 입력파일 한줄(LIne Reader)로 읽어서 각 줄마다 암복호 수행

enc+hex: 입력줄을 그대로 받아서 encrypt - HEX Encoding - 개행 추가
dec+hex: 입력줄을 검증(짝수,유효문자)후 Decoding - decrypt - 바이너리+개행

enc/dec + bin: 입력줄을 그대로 바이너리로 보고 enc/dec 하고 개행

각 줄마다 malloc free 를 수행하지만, 한줄이 끝날대마다 모두 해제해서 누수 없음
crypto_len == 0인 경우는 빈줄 케이스로 취급해서 개행만 출력

Exceptions
- cfg 검증 실패: 그대로 반환
- 파일 열기 실패: FH_ERR_OPEN
- lr_init/lr_next 실패: FH_ERR_READ/FH_STAGE_LINE
- HEX 길이 홀수, invalid HEX: FH_ERR_INVALID_ARG/FH_STAGE_LINE
- malloc 실패: FH_ERR_OOM/FH_STAGE_LINE
- CryptoOps ERR: FH_ERR_CRYPTO/FH_STAGE_CRYPTO
*/
FHStatus runner_exec_line(const RunnerConfig* cfg) {
    FHStatus vst = runner_validate_cfg(cfg);
    if(vst.code != FH_OK) return vst;
    FILE* in = NULL, *out = NULL;

    FHStatus st = fh_open(&in, cfg->input_path, "rb");
    if (st.code != FH_OK) return st;

    st = fh_open(&out, cfg->output_path, "wb");
    if (st.code != FH_OK) //return st;
    {
        fh_close(&in); return st;
    }

    LineReader lr;
    st = lr_init(&lr, in, 0);
    if (st.code != FH_OK) {
        fh_close(&in);fh_close(&out);
        return st;
    }

    while (1) {
        const uint8_t* line = NULL; size_t len = 0;
        st = lr_next(&lr, &line, &len);
        if (st.code != FH_OK) {
            lr_destroy(&lr); fh_close(&in); fh_close(&out);
            return st;
        }

        if (!line && len == 0) break;   // eof

        uint8_t* input_bytes = NULL; size_t input_len = 0;
        uint8_t* crypto_out = NULL; size_t crypto_len = 0;

        // enc block
        if (cfg->is_encrypt) {
            input_bytes = (uint8_t*)malloc(len ? len : 1);
            if (!input_bytes) {
                lr_destroy(&lr); fh_close(&in); fh_close(&out);
                return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "malloc");
            }
            if (len) memcpy(input_bytes, line, len);
            input_len = len;

            st = run_bytes_with_ops(cfg, input_bytes, input_len, &crypto_out, &crypto_len);
            if (st.code != FH_OK) {
                free(input_bytes); lr_destroy(&lr); fh_close(&in); fh_close(&out);
                return st;
            }

            if (cfg->use_hex) {
                size_t hex_len = crypto_len * 2;
                if (hex_len == 0) {
                    // [11.15] 추가 empty line 암호 결과가 0바이트인 경우 개행만 출력
                    st = fh_write_all(out, "\n", 1);
                    fh_secure_zero(crypto_out, crypto_len);
                    free(crypto_out); free(input_bytes);
                    if(st.code != FH_OK) {
                        lr_destroy(&lr); fh_close(&in); fh_close(&out); return st;
                    }
                    continue;
                }
                else {
                    uint8_t* hex = (uint8_t*)malloc(hex_len?hex_len:1);
                    if (!hex) {
                        fh_secure_zero(crypto_out, crypto_len);
                        free(crypto_out); free(input_bytes);
                        lr_destroy(&lr); fh_close(&in); fh_close(&out);
                        return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "malloc hex");
                    }
                    hex_encode(crypto_out, crypto_len, hex);
                    st = fh_write_all(out, hex, hex_len);
                    if (st.code == FH_OK) st = fh_write_all(out, "\n", 1);
                    fh_secure_zero(crypto_out, crypto_len);
                    free(hex); free(crypto_out); free(input_bytes);
                    if (st.code != FH_OK) {
                        lr_destroy(&lr); fh_close(&in); fh_close(&out);
                        return st;
                    }
                }
            }
            else {
                if (crypto_len == 0) {
                    // empty line
                    st = fh_write_all(out, "\n", 1);
                    fh_secure_zero(crypto_out, crypto_len);
                    free(crypto_out); free(input_bytes);
                    if (st.code != FH_OK) {
                        lr_destroy(&lr); fh_close(&in); fh_close(&out); return st;
                    }
                    continue;
                }
                else {
                    st = fh_write_all(out, crypto_out, crypto_len);
                    if (st.code == FH_OK) st = fh_write_all(out, "\n", 1);
                    fh_secure_zero(crypto_out, crypto_len);
                    free(crypto_out); free(input_bytes);
                    if (st.code != FH_OK) {
                        lr_destroy(&lr); fh_close(&in); fh_close(&out); return st;
                    }
                }
            }
        }

        else {
            // decrypt path: line -> optional HEX decode -> decrypt -> raw + '\n'
            if (cfg->use_hex) {
                if(len % 2 != 0) {
                    // 길이가 홀수면 형식 오류
                    lr_destroy(&lr); fh_close(&in); fh_close(&out); 
                    return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_LINE, "odd hex");
                }
                input_bytes = (uint8_t*)malloc(len/2 + 1);
                if(!input_bytes) {
                    lr_destroy(&lr); fh_close(&in); fh_close(&out);
                    return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "malloc input bytes");
                }
                long bl = hex_decode_line(line, len, input_bytes);
                if (bl < 0) {
                    // 잘못된 hex 문자 포함
                    free(input_bytes); lr_destroy(&lr); fh_close(&in); fh_close(&out);
                    return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_LINE, "hex decode");
                }
                input_len = (size_t)bl;
            }
            else {
                input_bytes = (uint8_t*)malloc(len?len:1);
                if (!input_bytes) {
                    lr_destroy(&lr); fh_close(&in); fh_close(&out);
                    return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "malloc");
                }
                if (len) memcpy(input_bytes, line, len);
                input_len = len;
            }

            st = run_bytes_with_ops(cfg, input_bytes, input_len, &crypto_out, &crypto_len);
            free(input_bytes);
            if (st.code != FH_OK) {
                lr_destroy(&lr); fh_close(&in); fh_close(&out); return st;
            }

            // 누락
            //st = fh_write_all(out, crypto_out, crypto_len);
            // 이전 버전에서 crypto_len == 0인 경우, fh_write_all 실패 > 조건부 호출로 수정(예외 방어만,,)
            st = (crypto_len > 0) ? fh_write_all(out, crypto_out, crypto_len) : fh_status_ok();
            if (st.code == FH_OK) st = fh_write_all(out, "\n", 1);
            fh_secure_zero(crypto_out, crypto_len);
            free(crypto_out);
            if (st.code != FH_OK) {
                lr_destroy(&lr); fh_close(&in); fh_close(&out); return st;
            }
        }
    }
    lr_destroy(&lr);
    fh_close(&in); fh_close(&out);
    return fh_status_ok();
}

/*
whole mode: 파일 전체를 한번에 메모리로 읽어서 암복호 수행

1) runner validation
2) 입출력 파일 open
3) read_all 으로 파일 전체 file buff에 로드
4) use_hex/is_encrypt 조합에 따라 in_bytes/in_len 준비
    - enc+hex: 평문 그대로 - CryptoOps - 최종 Hex_encode
    - dec+hex: squeeze_hex 로 텍스트에서 HEX 추출: hex_decode_line - CryptoOps
    - bin 모드: file buff 그대로 CryptoOps
5) run_bytes_with_ops
6) 결과를 HEX/Bin 으로 출력

Exception
- 파일 열기 실패 : FH_ERR_OPEN/FH_ERR_READ
- HEX문자 하나도 없음(sq==0&&filelen>0) : FH_ERR_INVALID_ARG
- HEX길이 홀수: fh_err_invalid_arg, "oddhex"
- hex_decode_line 실패: fh_err_invalid_arg, "hexdecode"
- malloc 실패: fh_err_oom
- cryptoops 실패: fh_err_crypto
*/
FHStatus runner_exec_whole(const RunnerConfig* cfg) {
    FHStatus vst = runner_validate_cfg(cfg);
    if (vst.code != FH_OK) return vst;

    FILE *in = NULL, *out = NULL;
    FHStatus st = fh_open(&in, cfg->input_path, "rb");
    if (st.code != FH_OK) return st;
    st = fh_open(&out, cfg->output_path, "wb");
    if (st.code != FH_OK) { fh_close(&in); return st; }

    uint8_t *filebuf = NULL; size_t filelen = 0;
    st = read_all(in, &filebuf, &filelen);
    if (st.code != FH_OK) { fh_close(&in); fh_close(&out); return st; }

    uint8_t *in_bytes = NULL; size_t in_len = 0;
    if (cfg->use_hex) {
        /* HEX 입력을 순수 HEX로 압축 후 디코드(복호 시), 암호 시엔 그냥 바이너리 → HEX 출력 */
        if (cfg->is_encrypt) {
            /* encrypt: 평문 바이너리 그대로 사용 */
            in_bytes = filebuf; in_len = filelen; filebuf = NULL; /* 소유권 이전 */
        } 
        else {
            /* decrypt: HEX 텍스트를 정리 후 디코드 */
            uint8_t* squeezed = NULL; size_t sq = 0;
            squeeze_hex(filebuf, filelen, &squeezed, &sq);
            free(filebuf); filebuf = NULL;
            
            // [11.16] - Exception Added :no Hex char, len > 0 : HEX format error
            if (sq == 0 && filelen > 0) {
                // 파일에 뭔가는 있지만, 유효한 HEX가 없음
                free(squeezed); fh_close(&in); fh_close(&out); return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_READ, "hex noneß");
            } 

            if ((sq % 2) != 0) { free(squeezed); fh_close(&in); fh_close(&out); return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_READ, "odd hex"); }

            in_bytes = (uint8_t*)malloc(sq/2 + 1);
            if (!in_bytes) { free(squeezed); fh_close(&in); fh_close(&out); return fh_status_make(FH_ERR_OOM, FH_STAGE_READ, "malloc"); }

            long bl = hex_decode_line(squeezed, sq, in_bytes);
            free(squeezed);
            if (bl < 0) { 
                // squeeze_hex 로 추출한 hex 문자열, 실제 디코딩 오류
                free(in_bytes); fh_close(&in); fh_close(&out); return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_READ, "hex decode");
            }
            in_len = (size_t)bl;
        }
    } else {
        /* 바이너리 입력 그대로 */
        in_bytes = filebuf; in_len = filelen; filebuf = NULL;
    }

    uint8_t *crypto_out = NULL; size_t crypto_len = 0;
    st = run_bytes_with_ops(cfg, in_bytes, in_len, &crypto_out, &crypto_len);
    if (in_bytes) { fh_secure_zero(in_bytes, in_len); free(in_bytes); }
    if (st.code != FH_OK) { fh_close(&in); fh_close(&out); return st; }

    if (cfg->use_hex && cfg->is_encrypt) {
        /* 암호문 바이트 → HEX 연속 출력 */
        size_t hex_len = crypto_len * 2;
        if (hex_len == 0) {
            // 결과 0, 아무것도 안씀(빈파일)
            st = fh_status_ok();
        }
        else {
            uint8_t* hex = (uint8_t*)malloc(hex_len ? hex_len : 1);
            if (!hex) {
                fh_secure_zero(crypto_out, crypto_len);
                free(crypto_out); fh_close(&in); fh_close(&out);
                return fh_status_make(FH_ERR_OOM, FH_STAGE_WRITE, "malloc hex");
            }
            hex_encode(crypto_out, crypto_len, hex);
            st = fh_write_all(out, hex, hex_len);
            free(hex);
        }
    } else {
        if (crypto_len == 0) {
            // dec. 결과 0바이트, 그대로 빈파일
            st = fh_status_ok();
        }
        else {
            /* 바이너리 출력(복호 결과 또는 비-HEX 암호 결과) */
            st = fh_write_all(out, crypto_out, crypto_len);
        }
    }

    fh_secure_zero(crypto_out, crypto_len);
    free(crypto_out);
    fh_close(&in);
    fh_close(&out);
    return st;
}
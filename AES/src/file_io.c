// AES_백승민_2020253045
// DES_백승민_2020253045 : 재사용
/* 파일 I/O 구현
   - 상태 헬퍼 -> 실패 지점 식별
   - 파일 래퍼 -> 인자검사/에러코드 일관화
   - secure_zero -> 메모리 덮어쓰기
   - LineReader -> 버퍼 자동 확장 + 개행 처리
*/

#include "file_io.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>


// ok function
/* 정상 상태 반환 -> code=OK, stage=NONE */
FHStatus fh_status_ok(void) {
    FHStatus status;
    status.code = FH_OK;
    status.stage = FH_STAGE_NONE;
    status.msg = "ok";
    return status;
}

// create function
/* 상태 객체 생성 -> 코드/스테이지/메시지 설정 */
FHStatus fh_status_make(FHStatusCode code, FHStage stage, const char* msg) {
    FHStatus status;
    status.code = code;
    status.stage = stage;
    status.msg = msg;
    return status;
}

// to string functions
/* 상태/스테이지 문자열화 -> 로그용 */
const char* fh_status_to_str(FHStatusCode code) {
    switch (code) {
        case FH_OK: return "OK";
        case FH_ERR_OPEN: return "OPEN ERROR";
        case FH_ERR_READ: return "READ ERROR";
        case FH_ERR_WRITE: return "WRITE ERROR";
        case FH_ERR_CLOSE: return "CLOSE ERROR";
        case FH_ERR_INVALID_ARG: return "INVALID ARG ERROR";
        case FH_ERR_OOM: return "OUT OF MEMEORY ERROR";
        case FH_ERR_INTERNAL: return "INTERNAL ERROR";
        case FH_ERR_CRYPTO: return "CRYPTO ERROR";  // [11.12] add
        default: return "UNKNOWN ERROR";
    }
}

const char* fh_stage_to_str(FHStage stage) {
    switch (stage) {
        case FH_STAGE_NONE: return "NONE";
        case FH_STAGE_OPEN: return "OPEN";
        case FH_STAGE_READ: return "READ";
        case FH_STAGE_WRITE: return "WRITE";
        case FH_STAGE_CLOSE: return "CLOSE";
        case FH_STAGE_LINE: return "LINE";
        case FH_STAGE_CRYPTO: return "CRYPTO";  // [11.12] add
        default: return "UNKNOWN STAGE";
    }
}

// file operations
/* 파일 열기
   입력검사 -> fopen -> 실패 시 errno 메시지 포함 */
FHStatus fh_open(FILE **fp, const char *path, const char* mode) {
    if (!fp || !path || !mode) {
        /* 예외: 인자 누락/NULL -> 잘못된 사용 */
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_OPEN, "Invalid argument to fh_open");
    }
    *fp = fopen(path, mode);
    if (!*fp) {
        /* 예외: OS 레벨 오픈 실패 -> errno 기반 메시지 */
        return fh_status_make(FH_ERR_OPEN, FH_STAGE_OPEN, strerror(errno));
    }
    return fh_status_ok();
}

/* 파일 읽기(단발 fread)
   - 0바이트 읽힘 + EOF -> 정상 종료
   - 그 외 0바이트 -> READ ERROR */
FHStatus fh_read(FILE* fp, uint8_t *buffer, size_t buf_size, size_t *nread) {
    if (!fp || !buffer || buf_size == 0 || !nread) {
        /* 예외: 인자 NULL 또는 사이즈 0 -> 잘못된 사용 */
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_READ, "Invalid argument to fh_read");
    }
    size_t read_bytes = fread(buffer, 1, buf_size, fp);
    if (read_bytes == 0) {
        if (feof(fp)) {
            /* EOF: 오류 아님 -> 정상 종료 신호 */
            *nread = 0;
            return fh_status_ok();
        }
        /* 예외: 읽기 실패(EOF 아님) -> 시스템 오류 */
        return fh_status_make(FH_ERR_READ, FH_STAGE_READ, strerror(errno));
    }
    *nread = read_bytes;
    return fh_status_ok();
}

/* 전체 쓰기 보장
   - fwrite 루프 -> 부분 쓰기 대응
   - 0 반환 시 errno로 WRITE ERROR */
FHStatus fh_write_all(FILE* fp, const void *buf, size_t nbytes) {
    if (!fp || !buf || nbytes == 0) {
        /* 예외: 인자 검증 실패 */
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_WRITE, "Invalid argument to fh_write_all");
    }
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = nbytes;   // bytes left to write
    while (left > 0) {
        size_t written = fwrite(p, 1, left, fp);
        if (written == 0)
            /* 예외: 시스템 레벨 쓰기 실패 */
            return fh_status_make(FH_ERR_WRITE, FH_STAGE_WRITE, strerror(errno));
        p += written;   // accumulate pointer
        left -= written;    // decrease left bytes
    }
    return fh_status_ok();
}

/* 안전한 닫기
   - NULL 안전, fclose 실패 시 CLOSE ERROR */
FHStatus fh_close(FILE **fp) {
    if (fp == NULL || *fp == NULL)
        /* 이미 닫힌 것으로 간주 -> OK */
        return fh_status_ok();
    FILE *f = *fp;
    *fp = NULL;
    if (fclose(f) != 0)
        /* 예외: OS 레벨 닫기 실패 */
        return fh_status_make(FH_ERR_CLOSE, FH_STAGE_CLOSE, strerror(errno));
    return fh_status_ok();
}

/* 보안 지우기
   - volatile 포인터로 최적화 회피 -> 실제 0으로 덮음 */
void fh_secure_zero(void *p, size_t n) {
    if (p == NULL || n == 0) return; /* 예외 아님: 무해 -> 그냥 반환 */
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/* LineReader 기본 cap 정책
   - 초기는 256 -> 필요 시 성장 */
static size_t lr_default_capacity(void) {
    return 256; // default initial capacity : Change if needed
}

/* LineReader 초기화
   - fp/버퍼 설정, cap=initial or 256
   - OOM -> FH_ERR_OOM */
FHStatus lr_init(LineReader *lr, FILE* fp, size_t initial_capacity) {
    if (!lr || !fp) 
        /* 예외: 리더 또는 파일 핸들 NULL */
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_LINE, "Invalid argument to lr_init");
    
    lr->fp = fp;
    lr->cap = (initial_capacity == 0) ? lr_default_capacity() : initial_capacity;//lr_default_capacity() : initial_capacity;
    lr->buf = (uint8_t*)malloc(lr->cap);
    
    if (lr->buf == NULL)
        /* 예외: 메모리 부족 */
        return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "Out of memory in lr_init");
    lr->len = 0;
    lr->eof_reached = 0;
    return fh_status_ok();
}

// ReAllocate Buffer if needed : Memory grow function
/* 내부: 버퍼 확장 정책
   - 4096 미만 -> 2배씩
   - 4096 이상 -> +4096 씩
   - 필요 용량을 만족할 때까지 반복 */
static FHStatus lr_grow(LineReader *lr, size_t need_more) {
    // if needed size is already satisfied
    if (lr->len + need_more <= lr->cap) return fh_status_ok(); /* 충분하면 스킵 */

    // double the capacity until satisfied
    size_t new_cap = lr->cap * 2;
    while (lr->len + need_more > new_cap) {
        // before 4096 : double, after 4096 : +4096 memory allocate
        if (new_cap < 4096) new_cap = new_cap * 2;
        else new_cap += 4096;
    }
    // allocate new memory
    uint8_t *tmp = (uint8_t*)realloc(lr->buf, new_cap);
    if (tmp == NULL)
        /* 예외: 확장 실패 -> OOM */
        return fh_status_make(FH_ERR_OOM, FH_STAGE_LINE, "Out of memory in lr_grow : REALLOC");
    lr->buf = tmp;
    lr->cap = new_cap;
    return fh_status_ok();
}

// read next line
/* 다음 줄 읽기
   - \r 무시, \n 기준
   - EOF에서 남은 데이터 있으면 마지막 줄로 반환
   - eof_reached 이후 -> out_line=NULL, out_len=0, OK */
FHStatus lr_next(LineReader *lr, const uint8_t **out_line, size_t *out_len) {
    if (!lr || !out_line || !out_len) 
        /* 예외: 인자 검증 실패 */
        return fh_status_make(FH_ERR_INVALID_ARG, FH_STAGE_LINE, "Invalid argument to lr_next");
    //*out_line = NULL;
    //*out_len = 0;
    // check eof
    //if (lr->eof_reached) return fh_status_ok();
    if (lr->eof_reached) {
        /* EOF 이미 처리된 상태 -> 빈 결과로 OK 반환 */
        *out_line = NULL;
        *out_len = 0;
        return fh_status_ok();
    }
    lr->len = 0;
    while (1) {
        // get one char
        int c = fgetc(lr->fp);
        if (c == EOF) {
            // if eof reached data exist
            if (lr->len > 0) {
                // 개행없음
                // return last line
                /* EOF이지만 버퍼에 데이터 있음 -> 마지막 줄 반환 */
                *out_line = lr->buf;
                *out_len = lr-> len;
                lr->len = 0;
                lr->eof_reached = 1;
                return fh_status_ok();
            }
            // eof reached no data
            /* EOF이고 버퍼도 비었음 -> 빈 결과로 종료 */
            lr->eof_reached = 1;
            *out_line = NULL;
            *out_len = 0;
            return fh_status_ok();
        }
        if (c == '\r') continue; // skip carriage return
        if (c == '\n') {
            /* 줄 종료 -> 현재 버퍼 반환 */
            *out_line = lr->buf;
            *out_len = lr->len;
            lr->len = 0;
            return fh_status_ok();
        }
        // grow buffer if needed
        FHStatus status = lr_grow(lr, 1);

        if (status.code != FH_OK) return status; /* 예외: 확장 실패 전파 */
        lr->buf[lr->len++] = (uint8_t)c;
    }
}

/* 파괴: 버퍼 zero -> free, 포인터/길이/상태 초기화 */
void lr_destroy(LineReader *lr) {
    if (!lr) return; /* 무해 */
    if (lr->buf != NULL) {
        fh_secure_zero(lr->buf, lr->cap);
        free(lr->buf);
    }
    lr->cap = 0;
    lr->len = 0;
    lr->fp = NULL;
    lr->buf = NULL;
    lr->eof_reached = 0;
}

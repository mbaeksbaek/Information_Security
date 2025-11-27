// Reused Module from DES
#ifndef __FILE_IO_H__
#define __FILE_IO_H__
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
/* 파일 I/O 공용 헤더
   - 상태코드/스테이지로 어디서 실패했는지 추적하기 쉽게
   - 기본 파일 열기/읽기/쓰기/닫기 래퍼
   - secure_zero: 민감 데이터 메모리 지우기
   - LineReader: 개행 단위로 안전하게 한 줄씩 읽기 */
/* 에러/상태 코드 -> 로그/리턴에 사용 */
typedef enum {
    FH_OK = 0,
    FH_ERR_OPEN,
    FH_ERR_READ,
    FH_ERR_WRITE,
    FH_ERR_CLOSE,
    FH_ERR_INVALID_ARG,
    FH_ERR_OOM,
    FH_ERR_INTERNAL,
    FH_ERR_CRYPTO,   // [11.12] - Added
    FH_ERR_FORMAT
} FHStatusCode;
/* 처리 단계 -> 어디서 실패했는지 파악용 */
typedef enum {
    FH_STAGE_NONE = 0,
    FH_STAGE_OPEN,
    FH_STAGE_READ,
    FH_STAGE_WRITE,
    FH_STAGE_CLOSE,
    FH_STAGE_LINE,
    FH_STAGE_CRYPTO, // [11.12] - Added
    FH_STAGE_HEX
} FHStage;

// state obj
typedef struct {
    FHStatusCode code;
    FHStage stage;
    const char *msg;
} FHStatus;
/* 상태 헬퍼
   fh_status_ok -> 정상
   fh_status_make -> 코드/스테이지/메시지 조합 */
FHStatus fh_status_ok(void);
FHStatus fh_status_make(FHStatusCode code, FHStage stage, const char* msg);

// to string functions : helper operations
const char* fh_status_to_str(FHStatusCode code);
const char* fh_stage_to_str(FHStage stage);

// file operations
/* 파일 래퍼
   fh_open -> fopen 래핑(인자검사 포함)
   fh_read -> 단발 fread, EOF는 OK
   fh_write_all -> 부분쓰기 루프 처리
   fh_close -> NULL 안전 */
FHStatus fh_open(FILE **fp, const char *path, const char* mode);
FHStatus fh_read(FILE* fp, uint8_t *buffer, size_t buf_size, size_t *nread);
FHStatus fh_write_all(FILE* fp, const void *buf, size_t nbytes);
FHStatus fh_close(FILE **fp);

// security functions : erase
/* 민감 데이터 지우기 -> volatile로 최적화 회피 */
void fh_secure_zero(void *p, size_t n);

// Line Readers
/* 파일에서 한 줄씩 읽기
   - \r 무시, \n 기준
   - 마지막 줄이 개행 없이 끝나도 반환 */
typedef struct LineReader {
    FILE *fp;
    uint8_t *buf;
    size_t cap;
    size_t len;
    int eof_reached;
} LineReader;

FHStatus lr_init(LineReader *lr, FILE* fp, size_t initial_capacity);
FHStatus lr_next(LineReader *lr, const uint8_t **out_line, size_t *out_len);
void lr_destroy(LineReader *lr);

#endif
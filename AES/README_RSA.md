RSA Test & CLI Quickstart
=========================

빌드 & 실행
-----------
- RSA 통합 테스트:
  ```
  gcc -Wall -Wextra -O2 -Iinclude -Itests \
    src/bigint/bigint.c \
    src/codec_hex.c src/file_io.c src/runner.c src/crypto_ops.c \
    src/rsa/rsa_core.c src/rsa/rsa_ops.c src/rsa/rsa_app.c \
    tests/kat/rsa_kat_vectors.c tests/test_all_rsa.c \
    -o build/test_all_rsa
  ./build/test_all_rsa
  ```
- RSA CLI 단일 실행:
  ```
  # 예시 키(3233,e=17,d=2753)로 line/raw 암호화
  ./build/app_rsa enc line input.txt output.bin 0CA10011 raw

  # 복호화
  ./build/app_rsa dec line output.bin recovered.txt 0CA10AC1 raw
  ```

CLI 사용법
----------
```
rsa_app enc line  <in> <out> <KEYHEX> [hex|raw]
rsa_app enc whole <in> <out> <KEYHEX> [hex|raw]
rsa_app dec line  <in> <out> <KEYHEX> [hex|raw]
rsa_app dec whole <in> <out> <KEYHEX> [hex|raw]

KEYHEX = big-endian hex of N||EXP (enc: EXP=e, dec: EXP=d)
[hex|raw] = plaintext/ciphertext file format
```

KEYHEX 예시
-----------
- 소형 테스트 키 (n=3233, e=17, d=2753):
  - 암호화 키: `0CA10011` (N||e)
  - 복호화 키: `0CA10AC1` (N||d)

RSA 벡터/KAT
-----------
- rsa_vectors.json(사전에 생성된 텍스트북 RSA KAT, 512/1024/2048비트)을 `tests/kat/rsa_kat_vectors.c`에 내장해 사용.
- `tests/kat/test_rsa_kat.c`로 각 벡터(6케이스 × 3키사이즈)를 검증.

파일 경로 정책
--------------
- 테스트에서 생성되는 임시 파일은 `res/test/runner/` 하위에 생성됨(클린업 용이).

테스트 실행 & 커버리지 개요
--------------------------
- 통합 실행: `./build/test_all_rsa`
  - file_io + codec_hex 유닛: 35/35 케이스 (LineReader 엣지 포함)
  - bigint 기본: 3 케이스 (BE 변환, div/mod, modexp)
  - bigint capacity: 2 케이스 (큰 수 roundtrip, modexp 범위)
  - rsa_core 확장: 6 케이스 (샘플 키 왕복, m>=n 실패, 길이 불일치 등)
  - rsa_ops 확장: 5 케이스 (roundtrip, 빈 입력, 잘못된 CT 길이, ks_init 에러, zero-padding strip)
  - RSA KAT: 18 케이스 (512/1024/2048비트 각 6개)
  - runner + dummy_ops 스모크: 4 케이스 (line/bin, line/hex, whole/hex dec, odd hex 오류)
  - RSA CLI 시스템: 8 케이스 (line/raw 왕복, whole/raw 왕복, 빈 파일, bad argc/mode/format/key_hex_length/ct_length)
- 총합: 약 81개 케이스 실행.
- 강도: 정상/에지/네거티브 케이스를 모두 포함하며, CLI 음수 케이스는 사용법/에러 메시지 출력이 정상 동작하는지 확인함.

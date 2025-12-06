#ifndef RSA_APP_H
#define RSA_APP_H

/*
 * RSA CLI Entry
 * Usage (AES와 동일한 패턴):
 *
 *   ./build/app_rsa enc line  <in_path> <out_path> <key_hex> hex
 *   ./build/app_rsa enc whole <in_path> <out_path> <key_hex> hex
 *   ./build/app_rsa dec line  <in_path> <out_path> <key_hex> hex
 *   ./build/app_rsa dec whole <in_path> <out_path> <key_hex> hex
 *
 * - enc/dec   : 암호화/복호화
 * - line/whole: 라인 단위 / 전체 파일 모드
 * - key_hex   : [N|EXP] (big-endian) 을 HEX 문자열로 표현한 값
 *               * enc: EXP = e
 *               * dec: EXP = d
 * - hex       : 결과를 HEX로 출력 (enc) / 입력을 HEX로 해석 (dec)
 *               "raw" 를 쓰면 바이너리 그대로 입/출력
 */

int rsa_cli_run(int argc, char **argv);

#endif /* RSA_APP_H */

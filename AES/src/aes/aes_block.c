// AES_백승민_2020253045
#include "aes/aes_block.h"
#include "aes/aes_tables.h"
#include <stdint.h>
#include <stddef.h>

/*
[11.15]
Goals : AES Operation Helpers + Block : Unit Test 
AES Block Layer :
- 16 byte Single Block Operation
- subBytes, shiftRows, mixColumns, addRoundKey

no user call func here : KeySchedule + aes -> api.
*/
/*
- This Layer is for "single 16 byte block" AES Round Operation
- Key Schedule 에서 rk[] & Nr을 받아와서 enc/dec 수행, 상위모듈(aes_modes, aes_ops)에서 호출
*/

// state operations
// in[16] => state[4][4] : AES Data Structure
// state[row][col] = in[4*col+row]
static void load_state(uint8_t state[4][4], const uint8_t in[16]) {
    for (int col = 0; col < 4; ++col)
        for (int row = 0; row < 4; ++row)
            state[row][col] = in[4 * col + row];
    return;
}

// state[4][4] -> out[16]; 위 load_state 역변환
static void store_state(const uint8_t state[4][4], uint8_t out[16]) {
    for (int col = 0; col < 4; ++col) 
        for (int row = 0; row < 4; ++row)
            out[4 * col + row] = state[row][col];
}

// operation helpers
// sub bytes : s box all bytes in state
static void sub_bytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; ++row)
        for (int col = 0; col < 4; ++col)
            state[row][col] = AES_SBOX[state[row][col]];
}

// 단일 row에 대한 연산으로 left circular shift
// row : abcd -> bcda (shift-1)
// shift : 0~3, 0x3 mask for protection
static void shift_row_left(uint8_t row[4], unsigned int shift) {
    uint8_t tmp[4];
    /*
    0123
    1230 
    -> 가독성때문에 그냥 작성
    */
   shift &= 0x3;
    for (int i = 0; i < 4; ++i) 
        tmp[i] = row[(i+(int)shift) & 0x3];

    for (int i = 0; i < 4; ++i)
        row[i] = tmp[i];
    return;
}

// shift rows :
// row0 shift0, (1,1) (2,2) (3,3)
static void shift_rows(uint8_t state[4][4]) {
    // Actual Block Shift Operation
    // row 0 : no change
    // row 1: left shift 1
    shift_row_left(state[1], 1);
    // row 2: left shift 2
    shift_row_left(state[2], 2);
    // row 3: left shift 3
    shift_row_left(state[3], 3);
    return;
}

/*
mix columns: column 상에서 fixed Matrix (table) Mult
*/
static void mix_columns(uint8_t state[4][4]) {
    for (int col = 0; col < 4; ++col) {
        uint8_t s[4];
        s[0] = state[0][col];
        s[1] = state[1][col];
        s[2] = state[2][col];
        s[3] = state[3][col];

        uint8_t r[4];
        r[0] = (uint8_t)(AES_MUL2[s[0]] ^ AES_MUL3[s[1]] ^ s[2] ^ s[3]);
        r[1] = (uint8_t)(s[0]^ AES_MUL2[s[1]] ^ AES_MUL3[s[2]] ^ s[3]);
        r[2] = (uint8_t)(s[0] ^ s[1] ^ AES_MUL2[s[2]] ^ AES_MUL3[s[3]]);
        r[3] = (uint8_t)(AES_MUL3[s[0]] ^ s[1] ^ s[2] ^ AES_MUL2[s[3]]);

        state[0][col] = r[0];
        state[1][col] = r[1];
        state[2][col] = r[2];
        state[3][col] = r[3];
    }
}

// add roundkey: round key(4word) 를 column 기준으로 XOR
// round words[col] word를 상위 바이트로부터 state[0~3][col] mapping
static void add_round_key(uint8_t state[4][4], const uint32_t round_words[4]) {
    for (int col = 0; col < 4; ++col) {
        uint32_t word = round_words[col];
        
        uint8_t b[4];
        b[0] = (uint8_t)(word >> 24);
        b[1] = (uint8_t)(word >> 16);
        b[2] = (uint8_t)(word >> 8);
        b[3] = (uint8_t)(word >> 0);

        state[0][col] = (uint8_t)(state[0][col] ^ b[0]);
        state[1][col] = (uint8_t)(state[1][col] ^ b[1]);
        state[2][col] = (uint8_t)(state[2][col] ^ b[2]);
        state[3][col] = (uint8_t)(state[3][col] ^ b[3]);
    }
}

// inverse op helper
// invsubbytes: aes inverse s-box
static void inv_sub_bytes(uint8_t state[4][4]) {
    for (int row=0; row<4; ++row)
        for (int col=0; col<4; ++col)
            state[row][col] = AES_INV_SBOX[state[row][col]];
    return;
}

// shift rows inverse
// right shift
static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;
    // row 1
    tmp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    // row 2 : rotate 2
    uint8_t t[2];
    t[0] = state[2][0]; t[1] = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t[0];
    state[2][3] = t[1];

    // row 3 : rot 3 > left 1
    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;

    return;
}

// inv mix columns : mix columns 의 역행렬 (tables)
static void inv_mix_columns(uint8_t state[4][4]) {
    for (int col = 0; col<4; ++col) {
        uint8_t s[4];
        s[0] = state[0][col];
        s[1] = state[1][col];
        s[2] = state[2][col];
        s[3] = state[3][col];

        uint8_t r[4];
        r[0] = AES_MUL14[s[0]] ^ AES_MUL11[s[1]] ^ AES_MUL13[s[2]] ^ AES_MUL9[s[3]];
        r[1] = AES_MUL9[s[0]]  ^ AES_MUL14[s[1]] ^ AES_MUL11[s[2]] ^ AES_MUL13[s[3]];
        r[2] = AES_MUL13[s[0]] ^ AES_MUL9[s[1]]  ^ AES_MUL14[s[2]] ^ AES_MUL11[s[3]];
        r[3] = AES_MUL11[s[0]] ^ AES_MUL13[s[1]] ^ AES_MUL9[s[2]]  ^ AES_MUL14[s[3]];

        state[0][col] = r[0];
        state[1][col] = r[1];
        state[2][col] = r[2];
        state[3][col] = r[3];
    }
    return;
}

// 단일 16바이트 블록 암호화
// 예외:
// - ks = NULL, in = NULL, out = NULL -> AES_ERR_INVALID_ARG
// - ks->Nr 이 10/12/14 가 아니면 AES_ERR_INVALID_ARG
AES_Status aes_encrypt_block(const AES_KeySchedule* ks, const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES]) {
    uint8_t state[4][4];
    int Nr;
    if (!ks || !in || !out) {
        return AES_ERR_INVALID_ARG; // exception: null ptr
    }
    Nr = ks-> Nr;
    if (Nr != 10 && Nr != 12 && Nr != 14) {
        return AES_ERR_INVALID_ARG; // wrong key schedule init
        //return AES_ERR_INTERNAL;
    }
    // input block -> state
    load_state(state, in);
    // round 0
    add_round_key(state, &ks->rk[0]);
    // 1 ~ NR-1 round : Sub Byte - ShiftRow - MixColum - AddRoundKey
    for (int round = 1; round < Nr; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ks->rk[4 * round]);
    }

    // last round : No Mix Col
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ks->rk[4 * Nr]);
    // state -> output
    store_state(state, out);

    return AES_OK;
}

// 단일 16바이트 블록 복호화
// 예외처리는 encrypt block 과 동일
AES_Status aes_decrypt_block(const AES_KeySchedule* ks, const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES]) {
    if (!ks || !in || !out)
        return AES_ERR_INVALID_ARG; // null ptr
    int Nr = ks->Nr;
    if (Nr != 10 && Nr != 12 && Nr != 14)
        return AES_ERR_INVALID_ARG; // worng round numb
    uint8_t state[4][4];
    // input block to state
    // load_state(state, in);
    // decrypt에서 load_state 대신 로딩
    for (int col = 0; col < 4; ++col)
        for (int row = 0; row < 4; ++row)
            state[row][col] = in[4 * col + row];
    
    const uint32_t* rk = ks->rk;
    // init add round key : last round key
    add_round_key(state, rk + 4 * Nr);

    // reverse Rounds
    // NR-1~1: InvShiftRows-InvSubBytes-AddRoundKey-InvMixColumns
    for (int round = Nr - 1; round >=1; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk + 4 * round);
        inv_mix_columns(state);
    }

    // final
    // invMixColumns 없음
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, rk);

    // store_state(state, out);
    // state > output block
    for (int col = 0; col < 4; ++col)
        for (int row = 0; row < 4; ++row)
            out[4*col+row] = state[row][col];
    return AES_OK;
}

/*
[WARNING] Below functions are for TEST ONLY : unit Test Purpose
*/

// row-major -=> state[4][4]
// in[4r + c] => state[r][c]
static void rowmajor_to_state(uint8_t state[4][4], const uint8_t in[AES_BLOCK_BYTES])
{
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = in[4 * r + c];
        }
    }
}

// state[4][4] -> row major matrx
static void state_to_rowmajor(const uint8_t state[4][4], uint8_t out[AES_BLOCK_BYTES])
{
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            out[4 * r + c] = state[r][c];
        }
    }
}

// Below Helpers:
/*
    - in/out null : AES_ERR_INVALID_ARG
    - state 변환 -> 연산 수행 -> 다시 row-major matrix
    - 테스트용
*/

// subbyte 테스트용
AES_Status aes_block_test_subbytes(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG; // null ptr
    }

    rowmajor_to_state(state, in);
    sub_bytes(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// shift rows 테스트용
AES_Status aes_block_test_shiftrows(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG; // null ptr
    }

    rowmajor_to_state(state, in);
    shift_rows(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// mix columns 테스트용
AES_Status aes_block_test_mixcolumns(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG; // null ptr
    }

    rowmajor_to_state(state, in);
    mix_columns(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// addroundkey 테스트용
AES_Status aes_block_test_addroundkey(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES], const uint32_t round_words[4])
{
    uint8_t state[4][4];

    if (!in || !out || !round_words) {
        return AES_ERR_INVALID_ARG;
    }

    rowmajor_to_state(state, in);
    add_round_key(state, round_words);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// invsubbytes 테스트용
AES_Status aes_block_test_inv_subbytes(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG;
    }

    rowmajor_to_state(state, in);
    inv_sub_bytes(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// invshiftrows 테스트용
AES_Status aes_block_test_inv_shiftrows(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG;
    }

    rowmajor_to_state(state, in);
    inv_shift_rows(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}

// inv mix columns 테스트용
AES_Status aes_block_test_inv_mixcolumns(const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES])
{
    uint8_t state[4][4];

    if (!in || !out) {
        return AES_ERR_INVALID_ARG;
    }

    rowmajor_to_state(state, in);
    inv_mix_columns(state);
    state_to_rowmajor(state, out);

    return AES_OK;
}
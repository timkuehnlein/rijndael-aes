/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdlib.h>
// TODO: Any other files you need to include should go here
#include <string.h>  // memcpy

#include "rijndael.h"

// lookup table for the s-box
const unsigned char s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
};

// lookup table for the r-con
const unsigned char r_con[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
    0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
};

/*
 * Rotates a word of n bytes
 */
void rotate_left(unsigned char *word, int n) {
  unsigned char temp = word[0];
  for (int i = 0; i < n - 1; i++) {
    word[i] = word[i + 1];
  }
  word[n - 1] = temp;
}

/*
 * Substitutes a single byte using the s-box
 */
void sub_byte(unsigned char *byte_to_substitute) {
  *byte_to_substitute = s_box[*byte_to_substitute];
}

/*
 * Substitutes each byte in a word using the s-box
 */
void sub_word(unsigned char *word) {
  for (int i = 0; i < WORD_SIZE; i++) {
    sub_byte(&word[i]);
  }
}

/*
 * XORs two words, replaces a
 */
void xor_words(unsigned char *a, unsigned char *b) {
  for (int i = 0; i < WORD_SIZE; i++) {
    a[i] = a[i] ^ b[i];
  }
}

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    sub_byte(&block[i]);
  }
}

void shift_rows(unsigned char *block) {
  unsigned char(*matrix)[4][4] = MATRIX(block);

  // row 1
  unsigned char temp = (*matrix)[0][1];
  // equivalent to: 
  // unsigned char temp = BLOCK_ACCESS(block, 0, 1);
  (*matrix)[0][1] = (*matrix)[1][1];
  (*matrix)[1][1] = (*matrix)[2][1];
  (*matrix)[2][1] = (*matrix)[3][1];
  (*matrix)[3][1] = temp;

  // row 2
  temp = (*matrix)[0][2];
  unsigned char temp2 = (*matrix)[1][2];
  (*matrix)[0][2] = (*matrix)[2][2];
  (*matrix)[1][2] = (*matrix)[3][2];
  (*matrix)[2][2] = temp;
  (*matrix)[3][2] = temp2;

  // row 3
  temp = (*matrix)[0][3];
  temp2 = (*matrix)[1][3];
  unsigned char temp3 = (*matrix)[2][3];
  (*matrix)[0][3] = (*matrix)[3][3];
  (*matrix)[1][3] = temp;
  (*matrix)[2][3] = temp2;
  (*matrix)[3][3] = temp3;
}

void mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block) {
  unsigned char(*m)[4][4] = MATRIX(block);

  // row 1
  unsigned char temp = (*m)[3][1];
  // equivalent to: 
  // unsigned char temp = BLOCK_ACCESS(block, 0, 3);
  (*m)[3][1] = (*m)[2][1];
  (*m)[2][1] = (*m)[1][1];
  (*m)[1][1] = (*m)[0][1];
  (*m)[0][1] = temp;

  // row 2
  temp = (*m)[3][2];
  unsigned char temp2 = (*m)[2][2];
  (*m)[3][2] = (*m)[1][2];
  (*m)[2][2] = (*m)[0][2];
  (*m)[1][2] = temp;
  (*m)[0][2] = temp2;

  // row 3
  temp = (*m)[3][3];
  temp2 = (*m)[2][3];
  unsigned char temp3 = (*m)[1][3];
  (*m)[3][3] = (*m)[0][3];
  (*m)[2][3] = temp;
  (*m)[1][3] = temp2;
  (*m)[0][3] = temp3;
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE * (ROUNDS + 1));

  // the first round key is the original key
  memcpy(output, cipher_key, BLOCK_SIZE);

  // iterate over the expanded key by round key, starting with the second
  for (int round = 1; round < ROUNDS + 1; round++) {
    // block size equals key size
    // therefore we can iterate over the expanded key in steps of block size
    unsigned char *last_key = &output[(round - 1) * BLOCK_SIZE];
    unsigned char *new_key = &output[round * BLOCK_SIZE];

    // first word in each round key is special
    unsigned char *first_word_of_new_key = new_key;
    unsigned char *first_word_of_last_key = last_key;

    // copy the previous word
    memcpy(first_word_of_new_key, first_word_of_new_key - WORD_SIZE, WORD_SIZE);
    // rotate
    rotate_left(first_word_of_new_key, WORD_SIZE);
    // sub bytes
    sub_word(first_word_of_new_key);
    // xor with word at the same position in the last key
    xor_words(first_word_of_new_key, first_word_of_last_key);
    // xor with r_con, where only the first byte is used
    first_word_of_new_key[0] = first_word_of_new_key[0] ^ r_con[round];

    // the other words of the round key behave the same
    for (int j = 1; j < 4; j++) {
      int word_offset = j * 4;
      // copy the previous word
      memcpy(&new_key[word_offset], &new_key[word_offset - WORD_SIZE],
             WORD_SIZE);

      // xor with word at the same position in the last key (== postion - 4)
      xor_words(&new_key[word_offset], &last_key[word_offset]);
    }
  }

  return output;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // rounds: 10
  // key: 128 bits / 16 bytes as hex
  // block: 128 bits / 16 bytes as hex

  // check if the key is 128 bits
  // check if the block is 128 bits
  // check if the block size is 128 bits
  if (BLOCK_SIZE != 16 || ROUNDS != 10) {
    return NULL;
  }

  // todo: if multiple blocks, only once expand the key, but encrypt each block

  // expand the key
  // 11 round keys, 16 bytes each, the first is the original key
  unsigned char *roundkeys = expand_key(key);

  // encrypt the block
  unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);

  memcpy(output, plaintext, BLOCK_SIZE);

  // round 1: add round key
  add_round_key(output, &roundkeys[0]);

  // round 2-9: sub bytes, shift rows, mix columns, add round key
  for (int i = 1; i < ROUNDS; i++) {
    sub_bytes(output);
    shift_rows(output);
    mix_columns(output);
    add_round_key(output, &roundkeys[i * BLOCK_SIZE]);
  }

  // round 10: sub bytes, shift rows, add round key
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, &roundkeys[ROUNDS]);

  // return the encrypted block
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
  return output;
}

/*
 * D23124833 / Tim Kühnlein
 *
 * This file contains the function prototypes for the main encryption
 * and decryption functions. Some macros are defined to make the code
 * more readable and to avoid magic numbers.
 *
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
// alternatively, we can use the following macro to cast the block to a 4x4
// matrix *matrix[col][row] in the python implementation, it is the other way
// around
#define MATRIX(pointer) ((unsigned char(*)[4][4])pointer)
#define BLOCK_SIZE 16
#define WORD_SIZE 4
#define ROUNDS 10

/*
 * These are the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif

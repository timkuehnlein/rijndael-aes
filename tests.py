# This file contains the tests for the AES implementation in C.
#
# The tests are written in Python and use the ctypes library to call the
# C functions. Each test compares the output of the C function with the
# output of the corresponding Python function from
# https://github.com/boppreh/aes.git

import ctypes
import random

import pytest
import python_aes.aes as python_aes

c_aes = ctypes.CDLL('./rijndael.so')
p_aes = python_aes.AES(b'\x00' * 16)

# helper functions to generate random bytes
def _random_block():
    return _random_bytes(16)

def _random_word():
    return _random_bytes(4)

def _random_byte():
    return _random_bytes(1)

def _random_bytes(number_of_bytes: int):
    return bytes([random.randint(0, 255) for _ in range(number_of_bytes)])

# is is not in the python implementation, so we test it in isolation
def test_rotate_left():
    word = b'\x00\x01\x02\x03'
    c_word = ctypes.create_string_buffer(word)
    c_aes.rotate_left(c_word, 4)
    result = ctypes.string_at(c_word, 4)
    assert result == b'\x01\x02\x03\x00'

@pytest.mark.parametrize('_', range(3))
def test_sub_byte(_):
    byte = _random_byte()
    print('random byte:', byte)
    c_byte = ctypes.create_string_buffer(byte)
    c_aes.sub_byte(c_byte)
    c_result = ctypes.string_at(c_byte, 1)

    # in the python implementation, sub byte is not isolated in a function, so we copy the code here
    p_result = python_aes.s_box[byte[0]]

    assert c_result == bytes([p_result])

@pytest.mark.parametrize('_', range(3))
def test_sub_word(_):
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    c_aes.sub_word(c_word)
    c_result = ctypes.string_at(c_word, 4)

    p_result = [python_aes.s_box[b] for b in word]
    assert c_result == bytes(p_result)

@pytest.mark.parametrize('_', range(3))
def test_invert_sub_byte(_):
    byte = _random_byte()
    print('random byte:', byte)
    c_byte = ctypes.create_string_buffer(byte)
    c_aes.invert_sub_byte(c_byte)
    c_result = ctypes.string_at(c_byte, 1)

    p_result = python_aes.inv_s_box[byte[0]]

    assert c_result == bytes([p_result])

@pytest.mark.parametrize('_', range(3))
def test_invert_sub_word(_):
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    c_aes.invert_sub_word(c_word)
    c_result = ctypes.string_at(c_word, 4)

    p_result = [python_aes.inv_s_box[b] for b in word]
    assert c_result == bytes(p_result)

@pytest.mark.parametrize('_', range(3))
def test_xor_words(_):
    word1 = _random_word()
    word2 = _random_word()
    print('random word1:', word1, 'random word2:', word2)
    c_word1 = ctypes.create_string_buffer(word1)
    c_word2 = ctypes.create_string_buffer(word2)
    c_aes.xor_words(c_word1, c_word2)
    c_result = ctypes.string_at(c_word1, 4)

    p_result = python_aes.xor_bytes(word1, word2)
    assert c_result == bytes(p_result)

@pytest.mark.parametrize('_', range(3))
def test_expand_key(_):
    # 16 byte block
    key = _random_block()
    print('random key:', key)

    c_key = ctypes.create_string_buffer(key)

    # https://docs.python.org/3/library/ctypes.html#return-types
    # "By default functions are assumed to return the C int type.
    # Other return types can be specified by setting the restype
    # attribute of the function object."
    # hint from https://stackoverflow.com/questions/55999102/segfault-when-accessing-large-memory-buffer-from-ctypes
    c_aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 176)
    address = c_aes.expand_key(c_key)
    c_keys = ctypes.string_at(address, 176)
    p_keys = p_aes._expand_key(key)

    print (c_keys)

    assert len(c_keys) == 176
    assert c_keys == _keys2bytes(p_keys)

    c_aes.my_free(address)

@pytest.mark.parametrize('_', range(3))
def test_sub_bytes(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    block = ctypes.create_string_buffer(buffer)

    c_aes.sub_bytes(block)
    c_result = ctypes.string_at(block, 16)

    matrix = python_aes.bytes2matrix(buffer)
    python_aes.sub_bytes(matrix)
    p_result = python_aes.matrix2bytes(matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_invert_sub_bytes(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    block = ctypes.create_string_buffer(buffer)

    c_aes.invert_sub_bytes(block)
    c_result = ctypes.string_at(block, 16)

    matrix = python_aes.bytes2matrix(buffer)
    python_aes.inv_sub_bytes(matrix)
    p_result = python_aes.matrix2bytes(matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_shift_rows(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    block = ctypes.create_string_buffer(buffer)

    c_aes.shift_rows.restype = ctypes.POINTER(ctypes.c_char * 16)
    c_aes.shift_rows(block)
    c_result = ctypes.string_at(block, 16)

    matrix = python_aes.bytes2matrix(buffer)
    python_aes.shift_rows(matrix)
    p_result = python_aes.matrix2bytes(matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_invert_shift_rows(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    c_block = ctypes.create_string_buffer(buffer)

    c_aes.invert_shift_rows.restype = ctypes.POINTER(ctypes.c_char * 16)
    c_aes.invert_shift_rows(c_block)
    c_result = ctypes.string_at(c_block, 16)

    p_matrix = python_aes.bytes2matrix(buffer)
    python_aes.inv_shift_rows(p_matrix)
    p_result = python_aes.matrix2bytes(p_matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_mix_single_column(_):
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    p_word = list(word)

    c_aes.mix_single_column(c_word)
    c_result = ctypes.string_at(c_word, 4)

    python_aes.mix_single_column(p_word)
    p_result = bytes(p_word)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_mix_columns(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    c_block = ctypes.create_string_buffer(buffer)

    c_aes.mix_columns(c_block)
    c_result = ctypes.string_at(c_block, 16)

    p_matrix = python_aes.bytes2matrix(buffer)
    python_aes.mix_columns(p_matrix)
    p_result = python_aes.matrix2bytes(p_matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_invert_mix_columns(_):
    # 16 byte block
    buffer = _random_block()
    print('random block:', buffer)
    c_block = ctypes.create_string_buffer(buffer)

    c_aes.invert_mix_columns(c_block)
    c_result = ctypes.string_at(c_block, 16)

    p_matrix = python_aes.bytes2matrix(buffer)
    python_aes.inv_mix_columns(p_matrix)
    p_result = python_aes.matrix2bytes(p_matrix)

    assert c_result == p_result

@pytest.mark.parametrize('_', range(3))
def test_add_round_key(_):
    block_buffer = _random_block()
    key_buffer = _random_block()
    print('random block:', block_buffer, 'random key:', key_buffer)
    c_block = ctypes.create_string_buffer(block_buffer)
    c_key = ctypes.create_string_buffer(key_buffer)

    # c_aes.add_round_key.restype = ctypes.POINTER(ctypes.c_char * 16)
    c_aes.add_round_key(c_block, c_key)
    c_result = ctypes.string_at(c_block, 16)

    block_matrix = python_aes.bytes2matrix(block_buffer)
    key_matrix = python_aes.bytes2matrix(key_buffer)
    python_aes.add_round_key(block_matrix, key_matrix)
    p_result = python_aes.matrix2bytes(block_matrix)

    assert c_result == p_result

# testing the entire encryption and decryption process three times
@pytest.mark.parametrize('_', range(3))
def test_aes_encrypt_and_decrypt_block(_):
    # 16 byte block
    block_buffer = _random_block()
    key_buffer = _random_block()
    print('random block:', block_buffer, 'random key:', key_buffer)
    block = ctypes.create_string_buffer(block_buffer)
    key = ctypes.create_string_buffer(key_buffer)

    # encrypt in c
    c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    address = c_aes.aes_encrypt_block(block, key)
    c_result_encryption = ctypes.string_at(address, 16)
    c_aes.my_free(address)

    # encrypt in python
    _p_aes = python_aes.AES(key_buffer)
    p_result = _p_aes.encrypt_block(block_buffer)

    assert c_result_encryption == bytes(p_result)

    # decrypt in c
    c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    address = c_aes.aes_decrypt_block(c_result_encryption, key)
    c_result_decryption = ctypes.string_at(address, 16)
    c_aes.my_free(address)

    # decrypt in python
    p_result = _p_aes.decrypt_block(p_result)

    assert c_result_decryption == bytes(p_result)

    assert block_buffer == c_result_decryption

# helper function, Converts a 3D list into a byte array.
def _keys2bytes(keys: list[list[list]]):
    # Flatten the list
    flat_list = [item for sublist1 in keys for sublist2 in sublist1 for item in sublist2]
    
    # Convert each integer to a byte and create a bytes object
    byte_array = bytes(flat_list)
    return byte_array
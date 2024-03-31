import ctypes
import random

import pytest
import python_aes.aes as python_aes

c_aes = ctypes.CDLL('./rijndael.so')
p_aes = python_aes.AES(b'\x00' * 16)

def _random_block():
    return _random_bytes(16)

def _random_word():
    return _random_bytes(4)

def _random_byte():
    return _random_bytes(1)

def _random_bytes(number_of_bytes: int):
    return bytes([random.randint(0, 255) for _ in range(number_of_bytes)])

#todo are all mallocs deallocated?

# todo is this in python?
def test_rotate_left():
    word = b'\x00\x01\x02\x03'
    c_word = ctypes.create_string_buffer(word)
    c_aes.rotate_left(c_word, 4)
    result = ctypes.string_at(c_word, 4)
    assert result == b'\x01\x02\x03\x00'

# assert, that c anc python implementations of substituting bytes are equal
def test_sub_byte():
    byte = _random_byte()
    print('random byte:', byte)
    c_byte = ctypes.create_string_buffer(byte)
    c_aes.sub_byte(c_byte)
    c_result = ctypes.string_at(c_byte, 1)

    p_result = python_aes.s_box[byte[0]]

    assert c_result == bytes([p_result])

def test_sub_word():
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    c_aes.sub_word(c_word)
    c_result = ctypes.string_at(c_word, 4)

    p_result = [python_aes.s_box[b] for b in word]
    assert c_result == bytes(p_result)

def test_invert_sub_byte():
    byte = _random_byte()
    print('random byte:', byte)
    c_byte = ctypes.create_string_buffer(byte)
    c_aes.invert_sub_byte(c_byte)
    c_result = ctypes.string_at(c_byte, 1)

    p_result = python_aes.inv_s_box[byte[0]]

    assert c_result == bytes([p_result])

def test_invert_sub_word():
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    c_aes.invert_sub_word(c_word)
    c_result = ctypes.string_at(c_word, 4)

    p_result = [python_aes.inv_s_box[b] for b in word]
    assert c_result == bytes(p_result)

def test_xor_words():
    word1 = _random_word()
    word2 = _random_word()
    print('random word1:', word1, 'random word2:', word2)
    c_word1 = ctypes.create_string_buffer(word1)
    c_word2 = ctypes.create_string_buffer(word2)
    c_aes.xor_words(c_word1, c_word2)
    c_result = ctypes.string_at(c_word1, 4)

    p_result = python_aes.xor_bytes(word1, word2)
    assert c_result == bytes(p_result)

def test_expand_key():
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
    c_keys = ctypes.string_at(
        address,
        176
    )
    p_keys = p_aes._expand_key(key)

    print (c_keys)

    assert len(c_keys) == 176
    assert c_keys == _keys2bytes(p_keys)

    c_aes.my_free(address)

def test_sub_bytes():
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

def test_invert_sub_bytes():
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

def test_shift_rows():
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

def test_invert_shift_rows():
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

def test_mix_single_column():
    word = _random_word()
    print('random word:', word)
    c_word = ctypes.create_string_buffer(word)
    p_word = list(word)

    c_aes.mix_single_column(c_word)
    c_result = ctypes.string_at(c_word, 4)

    python_aes.mix_single_column(p_word)
    p_result = bytes(p_word)

    assert c_result == p_result

def test_mix_columns():
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

def test_add_round_key():
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

@pytest.mark.skip(reason="not finished")
def test_aes_encrypt_block():
    # 16 byte block
    block_buffer = _random_block()
    key_buffer = _random_block()
    print('random block:', block_buffer, 'random key:', key_buffer)
    block = ctypes.create_string_buffer(block_buffer)
    key = ctypes.create_string_buffer(key_buffer)

    c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    address = c_aes.aes_encrypt_block(block, key)
    c_result = ctypes.string_at(address, 16)

    block_matrix = python_aes.bytes2matrix(block_buffer)
    key_matrix = python_aes.bytes2matrix(key_buffer)
    # p_aes = python_aes.AES(key_matrix)
    p_result = p_aes.encrypt_block(block_matrix)

    assert c_result == bytes(p_result)

    # c_aes.my_free(address)

# todo: test entire encryption and decryption process three times
    # generate 3 random plaintexts and keys, encrypt them with both
    # your code and the Python implementation, and ensure that the resulting ciphertexts match.
    # Then feed the key and ciphertexts into the decryption and ensure that the output matches the
    # original plaintext

# result = ctypes.string_at(
#     rijndael.aes_encrypt_block(plaintext, key),
#     16
# )

# @pytest.fixture
# def libfact():
#     yield rijndael


def _keys2bytes(keys: list[list[list]]):
    """ Converts a 3D list into a byte array. """
    # Flatten the list
    flat_list = [item for sublist1 in keys for sublist2 in sublist1 for item in sublist2]
    
    # Convert each integer to a byte and create a bytes object
    byte_array = bytes(flat_list)
    return byte_array
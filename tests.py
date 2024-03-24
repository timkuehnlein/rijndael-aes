import ctypes
import pytest
import python_aes.aes as python_aes

rijndael = ctypes.CDLL('./rijndael.so')
p_aes = python_aes.AES(b'\x00' * 16)

def test_fact():
    # 16 byte block
    buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    buffer += b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    block = ctypes.create_string_buffer(buffer)

    rijndael.sub_bytes(block)

    addresses = [[4, 5, 2, 1], [6, 7, 12, 0], [8, 9, 4, 4], [10, 11, 1, 2]]
    python_aes.sub_bytes(addresses)

    assert block.value == addresses

# result = ctypes.string_at(
#     rijndael.aes_encrypt_block(plaintext, key),
#     16
# )

# @pytest.fixture
# def libfact():
#     yield rijndael


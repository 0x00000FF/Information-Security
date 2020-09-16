from typing import List
from bitarray import bitarray


# modified return to return bitarray as is
def string_to_bits(string: str) -> bitarray:
    bits = bitarray()
    bits.frombytes(string.encode('utf-8'))
    
    return bits


def bits_to_string(bits: List[bool]) -> str:
    return bitarray(bits).tobytes().decode('utf-8')


def xor_encrypt_decrypt(message: str, key: str) -> str:
    """
    :param  message: plaintext
    :param  key    : key
    :return str    : encrypted cipher with key
    """
    pad_times  = int(len(message) / len(key)) + 1 
    padded_key = (key * pad_times)[:len(message)]

    message_bits = string_to_bits(message)
    key_bits     = string_to_bits(padded_key)
    
    return bits_to_string(message_bits ^ key_bits)

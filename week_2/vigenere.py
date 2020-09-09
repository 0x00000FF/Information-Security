import string
from enum import Enum

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


class EncryptionMode(Enum):
    ENC = 'ENCRYPT'
    DEC = 'DECRYPT'

def vigenere_crypt_key_range(key: str) -> int:
    key_ord = ord(key)
    
    if key in lower_alphabet_list:
        key_ord = key_ord - ord('a')
    elif key in upper_alphabet_list:
        key_ord = key_ord - ord('A')
    elif key in number_list:
        key_ord = key_ord - ord('0')
    
    return key_ord

def vigenere_crypt_pass(ch:str, key:int) -> str:
    target_list = None
    ch_ord = ord(ch)
    
    pos = 0
    pos_range = 26

    if ch in lower_alphabet_list:
        pos = ch_ord - ord('a')
        target_list = lower_alphabet_list
    elif ch in upper_alphabet_list:
        pos = ch_ord - ord('A')
        target_list = upper_alphabet_list
    elif ch in number_list:
        pos = ch_ord - ord('0')
        target_list = number_list
        pos_range = 10
    
    return target_list[(pos + key) % pos_range]

def vigenere_encrypt_decrypt(text: str, key: str, mode: EncryptionMode) -> str:
    """
    비제네르 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key의 배열
    :param mode: 암호화할 지 복호화할 지 구분하기 위한 값
    :return: 비제네르 암호를 이용한 암호문 혹은 복호화된 문자열
    """

    key_len     = len(key)
    enc_mode    = 1 if mode == EncryptionMode.ENC else -1
    result_list = []

    for i in range(0, len(text)):
        mod_key = vigenere_crypt_key_range(key[i % key_len]) * enc_mode
        result_list.append(vigenere_crypt_pass(text[i], mod_key))

    return str(''.join(result_list))

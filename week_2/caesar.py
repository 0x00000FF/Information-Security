import string

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)

def caesar_crypt_pass(ch:str, key:int) -> int:
    ch_ord = ord(ch)
    target_list = None

    pos = ch_ord
    pos_range = 26
    
    if ch in lower_alphabet_list:
        pos = ch_ord - ord('a') + key
        target_list = lower_alphabet_list

    elif ch in upper_alphabet_list:
        pos = ch_ord - ord('A') + key
        target_list = upper_alphabet_list

    elif ch in number_list:
        pos = ch_ord - ord('0') + key
        target_list = number_list
        pos_range = 10
    
    pos = pos % pos_range
    return target_list[pos]

def caesar_encrypt_decrypt(text: str, key: int) -> str:
    """
    시저 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key
    :return: 시저 암호를 이용한 암호문 혹은 복호화된 문자열
    """
    
    return str(''.join([caesar_crypt_pass(ch, key) for ch in list(text)]))
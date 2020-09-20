# Data Encryption Standard
# Run with output feedback (OFB) mode
# 201704150 Kangjun Heo

from bitarray import bitarray
import math

##############################################################
#
#    BEGIN: Tables for feistel processes
#
###############################################################

ip  = [
    58,  50,  42,  34,  26,  18,  10,  2,
    60,  52,  44,  36,  28,  20,  12,  4,
    62,  54,  46,  38,  30,  22,  14,  6,
    64,  56,  48,  40,  32,  24,  16,  8,
    57,  49,  41,  33,  25,  17,  9 ,  1,
    59,  51,  43,  35,  27,  19,  11,  3,
    61,  53,  45,  37,  29,  21,  13,  5,
    63,  55,  47,  39,  31,  23,  15,  7
]

ip_1 = [
    40,  8,  48,  16,  56,  24,  64,  32,
    39,  7,  47,  15,  55,  23,  63,  31,
    38,  6,  46,  14,  54,  22,  62,  30,
    37,  5,  45,  13,  53,  21,  61,  29,
    36,  4,  44,  12,  52,  20,  60,  28,
    35,  3,  43,  11,  51,  19,  59,  27,
    34,  2,  42,  10,  50,  18,  58,  26,
    33,  1,  41,  9 ,  49,  17,  57,  25
]

expansion = [
    32,  1 ,  2 ,  3 ,  4 ,  5 ,
    4 ,  5 ,  6 ,  7 ,  8 ,  9 ,
    8 ,  9 ,  10,  11,  12,  13,
    12,  13,  14,  15,  16,  17,
    16,  17,  18,  19,  20,  21,
    20,  21,  22,  23,  24,  25,
    24,  25,  26,  27,  28,  29,
    28,  29,  30,  31,  32,  1
]

permutation = [
    16,  7 ,  20,  21,  29,  12,  28,  17,
    1 ,  15,  23,  26,  5 ,  18,  31,  10,
    2 ,  8 ,  24,  14,  32,  27,  3 ,  9,
    19,  13,  30,  6 ,  22,  11,  4 ,  25
]

pc1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

pc2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

sbox = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

##############################################################
#
#    END: Tables for feistel processes
#    BEGIN: Feistel functionalities
#
###############################################################

def sbox_pass(expanded: bitarray):
    sbox_product = bitarray()

    for i in range(0, 8):
        s_row    = (expanded[i * 6] << 1) | expanded[i * 6 + 5]
        s_column = (expanded[i * 6 + 1] << 3) | (expanded[i * 6 + 2] << 2) | (expanded[i * 6 + 3] << 1) | (expanded[i * 6 + 4])

        append_bits(sbox[i][s_row][s_column], 4, sbox_product)

    return sbox_product

def pbox_pass(sbox_product: bitarray):
    permuted_bits = bitarray()

    for i in range(0, 32):
        permuted_bits.append(sbox_product[permutation[i] - 1])

    return permuted_bits

def expand(message: bitarray) -> bitarray:
    expanded_bits = bitarray()

    for i in range(0, 48):
        expanded_bits.append(message[expansion[i] - 1])

    return expanded_bits

def feistel(message: bitarray, key: bitarray) -> bitarray:
    # Initial permutation (IP)
    subject = message

    # divide
    left  = subject[0:32]
    right = subject[32:64]
    temp  = None

    # Round functions
    for i in range(1, 17):
        e = expand(right) ^ r_key(key, i)

        # TODO: pass e through sbox
        e = sbox_pass(e)

        # TODO: pass pbox
        left = pbox_pass(e)

        left ^= right

        # swap right and left
        temp = left
        left = right
        right = temp

    # Initial reverse permutation (IP-1)

    return left + right

##############################################################
#
#    END  : Feistel functionalities
#    BEGIN: Key generator
#
###############################################################

def pc1_pass(key:bitarray) -> (bitarray, bitarray):
    result_bits = bitarray()

    for i in range(0, 56):
        result_bits.append(key[pc1[i] - 1])

    return result_bits

def r_key(key: bitarray, round: int) -> bitarray:
    result_bits = bitarray()

    #drop_parities = key[0:7] + key[8:15] + key[16:23] + key[24:31] + key[32:39] + key[40:47] + key[48:55] + key[56:63]
    pc1_k = pc1_pass(key) 
    
    pc1_k_left  = pc1_k[0:28]
    pc1_k_right = pc1_k[28:]

    for i in range(1, round + 1):
        if i in (1,2,9,16):
            pc1_k_left = pc1_k_left[1:] + pc1_k_left[0:1]
            pc1_k_right = pc1_k_right[1:] + pc1_k_right[0:1]
        else:
            pc1_k_left = pc1_k_left[2:] + pc1_k_left[0:2]
            pc1_k_right = pc1_k_right[2:] + pc1_k_right[0:2]
    
    pc1_k = pc1_k_left + pc1_k_right

    for i in range(0, 48):
        result_bits.append(pc1_k[pc2[i] - 1])

    return result_bits

##############################################################
#
#    END  : Key generator 
#    BEGIN : Utility functions
#
##############################################################

def generate_blocks_str(message: str, key:str) -> (int, bitarray, bitarray):
    return generate_blocks(message.encode('utf-8'), key.encode('utf-8'))


def generate_blocks(message: bytes, key: bytes) -> (int, bitarray, bitarray):
    block_count = math.ceil(len(message) / 8)

    message_bits = bitarray()
    key_bits     = bitarray()

    message_bits.frombytes(message)
    key_bits.frombytes(key)

    return (block_count, message_bits, key_bits)

def generate_iv_bits(iv:bytes) -> bitarray:
    result_bits = bitarray()

    if iv == None:
        result_bits = bitarray(bytes(9))
    else:
        result_bits.frombytes(iv)

    return result_bits
    

def append_bits(val:int, width:int, bitarr:bitarray):
    bits = ("{0:" + str(width) + "b}").format(val)

    for i in bits:
        val = ord(i) - ord('0')
        bitarr.append(bool(val))

    pass

###############################################################
#
#    END  : Utility functions
#    BEGIN: User executable functions
#
###############################################################

def encrypt_des(message: str, key: str, mode: int, iv=None) -> (bytes, bytes):
    """
    :param message: plaintext
    :param key    : key
    :param mode   : operation mode of DES
    :param iv     : initialization vector for PCBC
    :return       : encrypted cipher
    """

    block_count, bits, key_bits = generate_blocks_str(message, key)
    result_bits  = bitarray()
    next_input   = generate_iv_bits(iv)
    padded_bytes = 0

    # ofb
    for i in range(0, block_count):
        block = bits[i * 64 : i* 64 + 64]

        if len(block) < 64:
            pad_bits  = bitarray()
            pad_bytes = bytes([math.ceil((64 - len(block) / 8))])

            pad_bits.frombytes(pad_bytes)

            block += pad_bits

        next_input   = feistel(next_input, key_bits)
        result_bits += next_input ^ block
    
    return (iv, result_bits.tobytes())


def decrypt_des(encrypted: bytes, key: str, mode: int, iv: bytes) -> str:
    """
    :param encrypted: encrypted cipher
    :param key      : key
    :param mode     : operation mode of DES
    :param iv       : initialization vector for PCBC
    :return         : original message
    """
    
    block_count, bits, key_bits = generate_blocks(encrypted, key.encode('utf-8'))
    result_bits = bitarray()
    next_input  = generate_iv_bits(iv)

    # ofb
    for i in range(0, block_count):
        block = bits[i * 64 : i * 64 + 64]

        if len(block) < 64:
            block += bitarray(bytes(math.ceil((64 - len(block)) / 8 + 1)))

        next_input   = feistel(next_input, key_bits)
        result_bits += next_input ^ block

    # strip padding
    decrypted_bytes = result_bits.tobytes()
    padded_bytes    = decrypted_bytes[len(decrypted_bytes) - 1]
    

    return result_bits.tobytes().decode('utf-8')


message = 'Hello Security abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890'
key = '12345678'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x01'
#iv = b'\xc1\x8eb*\xaf.;\xee'
#enc = b"Ad7\x921\xfbF:\xc1\x04\xd2\x19/\x1d\x0eB\xf4\xab\xddG7\xa2'\xa6\xdc\xc7\x8a\xd0\x82\xc9-\xb9\xf6YFp\x0f\x0b:i\x1e\xae\x08\nw\xa0\x11X\xe7ked\x19\xe0\x14\xf1\nkk?4\x9a\x807\x7f\xb9/\x9e\x1b\xdc\xfc\x88\xbe\x04\x04\xc3\x0bEz"
print(encrypt_des(message, key, 0, iv))


enc = b'\x13\x9a\x996ot\x93\xfa\xbe\xa9\xf5?v<T\xe8\xf9\xd9!;\x06v\xb8\xdaw\x95%\x8d\xa8Lb\xee\xeb\xaa+\t\xf0\x11\xfax\x05\xba\xdc\x1e\x03QE\xe9\xfc\xf6\xf2\x9c)OQWt\x98\xe2\xb8\x13cYUN\x90\xc8\x94 \x14\xf0\x86\xed\x8f\xe1\xcf\xd8,\x18\x0f'
print(decrypt_des(enc, key, 0, iv))
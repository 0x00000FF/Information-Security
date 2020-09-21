from Crypto.Cipher import DES

def encrypt_des(message: str, key: str, mode: int, iv=None) -> (bytes, bytes):
    """
    :param message: plaintext
    :param key    : key
    :param mode   : operation mode of DES
    :param iv     : initialization vector for PCBC
    :return       : encrypted cipher
    """
    
    des = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return (des.iv, des.encrypt(bytes(message, 'utf-8')))


def decrypt_des(encrypted: bytes, key: str, mode: int, iv: bytes) -> str:
    """
    :param encrypted: encrypted cipher
    :param key      : key
    :param mode     : operation mode of DES
    :param iv       : initialization vector for PCBC
    :return         : original message
    """
    
    des = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return des.decrypt(encrypted).decode('utf-8')



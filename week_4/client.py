from socket import *
import threading
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad(s: str or bytes) -> bytes:
    """
    pad given data to encrypt with block cipher algorithm

    :param s: bytes to be padded
    :return:  padded bytes
    """
    return (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes) -> bytes:
    """
    unpad given data to retrieve original message

    :param s: bytes to be unpadded
    :return:  unpadded bytes
    """
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    """
    Encrypt given data in AES with given key.

    :param data: a plaintext
    :param key:  key for AES cryptography
    :return:     ciphertext
    """

    iv      = get_random_bytes(16)
    message = data.encode('utf-8')
    cipher  = AES.new(key, AES.MODE_CBC, iv=iv)

    cipher_text = cipher.encrypt(message + pad(message).encode())
    
    return iv + cipher_text


def decrypt(data: bytes, key: bytes) -> str:
    """
    Decrypt given cipher text(data) in AES with given key

    :param data: a ciphertext
    :param key:  key for AES Cryptography
    :return:     decrypted plaintext
    """
    iv          = data[0:16]
    cipher_text = data[16:]
    cipher      = AES.new(key, AES.MODE_CBC, iv=iv)

    return unpad(cipher.decrypt(cipher_text)).decode('utf-8')


def send(sock, key):
    """
    Send an user message as encrypted state

    :param sock: connected socket with server
    :param key:  key for AES Cryptography
    :return:     nothing
    """
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    """
    Receive a message from server and decrypt

    :param sock: connected socket with server
    :param key:  key for AES Cryptography
    :return:     nothing
    """
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


port = 8081

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('127.0.0.1', port))

print('접속 완료')

key = input('key를 입력해주세요: ')
sender = threading.Thread(target=send, args=(clientSock, key.encode('utf-8')))
receiver = threading.Thread(target=receive, args=(clientSock, key.encode('utf-8')))

sender.start()
receiver.start()

while True:
    time.sleep(1)
    pass

from typing import Dict, List

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes or None) -> bytes:
    if key is None:
        return data.encode('utf-8')
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    if key is None:
        return data.decode('utf-8')
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


class Proxy:
    def __init__(self):
        self._linked_ip: Dict[str, "Client"] = {}
        self.msg_list: List[str] = []

    def link(self, client: "Client"):
        self._linked_ip[client.ip] = client

    def public_key(self, target_ip: str):
        """
        Public key는 올바르게 전송해줌을 가정합니다.
        :param target_ip: ip address of desired client with public key
        :return: public key of the client with ip address "target_ip"
        """
        return self._linked_ip[target_ip].key.publickey()

    def request(self, source_ip: str, target_ip: str, msg: bytes):
        try:
            self.msg_list.append(msg.decode('utf-8'))
        except UnicodeDecodeError:
            print("Can't read Data in proxy")

        self._linked_ip[target_ip].receive(msg, source_ip)

    def client(self, ip: str) -> "Client":
        """
        상대 client를 ip값과 proxy를 통해 얻을 수 있음
        :param ip: ip address of target client
        :return:   client object with ip address "ip"
        """
        return self._linked_ip[ip]


class Client:
    def __init__(self, ip: str, rsa_key=None):
        self.ip = ip
        self.session_key: Dict[str, bytes] = {}   # { ip : session key }
        if rsa_key is None:
            self.key = RSA.generate(2048)             # RSA Key
        else:
            self.key = rsa_key
        self.msg_list: List[str] = []

    def request(self, proxy: Proxy, target_ip: str, msg: str):
        """
        request to send an encrypted message(msg) to the client with "target_ip"
        do handshake if there's no session key for "target_ip"

        :param proxy: arbiter proxy between me and bob(or alice)
        :param target_ip: target ip of the targetted client
        :param msg: message to send as encrypted
        :return: nothing
        """
        if not self.session_key.get(target_ip):
            self.handshake(proxy, target_ip)

        enc = encrypt(msg, self.session_key[target_ip])
        proxy.request(self.ip, target_ip, enc)

    def receive(self, msg: bytes, source_ip: str):
        """
        decrypted an encrypted message from the client with "source_ip"
        requires "session key" acquired at handshake process

        "session key" is being matched using "source_ip"

        :param msg: encrypted message
        :param source_ip: ip address of message source client
        :return: nothing; adds a decrypted message to the message list
        """
        dec = decrypt(msg, self.session_key[source_ip])
        self.msg_list.append(dec)

    def handshake(self, proxy: Proxy, target_ip: str, session_key: bytes or None = None):
        """
        상대 ip에 대한 session key가 없을 경우 사용하는 함수
        target ip 주소의 client의 public key를 받아와 public key 로 암호화한 session key를 전송
        공유한 session key는 self.session_key 에 ip와 매핑하여 저장

        session key를 입력받았을 때는 암호화된 session_key를 받았음을 가정한다. test code 참고
        session key를 받지 않았을 경우 session key를 생성해 session key를 상대의 공개키로 암호화하여 handshake 진행

        :param proxy: arbiter proxy considered "target_ip" client is connected
        :param target_ip: target ip address of the targetted client
        :param session_key: session key for handshake; generate with random bytes if None
        :return: nothing; stores session key if handshake succeeds
        """

        # acquire target client
        target_client  = proxy.client(target_ip)

        # request handshake with newly generated session_key
        if session_key is None:
            # get public key of target client
            target_client_ku = target_client.key.publickey()

            # get rsa public key encryption instance
            rsa_pub          = PKCS1_OAEP.new(target_client_ku)

            # encrypt session key with public key of target client
            session_key = get_random_bytes(16)
            session_key_enc = rsa_pub.encrypt(session_key)    
        
            target_client.handshake(proxy, self.ip, session_key_enc)

        # commence handshake with received session_key
        else:
            # get rsa decryption instance 
            rsa_priv         = PKCS1_OAEP.new(self.key)

            # decrypt received session_key
            session_key = rsa_priv.decrypt(session_key)

        # store session key for further requests
        self.session_key[target_ip] = session_key
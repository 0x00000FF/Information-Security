import copy
from dataclasses import dataclass
from typing import List

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


@dataclass
class Cert:
    issuer: bytes
    public: bytes
    sign: bytes


class Issuer:
    def __init__(self, key: bytes, cert_chain=None):
        if cert_chain is None:
            cert_chain = []
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain: List[Cert] = cert_chain

    def change_secret(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain = []

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def issue(self, pub_key: bytes):
        """
        TODO:
        자신의 certificate chain 과
        issuer의 public key, holder의 public key와 public key의 Hash에 대한 서명을 가진 dictionary 반환

        :param pub_key: public key to be signed
        :return: cert_chain:
         [ { issuer: pub_key0, public_key: pub_key1, sign: Signature0(Hash(pub_key1)) }, ... ]
        """

        new_cert_chain = []

        # import previous cert chain into new cert chain
        for cert in self.cert_chain:
            new_cert_chain.append(cert)

        # sign given public key with secret
        signer   = DSS.new(self.__secret, 'fips-186-3')
        key_hash = SHA256.new(pub_key)
        new_cert = Cert(self.public, pub_key, signer.sign(key_hash))

        # append new cert to the new cert chain
        new_cert_chain.append(new_cert)
        return new_cert_chain


class Holder:
    def __init__(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert: List[Cert] = []

    def set_cert(self, cert: List[Cert]):
        self.cert = cert

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def present(self, nonce: bytes) -> (List[Cert], bytes):
        """
        TODO:

        자신이 발급받아온 cert chain을 통해
        :param nonce: 랜덤 값
        :return: cert_chain, sign(nonce)
        """

        # generate signer from secret
        signer     = DSS.new(self.__secret, 'fips-186-3')
        nonce_hash = SHA256.new(nonce)

        # return cert chain and nonce sign
        return self.cert, signer.sign(nonce_hash)


class Verifier:
    def __init__(self, root_pub: bytes):
        self.root = root_pub

    def verify(self, cert_chain: List[Cert], pub_key: bytes, nonce: bytes, sign: bytes):
        """
        TODO:

        cert_chain을 검증하고 pub_key의 서명을 확인함

        root issuer는 저장된 root ca에 대한 정보를 이용하여 확인

        cert chain 검증 결과 root ca로부터 연결된 신뢰 관계를 갖고 있을 경우 True 반환

        :param cert_chain: given cert chain
        :param pub_key: holder's public key
        :param nonce: nonce from holder
        :param sign: signed nonce
        :return: verification result
        """

        # add holder cert into cert chain
        holder_pub  = ECC.import_key(pub_key)
        holder_cert = Cert(holder_pub, nonce, sign)
        cert_chain.append(holder_cert)

        # get reversed chain to bottom-up verification
        reversed_chain     = cert_chain[::-1]

        for cert in reversed_chain:
            try:
                current_signer    = DSS.new(cert.issuer, 'fips-186-3')
                current_plaintext = cert.public
                current_sign      = cert.sign
            
                current_signer.verify(SHA256.new(current_plaintext), current_sign)
            except:
                return False

        # check top cert issuer of chain is a root CA
        top_issuer = reversed_chain[-1].issuer.export_key(format='DER')

        # if not, validation failed
        if top_issuer != self.root:
            return False

        return True
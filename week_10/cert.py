import json
from os.path import join, curdir, abspath
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def save(cert):
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'w') as f:
        json.dump(cert, f)


def load():
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'r') as f:
        return json.load(f)


def sign():
    """
    (cert.json) 인증서에 공개키와 서명을 저장

    Sign: sign( Hash ( student_id | is_success | week ) )

    서명은 bytes 값의 .hex()를 이용해 string으로 저장
    공개키는 .export_key(format='PEM')을 이용해 PEM 형태로 저장
    :return: None
    """
    
    # load json
    cert_json = load()

    # generate private key
    private_key = ECC.generate(curve='P-256')

    # store public key
    cert_json['public_key'] = private_key.public_key().export_key(format='PEM')

    # generate signer and hash
    signer      = DSS.new(private_key, 'fips-186-3')
    hash_val    = SHA256.new((cert_json['student_id'] + cert_json['is_success'] + str(cert_json['week'])).encode())

    # store sign and save
    cert_json['sign'] = signer.sign(hash_val).hex()
    save(cert_json)

def verify() -> bool:
    """
    (cert.json) 인증서에 저장된 공개키와 서명을 이용해 값을 검증하는 함수

    Sign: sign( Hash ( student_id | is_success | week ) )
    임을 이용해 해시를 생성한 후 서명 검증

    verifier.verify 함수를 이용할 때 true, false가 아닌 exception으로
    검증 여부가 판단되는 점을 주의
    try 문을 이용해 검증 성공 시 true, 실패시 false를 반환
    :return: verify result
    """

    try:    
        # load json
        cert_json = load()

        # get public key and generate verifier
        public_key = ECC.import_key(cert_json['public_key'])
        verifier   = DSS.new(public_key, 'fips-186-3')

        current_hash = SHA256.new((cert_json['student_id'] + cert_json['is_success'] + str(cert_json['week'])).encode())
        verifier.verify(current_hash, bytes.fromhex(cert_json['sign']))

        return True

    except: # exception raises when verification failed
        return False
    

if __name__ == '__main__':
    sign()

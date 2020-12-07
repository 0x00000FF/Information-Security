from socket import *
import threading
import time
from hashlib import sha256


def send(sock, send_data):
    sock.send(send_data)


def receive(sock, addr, dst):
    while True:
        recv_data = sock.recv(1024)
        try:
            print(f'{addr} :', recv_data.decode('utf-8'))
        except:
            print(f'{addr} :', recv_data)
        send(dst, recv_data)


def load_db():
    return [
        {
            'id': 'information',
            'password': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'  # abc
        },
        {
            'id': 'security',
            'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'  # password
        },
        {
            'id': '201950219',
            'password': '6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090'  # ?
        }
    ]

def read_credential_packet(sock: "Socket") -> (str, str):
    """
    reads packet from a socket and parse credentials
    :param sock: socket to receive packet
    :return: tuple of parsed id and password
    """

    # parse packet
    # | 4 bytes: sizeof(user_id)  | variable: user_id  | 
    # | 4 bytes: sizeof(password) | variable: password |

    size_id = int.from_bytes(sock.recv(4), byteorder='little')
    id = sock.recv(size_id).decode('utf-8')

    size_pw = int.from_bytes(sock.recv(4), byteorder='little')
    pw = sock.recv(size_pw).decode('utf-8')

    return (id, pw)

def verify_login(db, user_id, password) -> bool:
    """
    TODO: db에 있는 user id와 password의 해시값을 통해 입력받은 id와 password 값이 옳은 지 검증
    로그인 실패 시 false
    :param db: credential database
    :param user_id:  given user id
    :param password: given user password
    :return: true if given credential matches in db
    """

    # hash password with sha256
    password_bytes = password.encode('utf-8')
    password = sha256(password_bytes).hexdigest()

    return len(list(filter(lambda entry: entry['id'] == user_id and entry['password'] == password, db))) > 0


def connect_socket():
    port = 63000
    db = load_db()
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port))
    server_socket.listen(2)

    print('%d번 포트로 접속 대기중...' % port)

    connection_socket1, addr1 = server_socket.accept()
    connection_socket2, addr2 = server_socket.accept()

    print(str(addr1), '에서 접속되었습니다.')
    print(str(addr2), '에서 접속되었습니다.')

    # TODO: 두 클라이언트의 login 확인
    # 한 클라이언트라도 로그인 실패 시 server_socket.close() 호출 후 종료
    (id1, pw1) = read_credential_packet(connection_socket1)
    (id2, pw2) = read_credential_packet(connection_socket2)
    
    if (verify_login(db, id1, pw1) == False) or (verify_login(db, id2, pw2) == False):
        server_socket.close()
        exit(1)
    
    # TODO: 두 클라이언트 public key 전달
    connection_socket1.send(connection_socket2.recv(1024))
    connection_socket2.send(connection_socket1.recv(1024))

    receiver1 = threading.Thread(target=receive, args=(connection_socket1, addr1, connection_socket2))
    receiver2 = threading.Thread(target=receive, args=(connection_socket2, addr2, connection_socket1))

    receiver1.start()
    receiver2.start()

    try:
        while True:
            time.sleep(1)
            pass
    except KeyboardInterrupt:
        server_socket.close()


if __name__ == '__main__':
    connect_socket()
    # print(sha256('abc'.encode('utf-8')).hexdigest())
    # print(sha256('password'.encode('utf-8')).hexdigest())

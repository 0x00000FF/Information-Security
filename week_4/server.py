from socket import *
import threading
import time


def send(sock, send_data):
    """
    send data via given connected socket

    :param sock: destination socket for sending data
    :param send_data: data to send
    :return: nothing
    """
    sock.send(send_data)


def receive(sock, addr, dst):
    """
    receive data via given connected socket.

    :param sock: source socket for receiving data
    :param addr: destination address
    :param dst:  destination socket for sending data
    :return:
    """
    while True:
        recv_data = sock.recv(1024)
        send(dst, recv_data)


port = 8081

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('', port))
serverSock.listen(2)

print('%d번 포트로 접속 대기중...'%port)

connectionSock1, addr1 = serverSock.accept()
connectionSock2, addr2 = serverSock.accept()

print(str(addr1), '에서 접속되었습니다.')
print(str(addr2), '에서 접속되었습니다.')

receiver1 = threading.Thread(target=receive, args=(connectionSock1,addr1, connectionSock2))
receiver2 = threading.Thread(target=receive, args=(connectionSock2,addr2, connectionSock1))

receiver1.start()
receiver2.start()

try:
    while True:
        time.sleep(1)
        pass
except KeyboardInterrupt:
    serverSock.close()

import socket

from utils import HTTPRequest


class EmulatedClient(object):

    def __init__(self, timeout=5):
        socket.setdefaulttimeout(timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def sock_connect(self, dst_ip):
        self.server_address = (dst_ip, 21)
        self.sock.connect(self.server_address)

    def sock_send(self, data):
        self.sock.send(data)

    def sock_receive(self):
        response = b""

        try:
            buf = self.sock.recv(1024)
            if buf:
                response += buf
        except Exception as e:
            print(e)

        return response

    def sock_close(self):
        self.sock.close()
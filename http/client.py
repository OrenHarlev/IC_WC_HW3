import socket

from utils import HTTPRequest


class EmulatedClient(object):
    def __init__(self, timeout=3):
        socket.setdefaulttimeout(timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def sock_connect(self, data):
        self.server_address = (HTTPRequest(data).headers["HOST"], 80)
        self.sock.connect(self.server_address)

    def sock_send(self, data):
        self.sock.send(data)

    def sock_receive(self):
        response = b""

        while True:
            try:
                buf = self.sock.recv(1024)
                if not buf:
                    break
                else:
                    response += buf
            except Exception as e:
                break

        return response

    def sock_close(self):
        """ Closes the socket. """

        self.sock.close()
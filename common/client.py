""" Man in the middle emulated client module.
    the mitm server must be the one sending the original request to the outbound
    server. With the emulated client we are changing the typical structure:
        client <-> server
    To one that looks like so:
        client <-> mitm (server) <-> mitm (emulated client) <-> server
    Where we then reply back to the client with the response the emulated client
    retrieved from the server on behalf of the client. This module defines the
    mitm (emulated client) portion.
"""

import socket


class EmulatedClient(object):

    def __init__(self, timeout=3):
        socket.setdefaulttimeout(timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def sock_connect(self, source_port, server_ip, server_port):
        self.server_address = (server_ip, server_port)
        self.sock.bind(('', source_port))
        self.sock.connect(self.server_address)

    def sock_send(self, data):
        """ Sends data through the socket.
            Args:
            data (bytes): HTTP request.
        """
        self.sock.send(data)

    def sock_receive(self, recv_in_loop):
        """ Receives data through the socket. """

        response = b""

        while True:
            try:
                buf = self.sock.recv(1024)
                if buf:
                    response += buf
                if not recv_in_loop:
                    break
            except Exception as e:
                print(e)
                break

        return response

    def sock_close(self):
        """ Closes the socket. """

        self.sock.close()
#!/usr/bin/python3
from http.client import HTTPResponse
from io import BytesIO
import urllib3
import json
import socket
import socketserver
import threading
import time

HTTP_PORT = 800
CHUNK_SIZE = 4096
TIMEOUT = 5

class BytesIOSocket:
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle

def response_from_bytes(data):
    sock = BytesIOSocket(data)

    response = HTTPResponse(sock)
    response.begin()

    return urllib3.HTTPResponse.from_httplib(response)

class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.data = self.rfile.read()
        #original_dest = FW_utils.get_original_dest(self.client_address)
        original_dest = ('www.google.com', 80)
        if not original_dest:
            return

        response = self.get_response_from_server(original_dest, self.data)
        print(response)
        parsed_response = response_from_bytes(response)
        print(parsed_response.headers)

        #if(self.valid_response(response)):
        #    self.request.sendall(response)

    def get_response_from_server(self, dest, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(dest)
            sock.settimeout(TIMEOUT)
            sock.sendall(message)
            res = b''
            while True:
                chunk = sock.recv(CHUNK_SIZE)
                print(len(chunk))
                if len(chunk) == 0:
                    break
                res += chunk

        return res

    #def check_valid_response(self, response):


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    pass

def test_client(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(message)
        for i in range(5):
            print(sock.recv(10))
            print("shit")

if __name__ == "__main__":
    #    HOST, PORT = socket.gethostname(), HTTP_PORT
    #
    #    tcp_server = ThreadedTCPServer((HOST, PORT), RequestHandler)
    #    ip, port = tcp_server.server_address
    #    server_thread = threading.Thread(target=tcp_server.serve_forever)
    #    server_thread.daemon = True
    #    server_thread.start()
    #    print("Server loop running in thread:", server_thread.name)
    test_client("127.0.0.1", 800, b'GET / HTTP/1.1\r\nHost:www.google.com\r\n\r\n')
#    time.sleep(5)
#    tcp_server.shutdown()
#    tcp_server.server_close()
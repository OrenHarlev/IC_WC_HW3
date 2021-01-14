""" Man in the middle utilities module.
    This module contains useful tools that mitm utilizes to accomplish its goal.
"""

from http.server import BaseHTTPRequestHandler
from io import BytesIO
from socket import gethostname
import socket
import os
import ipaddress
from contextlib import closing
from guesslang import Guess, GuesslangError


FW_CONN_PATH = "/sys/class/fw/conns/conns"
C_SIMILAR_LANG = ["C", "C++", "Java", "Objective-C"]
SOURCE_CODE_MIN_LEN = 50

class HTTPRequest(BaseHTTPRequestHandler):
    """ Parses HTTP/HTTPS requests for easy interpolation.
        Note:
            https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler
    """

    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


class color:
    """ Allows the printing of color in console.
    Note:
        To use this class simply refer to the colors below as so:
            print(color.red("String in here."))
    """

    reset = "\u001b[0m"

    @staticmethod
    def red(text):
        return "\033[1;31;40m{}".format(text) + color.reset

    @staticmethod
    def green(text):
        return "\033[1;32;40m{}".format(text) + color.reset

    @staticmethod
    def yellow(text):
        return "\033[1;33;40m{}".format(text) + color.reset

    @staticmethod
    def blue(text):
        return "\033[1;34;40m{}".format(text) + color.reset

    @staticmethod
    def purple(text):
        return "\033[1;35;40m{}".format(text) + color.reset

    @staticmethod
    def cyan(text):
        return "\033[1;36;40m{}".format(text) + color.reset

    @staticmethod
    def white(text):
        return "\033[1;37;40m{}".format(text) + color.reset


def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))


def get_available_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def update_connection(client_ip, server_ip, client_port, server_port, local_port):
    client_ip = ip_to_int(client_ip)
    server_ip = ip_to_int(server_ip)
    with open(FW_CONN_PATH, 'w') as f:
        f.write("{} {} {} {} {}".format(client_ip, server_ip, client_port, server_port, local_port))


def get_server_ip_from_client(client_addr):
    with open(FW_CONN_PATH, 'r') as f:
        conn_table = f.read().splitlines()

    for line in conn_table:
        line = line.split()
        if client_addr[0] == line[1] and client_addr[1] == int(line[3]):
            return line[2]


def is_source_code(data):
    if len(data) < SOURCE_CODE_MIN_LEN:
        return False
    try:
        guess = Guess()
        lang = guess.language_name(data)
        for l in C_SIMILAR_LANG:
            if lang == l:
                return True
        return False
    except GuesslangError as e:
        print(color.red(e))

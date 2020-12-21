from http.server import BaseHTTPRequestHandler
from io import BytesIO
from socket import gethostname
import os


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):

        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class color:
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
import asyncio
import re

from client import EmulatedClient
from utils import HTTPRequest, color
from http.client import HTTPResponse
from io import BytesIO

NUM_REGEX = r"(0|[1-9][0-9]?|1[0-9][0-9]|2[0-5][0-5])"

class FTP(asyncio.Protocol):
    #TODO Get from OS
    def get_dst_ip(self, transport):
        return "127.0.0.1"

    def is_port(self, request):
        m = self.port_pattern.match(request.decode('ascii'))
        if m:
            print(self.num_pattern.search(request.decode('ascii')).group(0).split(','))
            return True
        return False

    def port_command_hook(self, reply):
        return

    def connection_made(self, transport):
        self.transport = transport
        self.emulated_client = EmulatedClient()
        dst_ip = self.get_dst_ip(self.transport)
        print(color.yellow("connection with {}{}\n".format(dst_ip, 21)))
        self.emulated_client.sock_connect(dst_ip)
        response = self.emulated_client.sock_receive()
        print(color.yellow("Answersing: {}\n".format(response.decode('ascii'))))
        self.transport.write(response)
        port_seq_pattern = r"(" + NUM_REGEX + ",){5}" + r"(" + NUM_REGEX + ")"
        self.port_pattern = re.compile(r"^PORT " + port_seq_pattern + r"\r\n$")
        self.num_pattern = re.compile(port_seq_pattern)

    def data_received(self, request):
        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        # Prints the data.
        print(request)

        if self.is_port(request):
            print(color.red("\nFound PORT request\n"))
            # Closing the EmulatedClient socket.
            #self.emulated_client.sock_close()

            # Closing connection with the client.
            #self.close()

        # Sends the data to the server.
        self.emulated_client.sock_send(request)

        # Recives the reply and responds back to client.
        reply = self.emulated_client.sock_receive()

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        #print(reply)


        self.transport.write(reply)


    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()


class Interceptor(asyncio.Protocol):
    def __init__(self):
        # Initiating our HTTP/HTTPS protocols.
        self.FTP = FTP()

    def connection_made(self, transport):
        # Setting our transport object.
        self.transport = transport

        # Getting the client address and port number.
        address, port = self.transport.get_extra_info("peername")

        # Prints opening client information.
        print(color.blue("CONNECTING WITH {}:{}".format(address, port)))
        self.FTP.connection_made(self.transport)

    # Called when a connected client sends data to the server.
    def data_received(self, data):
        self.FTP.data_received(data)
import asyncio

from client import EmulatedClient
from utils import HTTPRequest, color, FakeSocket
from http.client import HTTPResponse
from io import BytesIO

FORBIDDEN_TYPES = ["text/csv", "application/zip"]

class HTTP(asyncio.Protocol):

    def should_filter_out_reply(self, reply):
        response = HTTPResponse(FakeSocket(reply))
        response.begin()
        content_type = response.getheader('Content-Type')
        for forbidden_type in FORBIDDEN_TYPES:
            if forbidden_type in content_type:
                return True
        return False

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        # Creates emulated client.
        emulated_client = EmulatedClient()

        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        emulated_client.sock_connect(data)

        # Prints the data.
        print(data)

        # Sends the data to the server.
        emulated_client.sock_send(data)

        # Recives the reply and responds back to client.
        reply = emulated_client.sock_receive()

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        #print(reply)

        if not self.should_filter_out_reply(reply):
            self.transport.write(reply)
            return

        # Closing the EmulatedClient socket.
        emulated_client.sock_close()

        # Closing connection with the client.
        self.close()

    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()


class Interceptor(asyncio.Protocol):
    def __init__(self):
        self.HTTP = HTTP()

    def connection_made(self, transport):
        # Setting our transport object.
        self.transport = transport

        # Getting the client address and port number.
        address, port = self.transport.get_extra_info("peername")

        # Prints opening client information.
        print(color.blue("CONNECTING WITH {}:{}".format(address, port)))

    def data_received(self, data):
        # Parses the data the client has sent to the server.
        request = HTTPRequest(data)

        # Receives standard, non-encrypted data from the client (TLS/SSL is off).
        self.HTTP.connection_made(self.transport)
        self.HTTP.data_received(data)
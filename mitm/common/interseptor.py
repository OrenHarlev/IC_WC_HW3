import asyncio
from .utils import HTTPRequest, color


class Interceptor(asyncio.Protocol):
    def __init__(self, server):
        self.server = server

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
        self.server.connection_made(self.transport)
        self.server.data_received(data)
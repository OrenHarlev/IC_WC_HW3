""" Man in the middle server module.
    The objects below are the primary interface between the client and the mitm
    server. Interceptor, HTTP are defined as 'asyncio.Protocol' objects.
    MITM works in the following steps:
        1. Client request is intercepted by the Interceptor protocol.
        3. The HTTP protocol receives the clients data, and creates an
            EmulatedClient to send the information to the designated server.
        4. The HTTP protocol then replies back to the client via the
            transporter object.
"""

import asyncio
from common.client import EmulatedClient
from common.utils import HTTPRequest, color, get_available_port, update_connection, get_server_ip_from_client, is_source_code
from common.API import ManInTheMiddle
from common.interseptor import Interceptor
from http.client import HTTPResponse
from io import BytesIO


TYPES_TO_FILTER = ["text/csv", "application/zip"]


def should_drop_response(response):
    response = HTTPResponse(FakeSocket(response))
    response.begin()
    content_type = response.getheader('Content-Type')
    for forbidden_type in TYPES_TO_FILTER:
        if forbidden_type in content_type:
            return True
    data = response.read()
    if is_source_code(data):
        return True
    return False


class FakeSocket():
    #A 'hack' class to solve data read api problem
    def __init__(self, response_str):
        self._file = BytesIO(response_str)
    def makefile(self, *args, **kwargs):
        return self._file


class HTTP(asyncio.Protocol):
    """ Protocol for speaking with client via HTTP.
        This class overrides the methods described by the asyncio.Protocol class.
        Args:
            emulated_client (EmulatedClient): Emulated client that speakes to outbound server.
            transport (asyncio.BaseTransport): Transporter that read/writes to client.
            connect_statement (bytes):  The HTTP CONNECT method message.
    """

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        # Creates emulated client.
        emulated_client = EmulatedClient()

        # Updating fw connection table
        server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
        local_port = get_available_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        update_connection(client_ip, server_ip, client_port, 80, local_port)

        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        emulated_client.sock_connect(local_port, server_ip, 80)

        # Prints the data.
        print(data)

        # Sends the data to the server.
        emulated_client.sock_send(data)

        # Recives the reply and responds back to client.
        reply = emulated_client.sock_receive(True)

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        print(reply)

        # Closing if response is illegal
        if should_drop_response(reply):
            # Closing the EmulatedClient socket.
            emulated_client.sock_close()
            # Closing connection with the client.
            self.close()
        else:
            # Sending the response to the user
            self.transport.write(reply)
        return


    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()



ManInTheMiddle(host="10.0.2.15", port=800).run(lambda: Interceptor(HTTP()))
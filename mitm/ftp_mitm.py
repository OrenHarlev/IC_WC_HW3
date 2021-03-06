
import asyncio
import re

from common.utils import color, get_available_port, update_connection, get_server_ip_from_client
from common.client import EmulatedClient
from common.API import ManInTheMiddle
from common.interseptor import Interceptor


FTP_PORT = 21
FTP_DATA_PORT = 20
FTP_PROXY_PORT = 210

IP_NUM_REGEX = r"([0-9][0-9]?[0-9]?)"
PORT_ARG_REGEX = r"(" + IP_NUM_REGEX + ",){5}" + r"(" + IP_NUM_REGEX + ")"
PORT_REQ_REGEX = r"^PORT " + PORT_ARG_REGEX + r"\r\n$"
ARG_FROM_REQ_REGEX = PORT_ARG_REGEX + r"\r\n"


class FTP(asyncio.Protocol):
    def __init__(self):
        self.port_req_regex = re.compile(PORT_REQ_REGEX)
        self.port_arg_regex = re.compile(ARG_FROM_REQ_REGEX)
        self.expect_extra_response = False

    def connection_made(self, transport):
        self.transport = transport

        # Creates emulated client.
        self.emulated_client = EmulatedClient()

        # Updating fw connection table
        server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
        print(color.yellow("connection with {}{}\n".format(server_ip, FTP_PORT)))
        local_port = get_available_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        update_connection(client_ip, server_ip, client_port, FTP_PORT, local_port)

        # getting and printing the first response
        self.emulated_client.sock_connect(local_port, server_ip, FTP_PORT)
        response = self.emulated_client.sock_receive(False)
        print(color.yellow("Answersing: {}\n".format(response.decode('ascii'))))
        self.transport.write(response)

    def data_received(self, request):
        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        # Prints the data.
        print(request)

        is_port_req = self.port_req_regex.match(request.decode('ascii'))

        # A Port request detected
        if is_port_req:
            print(color.red("\nPORT request detected\n"))

            # Updating fw connection table with data connection
            args = re.split(",|\r\n", self.port_arg_regex.search(request.decode('ascii')).group(0))
            client_ip = "{}.{}.{}.{}".format(args[0], args[1], args[2], args[3])
            client_port = int(args[4]) * 256 + int(args[5])
            server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
            update_connection(server_ip, client_ip, FTP_DATA_PORT, client_port, 0)

        # Sends the data to the server.
        self.emulated_client.sock_send(request)

        # Recives the reply and responds back to client.
        reply = self.emulated_client.sock_receive(False)

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        print(reply)

        # Sending the response to the user
        self.transport.write(reply)

        # checking special case were server sends two responses
        if self.expect_extra_response:
            reply = self.emulated_client.sock_receive(False)

            print(color.yellow("\nSERVER REPLY:\n"))
            print(reply)

            self.transport.write(reply)
            self.expect_extra_response = False

        # setting the case were expecting two responses
        if is_port_req:
            self.expect_extra_response = True


    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()


ManInTheMiddle(host="10.0.2.15", port=FTP_PROXY_PORT).run(lambda: Interceptor(FTP()))

import asyncio

from common.utils import color, get_available_port, update_connection, get_server_ip_from_client
from common.client import EmulatedClient
from common.API import ManInTheMiddle

FOUR_LETTERS_CMD = ["conf", "cons", "crst", "dirs", "dump", "envi", "gtmk", "ruok", "stmk", "srvr", "srst", "stat", "wchc", "wchp", "wchs", "mntr", "isro", "hash"]

class IPS(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport

        # Creates emulated client.
        self.emulated_client = EmulatedClient()

        # Updating fw connection table
        server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
        print(color.yellow("connection with {}{}\n".format(server_ip, 21)))
        local_port = get_available_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        update_connection(client_ip, server_ip, client_port, 21, local_port)

        # getting and printing the first response
        self.emulated_client.sock_connect(local_port, server_ip, 21)
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
            update_connection(server_ip, client_ip, 20, client_port, 0)

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


ManInTheMiddle(host="10.0.2.15", port=210).run(lambda: Interceptor())

import asyncio
from common.client import EmulatedClient
from common.utils import color, get_available_port, update_connection, get_server_ip_from_client, is_source_code
from common.API import ManInTheMiddle
from common.interseptor import Interceptor


def should_drop_data(data):
    return is_source_code(data)


class SMTP(asyncio.Protocol):

    def __init__(self):
        self.expect_data = False

    def connection_made(self, transport):
        self.transport = transport

        # Creates emulated client.
        self.emulated_client = EmulatedClient()

        # Updating fw connection table
        server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
        local_port = get_available_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        update_connection(client_ip, server_ip, client_port, 25, local_port)

        # getting and printing the first response
        self.emulated_client.sock_connect(local_port, server_ip, 25)
        response = self.emulated_client.sock_receive(False)
        print(color.yellow("Answersing: {}\n".format(response)))
        self.transport.write(response)

    def data_received(self, data):
        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        # Prints the data.
        print(data)

        if self.expect_data:
            if should_drop_data(data):
                # Closing the EmulatedClient socket.
                self.emulated_client.sock_close()
                # Closing connection with the client.
                self.close()
                return
            self.expect_data = False


        if data == "DATA":
            self.expect_data = True

        # Sends the data to the server.
        self.emulated_client.sock_send(data)

        # Recives the reply and responds back to client.
        reply = self.emulated_client.sock_receive(True)

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        print(reply)

        # Sending the response to the user
        self.transport.write(reply)
        return


    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()



ManInTheMiddle(host="10.0.2.15", port=250).run(lambda: Interceptor(SMTP()))
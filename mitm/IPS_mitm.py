
import asyncio
from common.client import EmulatedClient
from common.utils import color, get_available_port, update_connection, get_server_ip_from_client
from common.API import ManInTheMiddle
from common.interseptor import SingleExchangeInterceptor

ZOOKEPPER_PORT = 2181
ZOOKEPPER_PROXY_PORT = 21810

FOUR_LETTERS_CMD = ["conf", "cons", "crst", "dirs", "dump", "envi", "gtmk", "ruok", "stmk", "srvr", "srst", "stat", "wchc", "wchp", "wchs", "mntr", "isro", "hash"]


def should_drop_request(request):
    for cmd in FOUR_LETTERS_CMD:
        if cmd == str(request):
            return True
    return False


class IPS(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        # Creates emulated client.
        emulated_client = EmulatedClient()

        # Updating fw connection table
        server_ip = get_server_ip_from_client(self.transport.get_extra_info("peername"))
        local_port = get_available_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        update_connection(client_ip, server_ip, client_port, ZOOKEPPER_PORT, local_port)

        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        emulated_client.sock_connect(local_port, server_ip, ZOOKEPPER_PORT)

        # Prints the data.
        print(data)

        if should_drop_request(data):
            # Closing the EmulatedClient socket.
            emulated_client.sock_close()
            # Closing connection with the client.
            self.close()
            return

        # Sends the data to the server.
        emulated_client.sock_send(data)

        # Recives the reply and responds back to client.
        reply = emulated_client.sock_receive(True)

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        print(reply)

        self.transport.write(reply)
        return


    def close(self):
        print(color.red("\nCLOSING CONNECTION\n"))

        # Closes connection with the client.
        self.transport.close()



ManInTheMiddle(host="10.0.2.15", port=ZOOKEPPER_PROXY_PORT).run(lambda: SingleExchangeInterceptor(IPS()))
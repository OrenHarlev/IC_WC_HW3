import asyncio

from common.client import EmulatedClient
from common.utils import HTTPRequest, color, FakeSocket, PortFinder, IpUtils
from common.API import ManInTheMiddle

from http.client import HTTPResponse
from io import BytesIO

CONN_FILE = "/sys/class/fw/conns/conns"
FORBIDDEN_TYPES = ["text/csv", "application/zip"]

class HTTP(asyncio.Protocol):

    def line_match_client_address(self, client_address, line):
        return client_address[0] == line[1] and client_address[1] == int(line[3])

    def get_server_ip(self):
        with open(CONN_FILE, 'r') as f:
            conn_table = f.read().splitlines()
        for line in conn_table:
            line = line.split()
            print(line)
            print(self.transport.get_extra_info("peername"))
            if self.line_match_client_address(self.transport.get_extra_info("peername"), line):
                return line[2]

    def update_port_y(self, src_ip, dst_ip, src_port, dst_port, port_y):
        src_ip = IpUtils.string_to_num(src_ip)
        dst_ip = IpUtils.string_to_num(dst_ip)
        with open(CONN_FILE, 'w') as f:
            print("{} {} {} {} {}".format(src_ip, dst_ip, src_port, dst_port, port_y))
            f.write("{} {} {} {} {}".format(src_ip, dst_ip, src_port, dst_port, port_y))


    def should_filter_out_reply(self, reply):
        response = HTTPResponse(FakeSocket(reply))
        response.begin()
        content_type = response.getheader('Content-Type')
        for forbidden_type in FORBIDDEN_TYPES:
            if forbidden_type in content_type:
                return True
        return False

    def connection_made(self, transport):
        print ("connection made")
        self.transport = transport

    def data_received(self, data):
        # Creates emulated client.
        emulated_client = EmulatedClient()

        port_y = PortFinder.find_free_port()
        server_ip = self.get_server_ip()
        client_ip, client_port = self.transport.get_extra_info("peername")
        self.update_port_y(client_ip, server_ip, client_port, 80, port_y)


        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        emulated_client.sock_connect(port_y, server_ip, 80)

        # Prints the data.
        print(data)

        # Sends the data to the server.
        emulated_client.sock_send(data)

        # Recives the reply and responds back to client.
        reply = emulated_client.sock_receive(True)

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



ManInTheMiddle(host="10.0.2.15", port=800).run(lambda: Interceptor())
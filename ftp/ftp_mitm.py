import asyncio
import re

from http.client import HTTPResponse
from common.utils import color, PortFinder, IpUtils
from common.client import EmulatedClient
from common.API import ManInTheMiddle

CONN_FILE = "/sys/class/fw/conns/conns"
#NUM_REGEX = r"(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9])"
NUM_REGEX = r"([0-9][0-9]?[0-9]?)"
#double_response = True


class FTP(asyncio.Protocol):
    def __init__(self):
        self.double_response = False
        port_seq_pattern = r"(" + NUM_REGEX + ",){5}" + r"(" + NUM_REGEX + ")"
        self.port_pattern = re.compile(r"^PORT " + port_seq_pattern + r"\r\n$")
        self.num_pattern = re.compile(port_seq_pattern + r"\r\n")


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


    def is_port(self, request):
        m = self.port_pattern.match(request.decode('ascii'))
        if m:
            return True
        return False

    def get_address_from_prot(self, request):
        adr = re.split(",|\r\n", self.num_pattern.search(request.decode('ascii')).group(0))
        print(adr)
        return ("{}.{}.{}.{}".format(adr[0], adr[1], adr[2], adr[3]), int(adr[4])* 256 + int(adr[5]))

    def port_command_hook(self, reply):
        return

    def connection_made(self, transport):
        self.transport = transport
        self.emulated_client = EmulatedClient()
        dst_ip = self.get_server_ip()
        print(color.yellow("connection with {}{}\n".format(dst_ip, 21)))
        port_y = PortFinder.find_free_port()
        client_ip, client_port = self.transport.get_extra_info("peername")
        self.update_port_y(client_ip, dst_ip, client_port, 21, port_y)
        self.emulated_client.sock_connect(port_y, dst_ip, 21)
        response = self.emulated_client.sock_receive(False)
        print(color.yellow("Answersing: {}\n".format(response.decode('ascii'))))
        self.transport.write(response)

    def data_received(self, request):
        #global double_response
        # Printing prompt.
        print(color.yellow("\nSENDING DATA:\n"))

        # Prints the data.
        print(request)

        if self.is_port(request):
            print(color.red("\nFound PORT request\n"))
            client_ip, client_port = self.get_address_from_prot(request)
            self.update_port_y(self.get_server_ip(), client_ip, 20, client_port, 0)

        # Sends the data to the server.
        self.emulated_client.sock_send(request)

        # Recives the reply and responds back to client.
        reply = self.emulated_client.sock_receive(False)

        # Printing the reply back to console.
        print(color.yellow("\nSERVER REPLY:\n"))
        print(reply)


        self.transport.write(reply)

        if self.double_response:
            print("IN DOUBLE RESPONSE")
            # Recives the reply and responds back to client.
            reply = self.emulated_client.sock_receive(False)

            # Printing the reply back to console.
            print(color.yellow("\nSERVER REPLY:\n"))
            print(reply)


            self.transport.write(reply)
            self.double_response = False



        if self.is_port(request):
            self.double_response = True



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
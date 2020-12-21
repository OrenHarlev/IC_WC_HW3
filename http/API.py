import asyncio

from utils import color
from server import Interceptor


class ManInTheMiddle(object):
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port

    def run(self):
        # Gets the current event loop (or creates one).
        self.loop = asyncio.get_event_loop()

        self.loop.create_task(self.start())

        self.loop.run_forever()

    async def start(self):
        # Creates the server instance.
        self.server = await self.loop.create_server(
            lambda: Interceptor(), host=self.host, port=self.port
        )

        # Prints information about the server.
        ip, port = self.server.sockets[0].getsockname()
        print(color.green("Routing traffic on server {}:{}.\n".format(ip, port)))
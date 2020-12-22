""" Man in the middle API module.
    This module is intended to make it easy to start an mitm server.
"""

import asyncio

from .utils import color


class ManInTheMiddle(object):

    """
        Attributes:
            host (str): Host's IP.
            port (int): Host's port.
            loop (asyncio.loop): Current asyncio loop.
            server (asyncio.Server): Mitm server.
    """

    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port

    def run(self, server_factory):
        # Gets the current event loop (or creates one).
        self.loop = asyncio.get_event_loop()

        self.loop.create_task(self.start(server_factory))

        self.loop.run_forever()

    async def start(self, server_factory):
        # Creates the server instance.
        self.server = await self.loop.create_server(
            server_factory, host=self.host, port=self.port
        )

        # Prints information about the server.
        ip, port = self.server.sockets[0].getsockname()
        print(color.green("Routing traffic on server {}:{}.\n".format(ip, port)))
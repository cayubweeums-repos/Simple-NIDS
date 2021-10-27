import logging
import socket
import multiprocessing
from objects.packet import Packet


class Sniffer(multiprocessing.Process):
    def __init__(self, _queue, _time):
        super(Sniffer, self).__init__()
        self.socket = None
        self.time = _time
        self.queue = _queue
        self.on = True
        self.raw_data = None

    def run(self):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while self.on:
            self.raw_data = self.socket.recv(65536)
            packet = Packet(self.raw_data)
            packet.parse()

            # For testing, allows to view all traffic coming in and out in the log
            # logging.basicConfig(filename='logs/{}.logs'.format(self.time), level=logging.INFO)
            # logging.info(packet)
            self.queue.put(packet)

    def stop(self):
        self.on = False
        self.join()
        # self.terminate()
        self.close()

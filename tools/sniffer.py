import logging
import socket
from multiprocessing import Process
from objects.packet import Packet


class Sniffer(Process):
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
            logging.basicConfig(filename='logs/' + self.time + '.log', level=logging.INFO)
            logging.info(packet)
            self.queue.put(packet)
            print(packet.signature)

    def stop(self):
        self.on = False

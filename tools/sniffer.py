import socket
import multiprocessing
import sys
from time import sleep
from signature.objects.packet import Packet
from rich.console import Console


class Sniffer(multiprocessing.Process):
    def __init__(self, _queue, log):
        super(Sniffer, self).__init__()
        self.console = Console()
        self.socket = None
        self.log = log
        self.queue = _queue
        self.on = False
        self.raw_data = None
        self.csv_file = None

    def run(self):
        while not self.on:
            sleep(1)
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        with self.console.status("[bold green]Sniffing Packets...") as status:
            while self.on:
                self.raw_data = self.socket.recv(65536)
                packet = Packet(self.raw_data, self.log)
                packet.parse()

                # For testing, allows to view all traffic coming in and out in the log
                # logging.basicConfig(filename='logs/{}.logs'.format(self.time), level=logging.INFO)
                # logging.info(packet)
                self.queue.put(packet)

    def stop(self):
        self.on = False
        self.join()
        self.close()

    def turn_on(self):
        self.on = True


    # def data_parser(self, training_pcap_loc):
    #     read_pcap = dpkt.pcap.Reader(open(training_pcap_loc))
    #     for x, y in read_pcap:
    #         eth_pkt = dpkt.ethernet.Ethernet(y)
    #         ip_pkt = eth_pkt.data
    #         proto_pkt = ip_pkt.data
    #     print()

import logging
import socket
import struct
from ipaddress import IPv4Address
import sys
from tools import helpers


class Packet:
    def __init__(self, data):
        self.flags = []
        self.name = self.__class__.__name__
        self.len = len(data)

        # Grab eth frames and unpack
        rec_mac, send_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        self.rec_mac = helpers.format_mac(rec_mac)
        self.send_mac = helpers.format_mac(send_mac)
        self.protocol = socket.htons(protocol)
        self._data = data[14:]
        self.signature = None

    # Grab ipv4 packets and unpack
    def parse(self):
        if self.protocol == 8:
            self.ipv4()
            if self.protocol == 6:
                self.tcp()
            elif self.protocol == 17:
                self.udp()
            elif self.protocol == 1:
                self.icmp()
            else:
                sys.stdout.write("######## UNKNOWN IPV4 PROTOCOL ########")
        else:
            sys.stdout.write("######## UNKNOWN ETH PROTOCOL ########")

    def ipv4(self):
        data = self._data
        self.send_ip = IPv4Address(data[12:16])
        self.rec_ip = IPv4Address(data[16:20])
        self.ihl = (data[0] & 15) * 4
        self.protocol = data[9]
        self.ip_header = data[:self.ihl]
        self._data = data[self.ihl:]

    def tcp(self):
        data = self._data
        # ORF = offset, reserved, and flags. All of these are packaged in a different sequence of bits than the others.
        # The others all get 16 bits per
        source_port, destination_port, sequence, acknowledgement, orf = struct.unpack('! H H L L H', data[:14])
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence = sequence
        self.acknowledgement = acknowledgement

        offset = (orf >> 12) * 4
        # all of the flags used in a three way handshake to determine a connection.

        if ((orf & 32) >> 5) == 1:
            self.flags.append('URG')
        elif ((orf & 16) >> 4) == 1:
            self.flags.append('ACK')
        elif ((orf & 8) >> 3) == 1:
            self.flags.append('PSH')
        elif ((orf & 4) >> 2) == 1:
            self.flags.append('RST')
        elif ((orf & 2) >> 1) == 1:
            self.flags.append('SYN')
        elif (orf & 1) == 1:
            self.flags.append('FIN')
        self.payload = data[offset:]
        self.signature = 'tcp {} {}'.format(self.send_ip, self.source_port) + ' -> {} {}'.format(self.rec_ip,
                                                                                                 self.destination_port)

    def udp(self):
        data = self._data
        source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
        self.source_port = source_port
        self.destination_port = destination_port
        self.size = size
        self.proto_header = data[:8]
        self.payload = data[8:]
        self.signature = 'udp {} {}'.format(self.send_ip, self.source_port) + ' -> {} {}'.format(self.rec_ip,
                                                                                                 self.destination_port)

    def icmp(self):
        data = self._data
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.payload = data[4:]
        self.signature = 'icmp {} {}'.format(self.send_ip, self.source_port) + ' -> {} {}'.format(self.rec_ip,
                                                                                                  self.destination_port)

    # For testing purposes
    def log(self, t):
        logging.basicConfig(filename='logs/{}.logs'.format(t), level=logging.INFO)
        if self.protocol == 6:
            logging.info(
                'TCP Packet: \n\t\tSource Port: {}, Destination Port: {}, Sequence: {}\n'.format(self.source_port,
                                                                                                 self.destination_port,
                                                                                                 self.sequence))
            logging.info('\t\tAcknowledgement: {}\n'.format(self.acknowledgement))
            logging.info('\t\tFlags: {}\n'.format(self.flags))
            logging.info('\t\tData:\n{}'.format(self.payload))
        elif self.protocol == 17:
            logging.info('\tUDP Packet:\n\t\tSource Port: {}, Destination Port: {}, Size: {}'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.size))
            logging.info('\t\tProto Header: {}'.format(self.proto_header))
            logging.info('\t\tData: \n{}'.format(self.payload))
        elif self.protocol == 1:
            logging.info('\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code,
                                                                                             self.checksum))
            logging.info('\t\tData: \n{}'.format(self.payload))
        else:
            sys.stdout.write("######## UNKNOWN IPV4 PROTOCOL ########")

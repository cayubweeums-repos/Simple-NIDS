import logging
import socket
import struct
from ipaddress import IPv4Address
import sys
from tools import helpers


class Packet:
    # TODO place packets in similar format to that of the dataset or parse the dataset packets into a generic format
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
        self.send_ip = None
        self.rec_ip = None
        self.source_port = None
        self.destination_port = None

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
        self.send_ip = '{}'.format(IPv4Address(data[12:16]))
        self.rec_ip = '{}'.format(IPv4Address(data[16:20]))
        self.ihl = (data[0] & 15) * 4
        self.protocol = data[9]
        self.ip_header = data[:self.ihl]
        self._data = data[self.ihl:]

    def tcp(self):
        data = self._data
        self.protocol = 'tcp'
        # ORF = offset, reserved, and flags. All of these are packaged in a different sequence of bits than the others.
        # The others all get 16 bits per
        source_port, destination_port, sequence, acknowledgement, orf = struct.unpack('! H H L L H', data[:14])
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence = sequence
        self.ack = '{}'.format(acknowledgement)

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
        self.protocol = 'udp'
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
        self.protocol = 'icmp'
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.payload = data[4:]
        self.signature = 'icmp {} {}'.format(self.send_ip, self.source_port) + ' -> {} {}'.format(self.rec_ip,
                                                                                                  self.destination_port)

    # Print the packet to the log based on its protocol in a readable way
    def log(self, t):
        logging.basicConfig(filename='logs/{}.logs'.format(t), level=logging.INFO)
        logging.info('IPv4 Packet: \n\t Sending IP: {}\n\tReceiving IP: {}\n\tProtocol: {}'.format(self.send_ip,
                                                                                                   self.rec_ip,
                                                                                                   self.protocol))
        if self.protocol == 'tcp':
            logging.info(
                '\t\tTCP Packet: \n\t\tSource Port: {}, Destination Port: {}, Sequence: {}\n'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.sequence))
            logging.info('\t\tAcknowledgement: {}\n'.format(self.ack))
            logging.info('\t\tFlags: {}\n'.format(self.flags))
            logging.info('\t\tData:\n{}'.format(self.payload))
        elif self.protocol == 'udp':
            logging.info('\tUDP Packet:\n\t\tSource Port: {}, Destination Port: {}, Size: {}'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.size))
            logging.info('\t\tProto Header: {}'.format(self.proto_header))
            logging.info('\t\tData: \n{}'.format(self.payload))
        elif self.protocol == 'icmp':
            logging.info('\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code,
                                                                                             self.checksum))
            logging.info('\t\tData: \n{}'.format(self.payload))
        else:
            sys.stdout.write("######## UNKNOWN IPV4 PROTOCOL ########")

    def error(self, t):
        logging.basicConfig(filename='logs/{}.logs'.format(t), level=logging.INFO)
        logging.info('IPv4 Packet: \n\t Sending IP: {}\n\tReceiving IP: {}\n\tProtocol: {}'.format(self.send_ip,
                                                                                                   self.rec_ip,
                                                                                                   self.protocol))
        if self.protocol == 'tcp':
            logging.error(
                '\t\tTCP Packet: \n\t\tSource Port: {}, Destination Port: {}, Sequence: {}\n'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.sequence) +
                '\t\tAcknowledgement: {}\n\t\tFlags: {}\n\t\tData:\n{}'.format(self.ack, self.flags, self.payload)
            )
        elif self.protocol == 'udp':
            logging.error('\tUDP Packet:\n\t\tSource Port: {}, Destination Port: {}, Size: {}'.format(self.source_port,
                                                                                                      self.destination_port,
                                                                                                      self.size) +
                          '\t\tProto Header: {}\n\t\tData: \n{}'.format(self.proto_header, self.payload)
                          )
        elif self.protocol == 'icmp':
            logging.error('\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code,
                                                                                              self.checksum) +
                          '\t\tData: \n{}'.format(self.payload)
                          )
        else:
            logging.error("######## UNKNOWN IPV4 PROTOCOL ########")

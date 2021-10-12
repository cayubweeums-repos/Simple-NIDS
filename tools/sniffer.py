import os
import socket
import struct
from ipaddress import IPv4Address
import time
import sys
import re


# Helper funcs

def format_mac(unparsed_mac):
    bytes_str = map('{:02X}'.format, unparsed_mac)
    return ':'.join(bytes_str)


# Protocol parsing

class Packet:
    def __init__(self, data):
        self.flags = []
        self.name = self.__class__.__name__
        self.time = time.time()
        self.len = len(data)

        # Grab eth frames and unpack
        rec_mac, send_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        self.rec_mac = format_mac(rec_mac)
        self.send_mac = format_mac(send_mac)
        self.protocol = socket.htons(protocol)
        self._data = data[14:]

    # Grab ipv4 packets and unpack
    def parse(self):
        if self.protocol == 8:
            print('\nEthernet Frame: ' + 'Receiver: {}, Sender: {}, Protocol: {}'.format(self.rec_mac, self.send_mac,
                                                                                         self.protocol))
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
        print('\t' + 'IPV4 Packet:')
        print('\t\t' + 'Protocol: {}, Sender: {}, Receiver: {}'.format(self.protocol, self.send_ip, self.rec_ip))

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

    def udp(self):
        data = self._data
        source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
        self.source_port = source_port
        self.destination_port = destination_port
        self.size = size
        self.proto_header = data[:8]
        self.payload = data[8:]

    def icmp(self):
        data = self._data
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.payload = data
        return icmp_type, code, checksum, data[4:]

    def print(self):
        if self.protocol == 6:
            print('\t' + 'TCP Packet:')
            print('\t\t' + 'Source Port: {}, Destination Port: {}, Sequence: {}'.format(self.source_port,
                                                                                        self.destination_port,
                                                                                        self.sequence))
            print('\t\t' + 'Acknowledgement: {}'.format(self.acknowledgement))
            print('\t\t' + 'Flags: {}'.format(self.flags))
            print('\t\t' + 'Data:\n {}'.format(self.payload))
        elif self.protocol == 17:
            print('\t' + 'UDP Packet:')
            print(
                '\t\t' + 'Source Port: {}, Destination Port: {}, Size: {}'.format(self.source_port,
                                                                                  self.destination_port, self.size))
            print('\t' + 'Proto Header: {}'.format(self.proto_header))
            print('\t' + 'Data: \n{}'.format(self.payload))
        elif self.protocol == 1:
            print('\t' + 'ICMP Packet:')
            print('\t\t' + 'ICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code, self.checksum))
            print('\t\t' + 'Data: {}'.format(self.payload))
        else:
            sys.stdout.write("######## UNKNOWN IPV4 PROTOCOL ########")
        pass


# Main Loop

def main():
    main_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = main_socket.recv(65536)
        packet = Packet(raw_data)
        packet.parse()
        packet.print()


main()

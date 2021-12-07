import logging
import socket
import struct
from ipaddress import IPv4Address
import sys
from tools import helpers, packet_signature_pipeline
from signature.objects.common_ports import get_name_4_value


class Packet:
    # TODO place packets in similar format to that of the dataset or parse the dataset packets into a generic format
    def __init__(self, data):
        self.flags = []
        self.name = self.__class__.__name__
        self.ip_len = len(data)
        self.protocol_len = None

        # Grab eth frames and unpack
        rec_mac, send_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        self.rec_mac = helpers.format_mac(rec_mac)
        self.send_mac = helpers.format_mac(send_mac)
        self.protocol = socket.htons(protocol)
        self.protocol_num = None
        self._data = data[14:]
        self.signature = None
        self.send_ip = None
        self.rec_ip = None
        self.source_port = None
        self.destination_port = None
        self.sequence = ''
        self.ack = ''
        self.icmp_type = ''
        self.icmp_code = ''
        self.icmp_checksum = None

    # Grab ipv4 packets and unpack
    def parse(self):
        if self.protocol == 8:
            self.ipv4()
            if self.protocol == 6:
                self.protocol_num = self.protocol
                self.tcp()
            elif self.protocol == 17:
                self.protocol_num = self.protocol
                self.udp()
            elif self.protocol == 1:
                self.protocol_num = self.protocol
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
        self.protocol_len = len(data)
        self.protocol = 'TCP'
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
        self.signature = self.get_pkt_signature()

    def udp(self):
        data = self._data
        self.protocol_len = len(data)
        self.protocol = 'UDP'
        source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
        self.source_port = source_port
        self.destination_port = destination_port
        self.size = size
        self.proto_header = data[:8]
        self.payload = data[8:]
        self.signature = self.get_pkt_signature()

    def icmp(self):
        data = self._data
        self.protocol_len = len(data)
        self.protocol = 'ICMP'
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        self.icmp_type = icmp_type
        self.icmp_code = code
        self.icmp_checksum = checksum
        self.payload = data[4:]
        self.signature = self.get_pkt_signature()

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
            logging.info(
                '\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.icmp_code,
                                                                                    self.icmp_checksum))
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
                '\t\tTCP Packet: \n\t\tSource Port: {}, Destination Port: {}, Sequence: '
                '{}\n'.format(self.source_port, self.destination_port, self.sequence) +
                '\t\tAcknowledgement: {}\n\t\tFlags: {}\n\t\tData:\n{}'.format(self.ack, self.flags, self.payload)
            )
        elif self.protocol == 'udp':
            logging.error('\tUDP Packet:\n\t\tSource Port: {}, Destination Port: {}, Size: '
                          '{}'.format(self.source_port, self.destination_port, self.size) +
                          '\t\tProto Header: {}\n\t\tData: \n{}'.format(self.proto_header, self.payload)
                          )
        elif self.protocol == 'icmp':
            logging.error('\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: '
                          '{}'.format(self.icmp_type, self.icmp_code, self.icmp_checksum) +
                          '\t\tData: \n{}'.format(self.payload)
                          )
        else:
            logging.error("######## UNKNOWN IPV4 PROTOCOL ########")

    def get_pkt_signature(self):
        # TODO figure out if the signature we have in the training_sets uses ip pkt length or just the protocol
        #  packet length
        raw_signature = ['{}'.format(self.protocol), '{}'.format(get_name_4_value(self.destination_port)),
                         '{}'.format(self.get_formatted_flags()), '{}'.format(self.ip_len),
                         '{}'.format(self.protocol_num), '{}'.format(self.sequence), '{}'.format(self.ack),
                         '{}'.format(self.icmp_type), '{}'.format(self.icmp_code), '{}'.format(self.protocol_len)
                         ]
        # Use test_signature to test the parsing of signatures and predictions in realtime
        test_signature = 'UDP', 'DHCP67', None, 328, None, None, None, None, None, 308

        # clean_signature = packet_signature_pipeline.get_normalized_packet_features(test_signature)
        # return clean_signature
        return raw_signature

    def get_formatted_flags(self):
        temp = ''
        if len(self.flags) == 0 or len(self.flags) is None: return ''
        if self.flags.__contains__('URG'):
            temp += 'U'
        if self.flags.__contains__('ACK'):
            temp += 'A'
        if self.flags.__contains__('PSH'):
            temp += 'P'
        if self.flags.__contains__('SYN'):
            temp += 'S'
        if self.flags.__contains__('FIN'):
            temp += 'F'
        return temp

    # Only use if you want console barf or need to test features
    def print(self):

        print('IPv4 Packet: \n\t Sending IP: {}\n\tReceiving IP: {}\n\tProtocol: {}'.format(self.send_ip,
                                                                                            self.rec_ip,
                                                                                            self.protocol))
        if self.protocol == 'TCP':
            print(
                '\t\tTCP Packet: \n\t\tSource Port: {}, Destination Port: {}, Sequence: {}\n'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.sequence))
            print('\t\tAcknowledgement: {}\n'.format(self.ack))
            print('\t\tFlags: {}\n'.format(self.flags))
            print('\t\tSignature:\n{}'.format(self.signature))
        elif self.protocol == 'UDP':
            print('\tUDP Packet:\n\t\tSource Port: {}, Destination Port: {}, Size: {}'.format(self.source_port,
                                                                                                     self.destination_port,
                                                                                                     self.size))
            print('\t\tProto Header: {}'.format(self.proto_header))
            print('\t\tSignature: \n{}'.format(self.signature))
        elif self.protocol == 'ICMP':
            print(
                '\tICMP Packet: \n\t\tICMP Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.icmp_code,
                                                                                    self.icmp_checksum))
            print('\t\tSignature: \n{}'.format(self.signature))

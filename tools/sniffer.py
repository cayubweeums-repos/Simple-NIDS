import socket
import struct
import sys
import re

# Helper funcs
import textwrap


def format_mac(unparsed_mac):
    bytes_str = map('{:02X}'.format, unparsed_mac)
    return ':'.join(bytes_str)


def format_ipv4(unparsed_ip):
    return '.'.join(map(str, unparsed_ip))


def format_multiline(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


# Protocol parsing


# Grab eth frames and unpack

def eth_frame(data):
    rec_mac, send_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(rec_mac), format_mac(send_mac), socket.htons(protocol), data[14:]


# Grab ipv4 packets and unpack

# Rename to parse when we encompass parsing
def ipv4_packet(data):
    # IP Header range containing version and IHL (Internet Header Length)
    header_vl = data[0]
    v = header_vl >> 4
    ihl = (header_vl & 15) * 4
    ttl, protocol, receiver, sender = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    print('\t' + 'IPV4 Packet:')
    print('\t\t' + 'Version: {}, IHL: {}, TTL: {}'.format(v, ihl, ttl))
    print('\t\t' + 'Protocol: {}, Sender: {}, Receiver: {}'.format(protocol, sender, receiver))
    return v, ihl, ttl, protocol, format_ipv4(sender), format_ipv4(receiver), data[ihl:]


# Grab ICMP packets and unpack
def parse_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print('\t' + 'ICMP Packet:')
    print('\t\t' + 'ICMP Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
    print('\t\t' + 'Data:')
    print(format_multiline(data))
    return icmp_type, code, checksum, data[4:]


# Grab UDP packets and unpack
def parse_udp(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    print('\t' + 'UDP Packet:')
    print('\t\t' + 'Source Port: {}, Destination Port: {}, Size: {}'.format(source_port, destination_port, size))
    print('\t\t' + 'Data:')
    print(format_multiline(data))
    return source_port, destination_port, size, data[8:]


def parse_tcp(data):
    # ORF = offset, reserved, and flags. All of these are packaged in a different sequence of bits than the others.
    # The others all get 16 bits per
    source_port, destination_port, sequence, acknowledgement, orf = struct.unpack('! H H L L H', data[:14])
    offset = (orf >> 12) * 4
    # all of the flags used in a three way handshake to determine a connection.
    flag_urg = (orf & 32) >> 5
    flag_ack = (orf & 16) >> 4
    flag_psh = (orf & 8) >> 3
    flag_rst = (orf & 4) >> 2
    flag_syn = (orf & 2) >> 1
    flag_fin = (orf & 1)
    print('\t' + 'TCP Packet:')
    print(
        '\t\t' + 'Source Port: {}, Destination Port: {}, Sequence: {}'.format(source_port, destination_port, sequence))
    print('\t\t' + 'Acknowledgement: {}, Flag Urg: {}, Flag ack: {}'.format(acknowledgement, flag_urg, flag_ack))
    print('\t\t' + 'Flag Psh: {}, Flag Rst: {}, Flag Syn: {}'.format(flag_psh, flag_rst, flag_syn))
    print('\t\t' + 'Flag Fin: {}'.format(flag_fin))
    print('\t\t' + 'Data:')
    print(format_multiline(data))
    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, \
           flag_fin, data[offset:]


# Main Loop

def main():
    main_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, ipaddress = main_socket.recvfrom(65536)  # Largest buffer size we can receive from is 65535
        rec_mac, send_mac, protocol, data = eth_frame(raw_data)
        print('\nEthernet Frame: ' + 'Receiver: {}, Sender: {}, Protocol: {}'.format(rec_mac, send_mac, protocol))

        # Eth protocol 8 = IPV4
        if protocol == 8:
            v, ihl, ttl, protocol, sender, receiver, data = ipv4_packet(data)

            # Check the packet data for the protocol
            # if protocol 1 == tcmp
            # if protocol 17 = udp
            # if protocol 6 == tcp
            if protocol == 1:
                icmp_type, code, checksum, data = parse_icmp(data)
            elif protocol == 6:
                source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, \
                flag_syn, flag_fin, data = parse_tcp(data)
            elif protocol == 17:
                source_port, destination_port, size, data = parse_udp(data)
            else:
                print('\t' + '########UNKNOWN IPV4 PROTOCOL########')
                print('\t' + 'Protocol: {}'.format(protocol))
                print('\t' + 'Data: {}'.format(data))
        else:
            print('\t' + '########UNKNOWN Eth PROTOCOL########')
            print('\t' + 'Protocol: {}'.format(protocol))
            print('\t' + 'Data: {}'.format(data))


main()

import socket
import struct
import sys
import re


# Helper funcs

def format_mac(bytes_mac):
    bytes_str = map('{:02X}'.format, bytes_mac)
    return ':'.join(bytes_str)


def eth_frame(data):
    rec_mac, send_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(rec_mac), format_mac(send_mac), socket.htons(protocol), data[:14]


# Main Loop
def main():
    main_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, ipaddress = main_socket.recvfrom(65536)  # Largest buffer size we can receive from is 65535
        rec_mac, send_mac, protocol, data = eth_frame(raw_data)
        print('\nEthernet Frame: ' + 'Receiver: {}, Sender: {}, Protocol: {}'.format(rec_mac, send_mac, protocol))


main()

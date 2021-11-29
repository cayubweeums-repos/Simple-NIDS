#!/usr/bin/env python3
import argparse
import os.path
import sys

import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP

"""
The following code is mainly code used from https://github.com/vnetman/pcap2csv and then expanded and adapted
to fit the needs of the IDS. The majority of the code in this file though is not mine along with the comments.
"""

"""pcap2csv
Script to extract specific pieces of information from a pcap file and
render into a csv file.
Usage: <program name> --pcap <input pcap file> --csv <output pcap file>
Each packet in the pcap is rendered into one row of the csv file.
The specific items to extract, and the order in which they are rendered
in the csv are hard-coded in the script, in the 'render_csv_row' function.
Also note that the separators in the csv are '|' characters, not commas.
This script uses *both* PyShark (https://kiminewt.github.io/pyshark/) and
Scapy to do its work. PyShark because we want to leverage tshark's powerful
protocol decoding ability to generate the "textual description" field of
the CSV, and Scapy because at the same time we want to access the "payload"
portion of the packet (PyShark seems to be unable to provide this).
"""


# --------------------------------------------------

def render_csv_row(pkt_sh, pkt_sc, fh_csv):
    """Write one packet entry into the CSV file.
    pkt_sh is the PyShark representation of the packet
    pkt_sc is a 'bytes' representation of the packet as returned from
    scapy's RawPcapReader
    fh_csv is the csv file handle
    """
    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc.type != 0x800:
        print('Ignoring non-IP packet')
        return False

    ip_pkt_sc = ether_pkt_sc[IP]  # <<<< Assuming Ethernet + IPv4 here
    proto = ip_pkt_sc.fields['proto']
    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)

        # Each line with a UDP packet in the CSV has this format
        fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}'
        #       |   |   |   |   |   |   |   |   |   |
        #       |   |   |   |   |   |   |   |   |   o-> {9} L4 payload hexdump
        #       |   |   |   |   |   |   |   |   o-----> {8}  total pkt length
        #       |   |   |   |   |   |   |   o---------> {7}  dst port
        #       |   |   |   |   |   |   o-------------> {6}  dst ip address
        #       |   |   |   |   |   o-----------------> {5}  src port
        #       |   |   |   |   o---------------------> {4}  src ip address
        #       |   |   |   o-------------------------> {3}  text description
        #       |   |   |
        #       |   |   o----------------------------------> {2}  highest protocol
        #       |   o--------------------------------------> {1}  time
        #       o------------------------------------------> {0}  frame number

        print(fmt.format(
            pkt_sh.number,  # {0}
            pkt_sh.sniff_time,  # {1}
            pkt_sh.ip.len,
            proto,  # {2}
            pkt_sh.transport_layer,  # {3}
            pkt_sh.ip.src,  # {4}
            pkt_sh[pkt_sh.transport_layer].srcport,  # {5}
            pkt_sh.ip.dst,  # {6}
            pkt_sh[pkt_sh.transport_layer].dstport,  # {7}
            pkt_sh[pkt_sh.transport_layer].length,
            l4_payload_bytes),  # {9}
            file=fh_csv)

        return True

    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)

        # Each line with a TCP packet in the CSV has this format
        fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}'
        #       |   |   |   |   |   |   |   |   |   |
        #       |   |   |   |   |   |   |   |   |   o-> {9} L4 payload hexdump
        #       |   |   |   |   |   |   |   |   o-----> {8}  total pkt length
        #       |   |   |   |   |   |   |   o---------> {7}  dst port
        #       |   |   |   |   |   |   o-------------> {6}  dst ip address
        #       |   |   |   |   |   o-----------------> {5}  src port
        #       |   |   |   |   o---------------------> {4}  src ip address
        #       |   |   |   o-------------------------> {3}  text description
        #       |   |   |
        #       |   |   o----------------------------------> {2}  highest protocol
        #       |   o--------------------------------------> {1}  time
        #       o------------------------------------------> {0}  frame number

        print(fmt.format(
            pkt_sh.number,  # {0}
            pkt_sh.sniff_time,  # {1}
            pkt_sh.ip.len,
            proto,  # {2}
            pkt_sh.transport_layer,  # {3}
            pkt_sh.ip.src,  # {4}
            pkt_sh[pkt_sh.transport_layer].srcport,  # {5}
            pkt_sh.ip.dst,  # {6}
            pkt_sh[pkt_sh.transport_layer].dstport,  # {7}
            pkt_sh[pkt_sh.transport_layer].seq,
            pkt_sh[pkt_sh.transport_layer].ack_raw,
            pkt_sh[pkt_sh.transport_layer].flags_str,
            l4_payload_bytes),  # {9}
            file=fh_csv)

        return True

    elif proto == 1:
        icmp_pkt_sc = ip_pkt_sc[ICMP]
        l4_payload_bytes = bytes(icmp_pkt_sc.payload)

        # Each line with a ICMP packet in the CSV has this format
        fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}'
        #       |   |   |   |   |   |   |   |   |   |
        #       |   |   |   |   |   |   |   |   |   o-> {9} L4 payload hexdump
        #       |   |   |   |   |   |   |   |   o-----> {8}  total pkt length
        #       |   |   |   |   |   |   |   o---------> {7}  dst port
        #       |   |   |   |   |   |   o-------------> {6}  dst ip address
        #       |   |   |   |   |   o-----------------> {5}  src port
        #       |   |   |   |   o---------------------> {4}  src ip address
        #       |   |   |   o-------------------------> {3}  text description
        #       |   |   |
        #       |   |   o----------------------------------> {2}  highest protocol
        #       |   o--------------------------------------> {1}  time
        #       o------------------------------------------> {0}  frame number

        print(fmt.format(
            pkt_sh.number,  # {0}
            pkt_sh.sniff_time,  # {1}
            pkt_sh.ip.len,
            proto,  # {2}
            'ICMP',  # {3}
            pkt_sh.ip.src,  # {4}
            pkt_sh.icmp.udp_srcport,  # {5}
            pkt_sh.ip.dst,  # {6}
            pkt_sh.icmp.udp_dstport,  # {7}
            pkt_sh.icmp.type,
            pkt_sh.icmp.code,
            pkt_sh.icmp.checksum,
            l4_payload_bytes),  # {9}
            file=fh_csv)

        return True

    else:
        # Currently not handling packets that are not UDP or TCP
        print('Ignoring non-UDP/TCP packet')
        return False

    # TODO generify the if statements. Need every row of the csv to be the same in the sense of fields they have.

    # --------------------------------------------------


def pcap2csv(in_pcap, out_csv):
    """Main entry function called from main to process the pcap and
    generate the csv file.
    in_pcap = name of the input pcap file (guaranteed to exist)
    out_csv = name of the output csv file (will be created)
    This function walks over each packet in the pcap file, and for
    each packet invokes the render_csv_row() function to write one row
    of the csv.
    """

    # Open the pcap file with PyShark in "summary-only" mode, since this
    # is the mode where the brief textual description of the packet (e.g.
    # "Standard query 0xf3de A www.cisco.com", "Client Hello" etc.) are
    # made available.
    pcap_pyshark = pyshark.FileCapture(in_pcap)
    pcap_pyshark.load_packets()
    pcap_pyshark.reset()

    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'w') as fh_csv:
        # Open the pcap file with scapy's RawPcapReader, and iterate over
        # each packet. In each iteration get the PyShark packet as well,
        # and then call render_csv_row() with both representations to generate
        # the CSV row.
        for (pkt_scapy, _) in RawPcapReader(in_pcap):
            try:
                pkt_pyshark = pcap_pyshark.next_packet()

                frame_num += 1
                if not render_csv_row(pkt_pyshark, pkt_scapy, fh_csv):
                    ignored_packets += 1
            except StopIteration:
                # Shouldn't happen because the RawPcapReader iterator should also
                # exit before this happens.
                break

    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))


# --------------------------------------------------

def command_line_args():
    """Helper called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--csv', metavar='<output csv file>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args


# --------------------------------------------------

def main():
    """Program main entry"""
    args = command_line_args()

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.csv):
        print('Output csv file "{}" already exists, '
              'won\'t overwrite'.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    pcap2csv(args.pcap, args.csv)


# --------------------------------------------------

if __name__ == '__main__':
    main()

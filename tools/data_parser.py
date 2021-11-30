#!/usr/bin/env python3
import argparse
import os.path
import sys

import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
import helpers

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

    srcport = ''
    dstport = ''

    sequence = ''
    ack_raw = ''
    flags_str = ''

    icmp_type = ''
    icmp_code = ''
    icmp_checksum = ''

    length = ''
    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        proto_name = 'UDP'
        srcport = pkt_sh[pkt_sh.transport_layer].srcport
        dstport = pkt_sh[pkt_sh.transport_layer].dstport
        length = pkt_sh[pkt_sh.transport_layer].length
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        proto_name = 'TCP'
        srcport = pkt_sh[pkt_sh.transport_layer].srcport
        dstport = pkt_sh[pkt_sh.transport_layer].dstport
        sequence = pkt_sh[pkt_sh.transport_layer].seq
        ack_raw = pkt_sh[pkt_sh.transport_layer].ack_raw
        flags_str = pkt_sh[pkt_sh.transport_layer].flags_str
        length = pkt_sh[pkt_sh.transport_layer].len
    elif proto == 1:
        icmp_pkt_sc = ip_pkt_sc[ICMP]
        l4_payload_bytes = bytes(icmp_pkt_sc.payload)
        proto_name = 'ICMP'
        # srcport = pkt_sh.icmp.udp_srcport
        # dstport = pkt_sh.icmp.udp_dstport
        icmp_type = pkt_sh.icmp.type
        icmp_code = pkt_sh.icmp.code
        icmp_checksum = pkt_sh.icmp.checksum
        # length = pkt_sh.icmp.udp_length
    else:
        # Currently not handling packets that are not UDP or TCP
        print('Ignoring non-UDP/TCP/ICMP packet')
        return False

    # Each line with a TCP packet in the CSV has this format
    fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}'
    #       |   |   |   |   |   |   |   |   |   |   |    |    |    |    |    |    |
    #       |   |   |   |   |   |   |   |   |   |   |    |    |    |    |    |    o-> {16} L4 payload hexdump
    #       |   |   |   |   |   |   |   |   |   |   |    |    |    |    |    o-----> {15}  protocol pkt length
    #       |   |   |   |   |   |   |   |   |   |   |    |    |    |    o--------->{14} ICMP checksum
    #       |   |   |   |   |   |   |   |   |   |   |    |    |    o------------->{13} ICMP code
    #       |   |   |   |   |   |   |   |   |   |   |    |    o----------------->{12} ICMP type
    #       |   |   |   |   |   |   |   |   |   |   |    o--------------------->{11} All Flags
    #       |   |   |   |   |   |   |   |   |   |   o------------------------->{10} Acknowledgment
    #       |   |   |   |   |   |   |   |   |   o---------------------------->{9} Sequence
    #       |   |   |   |   |   |   |   |   o------------------------------->{8} Destination Port
    #       |   |   |   |   |   |   |   o---------------------------------->{7} Destination IP
    #       |   |   |   |   |   |   o------------------------------------->{6} Source Port
    #       |   |   |   |   |   o---------------------------------------->{5} Source IP
    #       |   |   |   |   o------------------------------------------->{4} Protocol String
    #       |   |   |   o---------------------------------------------->{3} Protocol Number
    #       |   |   o------------------------------------------------->{2} IP pkt len
    #       |   o---------------------------------------------------->{1} Pkt Timestamp
    #       o------------------------------------------------------->{0} Pkt number (Beginning at first pkt)

    print(fmt.format(
        pkt_sh.number,
        helpers.correct_timestamp(pkt_sh.sniff_time),
        pkt_sh.ip.len,
        proto,
        proto_name,
        pkt_sh.ip.src,
        srcport,
        pkt_sh.ip.dst,
        dstport,
        sequence,
        ack_raw,
        flags_str,
        icmp_type,
        icmp_code,
        icmp_checksum,
        length,
        l4_payload_bytes),
        file=fh_csv)

    return True

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
    print('pre load packets')
    pcap_pyshark.load_packets()
    print('post load packets')
    pcap_pyshark.reset()
    print('post reset')

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
                if frame_num % 2 == 0:
                    print(frame_num)
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
    # TODO implement loop to handle all pcap files
    # TODO implement way to call the data parser from main and pass data locations here
    pcap2csv('Z:/main/Temp_Code_Loc/Simple-NIDS/data/defcon_23_ics_village_0.pcap',
             'Z:/main/Temp_Code_Loc/Simple-NIDS/data/training.csv')


# --------------------------------------------------

if __name__ == '__main__':
    main()

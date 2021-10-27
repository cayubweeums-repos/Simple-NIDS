import os
import socket
from time import sleep
import datetime
import logging
import multiprocessing
from tools.sniffer import Sniffer
from tools import helpers
from tools.comparator import Comparator
import socket
import urllib.request

print('\n\
╔═══╗      ╔╗      ╔═╗ ╔╗  ╔╗   \n\
║╔═╗║      ║║      ║║╚╗║║  ║║   \n\
║╚══╦╦╗╔╦══╣║╔══╗  ║╔╗╚╝╠╦═╝╠══╗\n\
╚══╗╠╣╚╝║╔╗║║║║═╬══╣║╚╗║╠╣╔╗║══╣\n\
║╚═╝║║║║║╚╝║╚╣║═╬══╣║ ║║║║╚╝╠══║\n\
╚═══╩╩╩╩╣╔═╩═╩══╝  ╚╝ ╚═╩╩══╩══╝\n\
        ║║                      \n\
        ╚╝                      ')


def main():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    hostname = socket.gethostname()
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    print('Hello {}@{}'.format(hostname, external_ip))
    local_ip = input('Please enter the local ip for {}\n> '.format(hostname))

    # No easy way to determine local ip due to not knowing if the user is running vlan's, vpn, v4 or v6, etc...
    # So we ping the user for this info
    # For test purposes I reassign the local IP to a static ip for the given machine I am using for testing
    local_ip = '192.168.1.102'

    network_info = helpers.set_network(local_ip, external_ip)

    _queue = multiprocessing.Queue()
    _time = datetime.datetime.now()
    logging.basicConfig(filename='logs/{}.log'.format(_time), level=logging.INFO)
    logging.info('~~~~~ Loading Ruleset ~~~~~')
    selected_ruleset = helpers.get_ruleset()
    print('~~~~~ Ruleset Loaded ~~~~~')
    logging.info('~~~~~ Ruleset Loaded ~~~~~')

    try:
        print('~~~~~ Begin Sniffing ~~~~~')
        logging.info('~~~~~ Begin Sniffing ~~~~~')
        _sniffer = Sniffer(_queue, _time)
        _comparator = Comparator(_queue, _time, selected_ruleset, network_info)
        _sniffer.start(), _comparator.start()

        while True:
            sleep(1)
    except KeyboardInterrupt:
        print('~~~~~ Stopping IDS ~~~~~')
        logging.info('~~~~~ Stopping IDS ~~~~~')
        _sniffer.stop()
        _comparator.stop()
        logging.shutdown()
        print('~~~~~ Done ~~~~~')


main()

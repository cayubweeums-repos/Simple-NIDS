import os
from time import sleep
import datetime
import logging
import multiprocessing
from tools.sniffer import Sniffer
from tools import helpers
from signature.objects.comparator import Comparator
from anomaly.engine import Engine
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
    # TODO reformat so the main files goes through the calls. Setup like this to easily test anomaly-based engine
    anomaly_based()

    if not os.path.exists('logs'):
        os.makedirs('logs')
    hostname = socket.gethostname()
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    print('Hello {}@{}'.format(hostname, external_ip))
    ids = input('Select IDS protocol anomaly-based(a) or signature-based(s)\n> ')
    if ids == 's':
        signature_based(hostname, external_ip)
    elif ids == 'a':
        anomaly_based()
    else:
        print('Please type either "s" or "a" to select ids protocol when prompted again.')


def anomaly_based():
    # All values for anomaly_based detection set to static values due to limited functionality implemented.
    # The values are inplace and the methods are abstracted enough to allow for implementation of various diff values
    # here.
    _time = datetime.datetime.now()
    # logging.basicConfig(filename='logs/{}.log'.format(_time), level=logging.INFO)
    # TODO uncomment dataset and feature set to prompt user
    # dataset = input('Select dataset (Only one dataset allowed therefore it is statically set later): \n\t\tnsl_kdd')
    dataset = 'nsl_kdd'
    # feature_type = int(input('Select running type: \n\t\t0. Binary\t\t1. Multi\n> '))
    feature_type = 'Binary'
    model = input('Select model: \n\t\tNaive Bayes [n]\t\tLSTM [l]\n> ')
    # iter_num = int(input('Type num of iterations: \n\t\t1\t\t15\t\t50\n> '))
    iter_num = 1
    _engine = Engine(feature_type, iter_num, dataset, model)
    _engine.run()


def signature_based(hostname, external_ip):
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

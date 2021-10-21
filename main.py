import os
from time import sleep, time
import datetime
import logging
from multiprocessing import Queue
from tools.sniffer import Sniffer
from tools import helpers
from tools.comparator import Comparator


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
    _queue = Queue()
    _time = datetime.datetime.now()
    logging.basicConfig(filename='logs/{}.log'.format(_time), level=logging.INFO)
    logging.info('~~~~~ Loading Ruleset ~~~~~')
    selected_ruleset = helpers.get_ruleset()
    print('~~~~~ Ruleset Loaded ~~~~~')
    logging.info('~~~~~ Ruleset Loaded ~~~~~')
    _comparator = Comparator(_queue, _time, selected_ruleset)

    try:
        print('~~~~~ Begin Sniffing ~~~~~')
        logging.info('~~~~~ Begin Sniffing ~~~~~')
        _sniffer = Sniffer(_queue, _time)
        _sniffer.run()
        _comparator.run()

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

import curses
import os
import sys
from time import sleep
import datetime
import multiprocessing
from tools.sniffer import Sniffer
from tools import helpers
from signature.objects.comparator import Comparator
from anomaly.engine import Engine
from signature.objects.menu import Menu
import socket
import urllib.request
from curses import wrapper
import logging
from rich.logging import RichHandler
from rich.traceback import install
from rich import pretty
from rich.console import Console

'''
Initialize a few values
#----------------------------------
'''
console = Console()
install()
pretty.install()
_time = datetime.date.today()
FORMAT = '%(asctime)s %(levelname)-8s %(message)s'
logging.basicConfig(filename='logs/{}.log'.format(_time), format=FORMAT, level=logging.INFO, datefmt="[%X]")
log = logging.getLogger("rich")
log.addHandler(RichHandler())
logo = '''
   _____ _                 _             _   _ _____ _____   _____ 
  / ____(_)               | |           | \ | |_   _|  __ \ / ____|
 | (___  _ _ __ ___  _ __ | | ___ ______|  \| | | | | |  | | (___  
  \___ \| | '_ ` _ \| '_ \| |/ _ \______| . ` | | | | |  | |\___ \ 
  ____) | | | | | | | |_) | |  __/      | |\  |_| |_| |__| |____) |
 |_____/|_|_| |_| |_| .__/|_|\___|      |_| \_|_____|_____/|_____/ 
                    | |                                            
                    |_|                                                               
'''

'''
#----------------------------------
'''


def main(stdscr):
    # TODO reformat so the main files goes through the calls. Setup like this to easily test anomaly-based engine
    stdscr.clear()
    os.system('clear')
    if not os.path.exists('logs'):
        os.makedirs('logs')
    hostname = socket.gethostname()
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    stdscr.addstr(f'{logo}')
    stdscr.addstr(f"Hello {hostname}@{external_ip}\n")
    stdscr.refresh()
    sleep(2)

    detection_menu = Menu(stdscr, 'Select a type of detection', ['Anomaly', 'Signature', 'Quit'])

    detection_method = detection_menu.get_selection()

    if detection_method == 1:
        signature_based(stdscr, hostname, external_ip)
    elif detection_method == 0:
        anomaly_based(stdscr, console)
    else:
        console.print("Goodbye :fire:", style="bold green")
        sleep(2)
        sys.exit(0)


def anomaly_based(stdscr, console):
    # All values for anomaly_based detection set to static values due to limited functionality implemented.
    # The values are inplace and the methods are abstracted enough to allow for implementation of various diff values
    # here.
    # TODO uncomment dataset and feature set to prompt user

    new_model = False
    testing = False
    selected_model = ''
    training_dataset = ''
    testing_dataset = ''

    train_menu = Menu(stdscr, 'Would you like to train a new model or use an existing one?', ['Train a new model',
                                                                                              'Use existing'])
    if train_menu.get_selection() == 0:
        new_model = True
        model_selection_menu = Menu(stdscr, 'What type of model would you like to train?', ['Naive Bayes', 'LSTM'])
        if model_selection_menu.get_selection() == 0:
            selected_model = 'n'
        else:
            selected_model = 'l'
        datasets = helpers.get_datasets()
        dataset_selection_menu = Menu(stdscr, 'Which dataset would you like to train and test on?',
                                      datasets)
        selected_dataset = datasets[dataset_selection_menu.get_selection()]

        stdscr.clear()
        stdscr.refresh()
        curses.endwin()
        os.system('clear')

        training_dataset, testing_dataset, train_pkts, test_pkts = helpers.split_selected_dataset(console,
                                                                                                  selected_dataset)

        stdscr.clear()
        stdscr.addstr(f'train packet num = {train_pkts}    test packet num= {test_pkts}')
        stdscr.refresh()
        stdscr.getch()

    else:
        models = helpers.get_models()
        model_selection_menu = Menu(stdscr, 'Which existing model would you like to predict with?',
                                    models)
        selected_model = models[model_selection_menu.get_selection()]
        testing_selection = Menu(stdscr, 'Would you like to Test or Predict with your selected model?',
                                 ['Test', 'Predict'])
        if testing_selection.get_selection() == 0:
            testing = True
            datasets = helpers.get_datasets()
            dataset_selection_menu = Menu(stdscr, 'Which dataset would you like to train and test on?',
                                          datasets)
            selected_dataset = datasets[dataset_selection_menu.get_selection()]

            stdscr.clear()
            stdscr.refresh()
            curses.endwin()
            os.system('clear')

            training_dataset, testing_dataset, train_pkts, test_pkts = helpers.split_selected_dataset(console,
                                                                                                      selected_dataset)

    stdscr.clear()
    stdscr.refresh()
    curses.endwin()
    os.system('clear')

    # TODO implement logic to run the correct items if only testing a model, if making a new model, or if making
    #  predictions
    #  i.e. sniffer should only be run if the user selected existing model and no testing

    _queue = multiprocessing.Queue()

    try:
        log.info('~~~~~ Begin Sniffing ~~~~~')
        _sniffer = Sniffer(_queue, _time)
        _engine = Engine(_queue, _time, training_dataset, testing_dataset, new_model, selected_model)
        _sniffer.start(), _engine.start()
        while True:
            if not KeyboardInterrupt:
                sleep(1)
            else:
                log.info('~~~~~ Stopping IDS ~~~~~')
                _sniffer.stop()
                _engine.stop()
                log.shutdown()
                sys.exit(0)
                break
    except KeyboardInterrupt:
        log.info('~~~~~ Stopping IDS ~~~~~')
        _sniffer.stop()
        _engine.stop()
        log.shutdown()
        sys.exit(0)


def signature_based(stdscr, hostname, external_ip):
    # input_menu = Menu(stdscr, f'Enter your local Ip address for {hostname}', [])
    # local_ip = input_menu.get_input()

    # No easy way to determine local ip due to not knowing if the user is running vlan's, vpn, v4 or v6, etc...
    # So we ping the user for this info
    # For test purposes I reassign the local IP to a static ip for the given machine I am using for testing
    local_ip = '192.168.1.198'

    network_info = helpers.set_network(local_ip, external_ip)
    _queue = multiprocessing.Queue()

    rules = helpers.get_ruleset()
    ruleset_menu = Menu(stdscr, 'Select your ruleset', rules)
    selected_ruleset = rules[ruleset_menu.get_selection()]

    stdscr.clear()
    stdscr.refresh()
    curses.endwin()
    os.system('clear')

    log.info('~~~~~ ' + selected_ruleset + ' Ruleset Loaded ~~~~~')
    selected_ruleset = helpers.format_ruleset(selected_ruleset)

    try:
        log.info('~~~~~ Begin Sniffing ~~~~~')
        sleep(2)
        _sniffer = Sniffer(_queue, log)
        _comparator = Comparator(_queue, log, selected_ruleset, network_info)
        _sniffer.start(), _comparator.start()

        while True:
            if not KeyboardInterrupt:
                sleep(1)
            else:
                log.info('~~~~~ Stopping IDS ~~~~~')
                _sniffer.stop()
                _comparator.stop()
                log.shutdown()
                sys.exit(0)
                break
    except KeyboardInterrupt:
        log.info('~~~~~ Stopping IDS ~~~~~')
        _sniffer.stop()
        _comparator.stop()
        log.shutdown()
        sys.exit(0)


wrapper(main)

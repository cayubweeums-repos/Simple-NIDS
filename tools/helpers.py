import os
import re
import numpy as np
from signature.objects.rule import Rule


def format_mac(unparsed_mac):
    bytes_str = map('{:02X}'.format, unparsed_mac)
    return ':'.join(bytes_str)


def get_ruleset():
    print('################################\n'
          '#     Select your ruleset      #\n'
          '################################\n')
    rulesets = []
    for f in os.listdir(os.getcwd() + '/signature/rules'):
        rulesets.append(f.split('.')[0])
    print(rulesets)
    selected = open(os.getcwd() + '/signature/rules/' + input('> ') + '.rules')
    all_rules = []
    print('~~~~~ Loading Ruleset ~~~~~')
    for r in selected:
        rule = Rule(data=r)
        rule.parse()
        all_rules.append(rule)
    return format_ruleset(all_rules)


def format_ruleset(data):
    tcp, udp, icmp = [], [], []
    for rule in data:
        if rule.protocol == 'udp':
            udp.append(rule)
        elif rule.protocol == 'tcp':
            tcp.append(rule)
        else:
            icmp.append(rule)
    return {'tcp': tcp, 'udp': udp, 'icmp': icmp}


def is_allowed_specific_char(string):
    charRe = re.compile(r'[^a-zA-Z0-9]')
    string = charRe.search(string)
    return not bool(string)


def set_network(local_ip, external_ip):
    local_range = '.'.join(local_ip.split('.')[:3])
    Networks = {'local_range': local_range, 'local_ip': local_ip, 'external_ip': external_ip}
    return Networks


def get_dataset(dataset):
    filepath = os.getcwd() + '/data/' + dataset
    return [np.loadtxt(filepath + '/normalized_train_data_features.csv', delimiter=','),
            np.loadtxt(filepath + '/normalized_train_data_results.csv', delimiter=','),
            np.loadtxt(filepath + '/normalized_test_data_features.csv', delimiter=','),
            np.loadtxt(filepath + '/normalized_test_data_results.csv', delimiter=',')]


def correct_timestamp(old_ts):
    pieces = old_ts.split('-')
    all_pieces = []
    for p in pieces:
        add = p.split(' ')
        for a in add:
            all_pieces.append(a)
    all_pieces[1:3] = ['/'.join(all_pieces[1:3])]
    all_pieces[1:3] = ['-'.join(all_pieces[1:3])]
    return all_pieces[1]

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
    str_ts = '{}'.format(old_ts)
    pieces = str_ts.split('-')
    all_pieces = []
    for p in pieces:
        add = p.split(' ')
        for a in add:
            all_pieces.append(a)
    hms = all_pieces[-1].split(':')
    hms[0] = '{}'.format(int(hms[0]) - 1)
    all_pieces[-1] = ':'.join(hms)
    all_pieces[1:3] = ['/'.join(all_pieces[1:3])]
    all_pieces[1:3] = ['-'.join(all_pieces[1:3])]
    return all_pieces[1]


def get_alert_pkts():
    alert_pkts = []
    for alert in get_file_lines('Z:/main/Temp_Code_Loc/Simple-NIDS/data/alert.csv'):
        split_line = get_csvfile_elements(alert)
        alert_pkts.append(split_line[0].replace(" ", ""))
    return alert_pkts


def get_binary_label(timestamp, alert_pkts):
    if timestamp in alert_pkts:
        return 'abnormal'
    else:
        return 'normal'


def get_file_lines(file):
    with open(file, 'r') as raw_lines:
        return raw_lines.readlines()


def get_csvfile_elements(csv_line):
    return [element.strip() for element in csv_line.split(',')]


def get_feature_value(feature, protocol_type, service, flag):
    protocol_type_count = len(protocol_type)
    service_count = len(service)
    flag_count = len(flag)

    second_index = int(protocol_type_count + 1)
    third_index = int(protocol_type_count + service_count + 1)
    forth_index = int(protocol_type_count + service_count + flag_count + 1)

    # index 1 is protocol_type
    feature[1:1] = protocol_type[feature[1]]
    feature.pop(second_index)

    # index 2 + protocol_type_count is service
    feature[second_index:second_index] = service[feature[second_index]]
    feature.pop(third_index)
    # # index 3 + protocol_type_count + service_count is flag
    feature[third_index:third_index] = flag[feature[third_index]]
    feature.pop(forth_index)

    # make all values np.float64
    feature = [np.float64(x) for x in feature]

    return np.array(feature)

    return

def get_result_value():

    return


# TODO have this method return the feature values in csv format? of a given packet for realtime predictions
def get_normalized_packet_features(features, results):
    protocol_type = dict()
    service = dict()
    flag = dict()
    attack = dict()
    attack_dict = {
        'normal': 'normal',
        'abnormal': 'abnormal',
    }

    for entry in features:
        protocol_type[entry[1]] = ""
        service[entry[2]] = ""
        flag[entry[3]] = ""

    for entry in results:
        attack[attack_dict[entry[0]]] = ""

    keys = list(protocol_type.keys())
    for i in range(0, len(keys)):
        protocol_type[keys[i]] = [int(d) for d in str(
            bin(i)[2:].zfill(len(protocol_type)))]

    keys = list(service.keys())
    for i in range(0, len(keys)):
        service[keys[i]] = [int(d)
                            for d in str(bin(i)[2:].zfill(len(service)))]

    keys = list(flag.keys())
    for i in range(0, len(keys)):
        flag[keys[i]] = [int(d) for d in str(bin(i)[2:].zfill(len(flag)))]

    keys = list(attack.keys())
    for i in range(0, len(keys)):
        attack[keys[i]] = [int(i)]


    return

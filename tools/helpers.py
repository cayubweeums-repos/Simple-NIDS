import os
import re
import codecs
import numpy as np
from signature.objects.rule import Rule
from signature.objects.common_ports import CommonPorts, get_name_4_value
from tools import data_parser


def format_mac(unparsed_mac):
    bytes_str = map('{:02X}'.format, unparsed_mac)
    return ':'.join(bytes_str)


def get_ruleset():
    rulesets = []
    for f in os.listdir(os.getcwd() + '/signature/rules'):
        rulesets.append(f.split('.')[0])
    return rulesets


def format_ruleset(selected_ruleset):
    selected = open(os.getcwd() + '/signature/rules/' + selected_ruleset + '.rules')
    all_rules = []
    for r in selected:
        rule = Rule(data=r)
        rule.parse()
        all_rules.append(rule)

    TCP, UDP, ICMP = [], [], []
    for rule in all_rules:
        if rule.protocol == 'UDP':
            UDP.append(rule)
        elif rule.protocol == 'TCP':
            TCP.append(rule)
        else:
            ICMP.append(rule)
    return {'TCP': TCP, 'UDP': UDP, 'ICMP': ICMP}


def is_allowed_specific_char(string):
    charRe = re.compile(r'[^a-zA-Z0-9]')
    string = charRe.search(string)
    return not bool(string)


def set_network(local_ip, external_ip):
    local_range = '.'.join(local_ip.split('.')[:3])
    Networks = {'local_range': local_range, 'local_ip': local_ip, 'external_ip': external_ip}
    return Networks


def get_datasets(training_file_loc, testing_file_loc):
    # TODO handle if the files have already been created and there is no need to run data_parser.py
    # if os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'data/training_sets/training_features.csv')):
    #     return np.loadtxt()
    return data_parser.main(training_file_loc, testing_file_loc)


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
    for alert in get_file_lines('Z:/main/Temp_Code_Loc/Simple-NIDS/data/alerts_0.csv'):
        split_line = get_csvfile_elements(alert)
        alert_pkts.append(split_line[0].replace(" ", ""))
    return alert_pkts


def get_binary_label(timestamp, alert_pkts):
    if timestamp in alert_pkts:
        return 'abnormal'
    else:
        return 'normal'


def get_file_lines(file):
    with codecs.open(file, 'r', encoding='utf-8', errors='ignore') as raw_lines:
        return raw_lines.readlines()


def get_csvfile_elements(csv_line):
    return [element.strip() for element in csv_line.split(',')]


# --------------------------------------

def get_feature_value(feature, protocol_type, service, flag):
    # Reconstruct csv line to format that will allow for AI to be trained on it
    # format when finished '{protocol}{service}{flags}{all rest of values in bumped over indexes}'
    new_features = []
    protocol_type_count = len(protocol_type)
    service_count = len(service)
    flag_count = len(flag)

    second_static_index = 4  # ----- is the str for the protocol type which needs to be removed
    third_static_index = 9  # ----- is the port number used for determining service
    forth_static_index = 11  # ----- is the str for the flags present in the packet

    second_index = int(protocol_type_count + 1)
    third_index = int(protocol_type_count + service_count + 1)

    # Add all features to the new features list then place them in the old features list and remove not needed strings

    # print('Key to index protocol type = {}'.format(feature[second_index]))
    # print('Value = {}'.format(protocol_type[feature[second_index]]))
    # print('all = {}'.format(protocol_type))

    new_features[:1] = protocol_type[feature[second_static_index]]
    new_features[second_index:second_index] = service[get_name_4_value(feature[third_static_index])]
    new_features[third_index:third_index] = flag[feature[forth_static_index]]

    # print(new_features)

    # Remove old str values of protocol type, flags, src/dst Ip, src/dst port, and payload
    # This leave very little data for the AI to use to predict incoming packets. This is a weak point
    # To make more accurate gather, implement gathering and parsing of more values
    # I.E. setting an urgent variable to 0 or 1 if the urgent flag is given with a pointer.
    feature.pop(second_static_index)
    feature.pop(second_static_index)
    feature.pop(second_static_index)
    feature.pop(second_static_index)
    feature.pop(second_static_index)
    feature.pop(second_static_index + 2)
    feature.pop(len(feature) - 1)

    feature[0:2] = new_features
    # print('final feature = {}'.format(feature))

    # index 8 will be service
    # feature[second_index:second_index] = service[get_name_4_value(feature[second_index])]
    # print('third index = {}'.format(feature[third_index]))
    # feature.pop(third_index)
    #
    # # index 3 + protocol_type_count + service_count is flag
    # feature[third_index:third_index] = flag[feature[third_index]]
    # print('fourth index = {}'.format(feature[third_index]))
    # feature.pop(forth_index)

    temp = []
    for x in feature:
        if x == '':
            temp.append(None)
        else:
            temp.append(x)
    feature = [np.float64(x) for x in temp]

    return np.array(feature)


def get_result_value(result, label, label_dict):
    second_index = int(1)
    # index 0 is attack
    result[0:0] = label[label_dict[result[0]]]
    result.pop(second_index)
    # make all values np.float64
    result = [np.float64(x) for x in result]
    return np.array(result)


def normalize_value(value, bottom, top):
    value = np.float64(value)
    bottom = np.float64(bottom)
    top = np.float64(top)

    if bottom == np.float64(0) and top == np.float64(0):
        return np.float64(0)
    result = np.float64((value - bottom) / (top - bottom))
    return result


def get_normalized_packet_features(features, results, _protocol_type, _service, _flag):
    protocol_type = _protocol_type
    service = _service
    flag = _flag
    label = dict()
    label_dict = {
        'normal': 'normal',
        'abnormal': 'abnormal',
    }

    if protocol_type.__len__() == 0:
        for entry in features:
            for service_name in CommonPorts:
                if entry[8] == service_name.value:
                    service[service_name.name] = ""
                else:
                    service['OTHER'] = ""
            protocol_type[entry[4]] = ""
            flag[entry[11]] = ""

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

    for entry in results:
        label[label_dict[entry[0]]] = ""

    keys = list(label.keys())
    for i in range(0, len(keys)):
        label[keys[i]] = [int(i)]

    # TODO need to reformat below possibly
    # train data
    numericalized_train_data_features = [get_feature_value(
        x, protocol_type, service, flag) for x in features]
    normalized_train_data_features = np.array(
        numericalized_train_data_features)

    numericalized_train_data_results = [get_result_value(
        x, label, label_dict) for x in results]
    normalized_train_data_results = np.array(
        numericalized_train_data_results)

    ymin_train = np.amin(numericalized_train_data_features, axis=0)
    ymax_train = np.amax(numericalized_train_data_features, axis=0)

    # normalize train
    for x in range(0, normalized_train_data_features.shape[0]):
        for y in range(0, normalized_train_data_features.shape[1]):
            normalized_train_data_features[x][y] = normalize_value(
                normalized_train_data_features[x][y], ymin_train[y],
                ymax_train[y])

    return normalized_train_data_features, normalized_train_data_results, protocol_type, service, flag, ymin_train, ymax_train

# --------------------------------------

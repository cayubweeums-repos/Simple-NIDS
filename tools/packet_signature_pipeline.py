# TODO make this a generic set of funcs in the helpers file
import numpy as np

from signature.objects.common_ports import CommonPorts, get_name_4_value


def get_feature_value(feature, protocol_type, service, flag):
    # Reconstruct csv line to format that will allow for AI to be trained on it
    # format when finished '{protocol}{service}{flags}{all rest of values in bumped over indexices}'
    new_features = []
    protocol_type_count = len(protocol_type)
    service_count = len(service)
    flag_count = len(flag)

    second_index = int(protocol_type_count + 1)
    third_index = int(protocol_type_count + service_count + 1)

    # Add all features to the new features list then place them in the old features list and remove not needed strings
    # print(flag)
    # print(protocol_type)
    # print(service)

    new_features[:1] = protocol_type[feature[0]]
    new_features[second_index:second_index] = service[get_name_4_value(feature[1])]
    new_features[third_index:third_index] = flag[feature[2]]

    feature[0:3] = new_features

    temp = []
    for x in feature:
        if x == '':
            temp.append(None)
        else:
            temp.append(x)
    feature = [np.float64(x) for x in temp]

    return np.array(feature)


def normalize_value(value, bottom, top):
    value = np.float64(value)
    bottom = np.float64(bottom)
    top = np.float64(top)

    if bottom == np.float64(0) and top == np.float64(0):
        return np.float64(0)
    result = np.float64((value - bottom) / (top - bottom))
    return result


def get_normalized_packet_features(raw_features, protocol_type, service, flag, ymin, ymax):
    # print(results)
    # for entry in results:
    #     label[label_dict[entry[0]]] = ""

    print('Getting numericalized features')
    numericalized_train_data_features = get_feature_value(raw_features, protocol_type, service, flag)
    normalized_pkt_features = np.array(
        numericalized_train_data_features)

    # normalize pkt
    print('Normalizing features')
    for x in range(0, normalized_pkt_features.shape[0]):
        normalized_pkt_features[x] = normalize_value(normalized_pkt_features[x], ymin[x], ymax[x])

    return normalized_pkt_features

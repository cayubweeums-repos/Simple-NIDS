from tools import helpers


def engine(feature_type, iter_num, dataset):
    data = helpers.parse_dataset(dataset, feature_type, iter_num)

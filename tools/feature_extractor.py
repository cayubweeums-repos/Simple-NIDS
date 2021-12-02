from tools import helpers


# TODO extract features from the train_0.csv file
# Using
# https://github.com/mehrdadep/deep-learning-nids/blob/fdff4a721a8444864ac5dd3f49ffb91761e3f387/services/process.py#L875
# to structure feature extractor
def get_features(file):
    dirty_training_data = helpers.get_trainfile_lines(file)
    print(dirty_training_data)

import datetime
import multiprocessing
import os
import time

import keras.models
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from keras.models import Sequential
from keras.layers import LSTM, Dropout, Dense, Activation

from tools import helpers, packet_signature_pipeline


class Engine(multiprocessing.Process):
    def __init__(self, _queue, _time, feature_type, iter_num, training_dataset, testing_dataset, model_type):
        super(Engine, self).__init__()
        self.time = _time
        self.queue = _queue
        self.feature_type = feature_type
        self.iter_num = iter_num
        self.training_dataset = training_dataset
        self.testing_dataset = testing_dataset
        self.model_type = model_type
        self.feature_filepath = os.path.join(os.path.dirname(__file__), '..', 'data/training_sets/features.csv')
        self.results_filepath = os.path.join(os.path.dirname(__file__), '..', 'data/training_sets/results.csv')
        self.model_filepath = None
        self.model = keras.Model
        self.x_train = None
        self.y_train = None
        self.x_test = None
        self.y_test = None
        self.on = True
        self.protocol_type = dict()
        self.service = dict()
        self.flags = dict()
        self.ymin = []
        self.ymax = []
        print("~~~~~~~ Engine Init ~~~~~~~")

    def run(self):
        print("~~~~~~~ Engine Run ~~~~~~~")
        # Temp coverage of all options aiming to add functionality for
        # print('Would you like to train a new model or use a provided one?')
        # print('Make sure the dataset you would like to use is in the data file and type the file name here')
        # print('The trained model will be placed in the models/trained/ folder')
        # print('Which model would you like to use?')
        # print('Make sure the model you would like to use is placed in the models/trained/ folder and type the filename

        # self.x_train, self.y_train, self.x_test, self.y_test = \
        #     helpers.get_dataset(self.dataset)

        self.x_train, self.y_train, self.x_test, self.y_test, self.protocol_type, self.service, self.flags, self.ymin, \
            self.ymax = helpers.get_datasets(self.training_dataset, self.testing_dataset)

        test_signature = ['UDP', 'DHCP67', '', 328, '', '', '', '', '', 308]
        # print(packet_signature_pipeline.get_normalized_packet_features(test_signature, self.protocol_type,
        #                                                               self.service, self.flags, self.ymin, self.ymax))

        # TODO implement a check that will grab the model selected if it exists or train it if it doesnt exist?
        if self.model_type == 'n':
            self.train_naive()
        else:
            self.train_lstm()

        """
            Main Loop
        """
        # print('Entering Main Loop')
        while self.on:
            print('Entering PREDICTION')
            self.predict(packet_signature_pipeline.get_normalized_packet_features(self.queue.get(),
                                                                                  self.protocol_type, self.service,
                                                                                  self.flags, self.ymin, self.ymax))

    def stop(self):
        self.on = False
        self.join()
        self.close()

    def train_naive(self):
        # Train and fit a Naive Bayes model to the data
        self.y_train = self.y_train.ravel()
        # self.y_test = self.y_test.ravel()

        model = GaussianNB()
        model.fit(self.x_train, self.y_train)
        # predict = model.predict(self.x_test)
        # score = accuracy_score(self.y_test, predict)
        #
        # print('Accuracy Score = {}'.format(score))

    def train_lstm(self):
        # Train and fit a recurrent Long Short-Term Memory model to the data
        # Reshape the datasets to x = {samples, time steps, features} and y {sampels,}
        self.x_train = np.reshape(self.x_train, (self.x_train.shape[0], 1, self.x_train.shape[1]))
        self.y_train = np.reshape(self.y_train, (self.y_train.shape[0]))

        self.x_test = np.reshape(self.x_test, (self.x_test.shape[0], 1, self.x_test.shape[1]))
        self.y_test = np.reshape(self.y_test, (self.y_test.shape[0]))
        print(self.x_test.shape)

        # this may be causing the issues
        shapes = (self.x_train.shape[1], self.x_train.shape[2])

        model = Sequential()
        model.add(LSTM(
            120,
            input_shape=shapes,
            return_sequences=True
        )
        )
        model.add(Dropout(0.2))
        model.add(LSTM(120, return_sequences=True))
        model.add(Dropout(0.2))
        model.add(LSTM(120, return_sequences=False))
        model.add(Dropout(0.2))
        model.add(Dense(1))
        model.add(Activation('sigmoid'))
        model.compile(
            loss='binary_crossentropy',
            optimizer='adam',
            metrics=['accuracy'],
        )
        model.summary()
        model.fit(
            self.x_train,
            self.y_train,
            validation_data=(self.x_test, self.y_test),
            epochs=20,
            batch_size=32,
            verbose=2
        )

        self.model = model

        loss, accuracy = model.evaluate(self.x_test, self.y_test, batch_size=32)
        print("\nLoss: %.2f, Accuracy: %.2f%%" % (loss, accuracy * 100))

        predictions = model.predict_classes(self.x_test)
        print("\nAnomalies in Test: ", np.count_nonzero(self.y_test, axis=0))
        print("\nAnomalies in Prediction: ", np.count_nonzero(predictions, axis=0))

        self.model_filepath = os.path.join(os.path.dirname(__file__), 'models', 'lstm',
                                           'lstm_model_{}.h5'.format(datetime.date.today()))
        model.save(self.model_filepath)
        print('############ Model Saved ############\n{}'.format(self.model_filepath))
        return

    def predict(self, current_packet_features):
        if self.model is None:
            self.model = keras.models.load_model(self.model_filepath)
        current_packet_features = np.reshape(current_packet_features, (1, 1,
                                                                       current_packet_features.shape[0]))
        self.model.summary()
        print('PREDICTING...............')
        predictions = self.model.predict_classes(current_packet_features)
        print('\nAnomalies in prediction: ', np.count_nonzero(predictions, axis=0))
        print(predictions)

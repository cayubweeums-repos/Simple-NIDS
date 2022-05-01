import datetime
import logging
import multiprocessing
import os
import time
from tools.sniffer import Sniffer
import keras.models
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from keras.models import Sequential
from keras.layers import LSTM, Dropout, Dense, Activation
from tools import data_parser
from tools import helpers, packet_signature_pipeline


# TODO implement logic to run the correct items if only testing a model, if making a new model, or if making
#  predictions
#  i.e. sniffer should only be run if the user selected existing model and no testing

class Engine(multiprocessing.Process):
    def __init__(self, _queue, log, sniffer, training_dataset, testing_dataset, new_model, selected_model, testing):
        super(Engine, self).__init__()
        self.log = log
        self.queue = _queue
        self.sniffer = sniffer
        self.training_dataset = training_dataset
        self.testing_dataset = testing_dataset
        self.new_model = new_model
        self.testing = testing

        # If new_model == true this value will either be 'l' or 'n'
        # If new_model == false then this value will be the file name of the model requested
        self.selected_model = selected_model

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

        self.log.info('~~~~~~~ Engine Init ~~~~~~~')

    def run(self):
        self.log.info('~~~~~~~ Engine Running ~~~~~~~')
        # Temp coverage of all options aiming to add functionality for
        # print('Would you like to train a new model or use a provided one?')
        # print('Make sure the dataset you would like to use is in the data file and type the file name here')
        # print('The trained model will be placed in the models/trained/ folder')
        # print('Which model would you like to use?')
        # print('Make sure the model you would like to use is placed in the models/trained/ folder and type the filename

        if self.new_model:
            self.x_train, self.y_train, self.x_test, self.y_test, self.protocol_type, self.service, self.flags, \
                self.ymin, self.ymax = data_parser.main(self.training_dataset, self.testing_dataset)
            if self.selected_model == 'n':
                self.log.info('~~~~~~~ Engine Training ~~~~~~~')
                self.train_naive()
            else:
                self.log.info('~~~~~~~ Engine Training ~~~~~~~')
                self.train_lstm()

        elif self.testing:
            if 'lstm' in self.selected_model:
                self.test_lstm()
            else:
                self.test_naive()

        else:
            """
                Prediction Loop
            """
            self.sniffer.turn_on()
            self.log.info('~~~~~ Sniffer Init ~~~~~')
            while self.on:
                # print('Entering PREDICTION')
                current_packet = self.queue.get()
                if current_packet.protocol == 'TCP' or current_packet.protocol == 'UDP' \
                        or current_packet.protocol == 'ICMP':
                    # print('\nPacket Signature being predicted:\n\t\t{}'.format(current_packet.signature))
                    # print('\nPacket protocol:\n\t\t{}'.format(current_packet.protocol))
                    self.predict(packet_signature_pipeline.get_normalized_packet_features(current_packet.signature,
                                                                                          self.protocol_type,
                                                                                          self.service, self.flags,
                                                                                          self.ymin, self.ymax),
                                 current_packet)
                else:
                    self.log.info('Non TCP, UDP, or ICMP packet ignored')
                    # current_packet.print()

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

    def test_naive(self):
        while True:
            self.log.error("Beep Boop Testing Naive model even though it isn't even functional yet Beep Boop")

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

        predictions = model.predict(self.x_test)
        print("\nAnomalies in Test: ", np.count_nonzero(self.y_test, axis=0))
        print("\nAnomalies in Prediction: ", np.count_nonzero(predictions, axis=0))

        self.model_filepath = os.path.join(os.path.dirname(__file__), 'models', 'lstm',
                                           'lstm_model_{}.h5'.format(datetime.date.today()))
        model.save(self.model_filepath)
        print('############ Model Saved ############\n{}'.format(self.model_filepath))
        return

    def test_lstm(self):
        self.log.error("Beep Boop Testing LSTM model Beep Boop")

    def predict(self, current_packet_features, current_packet):
        if self.model is None:
            self.model = keras.models.load_model(self.model_filepath)
        current_packet_features = np.reshape(current_packet_features, (1, 1,
                                                                       current_packet_features.shape[0]))
        print('PREDICTING...............')

        prediction = np.count_nonzero(self.model.predict(current_packet_features), axis=0)
        if prediction != 0:
            print('~~~~~~~~~~~~~~~~~~~ ANOMALY DETECTED ~~~~~~~~~~~~~~~~~~~')
            print('\t\tSource of Anomaly: {}\n\t\tTrying to reach port {}'.format(current_packet.send_ip,
                                                                                  current_packet.destination_port))
            # print('\nAnomalies in prediction: {}'.format(prediction))
            logging.info('~~~~~~~~~~~~~~~~~~~ ANOMALY DETECTED ~~~~~~~~~~~~~~~~~~~')
            logging.info('\nAnomalies in prediction: {}'.format(prediction))
            current_packet.log(self.time)

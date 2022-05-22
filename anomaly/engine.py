import datetime
import logging
import multiprocessing
import os
import sys
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
from rich.traceback import install
from rich import pretty
from tools.sniffer import Sniffer


class Engine(multiprocessing.Process):
    def __init__(self, _queue, log, console, training_dataset, testing_dataset, new_model, selected_model,
                 testing):
        super(Engine, self).__init__()

        install()
        pretty.install()

        self.log = log
        self.queue = _queue
        self.console = console
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

        if not new_model:
            if 'lstm' in self.selected_model:
                self.model_filepath = os.path.join(os.getcwd(), 'anomaly/models/lstm/' + self.selected_model + '.h5')
            else:
                self.model_filepath = os.path.join(os.getcwd(), 'anomaly/models/naive/' + self.selected_model + '.h5')

        self.log.info('~~~~~~~ Engine Init ~~~~~~~')

    def run(self):
        self.log.info('~~~~~~~ Engine Running ~~~~~~~')
        if self.new_model:
            self.x_train, self.y_train, self.x_test, self.y_test, self.protocol_type, self.service, self.flags, \
            self.ymin, self.ymax = data_parser.main(self.console, self.training_dataset, self.testing_dataset)

            if self.selected_model == 'n':
                self.log.info('~~~~~~~ Engine Training ~~~~~~~')
                self.train_naive()
                self.stop(None)
            else:
                self.log.info('~~~~~~~ Engine Training ~~~~~~~')
                self.train_lstm()
                self.stop(None)
        elif self.testing:
            if 'lstm' in self.selected_model:
                self.test_lstm()
                self.stop(None)
            else:
                self.test_naive()
                self.stop(None)
        else:
            """
                Prediction Loop
            """

            self.x_train, self.y_train, self.x_test, self.y_test, self.protocol_type, self.service, self.flags, \
            self.ymin, self.ymax = data_parser.main(self.console, self.training_dataset, self.testing_dataset)

            with self.console.status("[bold green]Analyzing incoming packets...", spinner='aesthetic') as status:
                while self.on:
                    # print('Entering PREDICTION')
                    current_packet = self.queue.get()
                    if current_packet.protocol == 'TCP' or current_packet.protocol == 'UDP' \
                            or current_packet.protocol == 'ICMP':
                        # print('\nPacket Signature being predicted:\n\t\t{}'.format(current_packet.signature))
                        # print('\nPacket protocol:\n\t\t{}'.format(current_packet.protocol))
                        print(self.flags)
                        self.predict(packet_signature_pipeline.get_normalized_packet_features(current_packet.signature,
                                                                                              self.protocol_type,
                                                                                              self.service, self.flags,
                                                                                              self.ymin, self.ymax),
                                     current_packet)
                    else:
                        self.log.info('Non TCP, UDP, or ICMP packet ignored')
                        # current_packet.print()

    def stop(self, sniffer):
        self.on = False
        if sniffer is not None:
            sniffer.stop()
        self.join()
        self.close()

    def train_lstm(self):
        # Train and fit a recurrent Long Short-Term Memory model to the data
        # Reshape the datasets to x = {samples, time steps, features} and y {sampels,}
        self.x_train = np.reshape(self.x_train, (self.x_train.shape[0], 1, self.x_train.shape[1]))
        self.y_train = np.reshape(self.y_train, (self.y_train.shape[0]))

        self.x_test = np.reshape(self.x_test, (self.x_test.shape[0], 1, self.x_test.shape[1]))
        self.y_test = np.reshape(self.y_test, (self.y_test.shape[0]))
        # print(self.x_test.shape)

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
        self.log.info(f'{self.model_filepath}')
        self.model = keras.models.load_model(self.model_filepath)

        self.x_train, self.y_train, self.x_test, self.y_test, self.protocol_type, self.service, self.flags, \
        self.ymin, self.ymax = data_parser.main(self.console, self.training_dataset, self.testing_dataset)

        self.x_test = np.reshape(self.x_test, (self.x_test.shape[0], 1, self.x_test.shape[1]))
        self.y_test = np.reshape(self.y_test, (self.y_test.shape[0]))

        loss, accuracy = self.model.evaluate(self.x_test, self.y_test, batch_size=32)
        self.console.print(f'Loss: {loss}, Accuracy: {accuracy}')

        predictions = self.model.predict(self.x_test)
        self.console.print(f'Anomalies in Test: {np.count_nonzero(self.y_test, axis=0)}')

        self.console.print(f'{self.y_test}')

        self.console.print(f'Anomalies in Prediction: {np.count_nonzero(predictions, axis=0)}')

    def predict(self, current_packet_features, current_packet):
        if self.model is None:
            self.model = keras.models.load_model(self.model_filepath)
        shaped_packet_features = np.reshape(current_packet_features, (1, 1,
                                                                      current_packet_features.shape[0]))

        prediction = np.count_nonzero(self.model.predict(shaped_packet_features), axis=0)
        if prediction != 0:
            print('~~~~~~~~~~~~~~~~~~~ ANOMALY DETECTED ~~~~~~~~~~~~~~~~~~~')

            # print('\nAnomalies in prediction: {}'.format(prediction))
            self.log.error('~~~~~~~~~~~~~~~~~~~ ANOMALY DETECTED ~~~~~~~~~~~~~~~~~~~')
            self.log.error('\t\tSource of Anomaly: {}\n\t\tTrying to reach port {}'.format(current_packet.send_ip,
                                                                                           current_packet.destination_port))
            self.log.error('\nAnomalies in prediction: {}'.format(prediction))
            # current_packet.log(self.time)

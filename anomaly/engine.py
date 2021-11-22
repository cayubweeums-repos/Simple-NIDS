import datetime
import multiprocessing
import os
import time
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from keras.models import Sequential
from keras.layers import LSTM, Dropout, Dense, Activation

from tools import helpers


class Engine(multiprocessing.Process):
    def __init__(self, feature_type, iter_num, dataset, model_type):
        super(Engine, self).__init__()
        # self.time = _time
        # self.queue = _queue
        self.feature_type = feature_type
        self.iter_num = iter_num
        self.dataset = dataset
        self.model_type = model_type
        self.model = None
        self.x_train = None
        self.y_train = None
        self.x_test = None
        self.y_test = None

    def run(self):
        # Temp coverage of all options aiming to add functionality for
        print('Would you like to train a new model or use a provided one?')
        print('Make sure the dataset you would like to use is in the data file and type the file name here')
        print('The trained model will be placed in the models/trained/ folder')
        print('Which model would you like to use?')
        print('Make sure the model you would like to use is placed in the models/trained/ folder and type the filename')

        self.x_train, self.y_train, self.x_test, self.y_test = \
            helpers.get_dataset(self.dataset)

        if self.model_type == 'n':
            self.train_naive()
        else:
            self.train_lstm()

    def train_naive(self):
        # Train and fit a Naive Bayes model to the data
        self.y_train = self.y_train.ravel()
        self.y_test = self.y_test.ravel()

        model = GaussianNB()
        model.fit(self.x_train, self.y_train)
        predict = model.predict(self.x_test)
        score = accuracy_score(self.y_test, predict)

        print('Accuracy Score = {}'.format(score))

    def train_lstm(self):
        # Train and fit a recurrent Long Short-Term Memory model to the data
        self.x_train = self.x_train.reshape(self.x_train.shape[0], 1, self.x_train.shape[1])
        self.x_test = self.x_test.reshape(self.x_test.shape[0], 1, self.x_test.shape[1])

        shape = (self.x_train.shape[1], self.x_train.shape[2])
        model = Sequential()
        model.add(LSTM(120, input_shape=shape, return_sequences=True))
        model.add(Dropout(0.2))
        model.add(LSTM(120, return_sequences=True))
        model.add(Dropout(0.2))
        model.add(LSTM(120, return_sequences=False))
        model.add(Dropout(0.2))
        model.add(Dense(1))
        model.add(Activation('sigmoid'))

        model.summary()
        model.compile(
            loss='binary_crossentropy',
            optimizer='adam',
            metrics=['accuracy'],
        )
        model.fit(
            self.x_train,
            self.y_train,
            validation_data=(self.x_test, self.y_test),
            epochs=20,
            batch_size=50,
        )
        model.save(os.getcwd() + '/anomaly/models/lstm')

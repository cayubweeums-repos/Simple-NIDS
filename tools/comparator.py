import multiprocessing
from tools import helpers
import logging


class Comparator(multiprocessing.Process):
    def __init__(self, _queue, _time, ruleset):
        super(Comparator, self).__init__()
        self.on = True
        self.queue = _queue
        self.time = _time
        self.ruleset = ruleset
        logging.basicConfig(filename='logs/{}.logs'.format(self.time), level=logging.INFO)

    def run(self):
        while self.on:
            self.queue.get().log(self.time)
            self.detection_engine(self.queue.get(), self.ruleset)

    def detection_engine(self, current_packet, ruleset):
        for rule in ruleset:
            print('detection_engine')

    def stop(self):
        self.on = False

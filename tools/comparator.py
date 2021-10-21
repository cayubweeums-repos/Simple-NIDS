from multiprocessing import Process
from tools import helpers


class Comparator(Process):
    def __init__(self, _queue, _time, ruleset):
        super(Comparator, self).__init__()
        self.on = True
        self.queue = _queue
        self.time = _time
        self.ruleset = ruleset

    def run(self):
        while self.on:
            try:
                print("########### QUEUE ###########")
                print(self.queue.get())
                # self.detection_engine(self.queue.get(), self.ruleset)
            except IndexError:
                raise ValueError()

    # def detection_engine(self, current_packet, ruleset):
    #     for rule in ruleset:
    #         print('nice')

    def stop(self):
        self.on = False
        print('sniffer on variable = ' + self.on.__str__())

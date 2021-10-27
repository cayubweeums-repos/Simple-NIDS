import multiprocessing
import logging


class Comparator(multiprocessing.Process):
    def __init__(self, _queue, _time, ruleset, network_info):
        super(Comparator, self).__init__()
        self.network_info = network_info
        self.on = True
        self.queue = _queue
        self.time = _time
        self.ruleset = ruleset
        logging.basicConfig(filename='logs/{}.logs'.format(self.time), level=logging.INFO)

    def run(self):
        while self.on:
            self.detection_engine(self.queue.get(), self.ruleset)

    def detection_engine(self, current_packet, ruleset):
        protocol_rules = ruleset.get(current_packet.protocol)
        if protocol_rules is not None and current_packet.send_ip is not None:
            if current_packet.send_ip == self.network_info.get('external_ip'):
                return
            for rule in protocol_rules:
                if rule.send_ip == current_packet.send_ip or rule.send_ip == 'any':
                    if rule.source_port == current_packet.source_port or rule.source_port == 'any':
                        if rule.rec_ip == current_packet.rec_ip or rule.rec_ip == 'any':
                            if rule.destination_port == current_packet.destination_port or rule.destination_port == 'any':
                                if rule.options.keys() is not None:
                                    for option in rule.options.keys():
                                        if option == 'flags':
                                            for f in current_packet.flags:
                                                if f not in rule.flags:
                                                    break
                                        elif rule.options.get(option) != current_packet.__getattribute__(option):
                                            break
                                    else:
                                        self.alert_handler(rule, current_packet)
                                else:
                                    self.basic_rule_flagged(rule, current_packet)

    def basic_rule_flagged(self, rule, packet):
        print('~~~~~~~~ basic rule flagged ~~~~~~~~')

    def alert_handler(self, rule, packet):
        logging.error('Intrusion Detected from IP {} msg: {}'.format(packet.send_ip, rule.message))
        logging.error(packet.error(self.time))
        print('Intrusion Detected from IP {} msg: {}'.format(packet.send_ip, rule.message))

    def stop(self):
        self.on = False
        self.join()
        # self.terminate()
        self.close()

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
            current_packet = self.queue.get()
            # current_packet.print()
            self.detection_engine(current_packet, self.ruleset)

    def detection_engine(self, current_packet, ruleset):
        print('###############')
        print(current_packet.protocol)
        print(self.ruleset.get(current_packet.protocol))
        protocol_rules = ruleset.get(current_packet.protocol)
        if protocol_rules is not None and current_packet.send_ip is not None:
            if current_packet.send_ip == self.network_info.get('external_ip'):
                return
            for rule in protocol_rules:
                print('Top')
                print(rule.send_ip)
                print(current_packet.send_ip)
                if rule.send_ip == current_packet.send_ip or rule.send_ip == 'any':
                    print('one')
                    if rule.source_port == current_packet.source_port or rule.source_port == 'any':
                        print('two  ')
                        print(rule.rec_ip)
                        print(current_packet.rec_ip)
                        if rule.rec_ip == current_packet.rec_ip or rule.rec_ip == 'any':
                            print('almostMid')
                            if rule.destination_port == current_packet.destination_port or rule.destination_port == 'any':
                                print('Mid')
                                if rule.options.keys() is not None:
                                    for option in rule.options.keys():
                                        if option == 'flags':
                                            for f in current_packet.flags:
                                                print('deepest level')
                                                print(current_packet.flags)
                                                logging.info('deepest level')
                                                if f not in rule.flags:
                                                    break
                                        elif rule.options.get(option) != current_packet.__getattribute__(option):
                                            break
                                    else:
                                        print('ALERT HANDLER TRIGGERED')
                                        logging.info('ALerthandler triggers')
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

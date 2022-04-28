import multiprocessing
import logging
from rich import pretty, inspect
from rich.traceback import install


class Comparator(multiprocessing.Process):
    def __init__(self, _queue, log, ruleset, network_info):
        super(Comparator, self).__init__()
        install()
        pretty.install()
        self.network_info = network_info
        self.on = True
        self.queue = _queue
        self.log = log
        self.ruleset = ruleset

    def run(self):
        while self.on:
            current_packet = self.queue.get()
            # current_packet.print()
            self.detection_engine(current_packet, self.ruleset)

    def detection_engine(self, current_packet, ruleset):
        # inspect(current_packet)
        protocol_rules = ruleset.get(current_packet.protocol)
        if protocol_rules is not None and current_packet.send_ip is not None:
            if current_packet.send_ip == self.network_info.get('external_ip'):
                return
            for rule in protocol_rules:
                # print('Top')
                # print(rule.send_ip)
                # print(current_packet.send_ip)
                if rule.send_ip == current_packet.send_ip or rule.send_ip == 'any':
                    # print('one')
                    if rule.source_port == current_packet.source_port or rule.source_port == 'any':
                        # print('two  ')
                        # print(rule.rec_ip)
                        # print(current_packet.rec_ip)
                        if rule.rec_ip == current_packet.rec_ip or rule.rec_ip == 'any':
                            # print('almostMid')
                            if rule.destination_port == current_packet.destination_port or rule.destination_port == 'any':
                                # print('Mid')
                                if rule.options.keys() is not None:
                                    for option in rule.options.keys():
                                        if option == 'flags':
                                            for f in current_packet.flags:
                                                # print('deepest level')
                                                # print(current_packet.flags)
                                                self.log.info('deepest level')
                                                if f not in rule.flags:
                                                    break
                                        elif rule.options.get(option) != current_packet.__getattribute__(option):
                                            break

                                    # TODO check if this is at the correct spot to flag a packet that matches a given rule
                                    #  I think this might be in the incorrect spot. Might need to be moved to an else
                                    #  after the `if f not in rule.flags:` statement
                                    else:
                                        self.log.warning('ALERT HANDLER TRIGGERED ')
                                        self.alert_handler(rule, current_packet)
                                else:
                                    self.basic_rule_flagged(rule, current_packet)

    def basic_rule_flagged(self, rule, packet):
        print('~~~~~~~~ basic rule flagged ~~~~~~~~')

    def alert_handler(self, rule, packet):
        self.log.error('Signature match from IP {} msg: {}'.format(packet.send_ip, rule.message))
        self.log.error(packet.error(self.time))

    def stop(self):
        self.on = False
        self.join()
        # self.terminate()
        self.close()

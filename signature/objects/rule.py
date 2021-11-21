class Rule:
    def __init__(self, data):
        self.header = None
        self.options = {}
        self.action = None
        self.protocol = None
        self.send_ip = None
        self.source_port = None
        self.rec_ip = None
        self.destination_port = None
        self.direction = None
        self.flags = []
        self.message = ''
        self.data = data

    def parse(self):
        self.header, raw_options = self.data.split('(')
        self.parse_options(raw_options)
        self.action, self.protocol, self.send_ip, self.source_port, self.direction, self.rec_ip, self.destination_port \
            = self.header.split(' ')[:-1]

    def parse_options(self, data):
        temp_options = (data.split(')')[0]).split(';')
        parsed_options = []
        for option in temp_options:
            parsed_options.append(option.split(' ', 1))
        for i in parsed_options:
            for x in i:
                b = x.find(":")
                if b >= 0:
                    if x.replace(':', '') == 'msg':
                        self.message = i[i.index(x) + 1]
                    elif x.replace(':', '') == 'flags':
                        temp = i[i.index(x) + 1].split(',')
                        for f in temp:
                            self.flags.append(f)
                        x = x.replace(':', '')
                        self.options[x] = ''
                    else:
                        self.options[x.replace(':', '')] = i[i.index(x) + 1]

    # For testing purposes
    def print(self):
        print('{} {} {} {} -> {} {} {}'.format(self.action, self.protocol, self.send_ip, self.source_port, self.rec_ip,
                                               self.destination_port, self.options))
        pass

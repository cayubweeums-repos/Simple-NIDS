import enum
from enum import Enum


def get_name_4_value(i):
    for service_name in CommonPorts:
        if i == service_name.value:
            return service_name.name
        else:
            return 'OTHER'


class CommonPorts(enum.Enum):
    FTP_DATA = '20'
    FTP = '21'
    SSH = '22'
    TELNET = '23'
    SMTP25 = '25'
    SMTP587 = '587'
    DNS = '53'
    DHCP67 = '67'
    DHCP68 = '68'
    FINGER = '79'
    HTTP = '80'
    MS_EXCHANGE = '102'
    NNTP = '119'
    NTP = '123'
    SNMP = '161'
    HTTPS = '443'
    REXEC = '512'
    RLOGIN = '513'
    SYSLOG = '514'
    RTSP = '554'
    RSYNC = '873'
    TELNETS = '992'
    HTTP_PROXY1 = '3124'
    HTTP_PROXY2 = '3128'
    HTTP_PROXY3 = '8080'
    MYSQL = '3306'
    UPNP = '5000'
    RTP5004 = '5004'
    RTP5005 = '5005'

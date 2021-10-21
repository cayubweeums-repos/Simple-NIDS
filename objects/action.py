from enum import Enum


class Action(Enum):
    ALERT = 'alert'
    WARNING = 'warning'
    LOG = 'log'
    TRACK = 'track'

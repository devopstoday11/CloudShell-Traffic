
from abc import ABCMeta
from abc import abstractmethod


class TrafficHandler(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def initialize(self, context, logger):
        pass

    @abstractmethod
    def tearDown(self):
        pass

"""
Test prerequisite:
'ixn test' environment - a minimal IXN environment with IXN controller and two Ixia ports.
"""

import os.path
import unittest

from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.traffic.handler import TrafficHandler
from cloudshell.traffic.driver import TrafficControllerDriver

import cloudshell.traffic.tg_helper as tg_helper


expected_logger_file = 'c:/temp/TestControllerDriver.log'


class TestTrafficHandler(TrafficHandler):

    def initialize(self, context, logger):
        pass

    def tearDown(self):
        pass


class TestControllerDriver(TrafficControllerDriver):

    def __init__(self):
        super(self.__class__, self).__init__()
        self.handler = TestTrafficHandler()


class TestCloudshellTraffic(unittest.TestCase):

    def setUp(self):
        self.session = CloudShellAPISession('localhost', 'admin', 'admin', 'Global')
        self.context = tg_helper.create_context(self.session, 'ixn test', 'IxNetwork Controller', '')
        if os.path.exists(expected_logger_file):
            os.remove(expected_logger_file)

    def tearDown(self):
        self.driver.cleanup()
        self.session.EndReservation(self.context.reservation.reservation_id)
        self.session.TerminateReservation(self.context.reservation.reservation_id)

    def test_init(self):
        self.driver = TestControllerDriver()
        self.driver.initialize(self.context)
        assert(os.path.exists(expected_logger_file))

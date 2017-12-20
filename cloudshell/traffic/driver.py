
import time

from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface

import tg_helper


class TrafficControllerDriver(ResourceDriverInterface):

    def __init__(self):
        super(TrafficControllerDriver, self).__init__()

    def initialize(self, context):
        self.logger = tg_helper.get_logger(context)
        self.handler.initialize(context, self.logger)

    def cleanup(self):
        self.handler.tearDown()

    def load_config(self, context):
        tg_helper.enqueue_keep_alive(context)

    def keep_alive(self, context, cancellation_context):

        while not cancellation_context.is_cancelled:
            time.sleep(2)
        if cancellation_context.is_cancelled:
            self.cleanup()

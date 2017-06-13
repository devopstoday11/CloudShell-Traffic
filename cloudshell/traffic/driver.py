
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface

import tg_helper


class TrafficControllerDriver(ResourceDriverInterface):

    def __init__(self):
        super(TrafficControllerDriver, self).__init__()
        self.logger = tg_helper.create_logger('c:/temp/{}.log'.format(type(self).__name__))

    def initialize(self, context):
        """
        :type context:  cloudshell.shell.core.driver_context.InitCommandContext
        """

        self.handler.initialize(context, self.logger)

    def cleanup(self):
        self.handler.tearDown()

    def load_config(self, context):
        """ Enqueue keep alive command.

        :type context: cloudshell.shell.core.driver_context.ResourceRemoteCommandContext
        """

        tg_helper.enqueue_keep_alive(context)

    def keep_alive(self, context, cancellation_context):

        while not cancellation_context.is_cancelled:
            pass
        if cancellation_context.is_cancelled:
            self.handler.tearDown()

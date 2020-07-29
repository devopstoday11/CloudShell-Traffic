"""
todo: move to tg and delete module.
"""

import logging

from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface


class TrafficDriver(ResourceDriverInterface):

    def initialize(self, context, log_group='traffic_shells'):
        self.logger = get_qs_logger(log_group=log_group, log_file_prefix=context.resource.name)
        self.logger.setLevel(logging.DEBUG)
        self.handler.initialize(context, self.logger)

    def cleanup(self):
        pass

    def get_inventory(self, context):
        return self.handler.load_inventory(context)


class TrafficHandler:

    def initialize(self, resource, logger, packages_loggers=[]):

        self.resource = resource
        self.service = resource
        self.logger = logger

        for package_logger in packages_loggers:
            package_logger = logging.getLogger(package_logger)
            package_logger.setLevel(self.logger.level)
            for handler in self.logger.handlers:
                if handler not in package_logger.handlers:
                    package_logger.addHandler(handler)

    def get_connection_details(self, context):
        self.address = context.resource.address
        self.logger.debug('Address - {}'.format(self.address))
        self.user = self.resource.user
        self.logger.debug('User - {}'.format(self.user))
        self.logger.debug('Encripted password - {}'.format(self.resource.password))
        self.password = CloudShellSessionContext(context).get_api().DecryptPassword(self.resource.password).Value
        self.logger.debug('Password - {}'.format(self.password))

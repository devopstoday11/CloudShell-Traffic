
import logging

from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.workflow.orchestration.sandbox import Sandbox
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface

from .helpers import get_reservation_id


class WriteMessageToReservationOutputHandler(logging.Handler):

    def __init__(self, sandbox):
        self.sandbox = sandbox
        if type(self.sandbox) == Sandbox:
            self.session = self.sandbox.automation_api
            self.sandbox_id = self.sandbox.id
        else:
            self.session = CloudShellAPISession(host=sandbox.connectivity.server_address,
                                                token_id=sandbox.connectivity.admin_auth_token,
                                                domain=sandbox.reservation.domain)
            self.sandbox_id = get_reservation_id(sandbox)
        super(self.__class__, self).__init__()

    def emit(self, record):
        log_entry = self.format(record)
        self.session.WriteMessageToReservationOutput(self.sandbox_id, log_entry)


class TrafficDriver(ResourceDriverInterface):

    def initialize(self, context, log_group='traffic_shells'):
        self.logger = get_qs_logger(log_group=log_group, log_file_prefix=context.resource.name)
        self.logger.setLevel(logging.DEBUG)
        self.handler.initialize(context, self.logger)

    def cleanup(self):
        pass

    def get_inventory(self, context):
        return self.handler.load_inventory(context)


class TrafficHandler(object):

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

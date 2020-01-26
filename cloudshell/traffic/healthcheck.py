
import logging
import time

from cloudshell.workflow.orchestration.sandbox import Sandbox
from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext

from tg_helper import get_qs_logger

ACS_MODEL = 'Acs'
ACS_STATUS_MODEL = 'Acs_Status'
CNR_MODEL = 'Cnr'
CNR_DHCP_STATUS_MODEL = 'Cnr_Dhcp_Status'
CNR_TFTP_STATUS_MODEL = 'Cnr_Tftp_Status'
CMTS_MODEL = 'Cmts'
CISCO_CMTS_MODEL = 'Cisco_CMTS_Shell'
CASA_CMTS_MODEL = 'Casa_CMTS_Shell'
ARRIS_CMTS_MODEL = 'Arris_CMTS_Shell'
CMTS_STATUS_MODEL = 'Cmts_Status'
RESOURCE_PROVIDER_MODEL = 'Resource_Provider'
JIRA_MODEL = 'Jira'
CABLE_MODEM_MODEL = 'Cable_Modem'


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


def set_live_status(context, report):
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    if report['result']:
        liveStatusName = 'Online'
    else:
        liveStatusName = 'Error'
    cs_session.SetServiceLiveStatus(reservationId=get_reservation_id(context),
                                    serviceAlias=context.resource.name,
                                    liveStatusName=liveStatusName,
                                    additionalInfo='tool_tip')


def get_reservation_id(context):
    """
    :param ResourceCommandContext context:
    """
    try:
        return context.reservation.reservation_id
    except Exception as _:
        return context.reservation.id


def add_resources_to_reservation(context, *resources_full_path):
    """
    :param ResourceCommandContext context:
    """
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    cs_session.AddResourcesToReservation(reservationId=reservation_id, resourcesFullPath=list(resources_full_path),
                                         shared=True)
    all_resources = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Resources
    new_resources = [r for r in all_resources if r.Name in resources_full_path]
    while len(new_resources) != len(resources_full_path):
        time.sleep(1)
        all_resources = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Resources
        new_resources = [r for r in all_resources if r.Name in resources_full_path]
    return new_resources


def add_service_to_reservation(context, service_name, alias=None, attributes=[]):
    """
    :param ResourceCommandContext context:
    """
    if not alias:
        alias = service_name
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    cs_session.AddServiceToReservation(reservationId=reservation_id,
                                       serviceName=service_name, alias=alias,
                                       attributes=attributes)
    all_services = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Services
    new_service = [s for s in all_services if s.ServiceName == service_name]
    while not new_service:
        time.sleep(1)
        all_services = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Services
        new_service = [s for s in all_services if s.ServiceName == service_name]
    return new_service[0]


def get_resources_from_reservation(context, resource_model):
    """
    :param ResourceCommandContext context: resource command context
    """
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resources = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Resources
    return [r for r in resources if r.ResourceModelName == resource_model]


def get_services_from_reservation(context, service_name):
    """
    :param ResourceCommandContext context: resource command context
    """
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    services = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Services
    return [s for s in services if s.ServiceName == service_name]


def get_mac_from_cable_modem(context):
    """
    :param ResourceCommandContext context: resource command context
    """
    cm_resource = get_resources_from_reservation(context, 'Cable_Modem')[0]
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    cm_resource_details = cs_session.GetResourceDetails(cm_resource.Name)
    return [a.Value for a in cm_resource_details.ResourceAttributes if a.Name == 'Cable_Modem.mac_address'][0]


def get_connection_details_from_resource(context, resource_model, requested_details=['User', 'Password']):
    """
    :param ResourceCommandContext context: resource command context
    """
    cm_resource = get_resources_from_reservation(context, resource_model)[0]
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resource_details = cs_session.GetResourceDetails(cm_resource.Name)
    details = {}
    details['Address'] = resource_details.Address
    for requested_detail in requested_details:
        attribute_name = '{}.{}'.format(resource_model, requested_detail)
        details[requested_detail] = [a.Value for a in resource_details.ResourceAttributes if a.Name == attribute_name][0]
    return details


def get_connection_details_from_cnr(context):
    """
    :param ResourceCommandContext context: resource command context
    """
    return get_connection_details_from_resource(context, 'Cnr', ['User', 'Password', 'DHCP Log File', 'TFTP Log File'])


def get_connection_details_from_acs(context):
    """
    :param ResourceCommandContext context: resource command context
    """
    return get_connection_details_from_resource(context, 'Acs')


def get_mac_from_cable_modem(context):
    """
    :param ResourceCommandContext context: resource command context
    """
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resources = cs_session.GetReservationDetails(get_reservation_id(context)).ReservationDescription.Resources
    cm_resource = [r for r in resources if r.ResourceModelName == 'Cable_Modem'][0]
    cm_resource_details = cs_session.GetResourceDetails(cm_resource.Name)
    return [a.Value for a in cm_resource_details.ResourceAttributes if a.Name == 'Cable_Modem.mac_address'][0]


class HealthCheckDriver(ResourceDriverInterface):

    def initialize(self, context):
        self.logger = get_qs_logger(log_group='traffic_shells', log_file_prefix=context.resource.name)
        self.logger.setLevel(logging.DEBUG)
        self.handler.initialize(context, self.logger)

    def cleanup(self):
        pass

    def get_inventory(self, context):
        return self.handler.load_inventory(context)

    def health_check(self, context, mac_address):
        if not mac_address:
            mac_address = get_mac_from_cable_modem(context)
        return self.handler.health_check(context, mac_address)


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


class HealthCheckHandler(TrafficHandler):

    def initialize(self, context, logger, resource):

        super(HealthCheckHandler, self).initialize(resource=resource, logger=logger, packages_loggers=['pycmts', 'pylgi'])

        self.address = context.resource.address
        if not self.address:
            self.address = self.resource.address
        self.user = self.resource.user
        self.logger.debug('User - {}'.format(self.user))
        self.logger.debug('Encripted password - {}'.format(self.resource.password))
        self.password = CloudShellSessionContext(context).get_api().DecryptPassword(self.resource.password).Value
        self.logger.debug('Password - {}'.format(self.password))

    def health_check(self):
        report = {}
        report['name'] = ''
        report['result'] = False
        report['status'] = ''
        report['summary'] = {}
        report['log'] = {}
        return report

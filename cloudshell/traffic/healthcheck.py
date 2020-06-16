import json

from cloudshell.api.cloudshell_api import CloudShellAPISession, InputNameValue

from tg_helper import (get_resources_from_reservation, get_connection_details_from_resource,
                       get_services_from_reservation)
from common import TrafficDriver, TrafficHandler, get_reservation_id

ACS_MODEL = 'Acs'
ACS_STATUS_MODEL = 'Acs_Status'
CNR_MODEL = 'Cnr'
CNR_DHCP_STATUS_MODEL = 'Cnr_Dhcp_Status'
CNR_TFTP_STATUS_MODEL = 'Cnr_Tftp_Status'
CMTS_STATUS_MODEL = 'Cmts_Status'
RESOURCE_PROVIDER_MODEL = 'Resource_Provider'
JIRA_MODEL = 'Jira'
CABLE_MODEM_MODEL = 'Cable_Modem'


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


def get_health_check(context, model, command_name='health_check', **params):
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resource = get_resources_from_reservation(context, model)[0]
    input_params = [InputNameValue(k, v) for k, v in params.items()]
    if resource:
        result = cs_session.ExecuteCommand(get_reservation_id(context), resource.Name, 'Resource',
                                           command_name, input_params)
    else:
        service = get_services_from_reservation(context, model)[0]
        result = cs_session.ExecuteCommand(get_reservation_id(context), service.Alias, 'Service',
                                           command_name, input_params)
    return json.loads(result.Output) if result.Output.lower() != 'none' else None


class HealthCheckDriver(TrafficDriver):

    def initialize(self, context, log_group='healthcheck_shells'):
        super(HealthCheckDriver, self).initialize(context, log_group)

    def health_check(self, context, mac_address):
        if not mac_address:
            mac_address = get_mac_from_cable_modem(context)
        return self.handler.health_check(context, mac_address)


class HealthCheckHandler(TrafficHandler):

    def initialize(self, context, logger, resource):
        super(HealthCheckHandler, self).initialize(resource=resource, logger=logger,
                                                   packages_loggers=['pycmts', 'pylgi'])
        self.get_connection_details(context)

    def health_check(self):
        report = {}
        report['name'] = ''
        report['result'] = False
        report['status'] = ''
        report['summary'] = {}
        report['log'] = {}
        return report

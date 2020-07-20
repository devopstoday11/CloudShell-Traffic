import json
import logging
from typing import Optional

from cloudshell.api.cloudshell_api import CloudShellAPISession, InputNameValue
from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.shell.core.driver_context import ResourceCommandContext
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext

from .helpers import get_reservation_id, get_reservation_description
from .helpers import get_resources_from_reservation, get_services_from_reservation

ACS_MODEL = 'Acs'
CNR_MODEL = 'Cnr'
CABLE_MODEM_MODEL = 'Cable_Modem'
RESOURCE_PROVIDER_MODEL = 'Resource_Provider'
JIRA_MODEL = 'Jira'
HEALTHCHECK_STATUS = 'Healthcheck_Status'


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


def set_health_check_status_live_status(context: ResourceCommandContext, status: bool,
                                        status_selector: Optional[str] = 'none') -> None:

    health_check_service = None
    description = get_reservation_description(context)
    resource_connectors = [c for c in description.Connectors if context.resource.name in [c.Source, c.Target]]
    for connector in resource_connectors:
        other_end_name = connector.Target if connector.Source == context.resource.name else connector.Source
        other_end_services = [s for s in description.Services if
                              s.Alias == other_end_name and s.ServiceName == HEALTHCHECK_STATUS]
        if status_selector != 'none':
            other_end_services = [s for s in other_end_services if
                                  (s for a in s.Attributes if a.Value == status_selector)]
        if other_end_services:
            health_check_service = other_end_services[0]
            break

    if health_check_service:
        cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                          token_id=context.connectivity.admin_auth_token,
                                          domain=context.reservation.domain)
        cs_session.ExecuteCommand(get_reservation_id(context), health_check_service.Alias, 'Service',
                                  'set_live_status',
                                  [InputNameValue('status', 'Online' if status else 'Error')])


class HealthCheckDriver(ResourceDriverInterface):

    def initialize(self, context, resource, log_group='healthcheck_shells', packages_loggers=None):

        super().initialize(context)

        self.resource = resource
        self.service = resource

        self.logger = get_qs_logger(log_group=log_group, log_file_prefix=context.resource.name)
        self.logger.setLevel(logging.DEBUG)

        for package_logger in packages_loggers or ['pycmts', 'pylgi']:
            package_logger = logging.getLogger(package_logger)
            package_logger.setLevel(self.logger.level)
            for handler in self.logger.handlers:
                if handler not in package_logger.handlers:
                    package_logger.addHandler(handler)

        self.get_connection_details(context)

    def get_connection_details(self, context):
        self.address = context.resource.address
        self.logger.debug(f'Address - {self.address}')
        self.user = self.resource.user
        self.logger.debug(f'User - {self.user}')
        self.logger.debug(f'Encripted password - {self.resource.password}')
        self.password = CloudShellSessionContext(context).get_api().DecryptPassword(self.resource.password).Value
        self.logger.debug(f'Password - {self.password}')

    @property
    def clean_report(self):
        report = {}
        report['name'] = ''
        report['result'] = False
        report['status'] = ''
        report['summary'] = {}
        report['log'] = {}
        return report

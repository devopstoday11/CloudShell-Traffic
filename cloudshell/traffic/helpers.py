
import logging
import re
import time
from typing import List, Union

from cloudshell.api.cloudshell_api import (ReservationDescriptionInfo, ReservedResourceInfo, ServiceInstance,
                                           SetConnectorRequest, CloudShellAPISession)
from cloudshell.shell.core.driver_context import ResourceCommandContext, ReservationContextDetails
from cloudshell.workflow.orchestration.sandbox import Sandbox


class WriteMessageToReservationOutputHandler(logging.Handler):

    def __init__(self, sandbox):
        self.sandbox = sandbox
        if type(self.sandbox) == Sandbox:
            self.session = self.sandbox.automation_api
            self.sandbox_id = self.sandbox.id
        else:
            self.session = get_cs_session(sandbox)
            self.sandbox_id = get_reservation_id(sandbox)
        super().__init__()

    def emit(self, record):
        log_entry = self.format(record)
        self.session.WriteMessageToReservationOutput(self.sandbox_id, log_entry)


def get_cs_session(context_or_sandbox: Union[ResourceCommandContext, Sandbox]) -> CloudShellAPISession:
    """ Get CS session from context. """
    if type(context_or_sandbox) == Sandbox:
        return context_or_sandbox.automation_api
    else:
        return CloudShellAPISession(host=context_or_sandbox.connectivity.server_address,
                                    token_id=context_or_sandbox.connectivity.admin_auth_token,
                                    domain=context_or_sandbox.reservation.domain)


def get_reservation_id(context_sandbox_reservation) -> str:
    """ Returns reservation ID from context, sandbox, or reservation.

    Do not add type hinting as there are way too many around cloudshell API.
    """
    try:
        return context_sandbox_reservation.id
    except AttributeError as _:
        pass
    try:
        return context_sandbox_reservation.reservation.reservation_id
    except AttributeError as _:
        pass
    try:
        return context_sandbox_reservation.reservation.id
    except AttributeError as _:
        pass
    try:
        return context_sandbox_reservation.Reservation.Id
    except AttributeError as _:
        pass


def get_reservation_description(context_or_sandbox: Union[ResourceCommandContext, Sandbox]) -> ReservationDescriptionInfo:
    """ Get reserservation description. """
    reservation_id = get_reservation_id(context_or_sandbox)
    cs_session = get_cs_session(context_or_sandbox)
    return cs_session.GetReservationDetails(reservation_id).ReservationDescription


def get_family_attribute(context_or_sandbox: Union[ResourceCommandContext, Sandbox], resource_name: str,
                         attribute: str) -> str:
    """ Get value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.
    """
    cs_session = get_cs_session(context_or_sandbox)
    res_details = cs_session.GetResourceDetails(resource_name)
    res_model = res_details.ResourceModelName
    res_family = res_details.ResourceFamilyName

    # check against all 3 possibilities
    model_attribute = f'{res_model}.{attribute}'
    family_attribute = f'{res_family}.{attribute}'
    attribute_names = [attribute, model_attribute, family_attribute]
    return [attr for attr in res_details.ResourceAttributes if attr.Name in attribute_names][0].Value


def set_family_attribute(context_or_sandbox: Union[ResourceCommandContext, Sandbox], resource_name: str, attribute: str,
                         value: str) -> None:
    """ Set value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.
    """

    cs_session = get_cs_session(context_or_sandbox)
    res_details = cs_session.GetResourceDetails(resource_name)
    res_model = res_details.ResourceModelName
    res_family = res_details.ResourceFamilyName

    model_attribute = f'{res_model}.{attribute}'
    family_attribute = f'{res_family}.{attribute}'
    attribute_names = [attribute, model_attribute, family_attribute]
    actual_attribute = [attr for attr in res_details.ResourceAttributes if attr.Name in attribute_names][0].Name
    cs_session.SetAttributeValue(resource_name, actual_attribute, value)


def add_resource_to_db(context: ResourceCommandContext, resource_model, resource_full_name, resource_address='na',
                       **attributes):
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)

    resources_w_requested_name = cs_session.FindResources(resourceFullName=resource_full_name).Resources
    if len(resources_w_requested_name) > 0:
        return

    cs_session.CreateResource(resourceFamily='CS_GenericResource',
                               resourceModel=resource_model,
                               resourceName=resource_full_name,
                               resourceAddress=resource_address)
    if context.reservation.domain != 'Global':
        cs_session.AddResourcesToDomain(domainName=context.reservation.domain,
                                        resourcesNames=[resource_full_name])
    for attribute, value in attributes.items():
        set_family_attribute(context, resource_full_name, attribute, value)


def wait_for_resources(cs_session: CloudShellAPISession, reservation_id: str, resources_names: Union[list, str],
                       timeout: int = 4) -> None:
    """ Wait untill all resources show in reservation detilas. """
    if type(resources_names) == str:
        resources_names = [resources_names]
    for _ in range(timeout + 1):
        all_resources = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Resources
        new_resources = [r for r in all_resources if r.Name in resources_names]
        if len(new_resources) == len(resources_names):
            return
        time.sleep(1)
    raise TimeoutError(f'Resources {resources_names} not in reservation after {timeout} seconds')


def wait_for_services(cs_session: CloudShellAPISession, reservation_id: str, aliases: Union[list, str],
                      timeout: int = 4) -> None:
    """ Wait untill all services show in reservation detilas. """
    if type(aliases) == str:
        aliases = [aliases]
    for _ in range(timeout + 1):
        all_services = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Services
        new_services = [s for s in all_services if s.Alias in aliases]
        if len(new_services) == len(aliases):
            return
        time.sleep(1)
    raise TimeoutError(f'Services {aliases} not in reservation after {timeout} seconds')


def wait_for_connectors(cs_session: CloudShellAPISession, reservation_id: str, aliases: Union[list, str],
                        timeout: int = 4) -> None:
    """ Wait untill all connectors show in reservation detilas. """
    if type(aliases) == str:
        aliases = [aliases]
    for _ in range(timeout + 1):
        all_connectors = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Connectors
        new_connectors = [c for c in all_connectors if c.Alias in aliases]
        if len(new_connectors) == len(aliases):
            return
        time.sleep(1)
    raise TimeoutError(f'Connectors {aliases} not in reservation after {timeout} seconds')


def get_resources_from_reservation(context_or_sandbox: Union[ResourceCommandContext, Sandbox],
                                   *resource_models: str) -> List[ReservedResourceInfo]:
    """ Get all resources with the requested resource model names. """
    resources = get_reservation_description(context_or_sandbox).Resources
    return [r for r in resources if r.ResourceModelName in resource_models]


def get_services_from_reservation(context_or_sandbox: Union[ResourceCommandContext, Sandbox],
                                  *service_names: str) -> List[ServiceInstance]:
    """ Get all services with the requested service names. """
    services = get_reservation_description(context_or_sandbox).Services
    return [s for s in services if s.ServiceName in service_names]


def get_location(port_resource) -> str:
    """ Extracts port location in format ip/module/port from port full address.

    :param port_resource: Port resource object.
    """
    return re.sub(r'M|PG[0-9]+\/|P', '', port_resource.FullAddress)

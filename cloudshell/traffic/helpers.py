
import re
import time
from typing import Dict, List, Optional

from cloudshell.api.cloudshell_api import (ReservationDescriptionInfo, ReservedResourceInfo, ServiceInstance,
                                           SetConnectorRequest)
from cloudshell.shell.core.driver_context import ResourceCommandContext

from cloudshell.api.cloudshell_api import CloudShellAPISession


def get_reservation_description(context: ResourceCommandContext) -> ReservationDescriptionInfo:
    """ Get reserservation description. """
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    return cs_session.GetReservationDetails(reservation_id).ReservationDescription


def get_family_attribute(context: ResourceCommandContext, resource_name: str, attribute: str) -> str:
    """ Get value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.
    """
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    res_details = cs_session.GetResourceDetails(resource_name)
    res_model = res_details.ResourceModelName
    res_family = res_details.ResourceFamilyName

    # check against all 3 possibilities
    model_attribute = '{}.{}'.format(res_model, attribute)
    family_attribute = '{}.{}'.format(res_family, attribute)
    attribute_names = [attribute, model_attribute, family_attribute]
    return [attr for attr in res_details.ResourceAttributes if attr.Name in attribute_names][0].Value


def set_family_attribute(context: ResourceCommandContext, resource_name: str, attribute: str, value: str):
    """ Set value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.
    """

    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    res_details = cs_session.GetResourceDetails(resource_name)
    res_model = res_details.ResourceModelName
    res_family = res_details.ResourceFamilyName

    model_attribute = '{}.{}'.format(res_model, attribute)
    family_attribute = '{}.{}'.format(res_family, attribute)
    attribute_names = [attribute, model_attribute, family_attribute]
    actual_attribute = [attr for attr in res_details.ResourceAttributes if attr.Name in attribute_names][0].Name
    cs_session.SetAttributeValue(resource_name, actual_attribute, value)


def get_address(port_resource):
    return re.sub('M|PG[0-9]+\/|P', '', port_resource.FullAddress)


def is_blocking(blocking):
    return True if blocking.lower() == "true" else False


def get_reservation_id(context: ResourceCommandContext) -> str:
    try:
        return context.reservation.reservation_id
    except Exception as _:
        return context.reservation.id


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


def add_resources_to_reservation(context: ResourceCommandContext, *resources_full_path):
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


def add_service_to_reservation(context: ResourceCommandContext, service_name, alias=None, attributes=[]):
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


def add_connector_to_reservation(context: ResourceCommandContext, source_name, target_name, direction='bi', attributes=[]):
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    connector = SetConnectorRequest(source_name, target_name, direction, attributes)
    cs_session.SetConnectorsInReservation(reservation_id, [connector])
    all_connectors = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Connectors
    new_connectors = [c for c in all_connectors if c.Source == source_name and c.Target == target_name]
    while len(new_connectors) == 0:
        time.sleep(1)
        all_connectors = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Connectors
        new_connectors = [c for c in all_connectors if c.Source == source_name and c.Target == target_name]
    return connector


def get_resources_from_reservation(context: ResourceCommandContext,
                                   *resource_models: List[str]) -> List[ReservedResourceInfo]:
    """ Get all resources with the requested resource model names. """
    resources = get_reservation_description(context).Resources
    return [r for r in resources if r.ResourceModelName in resource_models]


def get_services_from_reservation(context: ResourceCommandContext, *service_names: List[str]) -> List[ServiceInstance]:
    """ Get all services with the requested service names. """
    services = get_reservation_description(context).Services
    return [s for s in services if s.ServiceName in service_names]


def get_connection_details_from_resource(context: ResourceCommandContext, resource_model: str,
                                         requested_details: Optional[List[str]] = ['User', 'Password']) -> Dict[str, str]:
    cm_resource = get_resources_from_reservation(context, resource_model)[0]
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resource_details = cs_session.GetResourceDetails(cm_resource.Name)
    details = {'Address': resource_details.Address}
    for requested_detail in requested_details:
        attribute_name = '{}.{}'.format(resource_model, requested_detail)
        details[requested_detail] = [a.Value for a in resource_details.ResourceAttributes if a.Name == attribute_name][0]
    return details


import re
import logging
import time

from cloudshell.core.logger.qs_logger import get_qs_logger
from cloudshell.api.cloudshell_api import CloudShellAPISession


def get_logger(context):
    """

    :return: logger according to cloudshell standards.
    """

    logger = get_qs_logger(log_group='traffic_shells', log_file_prefix=context.resource.name)
    logger.setLevel(logging.DEBUG)
    return logger


def get_reservation_ports(session, reservation_id, model_name='Generic Traffic Generator Port'):
    """ Get all Generic Traffic Generator Port in reservation.

    :return: list of all Generic Traffic Generator Port resource objects in reservation
    """

    reservation_ports = []
    reservation = session.GetReservationDetails(reservation_id).ReservationDescription
    for resource in reservation.Resources:
        if resource.ResourceModelName == model_name:
            reservation_ports.append(resource)
    return reservation_ports


def get_family_attribute(context, resource_name, attribute):
    """ Get value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.

    :param CloudShellAPISession api:
    :param str resource_name:
    :param str attribute: the name of target attribute without prefixed-namespace
    :return attribute value
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


def set_family_attribute(context, resource_name, attribute, value):
    """ Set value of resource attribute.

    Supports 2nd gen shell namespace by pre-fixing family/model namespace.

    :param CloudShellAPISession api:
    :param str resource_name:
    :param str attribute: the name of target attribute without prefixed-namespace
    :param str value: attribute value
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


def add_resource_to_db(context, resource_model, resource_full_name, resource_address='na', **attributes):
    """
    :param ResourceCommandContext context:
    """
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


def get_resources_from_reservation(context, *resource_models):
    """
    :param ResourceCommandContext context: resource command context
    :param resource_models: list of resource models to retrieve
    """
    reservation_id = get_reservation_id(context)
    cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token,
                                      domain=context.reservation.domain)
    resources = cs_session.GetReservationDetails(reservation_id).ReservationDescription.Resources
    return [r for r in resources if r.ResourceModelName in resource_models]


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

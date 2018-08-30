
import time
import re
import logging

from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.context_utils import get_resource_name
from cloudshell.core.logger.qs_logger import get_qs_logger

import quali_rest_api_helper


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


def get_reservation_resources(session, reservation_id, *models):
    """ Get all resources of given models in reservation.

    :param session: CloudShell session
    :type session: cloudshell.api.cloudshell_api.CloudShellAPISession
    :param reservation_id: active reservation ID
    :param models: list of requested models
    :return: list of all resources of models in reservation
    """

    models_resources = []
    reservation = session.GetReservationDetails(reservation_id).ReservationDescription
    for resource in reservation.Resources:
        if resource.ResourceModelName in models:
            models_resources.append(resource)
    return models_resources


def get_family_attribute(session, resource, attribute):
    return session.GetAttributeValue(resource.Name, _family_attribute_name(resource, attribute))


def set_family_attribute(session, resource, attribute, value):
    session.SetAttributeValue(resource.Name, _family_attribute_name(resource, attribute), value)


def enqueue_keep_alive(context):
    my_api = CloudShellSessionContext(context).get_api()
    reservation_id = context.reservation.reservation_id
    resource_name = get_resource_name(context=context)
    my_api.EnqueueCommand(reservationId=reservation_id, targetName=resource_name, commandName="keep_alive",
                          targetType="Service")


def get_address(port_resource):
    return re.sub('M|PG[0-9]+\/|P', '', port_resource.FullAddress)


def is_blocking(blocking):
    return True if blocking.lower() == "true" else False


def write_to_reservation_out(context, message):
    my_api = CloudShellSessionContext(context).get_api()
    my_api.WriteMessageToReservationOutput(context.reservation.reservation_id, message)


def attach_stats_csv(context, logger, view_name, output, suffix='csv'):
    quali_api_helper = quali_rest_api_helper.create_quali_api_instance(context, logger)
    quali_api_helper.login()
    full_file_name = view_name.replace(' ', '_') + '_' + time.ctime().replace(' ', '_') + '.' + suffix
    quali_api_helper.upload_file(context.reservation.reservation_id, file_name=full_file_name, file_stream=output)
    write_to_reservation_out(context, 'Statistics view saved in attached file - ' + full_file_name)


def _family_attribute_name(resource, attribute):
    family_attribute_name = attribute
    if resource.ResourceFamilyName.startswith('CS_'):
        family_attribute_name = resource.ResourceFamilyName + '.' + family_attribute_name
    return family_attribute_name

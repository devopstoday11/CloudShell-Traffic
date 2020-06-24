
import json

from .helpers import get_resources_from_reservation, get_reservation_description, get_reservation_id
from .healthcheck import HealthCheckDriver, HealthCheckHandler


CMTS_MODEL = 'Cmts'
CISCO_CMTS_MODEL = 'Cisco_CMTS_Shell'
CASA_CMTS_MODEL = 'Casa_CMTS_Shell'
ARRIS_CMTS_MODEL = 'Arris_CMTS_Shell'


def get_mac_domain_from_sub_resource():
    return None


def get_cmts_model(context):
    if get_resources_from_reservation(context, CISCO_CMTS_MODEL):
        return CISCO_CMTS_MODEL
    if get_resources_from_reservation(context, CASA_CMTS_MODEL):
        return CASA_CMTS_MODEL
    return ARRIS_CMTS_MODEL


class CMTSDriver(HealthCheckDriver):

    def cleanup(self):
        self.handler.cleanup()

    def get_mac_state(self, context, mac_address):
        return self.handler.get_mac_state(mac_address)

    def get_mac_attributes(self, context, mac_address):
        return self.handler.get_mac_attributes(mac_address)

    def get_mac_domain(self, context, mac_address):
        return self.handler.get_mac_domain(mac_address)

    def health_check(self, context, mac_address, *states):
        return self.handler.health_check(context, mac_address, *states)


class CMTSHandler(HealthCheckHandler):

    def initialize(self, context, logger, resource, CmtsClass):
        super(CMTSHandler, self).initialize(context, logger, resource)
        self.cmts = CmtsClass(hostname=self.address, username=self.user, password=self.password)
        try:
            self.cmts.connect()
        except EOFError as _:
            raise EOFError('Failed to connect to CMTS {} with credentials {}/{}'.
                           format(self.address, self.user, self.password))

    def cleanup(self):
        if self.cmts:
            self.cmts.disconnect()

    def load_inventory(self, context, gen_chassis, GenericPortChannel):
        self.cmts.get_inventory()
        self.resource.add_sub_resource('C0', gen_chassis)
        for module in self.cmts.modules.values():
            self.logger.debug('Loading module {}'.format(module.name))
            self.load_module(gen_chassis, module)
        for mac_domain in self.cmts.mac_domains.values():
            self.logger.debug('Loading mac domain {}'.format(mac_domain.name))
            self.load_mac_domain(self.resource, mac_domain, GenericPortChannel)
        return self.resource.create_autoload_details()

    def load_mac_domain(self, resource, mac_domain, GenericPortChannel):
        mac_domain_name = mac_domain.name.replace('(', '[').replace(')', ']')
        gen_port_channel = GenericPortChannel('MacDomain-{}'.format(mac_domain_name))
        resource.add_sub_resource(mac_domain.name, gen_port_channel)
        down_stream_port = ['DownStream-Port-' + stream.index for stream in mac_domain.down_streams]
        up_stream_ports = ['UpStream-Port-' + stream.index for stream in mac_domain.up_streams]
        gen_port_channel.associated_ports = '{} {}'.format(' '.join(down_stream_port), ' '.join(up_stream_ports))
        cnr = mac_domain.get_helper()
        gen_port_channel.cnr_ip_address = cnr
        self.logger.info(gen_port_channel.cnr_ip_address)

    def get_mac_state(self, mac_address):
        self.cmts.get_cable_modems(mac_address)
        cable_modem = self.cmts.cable_modems.get(mac_address)
        if cable_modem:
            self.logger.debug('mac - {} -> cable modem state {}'.format(mac_address, cable_modem.state.name))
            return cable_modem.state.name
        self.logger.debug('no CM for mac - {}'.format(mac_address))
        return 'None'

    def get_mac_attributes(self, mac_address):
        self.cmts.get_cable_modems(mac_address)
        cable_modem = self.cmts.cable_modems.get(mac_address)
        if cable_modem:
            self.logger.debug('mac - {} -> cable modem attributes {}'.format(mac_address, cable_modem.attributes))
            return cable_modem.attributes
        self.logger.debug('no CM for mac - {}'.format(mac_address))
        return 'None'

    def get_mac_domain(self, mac_address):
        mac_domain = None
        self.cmts.get_cable_modems(mac_address)
        if self.cmts.cable_modems.get(mac_address):
            self.cmts.get_inventory()
            mac_domain = self.cmts.cable_modems.get(mac_address).mac_domain
        self.logger.debug('mac - {} -> mac domain {}'.format(mac_address, mac_domain))
        return mac_domain.name if mac_domain else ''

    def health_check(self, context, mac_address, *states):
        report = super(CMTSHandler, self).health_check()
        report['name'] = self.resource.name
        self.cmts.get_cable_modems(mac_address)
        try:
            mac = self.cmts.cable_modems[mac_address]
            self.logger.debug('attributes {}'.format(mac.attributes))
            report['result'] = mac.state in states
            report['status'] = mac.state.name
            report['summary'] = mac.attributes
            report['log'] = {}
        except Exception as e:
            report['result'] = False
            report['status'] = str(e)
        self.logger.info('CMTS health check report {}'.format(json.dumps(report, indent=2)))
        health_check = {'report': report, 'log': ''}
        self.logger.info(json.dumps(health_check, indent=2))

        description = get_reservation_description(context)
        resource_connectors = [c for c in description.Connectors if context.resource.name in [c.Source, c.Target]]
        for connector in resource_connectors:
            other_end_name = connector.Target if connector.Source == context.resource.name else c.Source
            other_end_services = [s for s in description.Services if s.Alias == other_end_name and s.ServiceName == 'Healthcheck_Status']
            if other_end_services:
                health_check_service = other_end_services[0]
                break

        from cloudshell.api.cloudshell_api import CloudShellAPISession, InputNameValue
        cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                          token_id=context.connectivity.admin_auth_token,
                                          domain=context.reservation.domain)
        cs_session.ExecuteCommand(get_reservation_id(context), health_check_service.Alias, 'Service',
                                  'set_live_status',
                                  [InputNameValue('status', 'Online' if report['result'] else 'Error')])
        return health_check

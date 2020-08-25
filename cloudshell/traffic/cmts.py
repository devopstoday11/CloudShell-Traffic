
import json
from abc import abstractmethod

from cloudshell.shell.core.driver_context import InitCommandContext

from .healthcheck import HealthCheckDriver, set_health_check_live_status
from .helpers import get_resources_from_reservation

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


class CmtsDriver(HealthCheckDriver):

    def initialize(self, context: InitCommandContext, resource, CmtsClass) -> None:
        super().initialize(context, resource)
        self.cmts = CmtsClass(hostname=self.address, username=self.user, password=self.password)
        self.cmts.connect()

    def cleanup(self):
        self.cmts.disconnect()
        super().cleanup()

    def load_inventory(self, gen_chassis, GenericPortChannel):
        self.cmts.get_inventory()
        self.resource.add_sub_resource('C0', gen_chassis)
        for module in self.cmts.modules.values():
            self.logger.debug(f'Loading module {module.name}')
            self.load_module(gen_chassis, module)
        for mac_domain in self.cmts.mac_domains.values():
            self.logger.debug(f'Loading mac domain {mac_domain.name}')
            self.load_mac_domain(self.resource, mac_domain, GenericPortChannel)
        return self.resource.create_autoload_details()

    @abstractmethod
    def load_module(self, gen_chassis, module):
        pass

    def load_mac_domain(self, resource, mac_domain, GenericPortChannel):
        mac_domain_name = mac_domain.name.replace('(', '[').replace(')', ']')
        gen_port_channel = GenericPortChannel(f'MacDomain-{mac_domain_name}')
        resource.add_sub_resource(mac_domain.name, gen_port_channel)
        down_stream_port = ['DownStream-Port-' + stream.index for stream in mac_domain.down_streams]
        up_stream_ports = ['UpStream-Port-' + stream.index for stream in mac_domain.up_streams]
        gen_port_channel.associated_ports = f'{" ".join(down_stream_port)} {" ".join(up_stream_ports)}'
        cnr = mac_domain.get_helper()
        gen_port_channel.cnr_ip_address = str(cnr)
        self.logger.info(gen_port_channel.cnr_ip_address)

    def get_cm_state(self, mac_address):
        cable_modem = self.cmts.get_cable_modems(mac_address).get(mac_address.lower())
        if cable_modem:
            self.logger.debug(f'mac - {mac_address} -> cable modem state {cable_modem.state.name}')
            return cable_modem.state.name
        self.logger.warning(f'no CM for mac - {mac_address}')
        return 'None'

    def get_cm_attributes(self, mac_address):
        cable_modem = self.cmts.get_cable_modems(mac_address).get(mac_address.lower())
        if cable_modem:
            attributes = cable_modem.get_attributes()
            self.logger.debug(f'mac - {mac_address} -> cable modem attributes {attributes}')
            return attributes
        self.logger.warning(f'no CM for mac - {mac_address}')
        return 'None'

    def get_cm_cpe(self, mac_address):
        cable_modem = self.cmts.get_cable_modems(mac_address).get(mac_address.lower())
        if cable_modem:
            cpe = cable_modem.get_cpe()
            if cpe:
                attributes = cpe.get_attributes()
                self.logger.debug(f'mac - {mac_address} -> CPE attributes {attributes}')
                return attributes
            self.logger.info(f'no CPE for mac - {mac_address}')
            return 'None'
        self.logger.warning(f'no CM for mac - {mac_address}')
        return 'None'

    def get_cm_domain(self, mac_address):
        mac_domain = None
        cable_modem = self.cmts.get_cable_modems(mac_address).get(mac_address.lower())
        if cable_modem:
            self.cmts.get_inventory()
            mac_domain = cable_modem.mac_domain
        self.logger.debug(f'mac - {mac_address} -> mac domain {mac_domain}')
        return mac_domain.name if mac_domain else ''

    def get_cm_health_check(self, context, mac_address, *states):
        report = super().clean_report
        report['name'] = self.resource.name
        cable_modem = self.cmts.get_cable_modems(mac_address).get(mac_address.lower())
        if cable_modem:
            mac = self.cmts.cable_modems[mac_address.lower()]
            attributes = mac.get_attributes()
            self.logger.debug(f'attributes {attributes}')
            report['result'] = mac.state in states
            report['status'] = mac.state.name
            report['summary'] = attributes
            report['log'] = {}
        else:
            report['result'] = False
            report['status'] = f'no CM for mac - {mac_address}'
        self.logger.info(f'CMTS health check report {json.dumps(report, indent=2)}')

        set_health_check_live_status(context, self.resource.name, report['result'])

        return {'report': report, 'log': ''}

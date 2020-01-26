
from healthcheck import HealthCheckDriver, HealthCheckHandler, get_mac_from_cable_modem


def get_mac_domain_from_sub_resource():
    return None


class CMTSDriver(HealthCheckDriver):

    def cleanup(self):
        self.handler.cleanup()

    def is_mac_exists(self, context, mac_address):
        if not mac_address:
            mac_address = get_mac_from_cable_modem(context)
        return self.handler.is_mac_exists(mac_address)

    def get_mac_domain(self, context, mac_address):
        if not mac_address:
            mac_address = get_mac_from_cable_modem(context)
        return self.handler.get_mac_domain(mac_address)


class CMTSHandler(HealthCheckHandler):

    def initialize(self, context, logger, resource, CmtsClass):
        super(CMTSHandler, self).initialize(context, logger, resource)
        self.cmts = CmtsClass(hostname=self.address, username=self.user, password=self.password)
        self.cmts.get_inventory()

    def cleanup(self):
        if self.cmts:
            self.cmts.disconnect()

    def load_inventory(self, context, gen_chassis, GenericPortChannel):
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

    def is_mac_exists(self, mac_address):
        self.cmts.get_cable_modems(mac_address)
        cable_modem = self.cmts.cable_modems.get(mac_address)
        self.logger.debug('mac - {} -> cable modem {}'.format(mac_address, cable_modem))
        return True if cable_modem else False

    def get_mac_domain(self, mac_address):
        self.cmts.get_cable_modems(mac_address)
        mac_domain = self.cmts.cable_modems.get(mac_address).mac_domain
        self.logger.debug('mac - {} -> mac domain {}'.format(mac_address, mac_domain))
        return mac_domain.name

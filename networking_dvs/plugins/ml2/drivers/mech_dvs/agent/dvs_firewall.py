from neutron.agent import firewall
from neutron.i18n import _LW, _LI
from oslo_log import log as logging

from networking_dvs.common import config
from networking_dvs.utils import dvs_util, security_group_utils as sg_util

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):
        self.networking_map = dvs_util.create_network_map_from_config(
            CONF.ML2_VMWARE)
        self.dvs_ports = {}  # Conaints the list of known ports, this may fill over time
        self._defer_apply = False
        # Map for known ports and dvs it is connected to.
        self.dvs_port_map = {}

    def prepare_port_filter(self, ports):
        self._process_port_filter(ports)

    def apply_port_filter(self, ports):
        self._process_port_filter(ports)

    def update_port_filter(self, ports):
        self._process_port_filter(ports)

    def remove_port_filter(self, ports):
        LOG.info(_LI("Clean up security group rules on deleted ports"))
        for p_id in ports:
            port = self.dvs_ports.get(p_id)
            if port is not None:
                self._remove_sg_from_dvs_port(port)
                self.dvs_ports.pop(port['device'], None)
                for port_set in self.dvs_port_map.values():
                    port_set.discard(port['id'])

    def filter_defer_apply_on(self):
        LOG.info("Defer apply on filter")
        pass

    def filter_defer_apply_off(self):
        LOG.info("Defer apply off filter")
        pass

    @property
    def ports(self):
        # LOG.info("ports")
        return self.dvs_ports

    def update_security_group_members(self, sg_id, ips):
        LOG.info("update_security_group_members")

    def update_security_group_rules(self, sg_id, rules):
        LOG.info("update_security_group_rules id {} rules {}".format(sg_id, rules))

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        LOG.info("security_group_updated action type {} ids {} device {}".format(action_type, sec_group_ids, device_id))

    def _process_port_filter(self, ports):
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])

        for port in ports:
            self.dvs_ports[port['device']] = port

        self._apply_sg_rules_for_port(ports)

    @dvs_util.wrap_retry
    def _apply_sg_rules_for_port(self, ports):
        for port in ports:
            # Call _get_dvs_for_port_id to set up dvs port map for ports
            self._get_dvs_for_port_id(
                port['id'], port.get('binding:vif_details', {}).get('dvs_port_key'))

        for dvs, port_id_list in self.dvs_port_map.iteritems():
            port_list = [p for p in self.dvs_ports.values()
                         if p['id'] in port_id_list]
            if port_list:
                sg_util.update_port_rules(dvs, port_list)

    def _get_dvs_for_port_id(self, port_id, p_key=None):
        # Check if port is already known
        known_ports = (set.union(*self.dvs_port_map.values())
                       if self.dvs_port_map.values() else {})
        # If port is not known - get fresh port_map from vCenter
        if port_id not in known_ports:
            if p_key:
                dvs = dvs_util.get_dvs_by_id_and_key(
                    self.networking_map.values(), port_id, p_key)
                if dvs:
                    return self._get_dvs_and_put_dvs_in_port_map(dvs, port_id)
            port_map = dvs_util.create_port_map(self.networking_map.values())
        else:
            port_map = self.dvs_port_map
        for dvs, port_list in port_map.iteritems():
            if port_id in port_list:
                return self._get_dvs_and_put_dvs_in_port_map(dvs, port_id)
        LOG.warning(_LW("Cannot find dvs for port %s"), port_id)

    def _get_dvs_and_put_dvs_in_port_map(self, dvs, port_id):
        # Check if dvs is known, otherwise add it in port_map with
        # corresponding port_id
        if dvs not in self.dvs_port_map:
            self.dvs_port_map[dvs] = set()
        self.dvs_port_map[dvs].add(port_id)
        return dvs

    def _remove_sg_from_dvs_port(self, port):
        port['security_group_rules'] = []
        dvs = self._get_dvs_for_port_id(
            port['id'], port.get('binding:vif_details', {}).get('dvs_port_key'))
        if dvs:
            sg_util.update_port_rules(dvs, [port])

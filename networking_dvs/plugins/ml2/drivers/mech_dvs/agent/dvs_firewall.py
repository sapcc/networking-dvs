import six
from collections import defaultdict

from neutron.agent import firewall
from neutron.i18n import _LW, _LI
from oslo_log import log as logging
from networking_dvs.common import config
from networking_dvs.utils import dvs_util, security_group_utils as sg_util
from networking_dvs.common.util import dict_merge

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):

        self.networking_map = dvs_util.create_network_map_from_config(CONF.ML2_VMWARE, integration_bridge)
        self.dvs_ports = {}  # Contains the list of known ports, this may fill over time
        self._defer_apply = False
        # Map for known ports and dvs it is connected to.
        self.dvs_port_map = {}

    def prepare_port_filter(self, ports):
        self._process_port_filter(ports)

    def apply_port_filter(self, ports):
        self._process_port_filter(ports)

    def update_port_filter(self, ports):
        self._process_port_filter(ports)

    def remove_port_filter(self, port_ids):
        self._remove_sg_from_dvs_port(port_ids)

    def filter_defer_apply_on(self):
        LOG.info("Defer apply on filter")

    def filter_defer_apply_off(self):
        LOG.info("Defer apply off filter")

    @property
    def ports(self):
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
            device = port['device']
            stored = self.dvs_ports.get(device, {})
            dict_merge(stored, port)
            port.update(stored)
            self.dvs_ports[device] = stored

        self._apply_sg_rules_for_port(ports)

    @dvs_util.wrap_retry
    def _remove_sg_from_dvs_port(self, port_ids):
        LOG.info(_LI("Clean up security group rules on deleted ports {}").format(port_ids))
        ports_by_dvs = defaultdict(list)

        for port_id in port_ids:
            dvs, port_key, device_id = self.dvs_port_map.pop(port_id, (None, None, None))
            port = self.dvs_ports.pop(device_id, {})
            port['id'] = port_id
            port['security_group_rules'] = None
            ports_by_dvs[dvs].append(port)

        for dvs, ports in six.iteritems(ports_by_dvs):
            if None: # dvs:
                sg_util.update_port_rules(dvs, ports)

    @dvs_util.wrap_retry
    def _apply_sg_rules_for_port(self, ports):
        ports_by_dvs = defaultdict(list)

        for port in ports:
            dvs = self._get_dvs_for_port(port)
            if dvs:
                ports_by_dvs[dvs].append(port)

        for dvs, port_list in six.iteritems(ports_by_dvs):
            if port_list:
                sg_util.update_port_rules(dvs, port_list)

    @staticmethod
    def _dvs_port_to_neutron(port, dvs_port):
        vif_details = port.get('binding:vif_details', {})
        vif_details['dvs_port_key'] = dvs_port.key
        vif_details['dvs_port_group_key'] = dvs_port.portgroupKey
        vif_details['dvs_uuid'] = dvs_port.dvsUuid
        port['binding:vif_details'] = vif_details

    def _get_dvs_for_port(self, port):
        port_id = port['id']
        device_id = port['device']

        # Check if port is already known
        if port_id in six.viewkeys(self.dvs_port_map):
            dvs, dvs_port_key, stored_device_id = self.dvs_port_map[port_id]
            if stored_device_id != device_id:
                self.dvs_port_map[port_id] = (dvs, dvs_port_key, device_id)
            vif_details = port.get('binding:vif_details', {})
            vif_details['dvs_port_key'] = dvs_port_key
            port['binding:vif_details'] = vif_details
            return dvs
        else:
            # If port is not known - get fresh port_map from vCenter
            dvs_port_key = port.get('binding:vif_details', {}).get('dvs_port_key')
            if dvs_port_key:
                dvs, dvs_port = dvs_util.get_dvs_and_port_by_id_and_key(
                    six.viewvalues(self.networking_map), port_id, dvs_port_key)

                if dvs and dvs_port:
                    DvsSecurityGroupsDriver._dvs_port_to_neutron(port, dvs_port)
                    return self._put_dvs_in_port_map(dvs, port_id, dvs_port_key)

            # Here it gets expensive, we practically have to fetch all the ports, so we can as well store the data
            # in the hope, that it will save us a future call

            port_map = dvs_util.create_port_map(six.viewvalues(self.networking_map))

            found_dvs = None

            for dvs, ports in six.iteritems(port_map):
                for port_key, dvs_port in six.iteritems(ports):
                    if port_id == dvs_port.config.name:
                        self._put_dvs_in_port_map(dvs, dvs_port.config.name, port_key, device_id)
                        found_dvs = dvs
                        DvsSecurityGroupsDriver._dvs_port_to_neutron(port, dvs_port)
                    else:
                        self._put_dvs_in_port_map(dvs, dvs_port.config.name, port_key, None)

            if found_dvs:
                return found_dvs
            else:
                LOG.warning(_LW("Cannot find dvs for port %s"), port_id)

    def _put_dvs_in_port_map(self, dvs, port_id, port_key, device_id):
        self.dvs_port_map[port_id] = (dvs, port_key, device_id)

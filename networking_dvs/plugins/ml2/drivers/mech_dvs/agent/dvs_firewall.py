import six
from collections import defaultdict

from neutron.agent import firewall
from neutron.i18n import _LW, _LI
from oslo_log import log as logging
from networking_dvs.common import config
from networking_dvs.utils import dvs_util, security_group_utils as sg_util
from networking_dvs.common.util import dict_merge
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent.vcenter_util import VCenter

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):
        self.v_center = integration_bridge if isinstance(integration_bridge, VCenter) else VCenter(self.conf.ML2_VMWARE)
        self._defer_apply = False
        self._ports_by_device_id = {} # Because the interface expects it that way
        self._port_id_to_device_id = {}

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
        self._defer_apply = True

    def filter_defer_apply_off(self):
        LOG.info("Defer apply off filter")
        self._defer_apply = False

    @property
    def ports(self):
        return self._ports_by_device_id

    def update_security_group_members(self, sg_id, ips):
        LOG.info("update_security_group_members")

    def update_security_group_rules(self, sg_id, rules):
        LOG.info("update_security_group_rules id {} rules {}".format(sg_id, rules))

    def security_group_updated(self, action_type, sec_group_ids, device_id=None):
        LOG.info("security_group_updated action type {} ids {} device {}".format(action_type, sec_group_ids, device_id))

    def _process_port_filter(self, ports):
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])

        stored_ports = []
        print('--------------------')
        for port in ports: # We skip on missing ports, as we will be called by the dvs_agent for new ports again
            port_id = port['id']
            stored = self.v_center.uuid_port_map.get(port_id, None)
            if stored:
                print("Found port   {}".format(port_id))
                dict_merge(stored, port)
                stored_ports.append(stored)
                self._ports_by_device_id[stored['device']] = stored
            else:
                print("Unknown port {}".format(port_id))
        print('--------------------')
        self._apply_sg_rules_for_port(stored_ports)

    def _remove_sg_from_dvs_port(self, port_ids):
        LOG.info(_LI("Clean up security group rules on deleted ports {}").format(port_ids))
        ports = []
        for port_id in port_ids:
            port = self.v_center.uuid_port_map.get(port_id, None)
            if port:
                ports.append(ports)
            else:
                device_id = self._port_id_to_device_id.pop(port_id, None)
                if device_id:
                    self._ports_by_device_id.pop(device_id, None)

        self._apply_sg_rules_for_port(ports)

    @dvs_util.wrap_retry
    def _apply_sg_rules_for_port(self, ports):
        ports_by_switch = defaultdict(list)

        for port in ports:
            if port:
                port_desc = port['port_desc']
                ports_by_switch[port_desc.dvs].append(port)

        for dvs, port_list in six.iteritems(ports_by_switch):
            sg_util.update_port_rules(dvs, port_list)

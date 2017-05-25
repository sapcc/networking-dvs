import six
from collections import defaultdict

from neutron.agent import firewall
from neutron.i18n import _LE, _LW, _LI
from oslo_log import log as logging
from oslo_utils.timeutils import utcnow
from networking_dvs.common import config
from networking_dvs.utils import dvs_util, security_group_utils as sg_util
from networking_dvs.common.util import dict_merge, stats
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent.vcenter_util import VCenter

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):
        self.v_center = integration_bridge if isinstance(integration_bridge, VCenter) else VCenter(self.conf.ML2_VMWARE)
        self._defer_apply = False
        self._ports_by_device_id = {}  # Device-id seems to be the same as port id

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
        now = utcnow()
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])

        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)

        self._apply_sg_rules_for_port(merged_ports, now)

    def _merge_port_info_from_vcenter(self, ports):
        merged_ports = []
        for port in ports: # We skip on missing ports, as we will be called by the dvs_agent for new ports again
            port_id = port['id']
            vcenter_port = self.v_center.uuid_port_map.get(port_id, None)
            if vcenter_port:
                # print("Found port  {}".format(port_id))
                dict_merge(vcenter_port, port)
                merged_ports.append(vcenter_port)
            else:
                LOG.error(_LE("Unknown port {}").format(port_id))
        return merged_ports

    def _update_ports_by_device_id(self, ports):
        for port in ports:
            self._ports_by_device_id[port['device']] = port

    def _remove_sg_from_dvs_port(self, port_ids):
        LOG.info(_LI("Clean up security group rules on deleted ports {}").format(port_ids))
        for port_id in port_ids:
            self._ports_by_device_id.pop(port_id, None)

    @staticmethod
    def _update_port_rules_callback(dvs, succeeded_keys, failed_keys):
        now = None
        for port_key in succeeded_keys:
            port = dvs.ports_by_key[port_key]
            port_desc = port.get('port_desc', None)
            if port_desc and port_desc.queued_since:
                now = now or utcnow()
                stats.timing('networking_dvs.security_group_updates', now - port_desc.queued_since)
                port_desc.queued_since = None

        if failed_keys:
            stats.increment('networking_dvs.security_group_updates.failures', len(failed_keys))

    @dvs_util.wrap_retry
    def _apply_sg_rules_for_port(self, ports, now=None):
        now = now or utcnow()
        ports_by_switch = defaultdict(list)

        for port in ports:
            if not port:
                continue

            port = port.copy()
            port_desc = port['port_desc']
            port_desc.queued_since = port_desc.queued_since or now
            port['security_group_rules'] = _patch_sg_rules(port['security_group_rules'])
            ports_by_switch[port_desc.dvs_uuid].append(port)

        for dvs_uuid, port_list in six.iteritems(ports_by_switch):
            dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
            LOG.info("DVS {} {}".format(dvs_uuid, [port.get('id', port.get('device_id', 'Missing')) for port in port_list]))
            sg_util.update_port_rules(dvs, port_list, callback=self._update_port_rules_callback)

def _patch_sg_rules(security_group_rules):
    patched_security_group_rules = []

    for rule in security_group_rules:
        if not 'protocol' in rule:
            for proto in ['icmp', 'udp', 'tcp']:
                new_rule = rule.copy()
                new_rule.update(protocol=proto,
                                port_range_min=0,
                                port_range_max=65535)
                patched_security_group_rules.append(new_rule)
        else:
            patched_security_group_rules.append(rule)

    return patched_security_group_rules
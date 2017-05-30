import pprint

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
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent import vcenter_util

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):
        self.v_center = integration_bridge if isinstance(integration_bridge, VCenter) else VCenter(self.conf.ML2_VMWARE)
        self._defer_apply = False
        self._ports_by_device_id = {}  # Device-id seems to be the same as port id
        self._sg_aggregates_per_dvs_uuid = defaultdict(lambda : defaultdict(dict))

    def prepare_port_filter(self, ports):
        LOG.info("prepare_port_filter called with %s", pprint.pformat(ports))

        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)

        self._process_ports(merged_ports, add=True, remove=False)
        self._apply_changed_sg_attr()

    def apply_port_filter(self, ports):
        LOG.info("apply_port_filter called with %s", pprint.pformat(ports))

        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)

        self._process_ports(merged_ports, add=True, remove=False)
        self._apply_changed_sg_attr()

    def update_port_filter(self, ports):
        LOG.info("update_port_filter called with %s", pprint.pformat(ports))
        ports_to_remove = [self._ports_by_device_id[port['device']] for port in ports]
        self._process_ports(ports_to_remove, add=False, remove=True)

        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)

        self._process_ports(merged_ports, add=True, remove=False)
        self._apply_changed_sg_attr()

    def remove_port_filter(self, port_ids):
        LOG.debug("remote_port_filter called for %s", pprint.pformat(port_ids))
        ports_to_remove = [self._ports_by_device_id[port_id] for port_id in port_ids]
        self._process_ports(ports_to_remove, add=False, remove=True)
        self._apply_changed_sg_attr()
        # -------------
        for port_id in port_ids:
            self._ports_by_device_id.pop(port_id, None)

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

    def _process_ports(self, ports, add=False, remove=False):
        ports = self._merge_port_info_from_vcenter(ports)
        """
        Process security group settings for port updates
        """
        if not add and not remove:
            LOG.error("Called with NO-OP parameters")
            return

        for dvs_uuid, port_list in six.iteritems(ports_by_switch(None, ports)):
            for port in port_list:
                sg_set = sg_util.security_group_set(port)
                sg_aggr = self._sg_aggregates_per_dvs_uuid[dvs_uuid][sg_set]
                if remove:
                    sg_util.apply_rules(port['security_group_rules'], sg_aggr, decrement=True)
                if add:
                    sg_util.apply_rules(port['security_group_rules'], sg_aggr, decrement=False)

    @dvs_util.wrap_retry
    def _apply_changed_sg_attr(self):
        for dvs_uuid, sg_aggregates in six.iteritems(self._sg_aggregates_per_dvs_uuid):

            dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
            client_factory = dvs.connection.vim.client.factory
            builder = sg_util.PortConfigSpecBuilder(client_factory)

            pg_per_sg = dvs.get_pg_per_sg_attribute(self.v_center.security_groups_attribute_key)

            for sg_set, sg_aggr in six.iteritems(sg_aggregates):
                if not sg_aggr["dirty"]:
                    continue

                sg_set_rules = sg_util.get_rules(sg_aggr)
                # build traffic rules from sg rules
                # build a port config update spec
                # port_config = ...

                port_config = sg_util.port_configuration(builder, None, sg_set_rules, {}, None, None).setting

                if sg_set in pg_per_sg:
                    pg = pg_per_sg[sg_set]
                    if len(sg_set_rules) == 0:
                        dvs._delete_port_group(pg["ref"], pg["name"])
                    else:
                        # a tagged dvportgroup exists, update it
                        dvs.update_dvportgroup(pg["ref"],
                                               pg["configVersion"],
                                               port_config)
                else:
                    # create a new dvportgroup and tag it
                    pg = dvs.create_dvportgroup(self.v_center.security_groups_attribute_key,
                                                sg_set, port_config)
                    # no need to update pg, e.g. pg_per_sg[sg_set] = pg

                sg_aggr["dirty"] = False
            """
            # reassign vms if they are not in the correct dvportgroup according to their security groups
            # Q: how to prevent loops ? (as the dvs agent will see a new port comming up..)
            """

def ports_by_switch(now, ports=None):
    now = now or utcnow()
    ports_by_switch = defaultdict(list)

    for port in ports:
        if not port:
            continue

        port = port.copy()
        port_desc = port['port_desc']
        port_desc.queued_since = port_desc.queued_since or now
        port['security_group_rules'] = sg_util._patch_sg_rules(port['security_group_rules'])
        ports_by_switch[port_desc.dvs_uuid].append(port)

    return ports_by_switch

#
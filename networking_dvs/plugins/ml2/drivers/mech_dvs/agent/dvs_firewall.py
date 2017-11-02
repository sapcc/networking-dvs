import copy
import os
import eventlet
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    eventlet.monkey_patch()

from eventlet.greenpool import GreenPool

import six
from collections import defaultdict, Counter
from functools import partial

from neutron.agent import firewall
from neutron.i18n import _LE, _LW, _LI
from oslo_log import log as logging
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util
from networking_dvs.common import config
from networking_dvs.utils import dvs_util, security_group_utils as sg_util
from networking_dvs.common.util import dict_merge, stats
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent.vcenter_util import VCenter
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent import vcenter_util

LOG = logging.getLogger(__name__)
CONF = config.CONF

def _uncurry(_, f, *args, **keywords):
    return f(*args, **keywords)

class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, integration_bridge=None):
        self.v_center = integration_bridge if isinstance(integration_bridge, VCenter) else VCenter(CONF.ml2_vmware)
        self._ports_by_device_id = {}  # Device-id seems to be the same as port id
        self._sg_aggregates_per_dvs_uuid = defaultdict(lambda : defaultdict(sg_util.SgAggr))
        self._green = self.v_center.pool or eventlet

    def prepare_port_filter(self, ports):
        # LOG.debug("prepare_port_filter called with %s", pprint.pformat(ports))
        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)
        self._process_ports(merged_ports)
        self._apply_changed_sg_aggregates()

    def apply_port_filter(self, ports):
        # This driver does all of its processing during the prepare_port_filter call
        pass

    def update_port_filter(self, ports):
        # LOG.debug("update_port_filter called with %s", pprint.pformat(ports))
        ports_to_remove = [self._ports_by_device_id[port['device']]
                           for port in ports
                           if port['device'] in self._ports_by_device_id]
        self._process_ports(ports_to_remove, decrement=True)

        merged_ports = self._merge_port_info_from_vcenter(ports)
        self._update_ports_by_device_id(merged_ports)

        self._process_ports(merged_ports)
        self._apply_changed_sg_aggregates()

    def remove_port_filter(self, port_ids):
        # LOG.debug("remote_port_filter called for %s", pprint.pformat(port_ids))
        ports_to_remove = [self._ports_by_device_id[port_id]
                           for port_id in port_ids
                           if port_id in self._ports_by_device_id]
        self._process_ports(ports_to_remove, decrement=True)
        self._apply_changed_sg_aggregates()
        for port_id in port_ids:
            self._ports_by_device_id.pop(port_id, None)

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass

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
            vcenter_port = copy.deepcopy(self.v_center.uuid_port_map.get(port_id, None))
            if vcenter_port:
                dict_merge(vcenter_port, port)
                merged_ports.append(vcenter_port)
            else:
                LOG.error(_LE("Unknown port {}").format(port_id))
        return merged_ports

    def _update_ports_by_device_id(self, ports):
        for port in ports:
            self._ports_by_device_id[port['device']] = port

    def _process_ports(self, ports, decrement=False):
        """
        Process security group settings for port updates
        """
        for dvs_uuid, port_list in six.iteritems(_ports_by_switch(ports)):
            for port in port_list:
                sg_set = sg_util.security_group_set(port)
                if not sg_set:
                    LOG.debug("Port {} has no security group set, skipping processing.".format(port['id']))
                    continue

                sg_aggr = self._sg_aggregates_per_dvs_uuid[dvs_uuid][sg_set]
                if not sg_aggr.pg_key:
                    dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
                    pg_per_sg = dvs.get_port_group_by_security_group()
                    pg = pg_per_sg.get(sg_set, {})
                    if pg:
                        sg_aggr.pg_key = pg["key"]
                        sg_aggr.vlan = pg["defaultPortConfig"].vlan.vlanId

                # Schedule for reassignment
                if not decrement:
                    if port['port_desc'].port_group_key != sg_aggr.pg_key:
                        sg_aggr.ports_to_assign.append(port)

                # Prepare and apply rules to the sg_aggr
                patched_sg_rules = sg_util._patch_sg_rules(port['security_group_rules'])
                sg_util.apply_rules(patched_sg_rules, sg_aggr, decrement)

    def _apply_changed_sg_aggr(self, dvs, sg_set, sg_aggr):
        client_factory = dvs.connection.vim.client.factory
        builder = sg_util.PortConfigSpecBuilder(client_factory)
        pg_per_sg = dvs.get_port_group_by_security_group()

        if not sg_aggr.dirty:
            if sg_aggr.pg_key:
                self._reassign_ports(sg_aggr)
            return

        # Mark as processed, might be reset below
        sg_aggr.dirty = False

        # Prepare a port config
        sg_set_rules = sg_util.get_rules(sg_aggr)
        port_config = sg_util.port_configuration(
                builder, None, sg_set_rules, {}, None, None).setting
        if sg_aggr.vlan:
            port_config.vlan = builder.vlan(sg_aggr.vlan)

        sg_tags=['security_group:' + sg_set, 'host:' + CONF.host]
        stats.gauge('networking_dvs._apply_changed_sg_aggr.security_group_rules', len(sg_set_rules), tags=sg_tags)

        pg = pg_per_sg.get(sg_set, None)
        if pg:
            sg_aggr.pg_key = pg["key"]
            if len(sg_set_rules) == 0:
                LOG.debug("No rules left")
            else:
                dvs.update_dvportgroup(pg, port_config)
            self._reassign_ports(sg_aggr)
        else:
            self._create_dvpg_and_update_sg_aggr(dvs,
                                                 sg_set,
                                                 port_config,
                                                 sg_aggr)

    @stats.timed()
    def _apply_changed_sg_aggregates(self):
        pool = self.v_center.pool or GreenPool()

        def _apply(dvs_uuid, sg_aggregates):
            dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
            apply_on_dvs = partial(self._apply_changed_sg_aggr, dvs)

            for result in pool.starmap(apply_on_dvs, six.iteritems(sg_aggregates)):
                pass

        for result in pool.starmap(_apply, six.iteritems(self._sg_aggregates_per_dvs_uuid)):
            pass

    def _reassign_ports(self, sg_aggr):
        """
        Reassigns VM to a dvportgroup based on its port's security group set
        """

        ports = sg_aggr.ports_to_assign
        sg_aggr.ports_to_assign = []

        if not sg_aggr.vlan and ports:
            vlan_ids = Counter([ port['segmentation_id']
                    for port in ports
                    if 'vlan' == port.get('network_type', None) and port.get('segmentation_id', None) ])
            sg_aggr.vlan, _ = vlan_ids.most_common(1)[0]

        port_keys_to_drop = defaultdict(list)
        for port in ports:
            sg_set = sg_util.security_group_set(port)
            if not sg_set:
                LOG.debug("Port {} has no security group set, skipping reassignment.".format(port['id']))
                continue
            port_desc = port['port_desc']
            if port_desc.port_group_key == sg_aggr.pg_key:
                # Existing ports can enter the reassignment queue
                # on agent boot before the pg_key has been set
                # on the sg_aggr object. Filter them here.
                continue
            dvs_uuid = port_desc.dvs_uuid
            dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
            client_factory = dvs.connection.vim.client.factory

            # Configure the backing to the required dvportgroup
            port_connection = client_factory.create('ns0:DistributedVirtualSwitchPortConnection')
            port_connection.switchUuid = dvs_uuid
            port_connection.portgroupKey = sg_aggr.pg_key
            port_backing = client_factory.create('ns0:VirtualEthernetCardDistributedVirtualPortBackingInfo')
            port_backing.port = port_connection

            # Specify the device that we are going to edit
            virtual_device = client_factory.create('ns0:' + port_desc.device_type)
            virtual_device.key = port_desc.device_key
            virtual_device.backing = port_backing
            virtual_device.addressType = "manual"
            virtual_device.macAddress = port_desc.mac_address

            # Create an edit spec for an existing virtual device
            virtual_device_config_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
            virtual_device_config_spec.operation = "edit"
            virtual_device_config_spec.device = virtual_device

            # Create a config spec for applying the update to the virtual machine
            vm_config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
            vm_config_spec.deviceChange = [virtual_device_config_spec]

            # Queue the update
            vm_ref = vim_util.get_moref(port_desc.vmobref, "VirtualMachine")
            self._green.spawn_n(reconfig_vm, dvs, vm_ref, vm_config_spec)

            # Store old port keys of reassigned VMs
            port_keys_to_drop[dvs_uuid].append(port_desc.port_key)

        # Remove obsolete port binding specs
        """
        This should be fixed in the design instead of adding corrective code!
        Still, it is a cheap fix and saves unnecessary API calls.
        """
        for dvs_uuid, port_keys in six.iteritems(port_keys_to_drop):
            dvs = self.v_center.get_dvs_by_uuid(dvs_uuid)
            dvs.filter_update_specs(lambda x : x.key not in port_keys)

        eventlet.sleep(0) # yield to allow VM network reassignments to take place

    def _create_dvpg_and_update_sg_aggr(self, dvs, sg_set, port_config, sg_aggr):
        pg = dvs.create_dvportgroup(sg_set, port_config)
        sg_aggr.pg_key = pg["key"]
        self._reassign_ports(sg_aggr)

@stats.timed()
def reconfig_vm(dvs, vm_ref, vm_config_spec):
    try:
        dvs.connection.invoke_api(dvs.connection.vim,
                                  "ReconfigVM_Task",
                                  vm_ref,
                                  spec=vm_config_spec)
    except vmware_exceptions.VimException as e:
        LOG.info("Unable to reassign VM, exception is %s.", e)

def _ports_by_switch(ports=None):
    ports_by_switch = defaultdict(list)
    for port in ports:
        if not port:
            continue
        ports_by_switch[port['port_desc'].dvs_uuid].append(port)

    return ports_by_switch

def noop(*args):
    pass

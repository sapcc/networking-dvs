# Copyright 2014 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet

    eventlet.monkey_patch()

from eventlet.queue import Full, Empty, LightQueue as Queue
from eventlet.event import Event
from eventlet import sleep

import attr
import six

from collections import defaultdict

from neutron.i18n import _LI, _LW, _LE
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.plugins.ml2 import models as models_ml2
import neutron.context

from oslo_log import log
from oslo_utils.timeutils import utcnow
from oslo_service import loopingcall
from oslo_utils import timeutils
from pyVmomi import vim, vmodl
from oslo_db.sqlalchemy import enginefacade
from osprofiler.profiler import trace_cls

from httplib import BadStatusLine
from networking_dvs.common import config as dvs_config
from networking_dvs.common import constants
from networking_dvs.common import util as c_util
from networking_dvs.utils import dvs_util
from networking_dvs.utils import spec_builder as builder
from networking_dvs.utils import security_group_utils as sg_util
from networking_dvs.common.db import string_agg

CONF = dvs_config.CONF
LOG = log.getLogger(__name__)

_DB_AGG_SEPARATOR = ','


def _create_session(config):
    """Create Vcenter Session for API Calling."""
    connection = dvs_util.connect(config)
    return connection


def _cast(value, _type=str):
    if value is None:
        return None
    return _type(value)


def get_all_cluster_mors(connection):
    """Get all the clusters in the vCenter."""
    query = c_util.get_objects(connection,
                               vim.ClusterComputeResource, 100, ['name'])
    with c_util.WithRetrieval(connection, query) as compute_resources:
        for mor in compute_resources:
            yield mor


def get_cluster_ref_by_name(connection, cluster_name):
    """Get reference to the vCenter cluster with the specified name."""
    all_clusters = get_all_cluster_mors(connection)
    for cluster in all_clusters:
        if (hasattr(cluster, 'propSet') and
                cluster.propSet[0].val == cluster_name):
            return cluster.obj


@attr.s(**constants.ATTR_ARGS)
class _DVSPortDesc(object):
    dvs_uuid = attr.ib(convert=str, cmp=True, hash=True)
    # port_key is an int, but the WDSL defines it as a string
    port_key = attr.ib(convert=str, cmp=True, hash=True)
    port_group_key = attr.ib(convert=str)
    mac_address = attr.ib(convert=str, cmp=True, hash=True)
    # connection_cookie: Same as with port_key, int represented as a string
    connection_cookie = attr.ib(convert=str)
    connected = attr.ib(default=False)
    status = attr.ib(convert=str, default='')
    # config_version: Same as with port_key, int represented as a string
    config_version = attr.ib(convert=str, default='')
    vlan_id = attr.ib(default=None)
    link_up = attr.ib(default=None)
    filter_config_key = attr.ib(convert=str, default='')
    connected_since = attr.ib(default=None)
    port_group_history = attr.ib(default=attr.Factory(list),
                                 cmp=False, hash=False)

    def is_connected(self):
        return self.mac_address and self.connected and self.status == 'ok'

    @staticmethod
    def from_dvs_port(port, **values):
        # Port can be either DistributedVirtualSwitchPortConnection,
        # or DistributedVirtualPort
        values.update(
            # switchUuid in connection, dvsUuid in port
            dvs_uuid=_cast(getattr(port, 'switchUuid', None)
                           or getattr(port, 'dvsUuid', None)),
            # portKey in connection, key in port
            port_key=_cast(getattr(port, 'portKey', None)
                           or getattr(port, 'key', None)),
            port_group_key=_cast(port.portgroupKey),
            connection_cookie=_cast(getattr(port, 'connectionCookie', None)),
        )
        # The next ones are not part of DistributedVirtualSwitchPortConnection
        # as returned by the backing.port, but a DistributedVirtualPort as
        # returned by FetchDVPorts
        port_config = getattr(port, 'config', None)
        if port_config:
            values['config_version'] = _cast(port_config.configVersion)

            setting = getattr(port_config, 'setting', None)

            try:
                if not setting.vlan.inherited:
                    values['vlan_id'] = setting.vlan.vlanId
            except AttributeError:
                pass

            try:
                fp = setting.filterPolicy
                if not fp.inherited:
                    values['filter_config_key'] = fp.filterConfig[0].key
            except AttributeError:
                pass

        port_state = getattr(port, 'state', None)
        if port_state:
            try:
                values['link_up'] = port_state.runtimeInfo.linkUp
            except AttributeError:
                pass

        return values


@attr.s(**constants.ATTR_ARGS)
class _DVSPortMonitorDesc(_DVSPortDesc):
    vmobref = attr.ib(convert=str, default=None)
    device_key = attr.ib(convert=int, default=None)
    device_type = attr.ib(convert=str, default=None)


class VCenterMonitor(object):
    def __init__(self, vc_api, config, connection=None, quit_event=None, pool=None):
        self._quit_event = quit_event or Event()
        self.changed = dict()
        self._property_collector = None
        self.down_ports = {}
        self.untried_ports = {}  # The host is simply down
        self.iteration = 0
        self.connection = connection
        # Map of the VMs and their NICs by the hardware key
        # e.g vmobrefs -> keys -> _DVSPortMonitorDesc
        self._hardware_map = defaultdict(dict)
        self.pool = pool or eventlet.greenpool.GreenPool(5)
        self.config = config
        self.thread = None
        self.vcenter_api = vc_api

    def start(self):
        self.thread = eventlet.spawn(self._run_safe)

    def stop(self):
        try:
            self._quit_event.send(True)
        except AssertionError:  # In case someone already send an event
            pass

        # This will abort the WaitForUpdateEx early,
        # so it will cancel leave the loop timely
        if self.connection and self._property_collector:
            try:
                self._property_collector.CancelWaitForUpdates()
            except vim.fault.VimFault:
                pass

    def _run(self):
        LOG.info(_LI('Monitor running... '))

        try:
            self.connection = self.connection or _create_session(self.config)

            version = None
            wait_options = builder.wait_options(60, 20)

            self._create_property_filter()

            while not self._quit_event.ready():
                try:
                    result = self._property_collector.WaitForUpdatesEx(
                        version=version, options=wait_options)
                    self.iteration += 1
                    if result:
                        version = result.version
                        if result.filterSet and result.filterSet[0].objectSet:
                            now = utcnow()
                            for update in result.filterSet[0].objectSet:
                                if isinstance(update.obj, vim.VirtualMachine):
                                    self._handle_virtual_machine(update, now)

                    changed = self.changed.values()
                    self.changed = dict()
                    if changed:
                        self.vcenter_api.vcenter_port_changes(changed)

                    now = utcnow()
                    for mac, (when, port_desc, iteration) in six.iteritems(self.down_ports):
                        if port_desc.status != 'untried' or 0 == self.iteration - iteration:
                            LOG.debug('Down: {} {} for {} {} {}'.format(
                                mac, port_desc.port_key,
                                self.iteration - iteration,
                                (now - when).total_seconds(),
                                port_desc.status))
                    sleep(0)
                except BadStatusLine:
                    sleep(1)
                    pass
        except vmodl.fault.RequestCanceled as e:
            # If the event is set, the request was canceled in self.stop()
            if not self._quit_event.ready():
                LOG.info("Waiting for updates was cancelled unexpectedly")
                # Kill the whole process and start again from scratch
                raise e

    def _run_safe(self):
        while not self._quit_event.ready():
            try:
                self._run()
            except:
                import traceback
                LOG.error(traceback.format_exc())
                os._exit(1)

    def _create_property_filter(self):
        if self._property_collector:
            return
        pc = self.connection.content.propertyCollector
        self._property_collector = pc.CreatePropertyCollector()
        connection = self.connection

        if not self.config.cluster_name:
            LOG.info("No cluster specified")
            container = connection.content.rootFolder
        else:
            container = get_cluster_ref_by_name(connection,
                                                self.config.cluster_name)
            if not container:
                LOG.error(_LE("Cannot find cluster with name '{}'").format(
                    self.config.cluster_name))
                exit(2)

        container_view = connection.content.viewManager.CreateContainerView(
                                               container=container,
                                               type=[vim.VirtualMachine],
                                               recursive=True)

        traversal_spec = c_util.build_traversal_spec('traverseEntities',
                                                     vim.ContainerView, 'view',
                                                     False, None)
        object_spec = c_util.build_object_spec(container_view,
                                               [traversal_spec])

        # Only static types work, so we have to get all hardware
        # still faster than retrieving individual items
        vm_properties = ['runtime.powerState', 'config.hardware.device']
        property_specs = [c_util.build_property_spec(vim.VirtualMachine,
                                                     vm_properties)]

        property_filter_spec = c_util.build_property_filter_spec(
            property_specs, [object_spec])

        # -> PropertyFilter
        return self._property_collector.CreateFilter(
            spec=property_filter_spec, partialUpdates=True)

    def _handle_removal(self, vm):
        vm_hw = self._hardware_map.pop(vm, {})
        for port_desc in six.itervalues(vm_hw):
            if isinstance(port_desc, _DVSPortMonitorDesc):
                mac_address = port_desc.mac_address
                port_desc.status = 'deleted'
                LOG.debug("Removed {} {}".format(mac_address,
                                                 port_desc.port_key))
                self.down_ports.pop(mac_address, None)
                self.untried_ports.pop(mac_address, None)
                self.changed[id(port_desc)] = port_desc

    def _handle_virtual_machine(self, update, now):
        vmobref = str(update.obj._moId) # String 'vmobref-#'
        change_set = getattr(update, 'changeSet', [])
        vm_hw = self._hardware_map[vmobref]

        last_port_desc = None

        for change in change_set:
            port_desc = self._handle_virtual_machine_change(
                change, vm_hw, vmobref)
            if port_desc:
                if id(last_port_desc) != id(port_desc):
                    self._handle_port_update(last_port_desc, now)
                    last_port_desc = port_desc

        if last_port_desc:
            self._handle_port_update(last_port_desc, now)

        if update.kind == 'leave':
            self._handle_removal(vmobref)

    def _handle_virtual_machine_change(self, change, vm_hw, vmobref):
        change_name = change.name
        change_val = getattr(change, 'val', None)
        if change_name == 'config.hardware.device':
            if 'assign' == change.op:
                for v in change_val:
                    port_desc = self._port_desc_from_nic_change(vmobref, v)
                    if port_desc:
                        vm_hw[port_desc.device_key] = port_desc
                        return port_desc
            elif 'indirectRemove' == change.op:
                self._handle_removal(vmobref)
        elif change_name.startswith('config.hardware.device['):
            id_end = change_name.index(']')
            device_key = int(change_name[23:id_end])
            if 'remove' == change.op:
                vm_hw.pop(device_key, None)
            else:
                # assume that change.op is assign
                port_desc = vm_hw.get(device_key, None)
                if port_desc:
                    attribute = change_name[id_end + 2:]
                    if 'connectable.connected' == attribute:
                        port_desc.connected = change_val
                        return port_desc
                    elif 'connectable.status' == attribute:
                        port_desc.status = change_val
                        return port_desc
                    elif 'macAddress' == attribute:
                        port_desc.mac_address = str(change_val)
                        return port_desc
                    elif 'backing.port.connectionCookie' == attribute:
                        port_desc.connection_cookie = str(change_val)
                        return port_desc
                    elif 'backing.port.portKey' == attribute:
                        port_desc.port_key = str(change_val)
                        return port_desc
                    elif 'backing.port.portgroupKey' == attribute:
                        change_val = str(change_val)
                        pgh = port_desc.port_group_history
                        # Save the old value
                        pgh.append(port_desc.port_group_key)
                        # Remove the current port-group-key from the history
                        port_desc.port_group_history = [
                            key for key in pgh if key != change_val]
                        port_desc.port_group_key = change_val
                        return port_desc
                else:
                    port_desc = self._port_desc_from_nic_change(vmobref,
                                                                change_val)
                    if port_desc:
                        vm_hw[port_desc.device_key] = port_desc
                        return port_desc

        elif change_name == 'runtime.powerState':
            # print("{}: {}".format(vm, change_val))
            vm_hw['power_state'] = change_val
            for port_desc in six.itervalues(vm_hw):
                if isinstance(port_desc, _DVSPortMonitorDesc):
                    return port_desc
        else:
            LOG.debug(change)

    def _port_desc_from_nic_change(self, vmobref, value):
        backing = getattr(value, 'backing', None)
        # If if is not a NIC, it will have no backing and/or port
        if not backing:
            return
        port = getattr(backing, 'port', None)
        if not port:
            return
        # port is a DistributedVirtualSwitchPortConnection
        connectable = getattr(value, 'connectable', None)
        port_desc = _DVSPortMonitorDesc(**_DVSPortDesc.from_dvs_port(
            port,
            mac_address=getattr(value, 'macAddress', None),
            connected=connectable.connected if connectable else None,
            status=connectable.status if connectable else None,
            vmobref=vmobref,
            device_key=value.key,
            device_type=value.__class__.__name__.rsplit('.', 1)[-1],
        ))

        return port_desc

    def _handle_port_update(self, port_desc, now):
        if not port_desc:
            return

        mac_address = port_desc.mac_address

        if not mac_address:
            return

        if port_desc.is_connected():
            then, _, iteration = self.down_ports.pop(
                mac_address, (None, None, None))
            self.untried_ports.pop(mac_address, None)
            if then:
                LOG.debug("Port {} {} {} was down for {} ({})".format(
                    mac_address, port_desc.port_key,
                    (now - then).total_seconds(),
                    (self.iteration - iteration)))
            else:
                LOG.debug("Update to connected port {} {}".format(
                    mac_address, port_desc.port_key))
            port_desc.connected_since = now
            self.changed[id(port_desc)] = port_desc
        else:
            power_state = self._hardware_map[port_desc.vmobref].get(
                'power_state', None)
            if power_state != 'poweredOn':
                self.untried_ports[mac_address] = port_desc
            elif not mac_address in self.down_ports:
                status = port_desc.status
                LOG.debug(
                    "Port {} {} registered as down: {} {}".format(
                        mac_address, port_desc.port_key, status, power_state))
                self.down_ports[mac_address] = (now, port_desc, self.iteration)


@trace_cls("vmwareapi", hide_args=True)
class VCenter(object):
    # PropertyCollector discovers changes on vms and their hardware
    # and produces
    #  (mac, switch, portKey, portGroupKey,
    #   connectable.connected, connectable.status)
    # internally, it keeps internally vm and key for identifying updates
    # Subsequently, the mac has to be identified with a port

    def __init__(self, config=None, pool=None, agent=None):
        self.pool = pool
        self.agent = agent
        self.config = config or CONF.ML2_VMWARE
        self.connection = _create_session(self.config)
        self._quit_event = Event()
        self._monitor_process = VCenterMonitor(
            self, self.config, quit_event=self._quit_event,
            connection=self.connection, pool=self.pool)
        self.queue = Queue(None)

        self.uuid_port_map = {}

        # Needed to keep the same port object across port-group moves
        self.mac_port_map = {}
        self.uuid_dvs_map = {}
        self.network_dvs_map = {}

        for network, dvs in six.iteritems(
                dvs_util.create_network_map_from_config(
                    self.config,
                    connection=self.connection, pool=pool,
                    quit_event=self._quit_event)):
            self.network_dvs_map[network] = dvs
            self.uuid_dvs_map[dvs.uuid] = dvs

        context = neutron.context.get_admin_context()
        for port in self._get_agent_ports(context):
            physical_network = port['physical_network']
            port_id = port['id']
            dvs = self.network_dvs_map.get(physical_network)
            if not dvs:
                LOG.error("Could not find switch"
                          " for the physical network %s (port %s)",
                          physical_network, port_id)
                continue
            sg_set = sg_util.security_group_set(port)
            if not sg_set:
                LOG.warning("No security group set for port %s", port_id)
                continue
            mac_address = port['mac_address']
            pg = dvs.get_port_group_for_security_group_set(sg_set)
            if not pg:
                LOG.warning("Could not get portgroup %s for port %s",
                            sg_set, port_id)
            else:
                pg.ports[mac_address] = port
            self.mac_port_map[mac_address] = port
            self.uuid_port_map[port_id] = port

    def vcenter_port_changes(self, changed):
        eventlet.spawn_n(self._vcenter_port_changes, changed)

    def _vcenter_port_changes(self, changed):
        ports_by_mac = dict()

        for port_desc in changed:
            dvs = self.get_dvs_by_uuid(port_desc.dvs_uuid)
            if not dvs:
                LOG.debug("Switch %s not managed by DVS-Agent",
                          port_desc.dvs_uuid)
                continue

            if port_desc.status != 'deleted':
                existing_port = self.mac_port_map.get(port_desc.mac_address)
                port = dvs.get_port_by_port_desc(port_desc, existing_port)
                ports_by_mac[port_desc.mac_address] = port
                self.mac_port_map[port_desc.mac_address] = port
            else:
                dvs.remove_port_by_port_desc(port_desc)
                ports_by_mac.pop(port_desc.mac_address, None)
                self.mac_port_map.pop(port_desc.mac_address, None)

        macs = set(six.iterkeys(ports_by_mac))
        if not macs:  # Maybe all the ports have been deleted
            return

        LOG.debug("Got the following macs %s", macs)
        self._read_dvs_ports(ports_by_mac)

        # We might skip getting objects from the db here,
        # if they are already present
        port_list = []

        for mac, port in six.iteritems(ports_by_mac):
            if 'port_id' in port:
                port_list.append(port)
                macs.discard(mac)

        context = neutron.context.get_admin_context()
        for neutron_info in self._get_ports_by_mac(context, macs):
            mac_address = neutron_info['mac_address']
            port_id = neutron_info['port_id']
            macs.discard(mac_address)
            port_info = ports_by_mac.get(mac_address)
            if port_info:
                c_util.dict_merge(port_info, neutron_info)
                self.uuid_port_map[port_id] = port_info
                port_list.append(port_info)
            else:
                LOG.warning("Missing port %s for port_info %s",
                            port_id, mac_address)

        if macs:
            LOG.warning(_LW("Could not find the following macs: %s"), macs)

        LOG.debug("Got port information from db for %d ports", len(port_list))
        for port in port_list:
            self.queue.put(port)

    def start(self):
        self._monitor_process.start()

    @staticmethod
    def update_port_desc(port, port_info):
        # Validate connectionCookie,
        # so we still have the same instance behind that portKey
        port_desc = port['port_desc']
        connection_cookie = _cast(getattr(port_info, 'connectionCookie', None))

        if port_desc.connection_cookie != connection_cookie:
            LOG.error("Cookie mismatch {} {} {} <> {}".format(
                port_desc.mac_address, port_desc.port_key,
                port_desc.connection_cookie, connection_cookie))
            return False

        for k, v in six.iteritems(_DVSPortDesc.from_dvs_port(port_info)):
            setattr(port_desc, k, v)
        return True

    def port_by_switch(self, ports):
        by_switch = defaultdict(list)
        for port in ports:
            dvs = self.get_dvs_by_uuid(port['port_desc'].dvs_uuid)
            by_switch[dvs].append(port)

        return six.iteritems(by_switch)

    @c_util.stats.timed()
    def bind_ports(self, ports, callback=None):
        for dvs, ports_on_switch in self.port_by_switch(ports):
            if not dvs:
                LOG.warning("Received ports without known switch")
                continue
            specs = []
            for port in ports_on_switch:
                network_type = port.get('network_type')
                if (network_type == 'vlan'
                        and not port.get('segmentation_id') is None)\
                        or network_type == 'flat':
                    spec = builder.neutron_to_port_config_spec(port)
                    if not CONF.AGENT.dry_run:
                        specs.append(spec)
                    else:
                        LOG.debug(spec)
                else:
                    LOG.debug("Skipping port %s", port['id'])

            dvs.queue_update_specs(specs, callback=callback)

    def get_dvs_by_uuid(self, uuid):
        return self.uuid_dvs_map.get(uuid, None)

    def get_port_by_uuid(self, uuid):
        return self.uuid_port_map.get(uuid, None)

    def _fetch_ports_by_mac(self, portgroup_key=None, mac_addr=None):
        for dvs in six.itervalues(self.uuid_dvs_map):
            port_keys = dvs._dvs.FetchDVPortKeys(
                dvs._dvs, criteria=builder.port_criteria())
            ports = dvs._dvs.FetchDVPorts(criteria=builder.port_criteria(
                port_group_key=portgroup_key, port_key=port_keys)
            )

        for port in ports:
            if hasattr(port, 'state'):
                if hasattr(port.state, 'runtimeInfo'):
                    if mac_addr == port.state.runtimeInfo.macAddress:
                        return port
                    else:
                        continue

            raise Exception('DVS port not found!')

    def get_new_ports(self, block=False, timeout=1.0, max_ports=None):
        ports_by_mac = dict()
        try:
            while max_ports is None or len(ports_by_mac) < max_ports:
                new_port = self.queue.get(block=block, timeout=timeout)
                port_desc = new_port['port_desc']
                block = False  # Only block on the first item
                if port_desc.status != 'deleted':
                    ports_by_mac[port_desc.mac_address] = new_port
                    new_port_id = new_port.get('id')
                    if new_port_id:
                        self.uuid_port_map[new_port_id] = new_port
                else:
                    ports_by_mac.pop(port_desc.mac_address, None)
        except Empty:
            pass
        return ports_by_mac

    def _read_dvs_ports(self, ports_by_mac):
        # This loop can get very slow, if get_port_info_by_portkey gets port
        # keys passed of instances, which are only partly connected,
        # meaning: the instance is associated, but the link is not quite up yet
        for dvs, ports in self.port_by_switch(six.itervalues(ports_by_mac)):
            if not dvs:
                LOG.warning("Received ports without known switch")
                continue
            ports_by_key = dict((port['port_desc'].port_key, port)
                                for port in ports)
            for port_info in dvs.get_port_info_by_portkey(
                    list(six.iterkeys(ports_by_key))):
                port = ports_by_key[port_info.key]
                if not VCenter.update_port_desc(port, port_info):
                    port_desc = port['port_desc']
                    ports_by_mac.pop(port_desc.mac_address)
        LOG.debug("Read all ports")

    @staticmethod
    def _query_results_to_ports(results):
        ports = []
        for port_id, tenant_id, mac, status, admin_state_up, \
                network_id, network_type, physical_network, segmentation_id, \
                security_group_ids in results:
            ports.append({
                'port_id': port_id,
                'id': port_id,
                'device': port_id,
                'mac_address': mac,
                'tenant_id': tenant_id,
                'admin_state_up': admin_state_up,
                'status': status,
                'network_id': network_id,
                'network_type': network_type,
                'segmentation_id': segmentation_id,
                'physical_network': physical_network,
                'security_groups': security_group_ids.split(_DB_AGG_SEPARATOR),
                'task': None,
            })

        return ports

    @enginefacade.reader
    def _query_ports(self, context, constraint=None):
        sgpb = sg_db.SecurityGroupPortBinding
        PortBindingLevel = models_ml2.PortBindingLevel

        columns = [
            models_v2.Port.id,
            models_v2.Port.tenant_id,
            models_v2.Port.mac_address,
            models_v2.Port.status,
            models_v2.Port.admin_state_up,
            models_ml2.NetworkSegment.network_id,
            models_ml2.NetworkSegment.network_type,
            models_ml2.NetworkSegment.physical_network,
            models_ml2.NetworkSegment.segmentation_id]

        query = context.session.query(*columns).\
                    add_column(string_agg(sgpb.security_group_id,
                                          _DB_AGG_SEPARATOR,
                                          sgpb.security_group_id)).\
                 join(PortBindingLevel).\
                 join(models_ml2.NetworkSegment).\
                 join(sgpb).\
                 filter(PortBindingLevel.host == self.agent.conf.host,
                        PortBindingLevel.driver == constants.DVS,
                        )

        if constraint is not None:
            query = query.filter(constraint)

        query = query.group_by(*columns)

        return self._query_results_to_ports(query)

    def _get_ports_by_mac(self, context, mac_addresses):
        if not mac_addresses:
            return []

        return self._query_ports(
            context, constraint=models_v2.Port.mac_address.in_(mac_addresses))

    def _get_agent_ports(self, context):
        return self._query_ports(context)

    def stop(self):
        try:
            self._quit_event.send(True)
        except AssertionError:
            # Someone already send an event
            pass

        self._monitor_process.stop()

        try:
            while True:
                self.queue.get_nowait()
        except Empty:
            pass


# Small test routine
def main():
    import sys
    from neutron.common import config as common_config
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    # Start everything.
    LOG.info(_LI("Test running... "))

    watch = timeutils.StopWatch()

    def print_message():
        try:
            print("T={:1.3g}".format(watch.elapsed()))
            watch.restart()
        except RuntimeError:
            watch.start()

    pool = eventlet.greenpool.GreenPool(10)
    loop = loopingcall.FixedIntervalLoopingCall(f=print_message)
    loop.start(1.0)

    util = VCenter(pool=pool)
    util.start()

    with timeutils.StopWatch() as w:
        ports = util.get_new_ports(True, 10.0)
        util._read_dvs_ports(ports)

    print(ports)
    print(w.elapsed())

    for dvs in six.itervalues(util.uuid_dvs_map):
        port_keys = dvs._dvs.FetchDVPortKeys(criteria=builder.port_criteria())
        ports = dvs._dvs.FetchDVPorts(criteria=builder.port_criteria(port_key=port_keys))

        configs = []
        for port in ports:
            cookie = getattr(port, 'connectionCookie', None)
            port_config = getattr(port, 'config', {})
            name = getattr(port_config, 'name', None)
            description = getattr(port_config, 'description', None)
            if not cookie and (name or description):
                configs.append(
                    builder.port_config_spec(
                        port.key,
                        version=port_config.configVersion,
                        name='', description=''))

        if configs:
            dvs.update_ports(configs)

    # import time
    # time.sleep(300)
    util.stop()
    loop.stop()
    pool.waitall()


if __name__ == "__main__":
    try:
        resolution = float(os.getenv('DEBUG_BLOCKING'))
        import eventlet.debug

        eventlet.debug.hub_blocking_detection(state=True, resolution=resolution)
    except (ValueError, TypeError):
        pass
    main()

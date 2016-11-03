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

import atexit
import six
from collections import defaultdict
from datetime import datetime

from neutron.i18n import _LI, _LW, _

from oslo_log import log
from oslo_service import loopingcall
from oslo_vmware import vim_util, exceptions, api as vmwareapi

from networking_dvs.common import config as dvs_config
from networking_dvs.utils import dvs_util
from itertools import chain

CONF = dvs_config.CONF

LOG = log.getLogger(__name__)


class RequestCanceledException(exceptions.VimException):
    msg_fmt = _("The task was canceled by a user.")
    code = 200

exceptions.register_fault_class('RequestCanceled', RequestCanceledException)


def _create_session(config):
    """Create Vcenter Session for API Calling."""
    kwargs = {'create_session': True}
    if config.wsdl_location:
        kwargs['wsdl_loc'] = config.wsdl_location
    connection = vmwareapi.VMwareAPISession(
        config.vsphere_hostname,
        config.vsphere_login,
        config.vsphere_password,
        config.api_retry_count,
        config.task_poll_interval,
        **kwargs)

    atexit.register(connection.logout)

    return connection


def _cast(value, _type=str):
    if value is None:
        return None
    return _type(value)


class _DVSPortDesc(object):
    __slots__ = ('dvs_uuid', 'port_key', 'port_group_key', 'mac_address', 'connection_cookie', 'connected', 'status',
                 'config_version', 'vlan_id', 'link_up', 'filter_config_key',)

    def __init__(self, dvs_uuid=None, port_key=None, port_group_key=None,
                 mac_address=None, connection_cookie=None, connected=None, status=None,
                 config_version=None, vlan_id=None, link_up=None, filter_config_key=None):
        self.dvs_uuid = _cast(dvs_uuid)
        self.port_key = _cast(port_key)  # It is an int, but the WDSL defines it as a string
        self.port_group_key = _cast(port_group_key)
        self.mac_address = _cast(mac_address)
        self.connection_cookie = _cast(connection_cookie)  # Same as with port_key, int which is represented as an int
        self.connected = connected
        self.status = _cast(status)
        self.config_version = _cast(config_version)
        self.vlan_id = vlan_id
        self.link_up = link_up
        self.filter_config_key = _cast(filter_config_key)

    def is_connected(self):
        return self.mac_address and self.connected and self.status == 'ok'

    @staticmethod
    def from_dvs_port(port, **values):
        # Port can be either DistributedVirtualSwitchPortConnection, or DistributedVirtualPort
        values.update(
            # switchUuid in connection, dvsUuid in port
            dvs_uuid=_cast(getattr(port, 'switchUuid', None) or getattr(port, 'dvsUuid', None)),
            # switchUuid in connection, dvsUuid in port
            # portKey in connection, key in port
            port_key=getattr(port, 'portKey', None) or getattr(port, 'key', None),
            port_group_key=_cast(port.portgroupKey),
            connection_cookie=_cast(getattr(port, "connectionCookie", None)),
        )
        # The next ones are not part of DistributedVirtualSwitchPortConnection as returned by the backing.port,
        # but a DistributedVirtualPort as returned by FetchDVPorts
        port_config = getattr(port, 'config', None)
        if port_config:
            filter_config_key = None
            vlan_id = None

            setting = getattr(port_config, 'setting', None)
            if setting:
                vlan_id = _cast(getattr(getattr(setting, 'vlan', None), 'vlanId', None), int)

            filter_policy = getattr(setting, "filterPolicy", None)
            if filter_policy:
                filter_config = getattr(filter_policy, "filterConfig", None)
                if filter_config:
                    filter_config_key = str(filter_config[0].key)

            link_up = None
            port_state = getattr(port, "state", None)
            if port_state:
                runtime_info = getattr(port_state, "runtimeInfo", {})
                link_up = getattr(runtime_info, "linkUp", None)

            values.update(config_version=_cast(port_config.configVersion),
                          # name=_cast(port_config.name),
                          # description=_cast(port_config.description),
                          vlan_id=vlan_id,
                          filter_config_key=filter_config_key,
                          link_up=link_up
                          )

        return values


    @classmethod
    def _slots(cls):
        return chain.from_iterable(getattr(cls2, '__slots__', tuple()) for cls2 in cls.__mro__)

    def update(self, source):
        if not source:
            return

        if isinstance(source, dict):
            for slot in self._slots():
                attr = source.get(slot, None)
                if not attr is None:
                    setattr(self, slot, source.get(slot))
        else:
            for slot in self._slots():
                attr = getattr(source, slot, None)
                if not attr is None:
                    setattr(self, slot, attr)

    def __repr__(self):
        return "%s(%r)" % (self.__class__, {s: getattr(self, s, None) for s in self._slots()})


class _DVSPortMonitorDesc(_DVSPortDesc):
    __slots__ = ('vmobref', 'device_key',)

    def __init__(self, vmobref=None, device_key=None, **kwargs):
        super(_DVSPortMonitorDesc, self).__init__(**kwargs)
        self.vmobref = str(vmobref)
        self.device_key = int(device_key)


class SpecBuilder(dvs_util.SpecBuilder):
    def neutron_to_port_config_spec(self, port):
        port_desc = port['port_desc']
        setting = self.port_setting(vlan=self.vlan(port["segmentation_id"]),
                                    blocked=self.blocked(not port["admin_state_up"]),
                                    filter_policy=self.filter_policy(None)
                                    )

        return self.port_config_spec(version=port_desc.config_version,
                                     key=port_desc.port_key,
                                     setting=setting,
                                     name=port["port_id"],
                                     description="Neutron port for network {}".format(port["network_id"]))

    def wait_options(self, max_wait_seconds=None, max_object_updates=None):
        wait_options = self.factory.create('ns0:WaitOptions')

        if max_wait_seconds:
            wait_options.maxWaitSeconds = max_wait_seconds

        if max_object_updates:
            wait_options.maxObjectUpdates = max_object_updates

        return wait_options

    def virtual_device_connect_info(self, allow_guest_control, connected, start_connected):
        virtual_device_connect_info = self.factory.create('ns0:VirtualDeviceConnectInfo')

        virtual_device_connect_info.allowGuestControl = allow_guest_control
        virtual_device_connect_info.connected = connected
        virtual_device_connect_info.startConnected = start_connected

        return virtual_device_connect_info

    def distributed_virtual_switch_port_connection(self, switch_uuid, port_key=None, portgroup_key=None):
        # connectionCookie is left out intentionally, it cannot be set
        distributed_virtual_switch_port_connection = self.factory.create('ns0:DistributedVirtualSwitchPortConnection')
        distributed_virtual_switch_port_connection.switchUuid = switch_uuid

        if port_key:
            distributed_virtual_switch_port_connection.portKey = port_key
        if portgroup_key:
            distributed_virtual_switch_port_connection.portgroupKey = portgroup_key

        return distributed_virtual_switch_port_connection

    def virtual_device_config_spec(self, device, file_operation=None, operation=None, profile=None):
        virtual_device_config_spec = self.factory.create('ns0:VirtualDeviceConfigSpec')
        virtual_device_config_spec.device = device

        if file_operation:
            virtual_device_config_spec.fileOperation = file_operation
        if operation:
            virtual_device_config_spec.operation = operation
        if profile:
            virtual_device_config_spec.profile = profile

        return virtual_device_config_spec

    def virtual_machine_config_spec(self, device_change=None, change_version=None):
        virtual_machine_config_spec = self.factory.create('ns0:VirtualMachineConfigSpec')

        if device_change:
            virtual_machine_config_spec.deviceChange = device_change
        if change_version:
            virtual_machine_config_spec.changeVersion = change_version

        return virtual_machine_config_spec


class VCenterMonitor(object):
    def __init__(self, config, queue=None, quit_event=None, error_queue=None, pool=None):
        self._quit_event = quit_event or Event()
        self.changed = set()
        self.queue = queue or Queue()
        self.error_queue = error_queue
        self._property_collector = None
        self.down_ports = {}
        self.untried_ports = {} # The host is simply down
        self.iteration = 0
        self.connection = None
        # Map of the VMs and their NICs by the hardware key
        # e.g vmobrefs -> keys -> _DVSPortMonitorDesc
        self._hardware_map = defaultdict(dict)
        # super(VCenterMonitor, self).__init__(target=self._run, args=(config,))
        pool = pool or eventlet
        self.thread = pool.spawn(self._run, config)

    def stop(self):
        try:
            self._quit_event.send(0)
        except AssertionError: # In case someone already send an event
            pass

        # This will abort the WaitForUpdateEx early, so it will cancel leave the loop timely
        if self.connection and self.property_collector:
            try:
                self.connection.invoke_api(self.connection.vim, 'CancelWaitForUpdates', self.property_collector)
            except exceptions.VimException:
                pass

    def _run(self, config):
        LOG.info(_LI("Monitor running... "))
        self.connection = _create_session(config)
        try:
            connection = self.connection
            vim = connection.vim
            builder = SpecBuilder(vim.client.factory)

            version = None
            wait_options = builder.wait_options(60, 20)

            self.property_collector = self._create_property_collector()
            self._create_property_filter(self.property_collector)

            while not self._quit_event.ready():
                result = connection.invoke_api(vim, 'WaitForUpdatesEx', self.property_collector,
                                               version=version, options=wait_options)
                self.iteration += 1
                if result:
                    version = result.version
                    if result.filterSet and result.filterSet[0].objectSet:
                        for update in result.filterSet[0].objectSet:
                            if update.obj._type == 'VirtualMachine':
                                self._handle_virtual_machine(update)

                for port_desc in self.changed:
                    self._put(self.queue, port_desc)
                self.changed.clear()

                now = datetime.utcnow()
                for mac, (when, port_desc, iteration) in six.iteritems(self.down_ports):
                    if port_desc.status != 'untried' or 0 == self.iteration - iteration:
                        print("Down: {} {} for {} {} {}".format(mac, port_desc.port_key, self.iteration - iteration, (now - when).total_seconds(), port_desc.status))
        except RequestCanceledException, e:
            # If the event is set, the request was canceled in self.stop()
            if not self._quit_event.ready():
                LOG.info("Waiting for updates was cancelled unexpectedly")
                raise e # This will kill the whole process and we start again from scratch
        finally:
            if self.connection:
                self.connection.logout

    def _create_property_filter(self, property_collector):
        connection = self.connection
        vim = connection.vim
        service_content = vim.service_content
        client_factory = vim.client.factory

        container_view = connection.invoke_api(vim, 'CreateContainerView', service_content.viewManager,
                                               container=service_content.rootFolder,
                                               type=['VirtualMachine'],
                                               recursive=True)

        traversal_spec = vim_util.build_traversal_spec(client_factory, 'traverseEntities', 'ContainerView', 'view',
                                                       False, None)
        object_spec = vim_util.build_object_spec(client_factory, container_view, [traversal_spec])

        # Only static types work, so we have to get all hardware, still faster then retrieving individual items
        vm_properties = ['runtime.powerState', 'config.hardware.device']
        property_specs = [vim_util.build_property_spec(client_factory, 'VirtualMachine', vm_properties)]

        property_filter_spec = vim_util.build_property_filter_spec(client_factory, property_specs, [object_spec])

        return connection.invoke_api(vim, 'CreateFilter', property_collector, spec=property_filter_spec,
                                     partialUpdates=True)  # -> PropertyFilter

    def _create_property_collector(self):
        vim = self.connection.vim
        _property_collector = self.connection.invoke_api(vim, 'CreatePropertyCollector',
                                                    vim.service_content.propertyCollector)

        return _property_collector

    def _handle_removal(self, vm):
        vm_hw = self._hardware_map.pop(vm, {})
        for port_desc in six.itervalues(vm_hw):
            if isinstance(port_desc, _DVSPortMonitorDesc):
                mac_address = port_desc.mac_address
                port_desc.status = 'deleted'
                LOG.debug("Removed {} {}".format(mac_address, port_desc.port_key))
                self.down_ports.pop(mac_address, None)
                self.untried_ports.pop(mac_address, None)
                self.changed.add(port_desc)

    def _handle_virtual_machine(self, update):
        vmobref = str(update.obj.value)  # String 'vmobref-#'
        change_set = getattr(update, 'changeSet', [])

        if update.kind != 'leave':
            vm_hw = self._hardware_map[vmobref]

        for change in change_set:
            change_name = change.name
            if change_name == "config.hardware.device":
                if "assign" == change.op:
                    for v in change.val[0]:
                        backing = getattr(v, 'backing', None)
                        # If if is not a NIC, it will have no backing and/or port
                        if not backing:
                            continue
                        port = getattr(backing, 'port', None)
                        if not port:
                            continue
                        # port is a DistributedVirtualSwitchPortConnection

                        connectable = getattr(v, 'connectable', None)

                        port_desc = _DVSPortMonitorDesc(**_DVSPortDesc.from_dvs_port(
                            port,
                            mac_address=getattr(v, 'macAddress', None),
                            connected=connectable.connected if connectable else None,
                            status=connectable.status if connectable else None,
                            vmobref=vmobref,
                            device_key=v.key
                            ))

                        vm_hw[port_desc.device_key] = port_desc
                        self._handle_port_update(port_desc)
                elif "indirectRemove" == change.op:
                    self._handle_removal(vmobref)
            elif change_name.startswith("config.hardware.device["):
                id_end = change_name.index("]")
                device_key = int(change_name[23:id_end])
                port_desc = vm_hw.get(device_key, None)
                if port_desc:
                    attribute = change_name[id_end + 2:]
                    if "connectable.connected" == attribute:
                        port_desc.connected = change.val
                        self._handle_port_update(port_desc)
                    elif "connectable.status" == attribute:
                        port_desc.status = change.val
                        self._handle_port_update(port_desc)
                    elif "macAddress" == attribute:
                        port_desc.mac_address = str(change.val)
                        self._handle_port_update(port_desc)

            elif change_name == 'runtime.powerState':
                # print("{}: {}".format(vm, change.val))
                vm_hw['power_state'] = change.val
                for port_desc in six.itervalues(vm_hw):
                    if isinstance(port_desc, _DVSPortMonitorDesc):
                        self._handle_port_update(port_desc)
            else:
                LOG.debug(change)

        if update.kind == 'leave':
            self._handle_removal(vmobref)
        else:
            pass

    def _handle_port_update(self, port_desc):
        now = datetime.utcnow()
        mac_address = port_desc.mac_address

        if not mac_address:
            return

        if port_desc.is_connected():
            then, _, iteration = self.down_ports.pop(mac_address, (None, None, None))
            self.untried_ports.pop(mac_address, None)
            if then:
                LOG.debug("Port {} {} was down for {} ({})".format(mac_address, port_desc.port_key,
                                                               (now - then).total_seconds(),
                                                               (self.iteration - iteration)))
            elif not port_desc in self.changed:
                LOG.debug("Port {} {} came up connected".format(mac_address, port_desc.port_key))
            self.changed.add(port_desc)
        else:
            power_state = self._hardware_map[port_desc.vmobref].get('power_state', None)
            if power_state != 'poweredOn':
                self.untried_ports[mac_address] = port_desc
            elif not port_desc in self.down_ports:
                status = port_desc.status
                LOG.debug("Port {} {} registered as down: {} {}".format(mac_address, port_desc.port_key, status, power_state))
                self.down_ports[mac_address] = (now, port_desc, self.iteration)
                if status == 'unrecoverableError' and self.error_queue:
                    self._put(self.error_queue, port_desc)

    def _put(self, queue, port_desc):
        while not self._quit_event.ready():
            try:
                queue.put_nowait(port_desc)
            except Full:
                continue
            break


class VCenter(object):
    # PropertyCollector discovers changes on vms and their hardware and produces
    #    (mac, switch, portKey, portGroupKey, connectable.connected, connectable.status)
    #    internally, it keeps internally vm and key for identifying updates
    # Subsequentally, the mac has to be identified with a port
    #

    def __init__(self, config=None, pool=None):
        self.pool = pool
        self.config = config or CONF.ML2_VMWARE
        self.connection = None
        self._monitor_process = VCenterMonitor(self.config, pool=self.pool)
        self.connection = _create_session(self.config)

        self.uuid_port_map = {}
        self.mac_port_map = {}

        self.uuid_dvs_map = {}

        for dvs in six.itervalues(dvs_util.create_network_map_from_config(self.config, self.connection)):
            self.uuid_dvs_map[dvs.uuid] = dvs

    @staticmethod
    def update_port_desc(port, port_info):
        # Validate connectionCookie, so we still have the same instance behind that portKey
        port_desc = port['port_desc']
        connection_cookie = _cast(getattr(port_info, 'connectionCookie', None))

        if port_desc.connection_cookie != connection_cookie:
            LOG.error("Cookie mismatch {} {} {} <> {}".format(port_desc.mac_address, port_desc.port_key,
                                                              port_desc.connection_cookie, connection_cookie))
            return False

        port.update(_DVSPortDesc.from_dvs_port(port_info))

        return True

    def ports_by_switch_and_key(self, ports):
        ports_by_switch_and_key = defaultdict(dict)
        for port in ports:
            port_desc = port['port_desc']
            dvs = self.get_dvs_by_uuid(port_desc.dvs_uuid)

            if dvs:
                ports_by_switch_and_key[dvs][port_desc.port_key] = port

        return ports_by_switch_and_key

    @dvs_util.wrap_retry
    def bind_ports(self, ports):
        ports_up = []
        ports_down = []

        ports_by_switch_and_key = self.ports_by_switch_and_key(ports)

        builder = SpecBuilder(self.connection.vim.client.factory)

        for dvs, ports_by_key in six.iteritems(ports_by_switch_and_key):
            specs = []
            for port in six.itervalues(ports_by_key):
                if port["network_type"] == "vlan":
                    spec = builder.neutron_to_port_config_spec(port)
                    specs.append(spec)
                else:
                    ports_down.append(port)
                    LOG.warning(_LW("Cannot configure port %s it is not of type vlan"), port["port_id"])

            dvs.update_ports_checked(ports, specs)

            for port_info in dvs.get_port_info_by_portkey(list(six.iterkeys(ports_by_key))):
                port_key = str(port_info.key)
                port = ports_by_key[port_key]
                port_desc = port['port_desc']
                if VCenter.update_port_desc(port, port_info):
                    if port["admin_state_up"]:
                        if port_desc.vlan_id == port["segmentation_id"] and port_desc.link_up:
                            ports_up.append(port)
                    else:  # Port down requested
                        if not port_desc.link_up:
                            ports_down.append(port)

        return ports_up, ports_down

    def get_dvs_by_uuid(self, uuid):
        return self.uuid_dvs_map.get(uuid,None)

    def get_port_by_uuid(self, uuid):
        return self.uuid_port_map.get(uuid, None)

    def get_new_ports(self, block=False, timeout=1.0, max_ports=None):
        ports_by_mac = defaultdict(dict)

        try:
            while max_ports is None or len(ports_by_mac) < max_ports:
                port_desc = self._monitor_process.queue.get(block=block, timeout=timeout)
                block = False # Only block on the first item
                if port_desc.status == 'deleted':
                    ports_by_mac.pop(port_desc.mac_address, None)
                    port = self.mac_port_map.pop(port_desc.mac_address, None)
                    if port:
                        self.uuid_port_map.pop(port['id'], None)
                else:
                    port = self.mac_port_map.get(port_desc.mac_address, {})
                    port.update({
                        'port_desc': port_desc,
                        'port': {
                            'binding:vif_details': {
                                'dvs_port_key': port_desc.port_key,
                                'dvs_uuid': port_desc.dvs_uuid
                            }, 'mac_address': port_desc.mac_address}
                    })
                    ports_by_mac[port_desc.mac_address] = port
        except Empty:
            pass

        ports_by_switch_and_key = self.ports_by_switch_and_key(six.itervalues(ports_by_mac))

        # This loop can get very slow, if get_port_info_by_portkey gets port keys passed of instances, which are only
        # partly connected, meaning: the instance is associated, but the link is not quite up yet
        for dvs, ports_by_key in six.iteritems(ports_by_switch_and_key):
            for port_info in dvs.get_port_info_by_portkey(list(six.iterkeys(ports_by_key))):  # View is not sufficient
                port = ports_by_key[port_info.key]
                port_desc = port['port_desc']
                if VCenter.update_port_desc(port, port_info):
                    state = getattr(port_info, "state", {})
                    runtime_info = getattr(state, "runtimeInfo", {})
                    if getattr(runtime_info, "linkUp", False):
                        LOG.error("Port Link Down: {}".format(port_info.key))
                else:
                    ports_by_mac.pop(port_desc.mac_address)

        return ports_by_mac

    def stop(self):
        self._monitor_process.stop()

        try:
            while True:
                self._monitor_process.queue.get_nowait()
        except Empty:
            pass


# Small test routine
def main():
    import sys
    from neutron.common import config as common_config
    from oslo_utils import timeutils
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

    with timeutils.StopWatch() as w:
        ports = util.get_new_ports(True, 10.0)
    print(ports)
    print(w.elapsed())

    for dvs in six.itervalues(util.uuid_dvs_map):
        builder = SpecBuilder(dvs.connection.vim.client.factory)
        port_keys = dvs.connection.invoke_api(
            dvs.connection.vim,
            'FetchDVPortKeys',
            dvs._dvs, criteria=builder.port_criteria())
        ports = dvs.connection.invoke_api(
            dvs.connection.vim,
            'FetchDVPorts',
            dvs._dvs, criteria=builder.port_criteria(port_key=port_keys))

        configs = []
        for port in ports:
            cookie = getattr(port, 'connectionCookie', None)
            port_config =  getattr(port, 'config', {})
            name = getattr(port_config, 'name', None)
            description = getattr(port_config, 'description', None)
            if not cookie and (name or description):
                configs.append(builder.port_config_spec(port.key, version=port_config.configVersion, name='', description=''))

        if configs:
            dvs.update_ports(configs)

    # import time
    # time.sleep(300)
    util.stop()
    loop.stop()
    pool.waitall()


if __name__ == "__main__":
    main()

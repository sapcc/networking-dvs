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

import atexit
import six
from collections import defaultdict
from datetime import datetime

from neutron.i18n import _LI, _LW, _

from oslo_log import log
from oslo_service  import loopingcall
from oslo_vmware import vim_util, api as vmwareapi
from oslo_vmware import exceptions as vmware_exceptions

try:
    import multiprocessing.Queue as mpq
except:
    import multiprocessing.queues as mqp

from networking_dvs.common import config as dvs_config, constants as dvs_const
from networking_dvs.utils import dvs_util

import multiprocessing

CONF = dvs_config.CONF
LOG = log.getLogger(__name__)


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


class _DVSPortDesc(object):
    def __init__(self, dvs_uuid=None, port_key=None, port_group_key=None,
                 mac_address=None, connection_cookie=None, connected=None, status=None,
                 config_version=None, vlan_id=None, link_up=None, vm=None):
        self.dvs_uuid = dvs_uuid
        self.port_key = port_key
        self.port_group_key = port_group_key
        self.mac_address = mac_address
        self.connection_cookie = connection_cookie
        self.connected = connected
        self.status = status
        self.config_version = config_version
        self.vlan_id = vlan_id
        self.link_up = link_up

    def update(self, source):
        self.__dict__.update(source.__dict__)

    def is_connected(self):
        return self.connected and self.status == 'ok'

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self.__dict__)


class _DVSPortMonitorDesc(_DVSPortDesc):
    def __init__(self, vm=None, device_key=None, **kwargs):
        super(_DVSPortMonitorDesc, self).__init__(**kwargs)
        self.vm = vm
        self.device_key = device_key


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


class VCenterRecovery(multiprocessing.Process):
    def __init__(self, config, queue=None, quit_event=None):
        self._quit_event = quit_event or multiprocessing.Event()
        self.queue = queue or multiprocessing.Queue()
        self.quarantine_by_switch = {}
        self.connection = None
        self._uuid_dvs_map = {}
        super(VCenterRecovery, self).__init__(target=self._run, args=(config,))

    def get_quarantine_key_for_switch(self, switch_uuid):
        quarantine_key = self.quarantine_by_switch.get(switch_uuid, None)
        if quarantine_key:
            return quarantine_key

        dvs = self._uuid_dvs_map[switch_uuid]

        network = {'id': 'quarantine', 'admin_state_up': False}
        segment = {'segmentation_id': 1}
        pg_name = dvs._get_net_name(dvs.dvs_name, network)
        pg = dvs._get_or_create_pg(pg_name, network, segment)

        vim = self.connection.vim
        quarantine_key = vim_util.get_object_property(vim, pg, 'key')

        self.quarantine_by_switch[switch_uuid] = quarantine_key
        return quarantine_key

    def _run(self, config):
        self.connection = _create_session(config)
        vim = self.connection.vim
        builder = SpecBuilder(vim.client.factory)

        for dvs in six.itervalues(dvs_util.create_network_map_from_config(config, self.connection)):
            self._uuid_dvs_map[dvs.uuid] = dvs

        while not self._quit_event.is_set():
            ports = []
            try:
                ports.append(self.queue.get(True, 0.1))
                while not self.queue.empty():
                    ports.append(self.queue.get_nowait())
            except mqp.Empty:
                pass

            ports_by_vm = defaultdict(list)
            for port_desc in ports:
                ports_by_vm[port_desc.vm].append(port_desc)

            for vm, ports in six.iteritems(ports_by_vm):
                vm = vim_util.get_moref(vm, 'VirtualMachine')

                device_by_key = {}
                items = vim_util.get_object_property(vim, vm, 'config.hardware.device') # -> ArrayOfVirtualDevice
                for type, devices in items:
                    for device in devices:
                        if hasattr(device, 'macAddress'):
                            device_by_key[int(device.key)] = device

                device_changes = []
                for port_desc in ports:
                    device = device_by_key[port_desc.device_key]
                    device.backing.port = builder.distributed_virtual_switch_port_connection(port_desc.dvs_uuid,
                                                                                             portgroup_key=self.get_quarantine_key_for_switch(port_desc.dvs_uuid),
                                                                                             port_key=None)

                    device.connectable = builder.virtual_device_connect_info(False, False, False)
                    change = builder.virtual_device_config_spec(device, operation='edit')
                    device_changes.append(change)

                config_spec = builder.virtual_machine_config_spec(device_change=device_changes)
                reconfig_task = self.connection.invoke_api(vim, 'ReconfigVM_Task', vm, spec=config_spec)

                result = self.connection.wait_for_task(reconfig_task)

                print(result)

                device_changes = []
                for port_desc in ports:
                    device = device_by_key[port_desc.device_key]
                    device.backing.port = builder.distributed_virtual_switch_port_connection(port_desc.dvs_uuid,
                                                                                             portgroup_key=port_desc.port_group_key,
                                                                                             port_key=None)
                    device.connectable = builder.virtual_device_connect_info(False, True, True)
                    change = builder.virtual_device_config_spec(device, operation='edit')
                    device_changes.append(change)

                config_spec = builder.virtual_machine_config_spec(device_change=device_changes)
                reconfig_task = self.connection.invoke_api(vim, 'ReconfigVM_Task', vm, spec=config_spec)

                result = self.connection.wait_for_task(reconfig_task)

                print(result)

        self.connection.logout


class VCenterMonitor(multiprocessing.Process):
    def __init__(self, config, queue=None, quit_event=None, error_queue=None):
        self._quit_event = quit_event or multiprocessing.Event()
        self.queue = queue or multiprocessing.Queue()
        self.error_queue = error_queue or multiprocessing.Queue()
        self.down_ports = {}
        self.untried_ports = {} # The host is simply down
        self.iteration = 0
        # Map of the VMs and their NICs by the hardware key
        # e.g vmobrefs -> keys -> _DVSPortMonitorDesc
        self._hardware_map = defaultdict(dict)
        loopingcall.FixedIntervalLoopingCall(lambda: LOG.debug("Tick")).start(10.0)
        super(VCenterMonitor, self).__init__(target=self._run, args=(config,))

    def stop(self, *args):
        self._quit_event.set()

    def _run(self, config):
        connection = _create_session(config)

        vim = connection.vim
        builder = SpecBuilder(vim.client.factory)

        version = None
        wait_options = builder.wait_options(1, 20)

        property_collector = self._create_property_collector(connection)
        self._create_property_filter(connection, property_collector)

        while not self._quit_event.is_set():
            result = connection.invoke_api(vim, 'WaitForUpdatesEx', property_collector,
                                           version=version, options=wait_options)
            self.iteration += 1
            if result:
                version = result.version
                if result.filterSet and result.filterSet[0].objectSet:
                    for update in result.filterSet[0].objectSet:
                        if update.obj._type == 'VirtualMachine':
                            self._handle_virtual_machine(update)

            now = datetime.utcnow()
            for mac, (when, port_desc, iteration) in six.iteritems(self.down_ports):
                print("Down: {} {} for {} {} {}".format(mac, port_desc.port_key, self.iteration - iteration, (now - when).total_seconds(), port_desc.status))

        connection.logout

    @staticmethod
    def _create_property_filter(connection, property_collector):
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

    @staticmethod
    def _create_property_collector(connection):
        vim = connection.vim
        _property_collector = connection.invoke_api(vim, 'CreatePropertyCollector',
                                                    vim.service_content.propertyCollector)

        return _property_collector

    def _handle_removal(self, vm):
        vm_hw = self._hardware_map.pop(vm, {})
        for port_desc in six.itervalues(vm_hw):
            if isinstance(port_desc, _DVSPortMonitorDesc):
                mac_address = port_desc.mac_address
                port_desc.status = 'deleted'
                print("Removed {} {}".format(mac_address, port_desc.port_key))
                self.down_ports.pop(mac_address, None)
                self.untried_ports.pop(mac_address, None)
                self.queue.put(port_desc)

    def _handle_virtual_machine(self, update):
        vm = update.obj.value  # vmobref (vm-#)
        change_set = getattr(update, 'changeSet', [])

        if update.kind != 'leave':
            vm_hw = self._hardware_map[vm]

        for change in change_set:
            change_name = change.name
            if change_name == "config.hardware.device":
                if "assign" == change.op:
                    for v in change.val[0]:
                        mac_address = getattr(v, 'macAddress', None)
                        if mac_address:
                            port = v.backing.port
                            mac_address = str(v.macAddress)
                            connectable = getattr(v, "connectable", None)
                            device_key=int(v.key)

                            port_desc = _DVSPortMonitorDesc(
                                mac_address=mac_address,
                                connected=connectable.connected if connectable else None,
                                status=str(connectable.status) if connectable else None,
                                port_key=str(port.portKey),
                                port_group_key=str(port.portgroupKey),
                                dvs_uuid=str(port.switchUuid),
                                connection_cookie=int(port.connectionCookie),
                                vm=vm,
                                device_key=device_key
                                )

                            vm_hw[port_desc.device_key] = port_desc
                            self._handle_port_update(port_desc)
                elif "indirectRemove" == change.op:
                    self._handle_removal(vm)
            elif change_name.startswith("config.hardware.device["):
                id_end = change_name.index("]")
                device_key = int(change_name[23:id_end])
                port_desc = vm_hw.get(device_key, None)
                if port_desc:
                    attribute = change_name[id_end + 2:]
                    if "connectable.connected" == attribute:
                        port_desc.connected = change.val
                    elif "connectable.status" == attribute:
                        port_desc.status = change.val
                    self._handle_port_update(port_desc)
            elif change_name == 'runtime.powerState':
                # print("{}: {}".format(vm, change.val))
                vm_hw['power_state'] = change.val
                for port_desc in six.itervalues(vm_hw):
                    if isinstance(port_desc, _DVSPortMonitorDesc):
                        self._handle_port_update(port_desc)

            else:
                print(change)

        if update.kind == 'leave':
            self._handle_removal(vm)
        else:
            pass

    def _handle_port_update(self, port_desc):
        now = datetime.utcnow()
        mac_address = port_desc.mac_address
        if port_desc.is_connected():
            self.queue.put(port_desc)
            then, _, iteration = self.down_ports.pop(mac_address, (None, None, None))
            self.untried_ports.pop(mac_address, None)
            if then:
                print("Port {} {} was down for {} ({})".format(mac_address, port_desc.port_key,
                                                               (now - then).total_seconds(),
                                                               (self.iteration - iteration)))
            else:
                pass
                # print("Port {} {} came up connected".format(mac_address, port_desc.port_key))
        else:
            power_state = self._hardware_map[port_desc.vm].get('power_state', None)
            if power_state != 'poweredOn':
                self.untried_ports[mac_address] = port_desc
            elif not port_desc in self.down_ports:
                status = port_desc.status
                print("Port {} {} registered as down: {} {}".format(mac_address, port_desc.port_key, status, power_state))
                self.down_ports[mac_address] = (now, port_desc, self.iteration)
                if status == 'unrecoverableError':
                    self.error_queue.put(port_desc)


class VCenter(object):
    # PropertyCollector discovers changes on vms and their hardware and produces
    #    (mac, switch, portKey, portGroupKey, connectable.connected, connectable.status)
    #    internally, it keeps internally vm and key for identifying updates
    # Subsequentally, the mac has to be identified with a port
    #

    def __init__(self, config=None):
        config = config or CONF.ML2_VMWARE
        self.connection = None
        self.quit_event = multiprocessing.Event()
        self._monitor_process = VCenterMonitor(config, quit_event=self.quit_event)
        # self._recovery_process = VCenterRecovery(config, quit_event=self.quit_event, queue=self._monitor_process.error_queue)
        self._monitor_process.start()

        if getattr(self, '_recovery_process', None):
            self._recovery_process.start()

        self.connection = _create_session(config)

        self.uuid_port_map = {}
        self.mac_port_map = {}

        self.uuid_dvs_map = {}

        for dvs in six.itervalues(dvs_util.create_network_map_from_config(config, self.connection)):
            self.uuid_dvs_map[dvs.uuid] = dvs


    @staticmethod
    def update_port_desc(port, port_info):
        # TODO validate connectionCookie, so we still have the same instance behind that portKey
        port_desc = port['port_desc']
        port_desc.config_version = port_info.config.configVersion
        if getattr(port_info.config, "setting", None) \
                and getattr(port_info.config.setting, "vlan", None) \
                and port_info.config.setting.vlan.vlanId:
            port_desc.vlan_id = port_info.config.setting.vlan.vlanId

        if getattr(port_info, "state", None) \
                and getattr(port_info.state, "runtimeInfo", None):
            port_desc.link_up = getattr(port_info.state.runtimeInfo, "linkUp", None)

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
                    specs.append(builder.neutron_to_port_config_spec(port))
                else:
                    ports_down.append(port)
                    LOG.warning(_LW("Cannot configure port %s it is not of type vlan"), port["port_id"])

            try:
                result = dvs.update_ports(specs)
                if result.state != "success":
                    LOG.warning("Binding did not succeed")
            except vmware_exceptions.VimFaultException as e:
                LOG.debug(e.msg)
                if dvs_const.CONCURRENT_MODIFICATION_TEXT in e.msg:
                    # TODO: We would have to validate, that the port key still pointing to the same port
                    pass
                else:
                    raise e

            for port_info in dvs.get_port_info_by_portkey(list(six.iterkeys(ports_by_key))):
                port_key = str(port_info.key)
                port = ports_by_key[port_key]
                VCenter.update_port_desc(port, port_info)
                port_desc = port['port_desc']
                connection_cookie = getattr(port_info, 'connectionCookie', None)
                if port_desc.connection_cookie != connection_cookie:
                    LOG.error("Cookie mismatch {} {} {} <> {}".format(port_desc.mac_address, port_desc.port_key,
                                                                      port_desc.connection_cookie, connection_cookie))

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

    def get_new_ports(self, block=False, timeout=1.0):
        ports_by_mac = defaultdict(dict)

        try:
            while True:
                port_desc = self._monitor_process.queue.get(block=block, timeout=timeout)
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
        except mqp.Empty:
            pass

        ports_by_switch_and_key = self.ports_by_switch_and_key(six.itervalues(ports_by_mac))

        # This loop can get very slow, if get_port_info_by_portkey gets port keys passed of instances, which are only
        # partly connected, meaning: the instance is associated, but the link is not quite up yet
        for dvs, ports_by_key in six.iteritems(ports_by_switch_and_key):
            keys = list(six.iterkeys(ports_by_key))
            for port_info in dvs.get_port_info_by_portkey(keys):  # View is not sufficient
                port = ports_by_key[port_info.key]
                port_desc = port['port_desc']
                if getattr(port_info, 'connectionCookie', None) != port_desc.connection_cookie:
                    LOG.error("Cookie mismatch: {} {} {} <> {}, Removing port {}".
                                format(getattr(port_info, 'connectionCookie', None), port_desc.connection_cookie,
                                       port_desc.mac_address, port_desc.port_key, port.get('id', port.keys)))
                    ports_by_mac.pop(port_desc.mac_address)
                else:
                    state = getattr(port_info, "state", None)
                    runtime_info = getattr(state, "runtimeInfo", None)
                    if getattr(runtime_info, "linkUp", False):
                        LOG.error("Port Link Down: {}".format(port_info.key))

                    VCenter.update_port_desc(port, port_info)

        return ports_by_mac

    def stop(self, *args):
        self.quit_event.set()


# Small test routine
def main():
    import signal
    import sys
    try:
        import multiprocessing.Queue as mpq
    except:
        import multiprocessing.queues as mqp

    from neutron.common import config as common_config
    from oslo_utils import timeutils
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    # Start everything.
    LOG.info(_LI("Test running... "))

    util = VCenter()

    with timeutils.StopWatch() as w:
        ports = util.get_new_ports(True, 1.0)
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
            name = getattr(port.config, 'name', None)
            description = getattr(port.config, 'description', None)
            if not cookie and (name or description):
                configs.append(builder.port_config_spec(port.key, version=port.config.configVersion, name='', description=''))

        if configs:
            dvs.update_ports(configs)

    util.stop()


if __name__ == "__main__":
    main()

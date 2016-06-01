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
from oslo_service import loopingcall
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
                 config_version=None, vlan_id=None, link_up=None):
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


class VCenterMonitor(multiprocessing.Process):
    def __init__(self, config, queue=None, quit_event=None):
        self._quit_event = quit_event or multiprocessing.Event()
        self.queue = queue or multiprocessing.Queue()
        self.down_ports = {}
        self.iteration = 0
        # Map of the VMs and their NICs by the hardware key
        # e.g vmobrefs -> keys -> _DVSPortDesc
        self._hardware_map = defaultdict(dict)
        super(VCenterMonitor, self).__init__(target=self._run, args=(config,))

    def stop(self, *args):
        self._quit_event.set()

    def _run(self, config):
        connection = _create_session(config)

        vim = connection.vim
        builder = SpecBuilder(vim.client.factory)

        version = None
        wait_options = builder.wait_options(10, 100)

        property_collector = self._create_property_collector(connection)
        self._create_property_filter(connection, property_collector)

        while not self._quit_event.is_set():
            result = connection.invoke_api(vim, 'WaitForUpdatesEx', property_collector,
                                                version=version, options=wait_options)
            if result:
                self.iteration += 1
                version = result.version
                if result.filterSet and result.filterSet[0].objectSet:
                    for update in result.filterSet[0].objectSet:
                        if update.obj._type == 'VirtualMachine':
                            self._handle_virtual_machine(update)

        connection.close

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

        # Only static types work, so we have to get all hardware
        vm_properties = ['config.hardware.device']
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
            mac_address = port_desc.mac_address
            port_desc.status = 'deleted'
            print("Removed {} {}".format(mac_address, port_desc.port_key))
            self.down_ports.pop(mac_address, None)
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

                            port_desc = _DVSPortDesc(
                                mac_address=mac_address,
                                connected=connectable.connected if connectable else None,
                                status=str(connectable.status) if connectable else None,
                                port_key=str(port.portKey),
                                port_group_key=str(port.portgroupKey),
                                dvs_uuid=str(port.switchUuid),
                                connection_cookie=int(port.connectionCookie))

                            vm_hw[int(v.key)] = port_desc
                            self._add_port(port_desc)
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
                    self._add_port(port_desc)
            else:
                print(change)

        if update.kind == 'leave':
            self._handle_removal(vm)
        else:
            pass

    def _add_port(self, port_desc):
        now = datetime.utcnow()
        mac_address = port_desc.mac_address
        if port_desc.is_connected():
            self.queue.put(port_desc)
            then, _, iteration = self.down_ports.pop(mac_address, (None, None, None))
            if then:
                print("Port {} {} was down for {} ({})".format(port_desc.port_key,
                                                               mac_address, (now - then).total_seconds(),
                                                               (self.iteration - iteration)))
            else:
                print("Port {} {} came up connected".format(port_desc.port_key,
                                                               mac_address))
        elif not port_desc in self.down_ports:
            print("Port {} {} registered as down: {}".format(port_desc.port_key, mac_address, port_desc))
            self.down_ports[mac_address] = (now, port_desc, self.iteration)


class VCenter(object):
    # PropertyCollector discovers changes on vms and their hardware and produces
    #    (mac, switch, portKey, portGroupKey, connectable.connected, connectable.status)
    #    internally, it keeps internally vm and key for identifying updates
    # Subsequentally, the mac has to be identified with a port
    #

    def __init__(self, config=None):
        config = config or CONF.ML2_VMWARE
        self.connection = None

        self._monitor_process = VCenterMonitor(config)
        self._monitor_process.start()

        self.connection = _create_session(config)

        self.uuid_port_map = {}
        self.mac_port_map = {}

        self._uuid_dvs_map = {}
        for dvs in six.itervalues(dvs_util.create_network_map_from_config(config, self.connection)):
            self._uuid_dvs_map[dvs.uuid] = dvs


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

                if port["admin_state_up"]:
                    if port_desc.vlan_id == port["segmentation_id"] and port_desc.link_up:
                        ports_up.append(port)
                else:  # Port down requested
                    if not port_desc.link_up:
                        ports_down.append(port)

        return ports_up, ports_down

    def get_dvs_by_uuid(self, uuid):
        return self._uuid_dvs_map[uuid]

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
                    LOG.warning("Different connection cookie then expected: Got {}, Expected {}".
                                format(getattr(port_info, 'connectionCookie', None), port_desc.connection_cookie))

                state = getattr(port_info, "state", None)
                runtime_info = getattr(state, "runtimeInfo", None)
                if getattr(runtime_info, "linkUp", False):
                    LOG.error("Port Link Down: {}".format(port_info.key))

                VCenter.update_port_desc(port, port_info)

        return ports_by_mac


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

    while True:
        ports = util.get_new_ports(True)
        print(ports)

    monitor = VCenterMonitor(CONF.ML2_VMWARE)
    monitor.start()

    signal.signal(signal.SIGTERM, monitor.stop)
    signal.signal(signal.SIGINT, monitor.stop)

    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, monitor.stop)



if __name__ == "__main__":
    main()

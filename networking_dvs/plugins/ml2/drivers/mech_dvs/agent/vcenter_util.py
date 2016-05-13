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

from neutron.i18n import _LI, _LW, _

from oslo_log import log
from oslo_vmware import vim_util, api as vmwareapi
from oslo_vmware import exceptions as vmware_exceptions

from networking_dvs.common import config as dvs_config, constants as dvs_const
from networking_dvs.utils import dvs_util

CONF = dvs_config.CONF
LOG = log.getLogger(__name__)


class _DVSPortDesc(object):
    def __init__(self, dvs=None, port_key=None, port_group_key=None,
                 mac_address=None, connection_cookie=None, connected=None, status=None,
                 config_version=None, vlan_id=None, link_up=None):
        self.dvs = dvs
        self.port_key = port_key
        self.port_group_key = port_group_key
        self.mac_address = mac_address
        self.connection_cookie = connection_cookie
        self.connected = connected
        self.status = status
        self.config_version = config_version
        self.vlan_id = vlan_id
        self.link_up = link_up

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


class VCenter(object):
    def __init__(self, config=None):
        config = config or CONF.ML2_VMWARE

        self.connection = None
        self._create_session(config)

        # Map of the VMs and their NICs by the hardware key
        # e.g vmobrefs -> keys -> _DVSPortDesc
        self._hardware_map = defaultdict(dict)
        self.uuid_port_map = {}

        self._uuid_dvs_map = {}
        for dvs in six.itervalues(dvs_util.create_network_map_from_config(config, self.connection)):
            self._uuid_dvs_map[dvs.uuid] = dvs

        self._version = None
        self._property_collector = None

    @staticmethod
    def update_port_desc(port, port_info):
        # TODO validate connectionCookie, so we still have the same instance behind that portKey
        port_desc = port['port_desc']
        port_desc.config_version = port_info.config.configVersion
        if hasattr(port_info.config, "setting") \
                and hasattr(port_info.config.setting, "vlan") \
                and port_info.config.setting.vlan.vlanId:
            port_desc.vlan_id = port_info.config.setting.vlan.vlanId

        if hasattr(port_info, "state") \
                and hasattr(port_info.state, "runtimeInfo") \
                and hasattr(port_info.state.runtimeInfo, "linkUp"):
            port_desc.link_up = port_info.state.runtimeInfo.linkUp

    @staticmethod
    def ports_by_switch_and_key(ports):
        ports_by_switch_and_key = defaultdict(dict)
        for port in ports:
            port_desc = port['port_desc']
            ports_by_switch_and_key[port_desc.dvs][port_desc.port_key] = port

        return ports_by_switch_and_key

    @dvs_util.wrap_retry
    def bind_ports(self, ports):
        ports_up = []
        ports_down = []

        ports_by_switch_and_key = VCenter.ports_by_switch_and_key(ports)

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

    @dvs_util.wrap_retry
    def get_new_ports(self):
        vim = self.connection.vim
        builder = SpecBuilder(vim.client.factory)
        wait_options = builder.wait_options(1, 200)

        ports_by_mac = {}

        finished = False
        while not finished:
            result = self.connection.invoke_api(vim, 'WaitForUpdatesEx', self._get_property_collector(),
                                                version=self._version, options=wait_options)
            if result:
                if result.filterSet and result.filterSet[0].objectSet:
                    for update in result.filterSet[0].objectSet:
                        if update.obj._type == 'VirtualMachine':
                            self._handle_virtual_machine(ports_by_mac, update)
                self._version = result.version
            finished = not result or not hasattr(result, 'truncated') or not result.truncated

        ports_by_switch_and_key = VCenter.ports_by_switch_and_key(six.itervalues(ports_by_mac))

        for dvs, ports_by_key in six.iteritems(ports_by_switch_and_key):
            port_info = dvs.get_port_info_by_portkey(list(six.iterkeys(ports_by_key)))  # View is not sufficient
            for pi in port_info:
                port = ports_by_key[pi.key]
                port_desc = port['port_desc']
                if hasattr(port_desc, 'connectionCookie') and pi.connectionCookie != port_desc.connection_cookie:
                    LOG.warning("Different connection cookie then expected: Got {}, Expected {}".
                                format(pi.connectionCookie, port_desc.connection_cookie))

                VCenter.update_port_desc(port, pi)

        return ports_by_mac

    def _handle_removal(self, vm):
        vm_hw = self._hardware_map.pop(vm, {})
        for port in six.itervalues(vm_hw):
            self.uuid_port_map.pop(port.get('port_id', None), None)

    def _handle_virtual_machine(self, ports_by_mac, update):
        vm = update.obj.value  # vmobref (vm-#)
        change_set = update.changeSet if hasattr(update, 'changeSet') else []

        if update.kind != 'leave':
            vm_hw = self._hardware_map[vm]

        for change in change_set:
            change_name = change.name
            if change_name == "config.hardware.device":
                if "assign" == change.op:
                    for v in change.val[0]:
                        if hasattr(v, 'macAddress'):
                            port = v.backing.port
                            mac_address = v.macAddress
                            connectable = v.connectable if hasattr(v, "connectable") else None
                            dvs = self.get_dvs_by_uuid(port.switchUuid)

                            port_desc = _DVSPortDesc(
                                    mac_address=mac_address,
                                    connected=connectable.connected if connectable else None,
                                    status=str(connectable.status) if connectable else None,
                                    port_key=port.portKey,
                                    port_group_key=port.portgroupKey,
                                    dvs=dvs,
                                    connection_cookie=port.connectionCookie)

                            port = {
                                'port_desc': port_desc,
                                'port': {
                                    'binding:vif_details': {
                                        'dvs_port_key': port_desc.port_key,
                                        'dvs_uuid': port_desc.dvs.uuid
                                    }, 'mac_address': port_desc.mac_address}}

                            vm_hw[int(v.key)] = port
                            self._add_port_by_mac(ports_by_mac, port)
                elif "indirectRemove" == change.op:
                    self._handle_removal(vm)
            elif change_name.startswith("config.hardware.device["):
                id_end = change_name.index("]")
                device_key = int(change_name[23:id_end])
                port = vm_hw.get(device_key, None)
                if port:
                    port_desc = port['port_desc']
                    attribute = change_name[id_end + 2:]
                    if "connectable.connected" == attribute:
                        port_desc.connected = change.val
                    elif "connectable.status" == attribute:
                        port_desc.status = change.val
                    self._add_port_by_mac(ports_by_mac, port)
            else:
                print(change)

        if update.kind == 'leave':
            self._handle_removal(vm)
        else:
            pass

    def _add_port_by_mac(self, ports_by_mac, port):
        port_desc = port['port_desc']
        if port_desc.is_connected():
            ports_by_mac[port_desc.mac_address] = port

    def _create_session(self, config):
        """Create Vcenter Session for API Calling."""
        kwargs = {'create_session': True}
        if config.wsdl_location:
            kwargs['wsdl_loc'] = config.wsdl_location
        self.connection = vmwareapi.VMwareAPISession(
            config.vsphere_hostname,
            config.vsphere_login,
            config.vsphere_password,
            config.api_retry_count,
            config.task_poll_interval,
            **kwargs)

        atexit.register(self.connection.logout)

    def _get_property_collector(self):
        if self._property_collector:
            return self._property_collector

        vim = self.connection.vim
        service_instance = vim.service_content
        client_factory = vim.client.factory

        container_view = self.connection.invoke_api(vim, 'CreateContainerView', service_instance.viewManager,
                                                    container=service_instance.rootFolder,
                                                    type=['VirtualMachine'],
                                                    recursive=True)

        traversal_spec = vim_util.build_traversal_spec(client_factory, 'traverseEntities', 'ContainerView', 'view',
                                                       False, None)
        object_spec = vim_util.build_object_spec(client_factory, container_view, [traversal_spec])

        # Only static types work, so we have to get all hardware
        vm_properties = ['config.hardware.device']
        property_specs = [vim_util.build_property_spec(client_factory, 'VirtualMachine', vm_properties)]

        property_filter_spec = vim_util.build_property_filter_spec(client_factory, property_specs, [object_spec])

        self._property_collector = self.connection.invoke_api(vim, 'CreatePropertyCollector',
                                                              service_instance.propertyCollector)

        self.connection.invoke_api(vim, 'CreateFilter', self._property_collector,
                                   spec=property_filter_spec, partialUpdates=True)  # result -> PropertyFilter

        return self._property_collector


# Small test routine
def main():
    import sys
    from neutron.common import config as common_config
    from oslo_utils import timeutils
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    # Start everything.
    LOG.info(_LI("Test running... "))

    util = VCenter()

    with timeutils.StopWatch() as w:
        ports = util.get_new_ports()
    print(ports)
    print(w.elapsed())


if __name__ == "__main__":
    main()

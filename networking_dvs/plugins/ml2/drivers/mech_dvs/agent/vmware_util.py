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

from networking_dvs.common import config as dvs_config
from networking_dvs.utils import dvs_util

CONF = dvs_config.CONF
LOG = log.getLogger(__name__)


class SpecBuilder(dvs_util.SpecBuilder):
    def neutron_to_port_config_spec(self, port_info):
        setting = self.port_setting(vlan=self.vlan(port_info["segmentation_id"]),
                                    blocked=self.blocked(not port_info["admin_state_up"]),
                                    filter_policy=self.filter_policy(None)
                                    )

        return self.port_config_spec(key=port_info["port"]["binding:vif_details"]["dvs_port_key"],
                                     setting=setting,
                                     name=port_info["port_id"],
                                     description="Neutron port {} for network {}".format(port_info["port_id"],
                                                                                         port_info["network_id"]))

    def wait_options(self, max_wait_seconds=None, max_object_updates=None):
        wait_options = self.factory.create('ns0:WaitOptions')

        if max_wait_seconds:
            wait_options.maxWaitSeconds = max_wait_seconds

        if max_object_updates:
            wait_options.maxObjectUpdates = max_object_updates

        return wait_options


class VMWareUtil():
    def __init__(self, config=None):
        config = config or CONF.ML2_VMWARE

        self.connection = None
        self._create_session(config)

        self.networking_map = dvs_util.create_network_map_from_config(config, self.connection)
        self._uuid_map = {}
        for dvs in six.itervalues(self.networking_map):
            self._uuid_map[dvs.uuid] = dvs

        self._version = None
        self._property_collector = None

    @dvs_util.wrap_retry
    def bind_ports(self, port_info):
        specs_by_switch = defaultdict(list)
        ports_up = []
        ports_down = []

        port_for_key = {}

        builder = SpecBuilder(self.connection.vim.client.factory)

        for pi in port_info:
            vif_details = pi["port"]["binding:vif_details"]
            switch_uuid = vif_details["dvs_uuid"]
            specs = specs_by_switch[switch_uuid]

            port_key = vif_details["dvs_port_key"]

            if (switch_uuid, port_key) in port_for_key:
                LOG.error("Duplicate port key {} matching port {} and {}".format(port_key, pi["port_id"],
                                                                                 port_for_key[(switch_uuid, port_key)]["port_id"]))

            port_for_key[(switch_uuid, port_key)] = pi
            if pi["network_type"] == "vlan":
                specs.append(builder.neutron_to_port_config_spec(pi))
            else:
                ports_down.append(pi)
                LOG.warning(_LW("Cannot configure port %s it is not of type vlan"), pi["port_id"])

        for switch_uuid, specs in six.iteritems(specs_by_switch):
            dvs = self.get_dvs_by_uuid(switch_uuid)
            result = dvs.update_ports(specs)

            if result.state == "success":
                port_keys = [str(spec.key) for spec in specs]
                dv_ports = dvs.get_port_info_by_portkey(port_keys)

                # Filter
                port_keys_down = set([str(p.key) for p in dv_ports
                                      if not hasattr(p, "state")
                                      or not hasattr(p.state, 'runtimeInfo')
                                      or not p.state.runtimeInfo.linkUp
                                      or not hasattr(p.state.runtimeInfo, 'vlanIds')
                                      or not p.state.runtimeInfo.vlanIds])
                port_keys_up = set(port_keys) - port_keys_down

                for spec in specs:
                    port_key = spec.key
                    if port_key in port_keys_up:
                        pi = port_for_key[(switch_uuid, port_key)]
                        ports_up.append(pi)
                        specs.remove(spec)

            for spec in specs:
                ports_down.append(port_for_key[(switch_uuid, spec.key)])

        return ports_up, ports_down

    def get_dvs_by_uuid(self, uuid):
        return self._uuid_map[uuid]

    def get_new_ports(self, _=True):
        vim = self.connection.vim
        builder = SpecBuilder(self.connection.vim.client.factory)
        wait_options = builder.wait_options(1, 50)

        results = {}

        finished = False
        while not finished:
            result = self.connection.invoke_api(vim, 'WaitForUpdatesEx', self._get_property_collector(),
                                                version=self._version, options=wait_options)
            if result:
                if result.filterSet and result.filterSet[0].objectSet:
                    for update in result.filterSet[0].objectSet:
                        if update.kind in ['enter', 'modify'] and update.obj._type == 'VirtualMachine':
                            for change in update.changeSet:
                                if "assign" == change.op and "config.hardware.device" == change.name:
                                    for v in change.val[0]:
                                        if hasattr(v, 'macAddress'):
                                            mac_address = v.macAddress
                                            port = v.backing.port

                                            results[mac_address] = {
                                                'current_state_up': v.connectable.connected if hasattr(v,
                                                                                                       "connectable") else None,
                                                'port': {
                                                    'binding:vif_details': {
                                                        'dvs_port_key': port.portKey,
                                                        'dvs_port_group_key': port.portgroupKey,
                                                        'dvs_uuid': port.switchUuid,
                                                        'dvs_connection_cookie': port.connectionCookie
                                                    }, 'mac_address': mac_address}}
                self._version = result.version
            finished = not result or not hasattr(result, 'truncated') or not result.truncated

        ports_by_switch_and_key = defaultdict(dict)
        for port in six.itervalues(results):
            vif = port['port']['binding:vif_details']
            ports_by_switch_and_key[vif['dvs_uuid']][vif['dvs_port_key']] = port

        for switch_uuid, ports_by_key in six.iteritems(ports_by_switch_and_key):
            dvs = self.get_dvs_by_uuid(switch_uuid)

            port_keys = list(six.iterkeys(ports_by_key))  # View is not sufficient
            dv_ports = dvs.get_port_info_by_portkey(port_keys)
            for p in dv_ports:
                if hasattr(p, "config") \
                        and hasattr(p.config, "setting") \
                        and hasattr(p.config.setting, "vlan") \
                        and p.config.setting.vlan.vlanId:
                    segmentation_id = p.config.setting.vlan.vlanId
                    port = ports_by_key[p.key]
                    port['current_segmentation_id'] = segmentation_id
                    if hasattr(p, "state") \
                            and hasattr(p.state, "runtimeInfo") \
                            and hasattr(p.state.runtimeInfo, "linkUp"):
                        port['current_state_up'] = p.state.runtimeInfo.linkUp

        return results

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

    util = VMWareUtil()

    with timeutils.StopWatch() as w:
        ports = util.get_new_ports()
    print(ports)
    print(w.elapsed())


if __name__ == "__main__":
    main()

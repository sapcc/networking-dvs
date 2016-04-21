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

from neutron.i18n import _LI, _

from oslo_log import log
from oslo_vmware import exceptions, vim_util, api as vmwareapi

from networking_dvs.common import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class ResourceNotFoundException(exceptions.VimException):
    """Thrown when a resource can not be found."""
    pass


def _get_object_by_type(results, type_value):
    """Get object by type.

    Get the desired object from the given objects
    result by the given type.
    """
    return [obj for obj in results
            if obj._type == type_value]


class VMWareUtil():
    def __init__(self, config=None):
        config = config or CONF.ML2_VMWARE
        self._session = None
        self._create_session(config)
        self._version = None
        self._property_collector = None

        self._dvs_name = config.dv_switch
        self._default_vlan = config.dv_default_vlan

        self._dvs_ref = self._get_dvs(self._dvs_name)
        self._dvs_uuid = self._session.invoke_api(vim_util, 'get_object_property', self._session.vim, self._dvs_ref, 'uuid')

        LOG.info(_LI("Using switch {} ({})".format(self._dvs_name, self._dvs_uuid)))

    def bind_ports(self, port_info):
        specs = []
        devices_up = []
        devices_down = []
        for port_info in port_info:
            if port_info["network_type"] == "vlan":
                specs.append(self._get_vlan_port_config_spec(port_info))
                devices_up.append(port_info["port_id"])
            else:
                devices_down.append(port_info["port_id"])
                LOG.info("Cannot configure port %s it is not of type vlan", port_info["port_id"])

        if specs:
            task = self._session.invoke_api(self._session.vim,
                                     "ReconfigureDVPort_Task",
                                            self._dvs_ref, port=specs)
            result = self._session.wait_for_task(task)
            if result.state == "success":
                return devices_up, devices_down

        return [], devices_down # Either we do not have any specs (for various reasons) or the task did not succeed.

    def get_new_ports(self, _=True):
        vim = self._session.vim
        client_factory = vim.client.factory
        wait_options = VMWareUtil._build_wait_options(client_factory, 1, 50)

        results = {}

        finished = False
        while not finished:
            result = self._session.invoke_api(vim, 'WaitForUpdatesEx', self._get_property_collector(), version=self._version, options=wait_options)
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
                                            results[mac_address] = {'port': {
                                                'binding:vif_details': {
                                                    'dvs_port_key': port.portKey,
                                                    'dvs_port_group_key': port.portgroupKey,
                                                    'dvs_uuid': port.switchUuid
                                                }, 'mac_address': mac_address}}
                self._version = result.version
            finished = not result or not hasattr(result, 'truncated') or not result.truncated

        reordered = defaultdict(dict)
        for port in six.itervalues(results):
            vif = port['port']['binding:vif_details']
            reordered[vif['dvs_uuid']][vif['dvs_port_key']] = port

        for switch_uuid, port_map in six.iteritems(reordered):
            if switch_uuid == self._dvs_uuid:
                port_keys = port_map.keys() # View doesn't work
                criteria = VMWareUtil._build_distributed_virtual_switch_port_criteria(client_factory, None, port_keys)
                dv_ports = self._session.invoke_api(self._session.vim, "FetchDVPorts",
                                                    self._dvs_ref, criteria=criteria)
                for p in dv_ports:
                    if hasattr(p, "config") \
                            and hasattr(p.config, "setting") \
                            and hasattr(p.config.setting, "vlan") \
                            and p.config.setting.vlan.vlanId:
                        segmentation_id = p.config.setting.vlan.vlanId
                        port = port_map[p.key]
                        port['current_segmentation_id'] = segmentation_id

        return results

    def _create_session(self, config):
        """Create Vcenter Session for API Calling."""
        kwargs = {'create_session': True}
        if config.wsdl_location:
            kwargs['wsdl_loc'] = config.wsdl_location
        self._session = vmwareapi.VMwareAPISession(
            config.vsphere_hostname,
            config.vsphere_login,
            config.vsphere_password,
            config.api_retry_count,
            config.task_poll_interval,
            **kwargs)

        atexit.register(self._session.logout)

    @staticmethod
    def _build_distributed_virtual_switch_port_criteria(client_factory, portgroup_keys=None, port_keys=None,
                                                        active=None, connected=None, inside=None, uplink_port=None):
        criteria = client_factory.create('ns0:DistributedVirtualSwitchPortCriteria')
        criteria.portgroupKey = portgroup_keys
        criteria.portKey = port_keys
        criteria.active = active
        criteria.connected = connected
        criteria.inside = inside
        criteria.uplinkPort = uplink_port

        return criteria

    @staticmethod
    def _build_port_config_spec(client_factory, port_key, name=None, description=None, setting=None, operation=None):
        config_spec = client_factory.create('ns0:DVPortConfigSpec')
        config_spec.key = port_key
        config_spec.name = name
        config_spec.description = description
        config_spec.setting = setting
        config_spec.operation = operation or "edit"

        return config_spec

    @staticmethod
    def _build_wait_options(client_factory, max_wait_seconds=None, max_object_updates=None):
        wait_options = client_factory.create('ns0:WaitOptions')
        wait_options.maxWaitSeconds = max_wait_seconds
        wait_options.maxObjectUpdates = max_object_updates
        return wait_options

    def _get_empty_port_config_spec(self, port):
        return VMWareUtil._build_port_config_spec(self._session.vim.client.factory, port.key, "", "")

    def _get_vlan_port_config_spec(self, port_info):
        client_factory = self._session.vim.client.factory

        vlan_setting = client_factory.create('ns0:VmwareDistributedVirtualSwitchVlanIdSpec')
        vlan_setting.vlanId = port_info["segmentation_id"]
        vlan_setting.inherited = False
        setting = client_factory.create('ns0:VMwareDVSPortSetting')
        setting.vlan = vlan_setting

        return VMWareUtil._build_port_config_spec(client_factory,
                                                  port_info["port"]["binding:vif_details"]["dvs_port_key"],
                                                  port_info["port_id"],
                                                  "Neutron port {} for network {}".format(port_info["port_id"],
                                                                                          port_info["network_id"]),
                                                  setting
                                                  )

    def _get_datacenter(self):
        """Get the datacenter reference."""
        results = self._session.invoke_api(
            vim_util, 'get_objects', self._session.vim,
            "Datacenter", 100, ["name"])
        return results.objects[0].obj

    def _get_network_folder(self):
        """Get the network folder from datacenter."""
        dc_ref = self._get_datacenter()
        results = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            dc_ref, "networkFolder")
        return results

    def _get_dvs(self, dvs_name):
        """Get the dvs by name"""
        net_folder = self._get_network_folder()
        results = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            net_folder, "childEntity")
        networks = results.ManagedObjectReference
        dvswitches = _get_object_by_type(networks,
                                         "VmwareDistributedVirtualSwitch")
        dvs_ref = None
        for dvs in dvswitches:
            name = self._session.invoke_api(
                vim_util, 'get_object_property',
                self._session.vim, dvs,
                "name")
            if name == dvs_name:
                dvs_ref = dvs
                break

        if not dvs_ref:
            raise ResourceNotFoundException(_("Distributed Virtual Switch "
                                              "%s not found!") % dvs_name)
        else:
            LOG.info(_LI("Got distributed virtual switch by name %s."),
                     dvs_name)

        return dvs_ref

    def _get_property_collector(self):
        if self._property_collector:
            return self._property_collector

        vim = self._session.vim
        service_instance = vim.service_content
        client_factory = vim.client.factory

        container_view = self._session.invoke_api(vim, 'CreateContainerView', service_instance.viewManager,
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

        self._property_collector = self._session.invoke_api(vim, 'CreatePropertyCollector',
                                                            service_instance.propertyCollector)

        self._session.invoke_api(vim, 'CreateFilter', self._property_collector,
                                          spec=property_filter_spec, partialUpdates=True) # result -> PropertyFilter

        return self._property_collector

#  Small test routine
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

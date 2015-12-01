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

import re
import time

from oslo_vmware import api as vmwareapi
from oslo_vmware import exceptions
from oslo_vmware import vim_util

from neutron.i18n import _LI, _LW
from oslo_log import log
from networking_dvs.plugins.ml2.drivers.mech_dvs import config

LOG = log.getLogger(__name__)
CONF = config.CONF


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
    def __init__(self):
        self._session = None
        self._create_session()

        self.dvs_name = CONF.ml2_vmware.dv_switch
        self.portgroup_name = CONF.ml2_vmware.dv_portgroup
        self.default_vlan = CONF.ml2_vmware.dv_default_vlan

        self.dvs_ref = self.get_dvs(self.dvs_name)
        self.dvpg = self.get_dvpg_by_name(self.portgroup_name)
        self.dvpg_key = self.dvpg.value

    def _create_session(self):
        """Create Vcenter Session for API Calling."""
        host_ip = CONF.ml2_vmware.host_ip
        host_username = CONF.ml2_vmware.host_username
        host_password = CONF.ml2_vmware.host_password
        wsdl_location = CONF.ml2_vmware.wsdl_location
        task_poll_interval = CONF.ml2_vmware.task_poll_interval
        api_retry_count = CONF.ml2_vmware.api_retry_count

        self._session = vmwareapi.VMwareAPISession(
            host_ip,
            host_username,
            host_password,
            api_retry_count,
            task_poll_interval,
            create_session=True,
            wsdl_loc=wsdl_location)


    def get_datacenter(self):
        """Get the datacenter reference."""
        results = self._session.invoke_api(
            vim_util, 'get_objects', self._session.vim,
            "Datacenter", 100, ["name"])
        return results.objects[0].obj

    def get_network_folder(self):
        """Get the network folder from datacenter."""
        dc_ref = self.get_datacenter()
        results = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            dc_ref, "networkFolder")
        return results

    def get_dvs(self, dvs_name):
        """Get the dvs by name"""
        net_folder = self.get_network_folder()
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
            LOG.info(_LI("Got distriubted virtual switch by name %s."),
                     dvs_name)

        return dvs_ref

    def get_dvpg_by_name(self, dvpg_name):
        """Get the dvpg ref by name"""
        dc_ref = self.get_datacenter()
        net_list = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            dc_ref, "network").ManagedObjectReference
        type_value = "DistributedVirtualPortgroup"
        dvpg_list = _get_object_by_type(net_list, type_value)
        dvpg_ref = None
        for pg in dvpg_list:
            name = self._session.invoke_api(
                vim_util, 'get_object_property',
                self._session.vim, pg,
                "name")
            if dvpg_name == name:
                dvpg_ref = pg
                break

        if not dvpg_ref:
            LOG.warning(_LW("Distributed Port Group %s not found!"),
                        dvpg_name)
        else:
            LOG.info(_LI("Got distriubted port group by name %s."),
                     dvpg_name)

        return dvpg_ref

    def bind_port(self, port_info):
        specs = []

        if port_info["neutron_info"]["network_type"] == "vlan" :
            specs.append(self.get_vlan_port_config_spec(port_info))
        else:
            LOG.info("Cannot configure port %s it is not of type vlan",port_info["neutron_info"]["port_id"])

        if specs:
            self._session.invoke_api(self._session.vim,
                                                     "ReconfigureDVPort_Task",
                                                     self.dvs_ref, port=specs)

    def get_empty_port_config_spec(self, port):
        client_factory = self._session.vim.client.factory
        config_spec = client_factory.create('ns0:DVPortConfigSpec')
        config_spec.key = port.key
        config_spec.name = ""
        config_spec.description = ""
        config_spec.operation = "edit"

        return config_spec

    def get_vlan_port_config_spec(self, port_info):
        client_factory = self._session.vim.client.factory
        config_spec = client_factory.create('ns0:DVPortConfigSpec')
        config_spec.key = port_info["vmware_port"]
        config_spec.name = port_info["neutron_info"]["port_id"]
        config_spec.description = "Neutron port {} for network {}".format(port_info["neutron_info"]["port_id"],port_info["neutron_info"]["network_id"])
        config_spec.operation = "edit"
        setting = client_factory.create('ns0:VMwareDVSPortSetting')
        vlan_setting = client_factory.create('ns0:VmwareDistributedVirtualSwitchVlanIdSpec')
        vlan_setting.vlanId = port_info["neutron_info"]["segmentation_id"]
        vlan_setting.inherited = False
        setting.vlan = vlan_setting
        config_spec.setting = setting

        return config_spec

    def get_connected_ports_on_dvpg(self,default_vlan_only = True):

        client_factory = self._session.vim.client.factory
        criteria = client_factory.create('ns0:DistributedVirtualSwitchPortCriteria')
        criteria.portgroupKey = self.dvpg_key
        criteria.inside = True

        start = time.time()
        ports = self._session.invoke_api(self._session.vim,
                                              "FetchDVPorts",
                                              self.dvs_ref, criteria=criteria)

        LOG.info("Fetch ports in {}".format(time.time()-start))

        port_info = {}
        reset_port_info_specs = []
        for p in ports:

            mac = None
            if hasattr(p,"config") and hasattr(p.config,"setting") and hasattr(p.config.setting,"vlan") and p.config.setting.vlan.vlanId:
                connected_vlan = p.config.setting.vlan.vlanId

                if connected_vlan == self.default_vlan:
                    if hasattr( p.config, "name") and p.config.name:
                        LOG.info("Adding reset port spec for {} {}".format(p.config.name,p.config.name==""))
                        reset_port_info_specs.append(self.get_empty_port_config_spec(p))

                if default_vlan_only and not connected_vlan == self.default_vlan:
                    # We do this to optimistically assume anything with a VLAN not the default has been bound already
                    # This saves a significant overhead (2-3 secs per port) to get the mac address from the VM
                    continue

            if hasattr(p,"state") and hasattr(p.state,"runtimeInfo") and hasattr(p.state.runtimeInfo, "macAddress") and p.state.runtimeInfo.macAddress and p.state.runtimeInfo.macAddress != "00:00:00:00:00:00":
                # If we have the MAC on the runtime state we don't need to go to the VM
                mac = p.state.runtimeInfo.macAddress

            elif hasattr(p,"connectee") and p.connectee is not None and p.connectee.connectedEntity._type == 'VirtualMachine':
                # So unfortunately we have an expensive call to get the VM to determine the MAC
                mac = self.get_vm_mac(p.connectee.connectedEntity.value,p.connectee.nicKey)

            if mac is not None:
                port_info[mac] = {"vmware_port":p.key,"connected_vlan":connected_vlan}


        if reset_port_info_specs:
            self._session.invoke_api(self._session.vim,
                                    "ReconfigureDVPort_Task",
                                     self.dvs_ref, port=reset_port_info_specs)

        return port_info





    def get_vm_mac(self,vm_name,nic_key):
        start = time.time()


        vm_props = self.get_vm_properties(vm_name,["name", "config.hardware"])

        LOG.info("get_vm_properties in {}".format(time.time()-start))

        mac = None
        if vm_props:
            for prop in vm_props:
                if prop.name == 'config.hardware':
                    for device in prop.val.device:
                        if str(device.key) == nic_key:
                            mac = device.macAddress

        LOG.info("Get VM mac in {}".format(time.time()-start))

        return mac

    def get_vm_ref(self, vm_key):
       vms = self._session.invoke_api(vim_util, "get_objects",self._session.vim,
            "VirtualMachine", 50,["name"])
       return self._get_object_from_results(vms, vm_key,self._get_ref_for_value)

       return vm

    def get_vm_properties(self, vm_key,properties):
       vms = self._session.invoke_api(vim_util, "get_objects",self._session.vim,
             "VirtualMachine", 50,properties)
       return self._get_object_from_results(vms, vm_key,self._get_propset_for_value)

    def _get_object_from_results(self, results, value, func):
        while results:
            object = func(results, value)
            if object:
               self._session.invoke_api(vim_util, 'cancel_retrieval',self._session.vim,results)

               return object
            results = self._session.invoke_api(vim_util, 'continue_retrieval',self._session.vim,results)

    def _get_ref_for_value(self,results, value):
        for object in results.objects:
            if object.obj.value == value:
                return object.obj

    def _get_propset_for_value(self,results, value):
        for object in results.objects:
            if object.obj.value == value:
                return object.propSet
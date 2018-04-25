# Copyright 2016 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from pyVmomi import vim, vmodl


def pg_config(default_port_config):
    spec = vim.DVPortgroupConfigSpec()
    spec.defaultPortConfig = default_port_config
    policy = vim.VMwareDVSPortgroupPolicy()
    policy.blockOverrideAllowed = True
    policy.livePortMovingAllowed = True
    policy.portConfigResetAtDisconnect = True
    policy.shapingOverrideAllowed = True
    policy.trafficFilterOverrideAllowed = True
    policy.vendorConfigOverrideAllowed = True
    policy.vlanOverrideAllowed = True
    policy.uplinkTeamingOverrideAllowed = True
    policy.securityPolicyOverrideAllowed = True
    policy.networkResourcePoolOverrideAllowed = True
    policy.ipfixOverrideAllowed = True
    spec.policy = policy
    return spec


def port_config_spec(key=None, version=None, setting=None, name=None, description=None):
    spec = vim.DVPortConfigSpec(operation='edit')

    if key:
        spec.key = key

    if version:
        spec.configVersion = version

    if setting:
        spec.setting = setting

    if name is not None:
        spec.name = name

    if description is not None:
        spec.description = description

    return spec


def port_lookup_criteria():
    return vim.DistributedVirtualSwitchPortCriteria()


def filter_policy(rules, filter_config_key=None):
    filter_policy = vim.DvsFilterPolicy()
    if rules:
        traffic_ruleset = vim.DvsTrafficRuleset()
        traffic_ruleset.enabled = True
        traffic_ruleset.rules = rules
        filter_config = vim.DvsTrafficFilterConfig()
        filter_config.agentName = "dvfilter-generic-vmware"
        filter_config.inherited = False
        filter_config.trafficRuleset = traffic_ruleset
        if filter_config_key:
            filter_config.key = filter_config_key
        filter_policy.filterConfig = [filter_config]
        filter_policy.inherited = False
    else:
        filter_policy.inherited = True
    return filter_policy


def port_criteria(port_key=None, port_group_key=None,
                  connected=None, active=None):
    criteria = vim.DistributedVirtualSwitchPortCriteria()
    if port_key:
        criteria.portKey = port_key
    if port_group_key:
        criteria.portgroupKey = port_group_key
        criteria.inside = '1'
    if connected:
        criteria.connected = connected
    if active:
        criteria.active = active
    return criteria


def vlan(vlan_tag):
    spec = vim.VmwareDistributedVirtualSwitchVlanIdSpec()
    spec.inherited = False
    spec.vlanId = vlan_tag
    return spec


def blocked(value):
    """Value should be True or False"""
    spec = vim.BoolPolicy()
    if value:
        spec.inherited = False
        spec.value = True
    else:
        spec.inherited = False
        spec.value = False
    return spec


def neutron_to_port_config_spec(port):
    port_desc = port['port_desc']
    setting = vim.VMwareDVSPortSetting()
    segmentation_id = port.get('segmentation_id')
    if segmentation_id:
        setting.vlan = vlan(segmentation_id)
    else:
        setting.vlan = vlan(0)
    setting.blocked = blocked(not port.get('admin_state_up', True))
    setting.filterPolicy = filter_policy(None)

    return port_config_spec(version=port_desc.config_version,
                            key=port_desc.port_key,
                            setting=setting,
                            name=port['port_id'],
                            description=port['network_id'])


def wait_options(max_wait_seconds=None, max_object_updates=None):
    wait_options = vmodl.query.PropertyCollector.WaitOptions()

    if max_wait_seconds:
        wait_options.maxWaitSeconds = max_wait_seconds

    if max_object_updates:
        wait_options.maxObjectUpdates = max_object_updates

    return wait_options


def virtual_device_connect_info(allow_guest_control, connected, start_connected):
    virtual_device_connect_info = vim.vm.device.VirtualDevice.ConnectInfo()

    virtual_device_connect_info.allowGuestControl = allow_guest_control
    virtual_device_connect_info.connected = connected
    virtual_device_connect_info.startConnected = start_connected

    return virtual_device_connect_info


def distributed_virtual_switch_port_connection(switch_uuid, port_key=None, portgroup_key=None):
    # connectionCookie is left out intentionally, it cannot be set
    distributed_virtual_switch_port_connection = vim.dvs.PortConnection()
    distributed_virtual_switch_port_connection.switchUuid = switch_uuid

    if port_key:
        distributed_virtual_switch_port_connection.portKey = port_key
    if portgroup_key:
        distributed_virtual_switch_port_connection.portgroupKey = portgroup_key

    return distributed_virtual_switch_port_connection


def virtual_device_config_spec(device, file_operation=None, operation=None, profile=None):
    virtual_device_config_spec = vim.vm.device.VirtualDeviceSpec()
    virtual_device_config_spec.device = device

    if file_operation:
        virtual_device_config_spec.fileOperation = file_operation
    if operation:
        virtual_device_config_spec.operation = operation
    if profile:
        virtual_device_config_spec.profile = profile

    return virtual_device_config_spec


def virtual_machine_config_spec(device_change=None, change_version=None):
    virtual_machine_config_spec = vim.vm.ConfigSpec()

    if device_change:
        virtual_machine_config_spec.deviceChange = device_change
    if change_version:
        virtual_machine_config_spec.changeVersion = change_version

    return virtual_machine_config_spec

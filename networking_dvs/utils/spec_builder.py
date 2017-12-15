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


class SpecBuilder(object):
    """Builds specs for vSphere API calls"""

    def __init__(self, spec_factory):
        self.factory = spec_factory

    def pg_config(self, default_port_config):
        spec = self.factory.create('ns0:DVPortgroupConfigSpec')
        spec.defaultPortConfig = default_port_config
        policy = self.factory.create('ns0:VMwareDVSPortgroupPolicy')
        policy.blockOverrideAllowed = '1'
        policy.livePortMovingAllowed = '1'
        policy.portConfigResetAtDisconnect = '1'
        policy.shapingOverrideAllowed = '1'
        policy.trafficFilterOverrideAllowed = '1'
        policy.vendorConfigOverrideAllowed = '1'
        policy.vlanOverrideAllowed = '1'
        policy.uplinkTeamingOverrideAllowed = '1'
        policy.securityPolicyOverrideAllowed = '1'
        policy.networkResourcePoolOverrideAllowed = '1'
        policy.ipfixOverrideAllowed = '1'
        spec.policy = policy
        return spec

    def dv_switch_config(self):
        spec = self.factory.create('ns0:VMwareDVSConfigSpec')
        return spec

    def port_config_spec(self, key=None, version=None, setting=None, name=None, description=None):
        spec = self.factory.create('ns0:DVPortConfigSpec')
        spec.operation = 'edit'

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

    def port_lookup_criteria(self):
        return self.factory.create('ns0:DistributedVirtualSwitchPortCriteria')

    def port_setting(self):
        return self.factory.create('ns0:VMwareDVSPortSetting')

    def filter_policy(self, rules, filter_config_key=None):
        filter_policy = self.factory.create('ns0:DvsFilterPolicy')
        if rules:
            traffic_ruleset = self.factory.create('ns0:DvsTrafficRuleset')
            traffic_ruleset.enabled = True
            traffic_ruleset.rules = rules
            filter_config = self.factory.create('ns0:DvsTrafficFilterConfig')
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

    def port_criteria(self, port_key=None, port_group_key=None,
                      connected=None, active=None):
        criteria = self.factory.create(
            'ns0:DistributedVirtualSwitchPortCriteria')
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

    def vlan(self, vlan_tag):
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
        spec = self.factory.create(spec_ns)
        spec.inherited = False
        spec.vlanId = vlan_tag
        return spec

    def blocked(self, value):
        """Value should be True or False"""
        spec = self.factory.create('ns0:BoolPolicy')
        if value:
            spec.inherited = False
            spec.value = True
        else:
            spec.inherited = False
            spec.value = False
        return spec

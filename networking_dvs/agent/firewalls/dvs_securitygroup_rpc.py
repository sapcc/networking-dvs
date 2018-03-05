# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
from oslo_log import log as logging

from neutron.agent import securitygroups_rpc
from neutron import manager
import neutron.context
from neutron.api.rpc.handlers.securitygroups_rpc import SecurityGroupServerRpcCallback
from neutron.i18n import _LI
from oslo_db.sqlalchemy import enginefacade

LOG = logging.getLogger(__name__)


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc):
    def __init__(self, *args, **kwargs):
        super(DVSSecurityGroupRpc, self).__init__(*args, **kwargs)
        self.context = neutron.context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self.callback = SecurityGroupServerRpcCallback()

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)

        devices = self.get_security_group_rules_for_devices(list(device_ids))
        self.firewall.prepare_port_filter(devices)

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Remove device filter for %r"), device_ids)
        self.firewall.remove_port_filter(device_ids)

    def refresh_firewall(self, device_ids=None):
        LOG.info(_LI("Refresh firewall rules for '{}'").format(device_ids))
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info(_LI("No ports here to refresh firewall"))
                return

        devices = self.get_security_group_rules_for_devices(list(device_ids))
        self.firewall.update_port_filter(devices)

    def get_security_group_rules_for_devices(self, device_ids):
        return self.get_security_group_rules_for_devices_db(device_ids)
        # return self.get_security_group_rules_for_devices_rpc(device_ids, chunk_size=1)

    @enginefacade.reader
    def get_security_group_rules_for_devices_db(self, device_ids):
        LOG.debug("Querying database for %s", device_ids)
        return self.callback.security_group_rules_for_devices(self.context, devices=device_ids).values()

    def get_security_group_rules_for_devices_rpc(self, device_ids, chunk_size=50):
        devices = []
        for i in range(0, len(device_ids), chunk_size):
            devices.extend(
                self.plugin_rpc.security_group_rules_for_devices(self.context, device_ids[i:i+chunk_size]).values()
            )
        return devices

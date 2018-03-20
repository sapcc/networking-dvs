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
import neutron.context
from copy import copy
from neutron.db.securitygroups_rpc_base import SecurityGroupServerRpcMixin
from neutron.i18n import _LI
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy.utils import get_table
from sqlalchemy.sql import select

LOG = logging.getLogger(__name__)


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc, SecurityGroupServerRpcMixin):
    def __init__(self, *args, **kwargs):
        super(DVSSecurityGroupRpc, self).__init__(*args, **kwargs)
        self.context = neutron.context.get_admin_context()
        if self.firewall:
            self.v_center = self.firewall.v_center
        else:
            self.v_center = None

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
    def get_ports_from_devices(self, devices):
        ports = {}

        if not devices:
            return ports

        session = self.context.session

        with session.begin(subtransactions=True):
            sgpb = get_table(session.get_bind(), 'securitygroupportbindings')
            for port_id, security_group_id in session.execute(
                    select([sgpb.c.port_id, sgpb.c.security_group_id],
                           sgpb.c.port_id.in_(devices))):
                port = ports.get(port_id)
                if not port:
                    port = copy(self.v_center.get_port_by_uuid(port_id))
                    port['security_group_source_groups'] = []
                    port['security_group_rules'] = []
                    port['security_groups'] = [security_group_id]
                    ports[port_id] = port
                else:
                    port['security_groups'].append(security_group_id)
        return ports

    @enginefacade.reader
    def get_security_group_rules_for_devices_db(self, device_ids):
        LOG.debug("Querying database for %s", device_ids)
        ports = self.get_ports_from_devices(device_ids)
        return self.security_group_rules_for_ports(self.context, ports).values()

    def get_security_group_rules_for_devices_rpc(self, device_ids, chunk_size=50):
        devices = []
        for i in range(0, len(device_ids), chunk_size):
            devices.extend(
                self.plugin_rpc.security_group_rules_for_devices(self.context, device_ids[i:i+chunk_size]).values()
            )
        return devices

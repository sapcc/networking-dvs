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

from oslo_log import log

from networking_dvs.api import dvs_agent_rpc_api
from networking_dvs.common import constants as dvs_constants
from neutron.agent import securitygroups_rpc
from neutron.plugins.ml2.drivers import mech_agent

try:
    from neutron._i18n import _
    from neutron_lib.api.definitions import portbindings
    from neutron_lib import constants as neutron_constants
    from neutron_lib import context
    from neutron_lib.plugins.ml2 import api
except ImportError:
    from neutron.i18n import _LI as _
    from neutron.extensions import portbindings
    from neutron.plugins.common import constants as neutron_constants
    from neutron import context
    from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class VMwareDVSMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using vmware agent.

    The VmwareMechanismDriver integrates the ml2 plugin with the
    vmware L2 agent. Port binding with this driver requires the vmware
    agent to be running on the port's host, and that agent to have
    connectivity to at least one segment of the port's network.
    """

    def __init__(self):
        LOG.info(_("VMware DVS mechanism driver initializing..."))
        self.agent_type = dvs_constants.AGENT_TYPE_DVS
        self.vif_type = dvs_constants.DVS
        self.version = 1

        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled}
        self.context = context.get_admin_context_without_session()
        self.dvs_notifier = dvs_agent_rpc_api.DVSClientAPI(self.context)
        super(VMwareDVSMechanismDriver, self).__init__(
            self.agent_type,
            self.vif_type,
            self.vif_details)

        LOG.info(_("VMware DVS mechanism driver initialized..."))

    def get_allowed_network_types(self, agent):
        return [neutron_constants.TYPE_VLAN, neutron_constants.TYPE_FLAT]

    def get_mappings(self, agent):
        config = agent['configurations']

        if 'network_maps_v2' in config:
            self.version = int(config.get('agent_version', 2))
            return config['network_maps_v2']
        else:
            self.version = int(config.get('agent_version', 1))
            return config.get('network_maps', {'default': 'dvSwitch0'})

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        port = context.current
        # We only do compute devices
        device_owner = port['device_owner']

        if not device_owner or not device_owner.startswith('compute'):
            return False

        if not agent.get('admin_state_up', False) \
                or not agent.get('alive', False) \
                or agent['agent_type'].lower() != \
                dvs_constants.AGENT_TYPE_DVS.lower():
            return False

        agent_host = agent.get('host', None)

        # If the agent is bound to a host, then it can only handle those
        if agent_host != port['binding:host_id']:
            return False

        mappings = self.get_mappings(agent)

        if not mappings:
            return False

        LOG.debug(_("Agent: {}, Segment: {}".format(agent, segment)))

        bridge_name = mappings.get(segment['physical_network'], None)

        if not bridge_name:
            return False

        vif_details = self.vif_details.copy()
        vif_details['bridge_name'] = bridge_name

        if self.version > 1:
            response = self.dvs_notifier.bind_port_call(
                port,
                [segment],
                context.network.current,
                context.host
            )
            if response:
                if 'vif_details' in response:
                    vif_details = response['vif_details']
                elif 'bridge_name' in response:
                    vif_details['bridge_name'] = response['bridge_name']

        context.set_binding(segment[api.ID], self.vif_type, vif_details)

        return True

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

from neutron.extensions import portbindings
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_constants

from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2 import driver_api as api
from oslo_log import log
from networking_dvs.plugins.ml2.drivers.mech_dvs import constants as dvs_constants

LOG = log.getLogger(__name__)



class VMwareDVSMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using vmware agent.

    The VmwareMechanismDriver integrates the ml2 plugin with the
    vmware L2 agent. Port binding with this driver requires the vmware
    agent to be running on the port's host, and that agent to have
    connectivity to at least one segment of the port's network.
    """



    def __init__(self):
        LOG.info(_LI("VMware DVS mechanism driver initializing..."))
        self.agent_type = dvs_constants.DVS_AGENT_TYPE
        self.vif_type = dvs_constants.VIF_TYPE_DVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}

        super(VMwareDVSMechanismDriver, self).__init__(
           self.agent_type,
           self.vif_type,
           self.vif_details)

        LOG.info(_LI("VMware DVS mechanism driver initialized..."))

    def get_allowed_network_types(self, agent):
        return ([p_constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('network_maps', {'default':'dvSwitch0'})



    def try_to_bind_segment_for_agent(self, context, segment, agent):
        LOG.info(_LI("try_to_bind_segment_for_agent"))
        LOG.info(context.current)

        compute_device = False

        device_owner = context.current['device_owner']

        if device_owner and device_owner.startswith('compute'):
            compute_device = True

        if compute_device and self.check_segment_for_agent(segment, agent):
            context.set_binding(segment[api.ID],
                                self.vif_type,
                                self.vif_details)
            return True
        else:
            return False


    def check_segment_for_agent(self, segment, agent):
         LOG.info(_LI("Checking segment for agent "+str(agent)+" "+str(agent['agent_type'])))
         return agent['agent_type'] == dvs_constants.DVS_AGENT_TYPE









    def create_network_precommit(self, context):
         LOG.info(_LI("create_network_precommit"))
         #self.vmware_util.create_dvpg(context)

    def delete_network_precommit(self, context):
         LOG.info(_LI("delete_network_precommit"))
         #self.vmware_util.delete_dvpg(context)
    #
    # def update_network_precommit(self, context):
    #     self.vmware_util.update_dvpg(context)
    #
    # def bind_port(self, context):
    #     LOG.info(_LI("********************** bind_port port %(port)s on "
    #                  "network %(network)s "+context.host
    #                  ),
    #              {'port': context.current['id'],
    #               'network': context.network.current['id']
    #               })
    #     return
    #
    #
    #     for segment in context.network.network_segments:
    #         context.set_binding(segment[api.ID],
    #                             self.vif_type,
    #                             self.vif_details,
    #                             status=n_const.PORT_STATUS_ACTIVE)
    #
    #
    #
    def create_port_precommit(self,context):
        LOG.info(_LI("*********************** create_port_precommit port %(port)s on "
             "network %(network)s"),
             {'port': context.current['id'],
             'network': context.network.current['id']})

    def create_port_postcommit(self,context):
        LOG.info(_LI("*********************** create_port_postcommit port %(port)s on "
              "network %(network)s"),
              {'port': context.current['id'],
              'network': context.network.current['id']})
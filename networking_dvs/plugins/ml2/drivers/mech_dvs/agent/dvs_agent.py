# Copyright 2015 Cloudbase Solutions Srl
#
# All Rights Reserved.
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

import collections
import signal
import six
import time

import eventlet

eventlet.monkey_patch()

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


import oslo_messaging
from oslo_log import log as logging
from oslo_service import loopingcall

import neutron.context
from neutron.agent import rpc as agent_rpc, securitygroups_rpc as sg_rpc
from neutron.common import config as common_config, topics, constants as n_const
from neutron.i18n import _LI, _LW, _LE

from networking_dvs.agent.firewalls import dvs_securitygroup_rpc as dvs_rpc
from networking_dvs.common import constants as dvs_constants, config
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent import vcenter_util
from networking_dvs.common.util import dict_merge

LOG = logging.getLogger(__name__)
CONF = config.CONF


class DVSPluginApi(agent_rpc.PluginApi):
    pass


class DvsNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):
    target = oslo_messaging.Target(version='1.4')

    def __init__(self,
                 quitting_rpc_timeout=None,
                 conf=None):

        super(DvsNeutronAgent, self).__init__()

        self.conf = conf or CONF

        self.agent_state = {
            'binary': 'neutron-dvs-agent',
            'host': self.conf.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {},
            'agent_type': dvs_constants.AGENT_TYPE_DVS,
            'start_flag': True}

        self.setup_rpc()

        report_interval = 30  # self.conf.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

        self.polling_interval = 10

        self.api = vcenter_util.VCenter(self.conf.ML2_VMWARE)

        self.enable_security_groups = self.conf.get('SECURITYGROUP', {}).get('enable_security_group', False)
        # Security group agent support
        if self.enable_security_groups:
            self.sg_agent = dvs_rpc.DVSSecurityGroupRpc(self.context,
                                                        self.sg_plugin_rpc,
                                                        local_vlan_map=None,
                                                        integration_bridge=self.api,  # Passed on to FireWall Driver
                                                        defer_refresh_firewall=False)

        self.run_daemon_loop = True
        self.iter_num = 0

        self.quitting_rpc_timeout = quitting_rpc_timeout

        self.updated_ports = {}
        self.known_ports = {}
        self.unbound_ports = {}
        self.deleted_ports = set()
        self.added_ports = set()

        self.network_ports = collections.defaultdict(set)

        self.catch_sigterm = False
        self.catch_sighup = False
        self.connection.consume_in_threads()

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        port_id = port['id']
        if port_id in self.known_ports and not port_id in self.deleted_ports:  # Avoid updating a port, which has not been created yet
            self.updated_ports[port_id] = port
        LOG.debug("port_update message processed for port {}".format(port_id))

    def port_delete(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        self.updated_ports.pop(port_id, None)
        self.deleted_ports.add(port_id)
        LOG.debug("port_delete message processed for port {}".format(port_id))

    def network_create(self, context, **kwargs):
        LOG.debug(_LI("Agent network_create"))

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        for port_id in self.network_ports[network_id]:
            # notifications could arrive out of order, if the port is deleted
            # we don't want to update it anymore
            if port_id not in self.deleted_ports:
                port = self.known_ports.get(port_id, None)
                if port:
                    self.updated_ports[port_id] = port
        LOG.debug("Agent network_update for network "
                  "%(network_id)s, with ports: %(ports)s",
                  {'network_id': network_id,
                   'ports': self.network_ports[network_id]})

    def network_delete(self, context, **kwargs):
        LOG.debug(_LI("Agent network_delete"))

    def setup_rpc(self):
        self.agent_id = 'dvs-agent-%s' % self.conf.host
        self.topic = topics.AGENT
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = neutron.context.get_admin_context_without_session()

        # Handle updates from service
        self.endpoints = [self]

        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.CREATE],
                     [topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.CREATE],
                     [topics.NETWORK, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def _report_state(self):
        # LOG.debug(_LI("******** Reporting state via rpc"))
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)

            self.agent_state.pop('start_flag', None)
            # LOG.debug(_LI("******** Reporting state completed"))
        except (oslo_messaging.MessagingTimeout, oslo_messaging.RemoteError, oslo_messaging.MessageDeliveryFailure):
            LOG.exception(_LE("Failed reporting state!"))

    def _check_and_handle_signal(self):
        if self.catch_sigterm:
            LOG.info(_LI("Agent caught SIGTERM, quitting daemon loop."))
            self.run_daemon_loop = False
            self.catch_sigterm = False

        if self.catch_sighup:
            LOG.info(_LI("Agent caught SIGHUP, resetting."))
            self.conf.reload_config_files()
            common_config.setup_logging()
            LOG.debug('Full set of CONF:')
            self.conf.log_opt_values(LOG, logging.DEBUG)
            self.catch_sighup = False

        return self.run_daemon_loop

    def _handle_sigterm(self, signum, frame):
        self.catch_sigterm = True
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def _handle_sighup(self, signum, frame):
        self.catch_sighup = True

    def _scan_ports(self):
        try:
            start = time.clock()
            ports_by_mac = self.api.get_new_ports(block=False, max_ports=25)
            macs = set(six.iterkeys(ports_by_mac))
            if not macs:
                LOG.debug(_LI("Scan 0 ports completed in {} seconds".format(time.clock() - start)))
            else:
                print("Looking for {} macs".format(len(macs)))
                neutron_ports = self.plugin_rpc.get_devices_details_list(self.context, devices=macs, agent_id=self.agent_id,
                                                                         host=self.conf.host)

                for neutron_info in neutron_ports:
                    if neutron_info:
                        # device <=> mac_address are the same, but mac_address is missing, when there is no data
                        mac = neutron_info.get("mac_address", None)
                        macs.discard(mac)
                        port_info = ports_by_mac.get(mac, None)
                        if port_info:
                            port_id = neutron_info.get("port_id", None)
                            if port_id:
                                port_info["port"]["id"] = port_id
                                dict_merge(port_info, neutron_info)
                                self.api.uuid_port_map[port_id] = port_info
                if macs:
                    LOG.warning(_LW("Could not find the following macs: {}").format(macs))

                LOG.debug(_LI("Scan {} ports completed in {} seconds (Missing {})".format(len(neutron_ports), time.clock() - start, len(macs))))

            return ports_by_mac.values()
        except (oslo_messaging.MessagingTimeout, oslo_messaging.RemoteError):
            LOG.exception(_LE("Failed to get ports via RPC"))
            return []

    def loop_count_and_wait(self, start_time, port_stats):
        # sleep till end of polling interval
        elapsed = time.clock() - start_time

        # LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
        #           "completed. Processed ports statistics: "
        #           "%(port_stats)s. Elapsed:%(elapsed).3f",
        #           {'iter_num': self.iter_num,
        #            'port_stats': port_stats,
        #            'elapsed': elapsed})

        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num += 1

    def process_ports(self):
        # LOG.info("******* Processing Ports *******")
        deleted_ports = self.deleted_ports.copy()
        if deleted_ports:
            # Nothing really to do on the VCenter - we let the vcenter unplug - so all we need to do is
            # trigger the firewall update and clear the deleted ports list
            if self.sg_agent:
                self.sg_agent.remove_devices_filter(deleted_ports)
            self.deleted_ports = self.deleted_ports - deleted_ports  # This way we miss fewer concurrent update
            for port_id in deleted_ports:
                self.known_ports.pop(port_id, None)
                self.unbound_ports.pop(port_id, None)

        # Get new ports on the VMWare integration bridge
        found_ports = self._scan_ports()

        port_up_ids = []
        port_down_ids = []
        ports_to_bind = []

        for port in found_ports:
            port_desc = port['port_desc']
            # This can happen for orphaned vms (summary.runtime.connectionState == "orphaned")
            # or vms not managed by openstack
            port_id = port.get('port_id', None)
            segmentation_id = port.get('segmentation_id', None)
            if not port_id or not segmentation_id:
                LOG.warning(_LW("Missing attribute in port {}").format(port))
            elif port_desc.vlan_id == segmentation_id and \
                            port_desc.link_up == port.get("admin_state_up", True):
                # The port is already in the expected state
                # Since we do not know if neutron knows about it, we still send an update
                if port_desc.link_up:
                    port_up_ids.append(port_id)
                else:
                    port_down_ids.append(port_id)
            else:
                ports_to_bind.append(port)

        if self.unbound_ports:
            unbound_ports = self.unbound_ports.copy()
            LOG.debug("Still down: {}".format(six.viewkeys(unbound_ports)))
            ports_to_bind.extend(six.itervalues(unbound_ports))
            for port_id in six.iterkeys(unbound_ports):
                self.unbound_ports.pop(port_id, None)

        updated_ports = self.updated_ports.copy()

        if ports_to_bind:
            LOG.debug("Ports to bind: {}".format([port["port_id"] for port in ports_to_bind]))
            ports_up, ports_down = self.api.bind_ports(ports_to_bind)
            for port in ports_down:
                port_id = port["port_id"]
                port_down_ids.append(port_id)
                # Updating the port will trigger a security group update conflicting with a subsequent configuration
                # updated_ports[port_id] = port
                self.unbound_ports[port_id] = port
            for port in ports_up:
                port_id = port["port_id"]
                port_up_ids.append(port_id)
                updated_ports[port_id] = port
                self.unbound_ports.pop(port_id, None)

        if port_up_ids or port_down_ids:
            LOG.debug("Update {} down {} agent {} host {}".format(port_up_ids, port_down_ids,
                                                              self.agent_id, self.conf.host))
            self.plugin_rpc.update_device_list(self.context, port_up_ids, port_down_ids, self.agent_id, self.conf.host)

        added_ports = set()
        known_ids = six.viewkeys(self.known_ports)
        for port in found_ports:
            port_id = port.get("port_id", None)
            if port_id and not port_id in known_ids:
                added_ports.add(port_id)
                self.known_ports[port_id] = port

        for port in six.iterkeys(updated_ports):
            self.updated_ports.pop(port, None)

        # update firewall agent if we have added or updated ports
        if self.sg_agent and (updated_ports or added_ports):
            # LOG.debug("Calling setup_port_filters")
            added_ports -= six.viewkeys(self.unbound_ports)
            updated_ports = six.viewkeys(updated_ports) - added_ports
            self.sg_agent.setup_port_filters(added_ports, updated_ports)

        return {
            'added': len(added_ports),
            'updated': len(updated_ports),
            'removed': len(deleted_ports)
        }

    def rpc_loop(self):
        while self._check_and_handle_signal():
            start = time.clock()
            port_stats = {'regular': self.process_ports()}
            self.loop_count_and_wait(start, port_stats)

    def daemon_loop(self):
        # Start everything.
        signal.signal(signal.SIGTERM, self._handle_sigterm)

        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_sighup)

        self.rpc_loop()


def main():
    try:
        import sys
        common_config.init(sys.argv[1:])
        common_config.setup_logging()

        agent = DvsNeutronAgent()

        # Start everything.
        LOG.info(_LI("Agent initialized successfully, now running... "))
        agent.daemon_loop()
    finally:
        print("Stopping")
        agent.api.stop()


if __name__ == "__main__":
    main()

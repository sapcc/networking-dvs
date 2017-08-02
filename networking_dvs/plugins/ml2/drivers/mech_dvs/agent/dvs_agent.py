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
import os

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet

    eventlet.monkey_patch()

from networking_dvs.patches import suds_patch
suds_patch.apply()

import collections
import signal
import six

from oslo_utils import timeutils

import oslo_messaging
from oslo_log import log as logging
from oslo_service import loopingcall

import neutron.context
from neutron.agent import rpc as agent_rpc, securitygroups_rpc as sg_rpc
from neutron.common import config as common_config, topics, constants as n_const, utils as neutron_utils
from neutron.i18n import _LI, _LW, _LE

from networking_dvs.agent.firewalls import dvs_securitygroup_rpc as dvs_rpc
from networking_dvs.common import constants as dvs_constants, config
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent import vcenter_util
from networking_dvs.common.util import dict_merge, stats


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

        self.pool = eventlet.greenpool.GreenPool(size=10) # Start small, so we identify possible bottlenecks

        self.conf = conf or CONF

        self.agent_state = {
            'binary': 'neutron-dvs-agent',
            'host': self.conf.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {
                'network_maps': neutron_utils.parse_mappings( self.conf.ML2_VMWARE.network_maps )
            },
            'agent_type': dvs_constants.AGENT_TYPE_DVS,
            'start_flag': True}

        self.setup_rpc()

        report_interval = self.conf.AGENT.report_interval or 5
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(interval=report_interval, stop_on_exception=False)

        self.polling_interval = 10

        self.api = vcenter_util.VCenter(self.conf.ML2_VMWARE, pool=self.pool)

        self.enable_security_groups = self.conf.get('SECURITYGROUP', {}).get('enable_security_group', False)
        # Security group agent support
        if self.enable_security_groups:
            self.api.setup_security_groups_support()
            self.sg_agent = dvs_rpc.DVSSecurityGroupRpc(self.context,
                                                        self.sg_plugin_rpc,
                                                        local_vlan_map=None,
                                                        integration_bridge=self.api,  # Passed on to FireWall Driver
                                                        defer_refresh_firewall=True) # Can only be false, if ...
            # ... we keep track of all the security groups of a port, and probably more changes

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
        # Avoid updating a port, which has not been created yet
        if port_id in self.known_ports and not port_id in self.deleted_ports:
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
        try:
            with timeutils.StopWatch() as w:
                self.state_rpc.report_state(self.context, self.agent_state)
            LOG.debug("Reporting state took {:1.3g}s".format(w.elapsed()))

            self.agent_state.pop('start_flag', None)
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

    @stats.timed()
    def _scan_ports(self):
        try:
            ports_by_mac = self.api.get_new_ports(block=False, max_ports=10)
            update_ports_thread = eventlet.spawn(self.api.read_dvs_ports, ports_by_mac)
            missing = self._read_neutron_ports(ports_by_mac)
            update_ports_thread.wait()
            for mac in missing:
                ports_by_mac.pop(mac, None)

            LOG.debug(_LI("Scan {} ports completed (Missing {})".format(len(ports_by_mac), missing)))

            return ports_by_mac.values()
        except (oslo_messaging.MessagingTimeout, oslo_messaging.RemoteError):
            LOG.exception(_LE("Failed to get ports via RPC"))
            return []

    def _read_neutron_ports(self, ports_by_mac):
        macs = set(six.iterkeys(ports_by_mac))
        if macs:
            with stats.timed('%s.%s' % (self.__module__, self.__class__.__name__)):
                neutron_ports = self.plugin_rpc.get_devices_details_list(self.context, devices=macs,
                                                                         agent_id=self.agent_id,
                                                                         host=self.conf.host)
        else:
            neutron_ports = []
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
        return macs

    def loop_count_and_wait(self, elapsed):
        # sleep till end of polling interval
        if elapsed < self.polling_interval:
            eventlet.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num += 1

    def _bound_ports(self, dvs, succeeded_keys, failed_keys):
        LOG.info(_LI("_bound_ports({}, {})").format(succeeded_keys, failed_keys))
        port_up_ids = []
        port_down_ids = []

        now = None
        with timeutils.StopWatch() as w:
            for port_key in succeeded_keys:
                port = dvs.ports_by_key[port_key]
                port_id = port["port_id"]
                self.unbound_ports.pop(port_id, None)
                if port["admin_state_up"]:
                    port_up_ids.append(port_id)
                else:
                    port_down_ids.append(port_id)

                port_desc = port.get('port_desc', None)
                if port_desc and port_desc.connected_since:
                    now = now or timeutils.utcnow()
                    stats.timing('networking_dvs.ports.bound', now - port_desc.connected_since)

        if failed_keys:
            stats.increment('networking_dvs.ports.bound.failures', len(failed_keys))

        if port_up_ids or port_down_ids:
            self.pool.spawn(self._update_device_list, port_down_ids, port_up_ids)

    @stats.timed()
    def process_ports(self):
        # LOG.info("******* Processing Ports *******")
        deleted_ports = self.deleted_ports.copy()
        if deleted_ports:
            self.deleted_ports = self.deleted_ports - deleted_ports  # This way we miss fewer concurrent update
            for port_id in deleted_ports:
                self.known_ports.pop(port_id, None)
                self.unbound_ports.pop(port_id, None)
            # Security group rules are how handled on a dvportgroup level and we don't
            # want to race against ourselves so removal is done synchronously.
            if self.sg_agent:
                self.sg_agent.remove_devices_filter(deleted_ports)

        # If the segmentation id, or the port status changed, it will land in the updated_ports
        updated_ports = self.updated_ports.copy()

        # Get new ports on the VMWare integration bridge
        found_ports = self._scan_ports()

        ports_to_bind = list(self.api.uuid_port_map[port_id] for port_id in six.iterkeys(updated_ports))
        ports_to_skip = collections.defaultdict(list)

        for port in found_ports:
            port_segmentation_id = port.get('segmentation_id', None)
            port_network_type = port.get('network_type', None)
            port_vlan_id = port['port_desc'].vlan_id

            if not port.get('port_id', None):
                # This can happen for orphaned vms (summary.runtime.connectionState == "orphaned")
                # or vms not managed by openstack
                LOG.warning(_LW("Missing attribute in port {}").format(port))
                continue

            if port_network_type == 'vlan' and port_segmentation_id:
                if port_segmentation_id != port_vlan_id:
                    ports_to_bind.append(port)
                else:
                    # Skip ports that are already bound to the same vlan.
                    # This happens on agent restart with existing instances.
                    ports_to_skip[port['port_desc'].dvs_uuid].append(port)
                continue

            if port_network_type == 'flat':
                ports_to_bind.append(port)
                continue

            LOG.warning("Unsupported port_network_type {} for port {}".format(port_network_type, port))

        if self.unbound_ports:
            unbound_ports = self.unbound_ports.copy()
            LOG.debug("Still down: {}".format(list(six.iterkeys(unbound_ports))))
            ports_to_bind.extend(six.itervalues(unbound_ports))
            for port_id in six.iterkeys(unbound_ports):
                self.unbound_ports.pop(port_id, None)

        if ports_to_bind:
            LOG.debug("Ports to bind: {}".format([port["port_id"] for port in ports_to_bind]))
            self.api.bind_ports(ports_to_bind, callback=self._bound_ports)

        added_ports = set()
        known_ids = six.viewkeys(self.known_ports)
        for port in found_ports:
            port_id = port.get("port_id", None)
            if not port_id:
                continue
            if port_id not in known_ids:
                added_ports.add(port_id)
                self.known_ports[port_id] = port
            else:
                known_port = self.known_ports[port_id]
                if port['port_desc'] != known_port['port_desc']:
                    self.known_ports[port_id] = port
                    updated_ports[port_id] = port

        for port in six.iterkeys(updated_ports):
            self.updated_ports.pop(port, None)

        # update firewall agent
        if self.sg_agent:
            # Needs to called, even if there is no added or updated ports, as it also executes the deferred updates
            added_ports -= six.viewkeys(self.unbound_ports)
            updated_ports = six.viewkeys(updated_ports) - added_ports
            self.sg_agent.setup_port_filters(added_ports, updated_ports)

        # Apply the changes
        for dvs in six.itervalues(self.api.uuid_dvs_map):
            dvs.apply_queued_update_specs()

        LOG.debug("Reporting skipped ports as bound to neutron: {}".format(ports_to_skip))
        for dvs_uuid, ports in six.iteritems(ports_to_skip):
            self._bound_ports(self.api.uuid_dvs_map[dvs_uuid],
                              [port['port_desc'].port_key for port in ports],
                              [])

    def _update_device_list(self, port_down_ids, port_up_ids):
        with stats.timed('%s.%s._update_device_list' % (self.__module__, self.__class__.__name__)):
            LOG.info(_LI("Update {} down {} agent {} host {}").format(port_up_ids, port_down_ids,
                                                                      self.agent_id, self.conf.host))
            self.plugin_rpc.update_device_list(self.context, port_up_ids, port_down_ids, self.agent_id, self.conf.host)

    def rpc_loop(self):
        while self._check_and_handle_signal():
            with timeutils.StopWatch() as w:
                self.process_ports()
            self.loop_count_and_wait(w.elapsed())

    def daemon_loop(self):
        # Start everything.
        signal.signal(signal.SIGTERM, self._handle_sigterm)

        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_sighup)

        self.rpc_loop()
        if self.api:
            self.api.stop()
        if self.pool:
            self.pool.waitall()


def _main():
    import sys
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    agent = DvsNeutronAgent()

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()


def main():
    try:
        resolution = float(os.getenv('DEBUG_BLOCKING'))
        import eventlet.debug
        eventlet.debug.hub_blocking_detection(state=True, resolution=resolution)
    except (ValueError, TypeError):
        pass

    try:
        import yappi as profiler

        profiler.set_clock_type('wall')
        profiler.start(builtins=True)
    except ImportError:
        profiler = None
        pass

    try:
        _main()
    except KeyboardInterrupt:
        pass

    if profiler:
        print("Stopping profiler")
        profiler.stop()
        stats = profiler.get_func_stats()
        stats.save('/tmp/profile.callgrind', type='callgrind')
        print("Done")

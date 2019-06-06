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

import collections
import signal
import six
import sys
from collections import defaultdict
import oslo_messaging

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import eventlet_backdoor
from oslo_utils import timeutils
from osprofiler.profiler import trace_cls

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron.common import profiler
from neutron.api.rpc.handlers import securitygroups_rpc

try:
    from neutron._i18n import _
    from neutron_lib import context as neutron_context
    from neutron_lib import constants as n_const
    from neutron_lib.utils.helpers import parse_mappings
except ImportError:
    from neutron import context as neutron_context
    from neutron.i18n import _LI as _
    from neutron.common import constants as n_const
    from neutron.common.utils import parse_mappings

from networking_dvs.agent.firewalls import dvs_securitygroup_rpc as dvs_rpc
from networking_dvs.utils.dvs_util import dvportgroup_name
from networking_dvs.api import dvs_agent_rpc_api
from networking_dvs.common import constants as dvs_const
from networking_dvs.common import config
from networking_dvs.plugins.ml2.drivers.mech_dvs.agent import vcenter_util
from networking_dvs.common.util import stats, dict_merge
from networking_dvs.utils import dvs_util
from networking_dvs.utils import security_group_utils as sg_util
from networking_dvs.utils import spec_builder as builder
from pyVmomi import vim
from pyVmomi import vmodl
from pyVim.task import WaitForTask as wait_for_task

LOG = logging.getLogger(__name__)

_core_opts = [
    cfg.StrOpt('port-id',
               default='',
               help=_('ID for the specific port'),
               deprecated_for_removal=False),
    cfg.StrOpt('correct',
               default='False',
               help='Specify --correct for changing specific configuration',
               deprecated_for_removal=False),
]
CONF = config.CONF
CONF.register_cli_opts(_core_opts)


def touch_file(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)


@trace_cls("rpc")
class DVSPluginApi(agent_rpc.PluginApi):
    pass


##
# The SecurityGroupAgentRpcCallbackMixin will forward all
# security group rpc calls to self.sg_agent

@trace_cls("rpc", trace_private=True)
class DvsNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      dvs_agent_rpc_api.ExtendAPI):
    target = oslo_messaging.Target(version='1.4')

    def __init__(self, quitting_rpc_timeout=None, conf=None):
        super(DvsNeutronAgent, self).__init__()

        # Start small, so we identify possible bottlenecks
        pool_size = CONF.DVS.vcenter_task_pool_size
        self.pool = eventlet.greenpool.GreenPool(size=pool_size)
        self.conf = conf or CONF
        self.context = neutron_context.get_admin_context()

        network_maps = parse_mappings(
            self.conf.ML2_VMWARE.network_maps)
        network_maps_v2 = {}

        self.agent_state = {
            'binary': 'neutron-dvs-agent',
            'host': self.conf.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {
                'agent_version': 2,
                'network_maps': network_maps,
                'network_maps_v2': network_maps,
            },
            'agent_type': dvs_const.AGENT_TYPE_DVS,
            'start_flag': True}

        self.setup_rpc()

        report_interval = self.conf.AGENT.report_interval or 5
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(interval=report_interval, stop_on_exception=False)

        self.polling_interval = 10

        self.enable_security_groups = self.conf.get('SECURITYGROUP', {}). \
            get('enable_security_group', False)

        self.api = vcenter_util.VCenter(self.conf.ML2_VMWARE,
                                        pool=self.pool, agent=self)

        for network, dvs in six.iteritems(self.api.network_dvs_map):
            network_maps_v2[network] = dvs.uuid.replace(" ", "")

        # Security group agent support
        if self.enable_security_groups:
            self.sg_agent = dvs_rpc.DVSSecurityGroupRpc(self.context,
                                                        self.sg_plugin_rpc,
                                                        self.api,
                                                        self.conf,
                                                        self.pool)
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

    def book_port(self, port, network_segments, network_current):
        # LOG.debug("{} {}".format(port, network_segments))

        dvs = None
        dvs_segment = None
        for segment in network_segments:
            physical_network = segment['physical_network']
            dvs = self.api.network_dvs_map.get(physical_network, None)
            if dvs:
                dvs_segment = segment
                break

        if not dvs:
            return {}

        self.mtu_update(dvs, network_current)

        sg_set = sg_util.security_group_set(port)
        if not sg_set:
            return {}

        port['segmentation_id'] = dvs_segment['segmentation_id']
        port['physical_network'] = dvs_segment['physical_network']
        dvs, port_group = self._get_or_create_port_group(port)

        if not port_group:
            LOG.warning('Failed to create port-group')
            return {}

        return {
            'bridge_name': port_group.name,
            'vif_details': {
                # Those keys are compatible with networking-vsphere
                # And have the corresponding upstream change
                'dvs_id': dvs.uuid,
                'pg_id': port_group.key,
                # Those are legacy keys and can removed,
                # if nova has been rolled out with sapcc/nova#66
                'dvs_port_group_name': port_group.name,
                'dvs_port_group_key': port_group.key,
                'dvs_uuid': dvs.uuid,
            }
        }

    @staticmethod
    def mtu_update(dvs, network_current):
        if network_current.get('mtu') is not None and dvs.mtu is not None:
            network_mtu = network_current.get('mtu')
            if int(network_mtu) > int(dvs.mtu):
                LOG.warning("Network: %s has MTU of %s "
                            "which is bigger than the DVS MTU.",
                            network_current['name'], network_mtu)
                LOG.info('Updating DVS mtu...')
                dvs.update_mtu(network_mtu)

    def port_update(self, context, port=None, network_type=None,
                    physical_network=None, segmentation_id=None):
        # LOG.info("port_update message {}".format(kwargs))
        port_id = port['id']
        # Avoid updating a port, which has not been created yet
        if port_id in self.known_ports and port_id not in self.deleted_ports:
            self.updated_ports[port_id] = port
        # LOG.debug("port_update message processed for {}".format(kwargs))

    def port_delete(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        self.updated_ports.pop(port_id, None)
        self.deleted_ports.add(port_id)
        LOG.debug("port_delete message processed for port {}".format(port_id))

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

    def setup_rpc(self):
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)

        self.agent_id = 'dvs-agent-%s' % self.conf.host

        self.topic = topics.AGENT
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init

        # Handle updates from service
        endpoints = [self]

        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [dvs_const.DVS, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def _report_state(self):
        try:
            with timeutils.StopWatch() as w:
                self.state_rpc.report_state(self.context, self.agent_state)
            LOG.debug("Reporting state took {:1.3g}s".format(w.elapsed()))

            self.agent_state.pop('start_flag', None)
        except (oslo_messaging.MessagingTimeout, oslo_messaging.RemoteError,
                oslo_messaging.MessageDeliveryFailure):
            LOG.exception(_("Failed reporting state!"))

    def _check_and_handle_signal(self):
        if self.catch_sigterm:
            LOG.info(_("Agent caught SIGTERM, quitting daemon loop."))
            self.run_daemon_loop = False
            self.catch_sigterm = False

        if self.catch_sighup:
            LOG.info(_("Agent caught SIGHUP, resetting."))
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

    def _scan_ports(self, blocking_duration):
        return self.api.get_new_ports(
            block=blocking_duration is not None,
            max_ports=self.conf.DVS.max_ports_per_iteration,
            timeout=blocking_duration
        ).values()

    def read_neutron_ports(self, macs):
        macs = set(macs)
        if not macs:
            return []

        with stats.timed('%s.%s' % (self.__module__, self.__class__.__name__)):
            neutron_ports = self.plugin_rpc.get_devices_details_list(
                self.context, devices=macs,
                agent_id=self.agent_id,
                host=self.conf.host)
        LOG.debug(_("Received port details".format(len(neutron_ports))))

    def loop_count(self, elapsed):
        # sleep till end of polling interval
        if elapsed < self.polling_interval:
            return self.polling_interval - elapsed
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
            return 0.0
        self.iter_num += 1

    def _bound_ports(self, dvs, succeeded_keys, failed_keys):
        port_up_ids = []
        port_down_ids = []

        now = None
        for port_key in succeeded_keys:
            port = dvs.ports_by_key.get(port_key, None)
            if not port:
                LOG.debug("Port with key {} has already been removed."
                          .format(port_key))
                continue

            port_id = port.get('port_id') or port.get('id')
            self.unbound_ports.pop(port_id, None)
            if port.get('admin_state_up', True):
                port_up_ids.append(port_id)
            else:
                port_down_ids.append(port_id)

            port_desc = port.get('port_desc')
            if not port_desc:
                continue
            if port_desc.connected_since:
                now = now or timeutils.utcnow()
                stats.timing('networking_dvs.ports.bound',
                             now - port_desc.connected_since)

        if failed_keys:
            stats.increment('networking_dvs.ports.bound.failures',
                            len(failed_keys))

        LOG.info(_("_bound_ports({}, {}) ({} failures)").format(
            port_up_ids, port_down_ids, len(failed_keys)))

        if port_up_ids or port_down_ids:
            self.pool.spawn(self._update_device_list,
                            port_down_ids, port_up_ids)

    @stats.timed()
    def process_ports(self, blocking_duration=0.0):
        LOG.debug("Entered")
        touch_file('/tmp/neutron-dvs-agent.alive')
        deleted_ports = self.deleted_ports.copy()
        if deleted_ports:
            # This way we miss fewer concurrent update
            self.deleted_ports = self.deleted_ports - deleted_ports
            for port_id in deleted_ports:
                self.known_ports.pop(port_id, None)
                self.unbound_ports.pop(port_id, None)

        # If the segmentation id, or the port status changed,
        # it will land in the updated_ports
        updated_ports = self.updated_ports.copy()

        # Get new ports on the VMWare integration bridge
        found_ports = self._scan_ports(blocking_duration)
        ports_to_bind = list(self.api.uuid_port_map[port_id]
                             for port_id in six.iterkeys(updated_ports))

        for port in found_ports:
            port_segmentation_id = port.get('segmentation_id')
            port_network_type = port.get('network_type')
            port_vlan_id = port['port_desc'].vlan_id
            if not port.get('port_id', None):
                # This can happen for orphaned vms
                #   (summary.runtime.connectionState == "orphaned")
                # or vms not managed by openstack
                LOG.warning(_("Missing attribute in port {}").format(port))
            elif port_network_type == 'vlan' and port_segmentation_id:
                if (port_segmentation_id != port_vlan_id or
                        port['admin_state_up'] !=
                        (port.get('status') == 'ACTIVE')):
                    # Either mismatch in VLAN or status
                    ports_to_bind.append(port)
            elif port_network_type == 'flat':
                ports_to_bind.append(port)
            else:
                LOG.warning(
                    "Unsupported port_network_type {} for port {}".format(
                        port_network_type, port))

        if self.unbound_ports:
            unbound_ports = self.unbound_ports.copy()
            LOG.debug("Still down: %s",
                      list(six.iterkeys(unbound_ports)))
            ports_to_bind.extend(six.itervalues(unbound_ports))
            for port_id in six.iterkeys(unbound_ports):
                self.unbound_ports.pop(port_id, None)

        if ports_to_bind:
            LOG.debug("Ports to bind: %s",
                      [port['port_id'] for port in ports_to_bind])
            self.api.bind_ports(ports_to_bind, callback=self._bound_ports)

        added_ports = set()
        known_ids = six.viewkeys(self.known_ports)
        for port in found_ports:
            port_id = port.get('port_id') or port.get('id')
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

        for port_id, updated_port in six.iteritems(updated_ports):
            known_port = self.known_ports.get(port_id)
            if known_port:
                dict_merge(known_port, updated_port)
            self.updated_ports.pop(port_id, None)

        added_ports -= six.viewkeys(self.unbound_ports)
        updated_ports = six.viewkeys(updated_ports) - added_ports

        self._reassign_ports(added_ports | updated_ports)

        # Apply the changes
        for dvs in six.itervalues(self.api.uuid_dvs_map):
            dvs.apply_queued_update_specs()

        LOG.debug("Left")

    def _reassign_ports(self, port_ids):
        for port_id in port_ids:
            port = self.api.uuid_port_map.get(port_id)
            if not port:
                LOG.warn("Could not find port with id %s", port_id)

            dvs, port_group = self._get_or_create_port_group(port)
            if not dvs or not port_group:
                continue
            port_desc = port['port_desc']
            if port_desc.port_group_key != port_group.key:
                # Configure the backing to the required dvportgroup
                old_task = port.get('task')
                # Delay the sync in case we have
                port['task'] = eventlet.spawn_after(0.25,
                                                    self._reassign_port_async,
                                                    port, old_task)

    def _get_or_create_port_group(self, port):
        port_id = port['id']
        physical_network = port['physical_network']
        dvs = self.api.network_dvs_map.get(physical_network, None)
        if not dvs:
            LOG.warn("Cannot find dvs for physical network %s on port %s",
                     physical_network, port_id)
            return None, None

        sg_set = sg_util.security_group_set(port)
        if not sg_set:
            LOG.warning("No security groups for port %s", port_id)
            port_group_name = physical_network
        else:
            port_group_name = dvportgroup_name(dvs.uuid, sg_set)

        segmentation_id = port['segmentation_id']

        port_config = vim.VMwareDVSPortSetting(
            vlan=builder.vlan(segmentation_id),
        )

        port_group = dvs.create_dvportgroup(port_group_name, port_config,
                                            description=sg_set, update=True)
        return dvs, port_group

    def _reassign_port_async(self, port, task=None):
        if task:
            task.wait()

        dvs, port_group = self._get_or_create_port_group(port)
        if not dvs or not port_group:
            return

        port_desc = port['port_desc']
        if port_desc.port_group_key == port_group.key:
            return

        port_connection = vim.DistributedVirtualSwitchPortConnection(
            switchUuid=dvs.uuid, portgroupKey=port_group.key)
        port_backing = \
            vim.VirtualEthernetCardDistributedVirtualPortBackingInfo(
                port=port_connection)
        # Specify the device that we are going to edit
        virtual_device = getattr(vim.vm.device, port_desc.device_type)(
            key=port_desc.device_key,
            backing=port_backing,
            addressType='manual',
            macAddress=port_desc.mac_address,
        )
        # Create an edit spec for an existing virtual device
        virtual_device_config_spec = vim.VirtualDeviceConfigSpec(
            operation='edit',
            device=virtual_device,
        )
        # Create a config spec for applying the update to the virtual machine
        vm_config_spec = vim.VirtualMachineConfigSpec(
            deviceChange=[virtual_device_config_spec]
        )
        # Queue the update
        vm_ref = vim.VirtualMachine(port_desc.vmobref)
        vm_ref._stub = self.api.connection._stub
        if CONF.AGENT.dry_run:
            LOG.debug("Reassign: %s", vm_config_spec)
        else:
            task = reconfigure_vm(vm_ref, vm_config_spec)
            for i in six.moves.range(3):
                try:
                    wait_for_task(task)
                    # The task will complete _after_ the corresponding event
                    # been issued to the collector, so we should be here not
                    # waiting more than some fractions of a second
                    for j in six.moves.range(10):
                        port_desc = port['port_desc']
                        if port_desc.port_group_key == port_group.key:
                            # stats.timing('networking_dvs.ports.reassigned',
                            #             port_desc.firewall_end)
                            break
                        eventlet.sleep(0.1)
                    break
                except vmodl.fault.SystemError:
                    LOG.exception("Failed to re-assign port")

    def _update_device_list(self, port_down_ids, port_up_ids):
        with stats.timed('%s.%s._update_device_list' % (
                self.__module__, self.__class__.__name__)):
            LOG.info(_("Update {} down {} agent {} host {}").format(
                port_up_ids, port_down_ids, self.agent_id, self.conf.host))
            if not CONF.AGENT.dry_run:
                self.plugin_rpc.update_device_list(
                    self.context, port_up_ids, port_down_ids,
                    self.agent_id, self.conf.host)

    def rpc_loop(self):
        blocking_duration = 0.0
        while self._check_and_handle_signal():
            with timeutils.StopWatch() as w:
                self.process_ports(blocking_duration)

            blocking_duration = self.loop_count(w.elapsed())

    def daemon_loop(self):
        # Start everything.
        signal.signal(signal.SIGTERM, self._handle_sigterm)

        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_sighup)

        self.api.start()

        self.rpc_loop()
        if self.api:
            self.api.stop()
        if self.pool:
            self.pool.waitall()


@stats.timed()
def reconfigure_vm(vm_ref, vm_config_spec):
    try:
        return vm_ref.ReconfigVM_Task(spec=vm_config_spec)
    except vim.fault.VimFault as e:
        LOG.info("Unable to reassign VM, exception is %s.", e)


def neutron_dvs_cli():
    """
    CLI command for retrieving a port from Neutron by id;
    Comparing the retrieved port to a port in the linked
    portgroup from vSphere;
    The port from vSphere is fetched by the Neutron port
    MAC address and the portgroup key;
    If --correct opt is set a reconfigure task on the port
    will be started which will apply the rules from
    the Neutron port to the DVS port
    """
    common_config.init(sys.argv[1:])
    port_id = CONF.port_id
    correct = CONF.correct

    profiler.setup('neutron-dvs-agent-cli', cfg.CONF.host)
    agent = DvsNeutronAgent()
    neutron_ports = agent.plugin_rpc.get_devices_details_list(
        agent.context, devices=[port_id],
        agent_id=agent.agent_id, host=agent.conf.host)

    mac_addr = neutron_ports[0]['mac_address']

    sg_api = securitygroups_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
    sg_info = sg_api.security_group_info_for_devices(
        agent.context, [neutron_ports[0]['port_id']])

    rules = sg_api.security_group_rules_for_devices(agent.context, [port_id])
    patched_sg_rules = sg_util.patch_sg_rules(
        rules[port_id]['security_group_rules'])

    sg_set = sg_util.security_group_set(sg_info)

    dvs = agent.api.network_dvs_map.get(neutron_ports[0]['physical_network'],
                                        None)
    sg_aggr_obj = defaultdict(lambda: defaultdict(sg_util.SgAggr))
    sg_aggr = sg_aggr_obj[dvs.uuid][sg_set]
    sg_util.apply_rules(patched_sg_rules, sg_aggr)

    sg_set_rules = sg_util.get_rules(sg_aggr)
    port_config = sg_util.port_configuration(None, sg_set_rules, {}, None,
                                             None).setting

    neutron_vlan_id = neutron_ports[0]['segmentation_id']
    dvs_util.dvportgroup_name(dvs.uuid, sg_set)

    """
    Retrieving the DVS portgroup and properties
    """
    port_group = dvs.get_port_group_for_security_group_set(sg_set)
    portgroup_key = port_group['ref']['value']

    dvs_vlan_id = port_group['defaultPortConfig'].vlan.vlanId

    dvs_port = agent.api._fetch_ports_by_mac(portgroup_key, mac_addr)
    neutron_port_rules = port_config.filterPolicy.filterConfig[
        0].trafficRuleset.rules
    dvs_port_rules = dvs_port.config.setting.filterPolicy.filterConfig[
        0].trafficRuleset.rules

    match = False

    for i in range(len(dvs_port_rules)):
        config_match = dvs_util._config_differs(dvs_port_rules[i],
                                                neutron_port_rules[i])
        if config_match:
            match = True
            print("Neutron Port configuration rule not matched for : ",
                  neutron_port_rules[i])
            print("DVS Port configuration rule: ", dvs_port_rules[i])

    if match is False:
        print("Neutron port config matches DVS port config")
    else:
        if correct == 'True':
            print("Updating port configuration")
            if neutron_vlan_id != dvs_vlan_id:
                port_config.vlan = builder.vlan(neutron_vlan_id)

            dv_port_config_spec = builder.port_config_spec(
                key=dvs_port.key,
                version=dvs_port.config.configVersion,
                setting=port_config)
            dvs.update_ports([dv_port_config_spec])


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    profiler.setup('neutron-dvs-agent', cfg.CONF.host)
    try:
        resolution = float(os.getenv('DEBUG_BLOCKING'))
        import eventlet.debug
        eventlet.debug.hub_blocking_detection(state=True,
                                              resolution=resolution)
    except (ValueError, TypeError):
        pass

    eventlet_backdoor.initialize_if_enabled(cfg.CONF)

    try:
        agent = DvsNeutronAgent()
        # Start everything.
        LOG.info(_("Agent initialized successfully, now running... "))
        agent.daemon_loop()
    except KeyboardInterrupt:
        pass

from oslo_config import cfg

from neutron.agent.common import config

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.IntOpt('quitting_rpc_timeout', default=10,
               help=_("Set new timeout in seconds for new rpc calls after "
                      "agent receives SIGTERM. If value is set to 0, rpc "
                      "timeout won't be changed")),
    cfg.ListOpt(
        'physical_network_vswitch_mappings',
        default=[],
        help=_('List of <physical_network>:<vswitch> '
               'where the physical networks can be expressed with '
               'wildcards, e.g.: ."*:external"')),
    cfg.StrOpt(
        'local_network_vswitch',
        default='private',
        help=_('Private vswitch name used for local networks')),
    cfg.BoolOpt('enable_metrics_collection',
                default=False,
                help=_('Enables metrics collections for switch ports by using '
                       'Hyper-V\'s metric APIs. Collected data can by '
                       'retrieved by other apps and services, e.g.: '
                       'Ceilometer. Requires Hyper-V / Windows Server 2012 '
                       'and above')),
    cfg.IntOpt('metrics_max_retries',
               default=100,
               help=_('Specifies the maximum number of retries to enable '
                      'Hyper-V\'s port metrics collection. The agent will try '
                      'to enable the feature once every polling_interval '
                      'period for at most metrics_max_retries or until it '
                      'succeedes.'))
]


vmware_opts = [
    cfg.FloatOpt(
        'task_poll_interval',
        default=2,
        help=_('The interval of task polling in seconds.')),
    cfg.IntOpt(
        'api_retry_count',
        default=10,
        help=_('number of times an API must be retried upon '
               'session/connection related errors')),
    cfg.StrOpt('vsphere_login', default='administrator',
               help=_("Vsphere login.")),
    cfg.ListOpt('network_maps',
               default=DEFAULT_BRIDGE_MAPPINGS,
               help=_("List of <physical_network>:<bridge>.")),
    cfg.StrOpt('vsphere_hostname', default='vsphere',
               help=_("Vsphere host name or IP.")),
    cfg.StrOpt('vsphere_password', default='',
               help=_("Vsphere password.")),
    cfg.StrOpt(
        'wsdl_location',
        default=None,
        help=_('The location of API SDK Client File.')),
    cfg.StrOpt(
        'dv_switch',
        default="dvSwitch0",
        help=_('The DVS switch to use for configuring ports')),
    cfg.StrOpt(
        'dv_portgroup',
        default="br-int",
        help=_('The portgroup to scan for newly plugged devices')),
    cfg.FloatOpt(
        'dv_default_vlan',
        default=1,
        help=_('The default VLAN of the port group'))
]

dvs_opts = [
    cfg.BoolOpt('clean_on_restart',
               default=True,
               help=_("Run DVS cleaning procedure on agent restart.")),
    cfg.BoolOpt('precreate_networks',
               default=True,
               help=_("Precreate networks on DVS")),
]

cfg.CONF.register_opts(dvs_opts, "DVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(vmware_opts, "ML2_VMWARE")
config.register_agent_state_opts_helper(cfg.CONF)
CONF = cfg.CONF

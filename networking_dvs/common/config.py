from oslo_config import cfg

try:
    from neutron.conf.agent import common as config
except ImportError:
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
    cfg.BoolOpt('dry_run', default=False,
                help=_("Should the agent run without applying changes")),
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
    cfg.IntOpt(
        'connections_pool_size',
        default=100,
        help=_('number of vsphere connections pool '
               'must be higher for intensive operations')),
    cfg.IntOpt(
        'host_rectify_timeout',
        default=120,
        help=_('Seconds between rectify calls in case of dvs bulk faults.')),
    cfg.StrOpt('vsphere_login', default='administrator',
               help=_("Vsphere login.")),
    cfg.ListOpt('network_maps',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("List of <physical_network>:<bridge>.")),
    cfg.StrOpt('vsphere_hostname', default='vsphere',
               help=_("Vsphere host name or IP.")),
    cfg.StrOpt('vsphere_password', default='',
               help=_("Vsphere password.")),
    cfg.StrOpt('cluster_name', default='',
               help=_("Name of the cluster.")),
    cfg.StrOpt('ca_certs',
               default='',
               help=_("Path to certificates bundle.")),
]

dvs_opts = [
    cfg.BoolOpt('clean_on_restart',
                default=True,
                help=_("Run DVS cleaning procedure on agent restart.")),
    cfg.BoolOpt('precreate_networks',
                default=True,
                help=_("Precreate networks on DVS")),
    cfg.IntOpt('trace_every_nth_iteration',
               default=0,
               help=_("Create a profile trace for every nth iteration"
                      " (if profiling is enabled)")),
    cfg.IntOpt('max_ports_per_iteration',
               default=10,
               help=_("Number of ports to get per iteration")),
    cfg.IntOpt('default_initial_num_ports',
               default=2,
               help=_("Number of ports a newly "
                      "created port-group should have")),
    cfg.IntOpt('portgroup_retention_iterations',
               default=20,
               help=_("Number of iterations a 6 seconds an empty portgroup is"
                      " kept before deleting it.")),
    cfg.IntOpt('vcenter_task_pool_size',
               default=10,
               help=_("Size of the shared GreenPool for parallel change "
                      "operations / tasks against the vCenter.")),
]

cfg.CONF.register_opts(dvs_opts, "DVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(vmware_opts, "ML2_VMWARE")
config.register_agent_state_opts_helper(cfg.CONF)
CONF = cfg.CONF

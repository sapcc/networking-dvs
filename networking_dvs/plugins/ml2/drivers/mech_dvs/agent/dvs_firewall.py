

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent import firewall


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

class DvsSecurityGroupsDriver(firewall.FirewallDriver):

    def __init__(self):
        LOG.info("**************************************")
        LOG.info("DVS Security Group Driver initializing")
        LOG.info("**************************************")


    def prepare_port_filter(self, port):
        LOG.info("Prepare port filter {}".format(port))
        pass

    def apply_port_filter(self, port):
        LOG.info("Apply port filter {}".format(port))
        pass

    def update_port_filter(self, port):
        LOG.info("Update port filter {}".format(port))
        pass

    def remove_port_filter(self, port):
        LOG.info("Remove port filter {}".format(port))
        pass

    def filter_defer_apply_on(self):
        LOG.info("Defer apply on filter")
        pass

    def filter_defer_apply_off(self):
        LOG.info("Defer apply off filter")
        pass

    @property
    def ports(self):
        LOG.info("ports")
        return {}

    def update_security_group_members(self, sg_id, ips):
        LOG.info("update_security_group_members")
        pass

    def update_security_group_rules(self, sg_id, rules):
        LOG.info("update_security_group_rules id {} rules {}".format(sg_id, rules))
        pass

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        LOG.info("security_group_updated action type {} ids {} device {}".format(action_type,sec_group_ids,device_id))
        pass

import os

import eventlet

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    eventlet.monkey_patch()

from neutron.agent import firewall


class DvsSecurityGroupsDriver(firewall.FirewallDriver):
    def __init__(self, **kwargs):
        pass

    def prepare_port_filter(self, ports):
        pass

    def apply_port_filter(self, ports):
        # This driver does all of its processing during the prepare_port_filter call
        pass

    def update_port_filter(self, ports):
        pass

    def remove_port_filter(self, port_ids):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass

    @property
    def ports(self):
        return {}

    def update_security_group_members(self, sg_id, ips):
        pass

    def update_security_group_rules(self, sg_id, rules):
        pass

    def security_group_updated(self, action_type, sec_group_ids, device_id=None):
        pass

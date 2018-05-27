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
import weakref
from collections import defaultdict, Counter

import attr
import eventlet
import six
from netaddr import IPNetwork
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from oslo_concurrency import lockutils
from oslo_utils import timeutils
from pyVmomi import vim
from sqlalchemy.sql import distinct, or_

from networking_dvs.common import exceptions
from networking_dvs.common.constants import DVS, ATTR_ARGS
from networking_dvs.common.db import string_agg
from networking_dvs.common.util import stats
from networking_dvs.utils import security_group_utils as sg_util
from networking_dvs.utils import spec_builder as builder
from networking_dvs.utils.dvs_util import dvportgroup_name
from neutron.db import securitygroups_db as sg_db
from neutron.db.securitygroups_rpc_base import SecurityGroupServerRpcMixin
from neutron.db.securitygroups_rpc_base import DIRECTION_IP_PREFIX
from neutron.plugins.ml2.models import PortBindingLevel
from neutron import context as neutron_context

LOG = logging.getLogger(__name__)

ANY_IPV4 = IPNetwork('0.0.0.0/0', version=4)
ANY_IPV6 = IPNetwork('::/0', version=6)

_RULES_GAUGE = 'networking_dvs._apply_changed_sg_aggr.security_group_rules'
_RULES_TIMING = 'networking_dvs.security_group_delay'


@attr.s(**ATTR_ARGS)
class SecurityGroup(object):
    id_ = attr.ib()
    project_id = attr.ib(default=None)
    rules = attr.ib(default=attr.Factory(list))
    port_groups_by_dvs = attr.ib(
        default=attr.Factory(lambda: defaultdict(dict))
    )
    security_group_source_groups = attr.ib(default=attr.Factory(set))
    dependent_groups = attr.ib(default=attr.Factory(set))


class Any(object):
    def __init__(self, *answer): self.answer = answer

    def get(self, _): return self.answer


def _record_timing(_, oldest, tags):
    dt = timeutils.utcnow_ts(True) - oldest
    stats.timing(_RULES_TIMING, dt, tags=tags)


class DVSSecurityGroupRpc(SecurityGroupServerRpcMixin):
    def __init__(self, context=None, plugin_rpc=None,
                 v_center=None, config=None):
        super(DVSSecurityGroupRpc, self).__init__()
        self.context = context or neutron_context.get_admin_context()
        self.plugin_rpc = plugin_rpc
        self.v_center = v_center
        self.config = config
        self._security_groups = dict()  # id -> SecurityGroup
        self._pg_to_sgs = dict()
        provider_rules = {'network_id': None, 'security_group_rules': []}
        self._add_ingress_ra_rule(provider_rules, Any(ANY_IPV6))
        self._add_ingress_dhcp_rule(provider_rules, Any(ANY_IPV4, ANY_IPV6))
        self._provider_rules = sg_util.patch_sg_rules(
            provider_rules['security_group_rules']
        )
        self._to_refresh = dict()
        self._update_security_groups(self.context)

    ##
    #

    def _get_security_group_obj(self, security_group_id):
        sg = self._security_groups.get(security_group_id)

        if not sg:
            sg = SecurityGroup(id_=security_group_id)
            self._security_groups[security_group_id] = sg

        return sg

    def _find_security_groups_for_port_group(self, pg):
        if not pg:
            return
        sgs = self._pg_to_sgs.get(pg.name)
        if sgs:
            return sgs

        sgs = pg.description.split(',')
        if len(sgs[0]) == 36:
            return sgs
        else:
            sg_binding_sgid = sg_db.SecurityGroupPortBinding.security_group_id
            constraints=[sg_binding_sgid.startswith(sg_prefix)
                         for sg_prefix in sgs]
            for t in self._get_active_security_group_tuples(
                    self.context, constraints=or_(*constraints)):
                if len(t) == len(sgs):
                    self._pg_to_sgs[pg.name] = t
                    return t

    def _refresh_async(self):
        to_refresh = self._to_refresh
        self._to_refresh = dict()
        if to_refresh:
            self._update_security_groups(self.context, to_refresh)

    def _port_group_added_callback(self, dvs, pg):
        sg_ids = self._find_security_groups_for_port_group(pg)
        if not sg_ids:
            return

        now = timeutils.utcnow_ts(True)
        for sg_id in sg_ids:
            sg = self._get_security_group_obj(sg_id)
            LOG.debug("Storing %s for security-group %s", pg.name, sg_id)
            sg.port_groups_by_dvs[dvs.uuid][pg.name] = weakref.ref(pg)
            if sg_id not in self._to_refresh:
                self._to_refresh[sg_id] = now

        eventlet.spawn_after(0.25, self._refresh_async)

    def _port_group_removed_callback(self, dvs, pg):
        sg_ids = self._find_security_groups_for_port_group(pg)
        if not sg_ids:
            return

        dvs_uuid = dvs.uuid
        for security_group_id in sg_ids:
            self._remove_port_group_from_security_group(security_group_id,
                                                        dvs_uuid, pg.name)

        self._pg_to_sgs.pop(pg.name, None)

    def _remove_port_group_from_security_group(self, security_group_id,
                                               dvs_uuid, pg_name):
        sg = self._security_groups.get(security_group_id)
        if not sg:
            return

        sg.port_groups_by_dvs[dvs_uuid].pop(pg_name, None)

        for ref_id in sg.security_group_source_groups:
            ref_sg = self._security_groups.get(ref_id)
            if ref_sg:
                ref_sg.dependent_groups.discard(security_group_id)

        if not sg.port_groups_by_dvs[dvs_uuid]:
            sg.port_groups_by_dvs.pop(dvs_uuid, None)

        if not sg.port_groups_by_dvs and not sg.dependent_groups:
            self._security_groups.pop(sg.id_, None)

    @enginefacade.reader
    def _setup_port_groups(self, context, security_group_ids=None):
        local_security_groups = set()
        for security_groups in self._get_active_security_group_tuples(
                context, security_group_ids=security_group_ids):
            sg_set = sg_util.security_group_set({'security_groups':
                                                     security_groups})
            for dvs_uuid, dvs in six.iteritems(self.v_center.uuid_dvs_map):
                dvs.port_group_added.add(self._port_group_added_callback)
                dvs.port_group_removed.add(self._port_group_removed_callback)
                port_group_name = dvportgroup_name(dvs_uuid, sg_set)
                for security_group_id in security_groups:
                    local_security_groups.add(security_group_id)
                    sg = self._get_security_group_obj(security_group_id)
                    self._pg_to_sgs[port_group_name] = security_groups
                    # We will have to fetch that object later
                    sg.port_groups_by_dvs[dvs_uuid][port_group_name] = None

        return local_security_groups

    @lockutils.synchronized(__name__)
    @enginefacade.reader
    def _update_security_groups(self, context, timed_security_group_ids=None):
        if timed_security_group_ids is None:
            security_group_ids = None
        else:
            security_group_ids = timed_security_group_ids.keys()

        ids = self._setup_port_groups(context, security_group_ids)
        LOG.debug("Local Security-Group ids: %s", ids)
        if not ids:
            return

        to_configure = set()
        once = True  # Only refresh port-group once
        for sg_id, rules in six.iteritems(self._get_rules(context, ids)):
            sg = self._security_groups[sg_id]
            sg.project_id = rules['tenant_id']

            current_source_groups = set(rules['security_group_source_groups'])
            old_source_groups = sg.security_group_source_groups
            for ref_id in current_source_groups - old_source_groups:
                referenced = self._get_security_group_obj(ref_id)
                referenced.dependent_groups.add(sg_id)
            for ref_id in old_source_groups - current_source_groups:
                referenced = self._get_security_group_obj(ref_id)
                referenced.dependent_groups.pop(sg_id)
            sg.security_group_source_groups = current_source_groups

            sg.rules = sg_util.patch_sg_rules(rules['security_group_rules'])
            dvs_uuids = list(six.iterkeys(sg.port_groups_by_dvs))
            for dvs_uuid in dvs_uuids:
                dvs = self.v_center.uuid_dvs_map.get(dvs_uuid)
                if not dvs:
                    LOG.warning("No DVS for %s", dvs_uuid)
                    continue

                port_groups = sg.port_groups_by_dvs.get(dvs_uuid)
                names = list(six.iterkeys(port_groups))
                for pg_name in names:
                    port_group = port_groups.get(pg_name)
                    if port_group:
                        try:
                            to_configure.add((dvs, pg_name, port_group))
                        except TypeError:
                            LOG.debug("Port-Group %s is gone", pg_name)
                            pass
                    else:
                        try:
                            port_group = weakref.ref(dvs.get_portgroup_by_name(
                                pg_name, refresh_if_missing=once))
                            port_groups[pg_name] = port_group
                            to_configure.add((dvs,
                                              pg_name,
                                              port_group))
                        except exceptions.PortGroupNotFound:
                            once = False
                            LOG.warn("Could not find port-group %s "
                                     "for security-group %s",
                                     pg_name, sg_id)
                            port_groups.pop(pg_name, None)
                            continue
                        except TypeError:
                            LOG.debug("Port-Group %s is gone", pg_name)
                            continue

        for dvs, pg_name, port_group in to_configure:
            port_group = port_group()
            if not port_group:
                sg_ids = self._pg_to_sgs.get(pg_name)
                if not sg_ids:
                    continue

                # Port-group is gone now, so we clean it up
                dvs_uuid = dvs.uuid
                for security_group_id in sg_ids:
                    self._remove_port_group_from_security_group(
                        security_group_id, dvs_uuid, pg_name)
                self._pg_to_sgs.pop(pg_name, None)
            else:
                sg_ids = self._find_security_groups_for_port_group(port_group)
                if not sg_ids:
                    continue

                port_config, project_id = self.compile_rules(sg_ids)

                vlan = self._select_default_vlan(port_group)
                if vlan:
                    port_config.vlan = vlan

                sg_tags = ['port_group:' + pg_name,
                           'security_group:' + '-'.join(sg_ids),
                           'host:' + self.config.host]

                if project_id:
                    sg_tags.append('project_id:' + project_id),

                old_task = port_group.task
                new_task = eventlet.spawn(dvs.update_dvportgroup,
                                          port_group,
                                          port_config,
                                          sync=old_task)

                if timed_security_group_ids:
                    oldest = None
                    for sg_id in sg_ids:
                        ts = timed_security_group_ids.get(sg_id)
                        if not ts:
                            continue
                        if not oldest or ts < oldest:
                            oldest = ts
                    if oldest:
                        new_task.link(_record_timing, oldest, sg_tags)

                port_group.task = new_task

                filter_config = port_config.filterPolicy.filterConfig[0]
                num_rules = len(filter_config.trafficRuleset.rules)
                stats.gauge(_RULES_GAUGE, num_rules, tags=sg_tags)

    def compile_rules(self, security_group_ids):
        port_config = vim.VMwareDVSPortSetting()
        if not security_group_ids:
            return port_config, None

        rules = set(self._provider_rules)
        project_id = None
        missing = False
        for security_group_id in security_group_ids:
            sg = self._security_groups.get(security_group_id)
            if not sg:
                LOG.warn("Have not loaded security-group %s",
                         security_group_id)
                missing = True
            project_id = project_id or sg.project_id
            rules.update(sg.rules)

        if missing:
            port_config.filterPolicy = builder.filter_policy([])
        else:
            sg_rules = sg_util.consolidate_rules(rules)
            port_config.filterPolicy = sg_util.compile_filter_policy(
                sg_rules=sg_rules)

        return port_config, project_id

    @staticmethod
    def _select_default_vlan(port_group):
        if not port_group or not port_group.ports:
            return None

        ports = six.viewvalues(port_group.ports)

        # Ensure that we do not set a default,
        # if any port is not configured yet individually
        if not all(port.get('port_desc')
                   and port.get('port_desc').vlan_id for port in ports):
            return None

        vlans = Counter(port.get('segmentation_id') for port in ports)

        if None in vlans:
            return None

        return vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec(
            vlanId=vlans.most_common(1)[0][0])

    ##
    # Called as RPC

    def security_groups_rule_updated(self, security_groups):
        """Callback for security group rule update.

        :param security_groups: list of updated security_groups
        """
        if not security_groups:
            return

        now = None
        for sg_id in security_groups:
            if not sg_id in self._to_refresh:
                now = now or timeutils.utcnow_ts(True)
                self._to_refresh[sg_id] = now

        # This way, we can accumulated some changes
        eventlet.spawn_after(0.25, self._refresh_async)

    def security_groups_member_updated(self, security_groups):
        """Callback for security group member update.

        :param security_groups: list of updated security_groups
        """
        if not security_groups:
            return

        dependent_groups = [group
                            for sg_id in security_groups
                            if sg_id in self._security_groups
                            for group in
                            self._security_groups.get(sg_id).dependent_groups
                            ]

        if not dependent_groups:
            return

        now = None
        for sg_id in dependent_groups:
            if not sg_id in self._to_refresh:
                now = now or timeutils.utcnow_ts(True)
                self._to_refresh[sg_id] = now

        # This way, we can accumulated some changes
        eventlet.spawn_after(0.25, self._refresh_async)

    def security_groups_provider_updated(self, devices_to_update):
        """Callback for security group provider update.
        :param devices_to_update: list of devices to update
        """
        if not devices_to_update:
            return

    ####
    # end of RPC-API

    @enginefacade.reader
    def _get_active_security_group_tuples(self, context,
                                          security_group_ids=None,
                                          constraints=None):
        session = context.session
        sg_binding_port = sg_db.SecurityGroupPortBinding.port_id
        sg_binding_sgid = sg_db.SecurityGroupPortBinding.security_group_id

        security_groups = []
        separator = ','

        query = session.query(
            distinct(string_agg(sg_binding_sgid, separator, sg_binding_sgid))
            ).join(PortBindingLevel,
                   PortBindingLevel.port_id == sg_binding_port).\
            filter(PortBindingLevel.host == self.config.host,
                   PortBindingLevel.driver == DVS,
                   PortBindingLevel.segment_id.isnot(None),  # Unbound ports
                   )

        if constraints is not None:
            query = query.filter(constraints)

        if security_group_ids is not None:
            subquery = session.query(sg_binding_port).\
                join(PortBindingLevel,
                     PortBindingLevel.port_id == sg_binding_port). \
                filter(PortBindingLevel.host == self.config.host,
                   PortBindingLevel.driver == DVS,
                   PortBindingLevel.segment_id.isnot(None),  # Unbound ports
                   sg_binding_sgid.in_(security_group_ids)
                   ).subquery()
            query = query.filter(sg_binding_port.in_(subquery))

        for sgs, in query.group_by(sg_binding_port):
            security_groups.append(sgs.split(separator))

        return security_groups

    ##
    # We hopefully can move the following two functions into neutron

    @staticmethod
    def _select_rules_for_security_groups(context, security_groups):
        if not security_groups:
            return []

        sg_id = sg_db.SecurityGroup.id
        tenant_id = sg_db.SecurityGroup.tenant_id
        sgr_sgid = sg_db.SecurityGroupRule.security_group_id

        query = context.session.query(sg_id,
                                      tenant_id,
                                      sg_db.SecurityGroupRule)
        query = query.join(sg_db.SecurityGroupRule,
                           sgr_sgid == sg_id)
        query = query.filter(sg_id.in_(security_groups))

        return query.all()

    def _get_rules(self, context, security_groups):
        if not security_groups:
            return {}

        rules_in_db = self._select_rules_for_security_groups(context,
                                                             security_groups)
        security_groups_result = {}
        for (sg_id, tenant_id, rule_in_db) in rules_in_db:
            security_group = security_groups_result.get(sg_id)
            if not security_group:
                security_group = {
                    'security_group_source_groups': [],
                    'security_group_rules': [],
                    'security_groups': [sg_id],
                    'tenant_id': tenant_id
                }
                security_groups_result[sg_id] = security_group

            direction = rule_in_db['direction']
            rule_dict = {
                # 'security_group_id' Removed, as it isn't used
                'direction': direction,
                'ethertype': rule_in_db['ethertype'],
            }
            for key in ('protocol', 'port_range_min', 'port_range_max',
                        'remote_ip_prefix', 'remote_group_id'):
                if rule_in_db.get(key) is not None:
                    if key == 'remote_ip_prefix':
                        direction_ip_prefix = DIRECTION_IP_PREFIX[direction]
                        rule_dict[direction_ip_prefix] = rule_in_db[key]
                        continue
                    rule_dict[key] = rule_in_db[key]
            security_group['security_group_rules'].append(rule_dict)

        return self._convert_remote_group_id_to_ip_prefix(
            context, security_groups_result)

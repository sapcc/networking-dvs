# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import bisect
import copy
from collections import defaultdict

import attr
import six
from eventlet import sleep
from ipaddress import IPv4Network, IPv6Network, collapse_addresses, ip_network
from oslo_log import log
from pyVmomi import vim

from networking_dvs.common import constants as dvs_const
from networking_dvs.common.util import optional_attr
from networking_dvs.utils import spec_builder as builder

try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _LI as _

LOG = log.getLogger(__name__)

_ANY_IPS = {
    'IPv4': ip_network(six.u('0.0.0.0/0'), strict=False),
    'IPv6': ip_network(six.u('::/0'), strict=False)
}


def _to_ip_network(x):
    if isinstance(x, (IPv4Network, IPv6Network)):
        return x
    else:
        return ip_network(six.text_type(x), strict=False)


@attr.s(**dvs_const.ATTR_ARGS)
class Rule(object):
    direction = attr.ib(default=None)
    ethertype = attr.ib(default=None)
    protocol = attr.ib(default=None)

    dest_ip_prefix = attr.ib(default=None,
                             convert=optional_attr(_to_ip_network))
    port_range_min = attr.ib(default=0, convert=int)
    port_range_max = attr.ib(default=0, convert=int)

    source_ip_prefix = attr.ib(default=None,
                               convert=optional_attr(_to_ip_network))
    source_port_range_min = attr.ib(default=0, convert=int)
    source_port_range_max = attr.ib(default=0, convert=int)

    @property
    def ip_prefix(self):
        if self.direction == 'ingress':
            return self.source_ip_prefix
        else:
            return self.dest_ip_prefix

    @ip_prefix.setter
    def ip_prefix(self, value):
        if self.direction == 'ingress':
            self.source_ip_prefix = value
        else:
            self.dest_ip_prefix = value


@attr.s(**dvs_const.ATTR_ARGS)
class SgAggr(object):
    pg = attr.ib(default=None)
    rules = attr.ib(default=attr.Factory(dict))
    ports_to_assign = attr.ib(default=attr.Factory(list))
    dirty = attr.ib(default=True)
    project_id = attr.ib(default=None, hash=False, cmp=False)
    task = attr.ib(default=None, hash=False, cmp=False)


@six.add_metaclass(abc.ABCMeta)
class TrafficRuleBuilder(object):
    action = vim.dvs.TrafficRule.AcceptAction
    direction = 'both'
    reverse_class = None
    _backward_port_range = (None, None)
    _port_range = (None, None)

    def __init__(self, ethertype, protocol, name=None):
        self.rule = vim.DvsTrafficRule()
        self.rule.action = self.action()

        self.ip_qualifier = vim.DvsIpNetworkRuleQualifier()

        self.ethertype = ethertype
        if ethertype:
            self.cidr = _ANY_IPS[ethertype]

        self.protocol = protocol
        if protocol:
            protocol_number = dvs_const.PROTOCOL.get(protocol, None)
            if not protocol_number:
                raise ValueError("Unknown protocol %s", protocol)
            int_exp = vim.IntExpression()
            int_exp.value = protocol_number
            self.ip_qualifier.protocol = int_exp

        self.name = name

    def reverse(self, cidr_bool):
        """Returns reversed rule"""
        name = 'reversed ' + (self.name or '')
        rule = self.reverse_class(self.ethertype,
                                  self.protocol, name=name.strip())
        if cidr_bool:
            rule.cidr = self.cidr
        elif self.ethertype:
            rule.cidr = _ANY_IPS[self.ethertype]
        rule.port_range = self.backward_port_range
        rule.backward_port_range = self.port_range
        return rule

    def build(self, sequence):
        self.rule.qualifier = [self.ip_qualifier]
        self.rule.direction = self.direction
        self.rule.sequence = sequence
        self.name = '%d. %s' % (sequence, self.name or '')
        self.name = self.name.strip()
        self.rule.description = self.name.strip()
        return self.rule

    @property
    def port_range(self):
        return self._port_range

    @property
    def backward_port_range(self):
        return self._backward_port_range

    @property
    def cidr(self):
        return self._cidr

    def _port_range_spec(self, begin, end):
        if begin is None \
                or begin == 0 and end == 0 \
                or begin <= 1 and end >= dvs_const.MAX_EPHEMERAL_PORT:
            return None

        if begin == end:
            result = vim.DvsSingleIpPort()
            result.portNumber = begin
        else:
            result = vim.DvsIpPortRange()
            result.startPortNumber = begin
            result.endPortNumber = end
        return result

    def _cidr_spec(self, cidr):
        if not cidr:
            return None

        if cidr.prefixlen <= 0:
            cidr = _ANY_IPS[self.ethertype]
            result = vim.IpRange()
            result.addressPrefix = str(cidr.network_address)
            result.prefixLength = 0
        elif cidr.prefixlen < cidr.max_prefixlen:
            result = vim.IpRange()
            result.addressPrefix = str(cidr.network_address)
            result.prefixLength = cidr.prefixlen
        else:
            result = vim.SingleIp()
            result.address = str(cidr.network_address)

        return result

    def _has_port(self, min_port):
        if min_port:
            if self.protocol == 'icmp':
                LOG.info(_('Vmware dvs driver does not support '
                           '"type" and "code" for ICMP protocol.'))
                return False
            else:
                return True
        else:
            return False


class IngressRule(TrafficRuleBuilder):
    direction = 'incomingPackets'

    def __init__(self, ethertype, protocol, name=None):
        super(IngressRule, self).__init__(
            ethertype, protocol, name)
        self.reverse_class = EgressRule

    @TrafficRuleBuilder.port_range.setter
    def port_range(self, range_):
        begin, end = self._port_range = range_
        spec = self._port_range_spec(begin, end)
        if spec:
            self.ip_qualifier.destinationIpPort = spec

    @TrafficRuleBuilder.backward_port_range.setter
    def backward_port_range(self, range_):
        begin, end = self._backward_port_range = range_
        spec = self._port_range_spec(begin, end)
        if spec:
            self.ip_qualifier.sourceIpPort = spec

    @TrafficRuleBuilder.cidr.setter
    def cidr(self, cidr):
        self._cidr = cidr
        spec = self._cidr_spec(cidr)
        if spec:
            self.ip_qualifier.sourceAddress = spec


class EgressRule(TrafficRuleBuilder):
    direction = 'outgoingPackets'

    def __init__(self, ethertype, protocol, name=None):
        super(EgressRule, self).__init__(
            ethertype, protocol, name)
        self.reverse_class = IngressRule

    @TrafficRuleBuilder.port_range.setter
    def port_range(self, range_):
        begin, end = self._port_range = range_
        spec = self._port_range_spec(begin, end)
        if spec:
            self.ip_qualifier.destinationIpPort = spec

    @TrafficRuleBuilder.backward_port_range.setter
    def backward_port_range(self, range_):
        begin, end = self._backward_port_range = range_
        spec = self._port_range_spec(begin, end)
        if spec:
            self.ip_qualifier.sourceIpPort = spec

    @TrafficRuleBuilder.cidr.setter
    def cidr(self, cidr):
        self._cidr = cidr
        spec = self._cidr_spec(cidr)
        if spec:
            self.ip_qualifier.destinationAddress = spec


class DropAllRule(TrafficRuleBuilder):
    action = vim.DvsDropNetworkRuleAction


def compile_filter_policy(sg_rules=None, hashed_rules=None,
                          filter_config_key=None):
    hashed_rules = hashed_rules or {}
    sg_rules = sg_rules or []
    rules = []
    seq = 0
    reverse_seq = len(sg_rules) * 10
    sleep_counter = 500
    for rule_info in sg_rules:
        if rule_info in hashed_rules:
            rule, reverse_rule = hashed_rules[rule_info]
            built_rule = copy.copy(rule)
            built_reverse_rule = copy.copy(reverse_rule)
            built_rule.description = '%d.' % seq
            built_rule.sequence = seq
            built_reverse_rule.description = '%d. rev %d' % (
                reverse_seq, seq)
            built_reverse_rule.sequence = reverse_seq
        else:
            rule = _create_rule(rule_info, name='')
            built_rule = rule.build(seq)
            cidr_revert = not _rule_excepted(rule)
            reverse_rule = rule.reverse(cidr_revert)
            built_reverse_rule = reverse_rule.build(reverse_seq)
            hashed_rules[rule_info] = (built_rule, built_reverse_rule)

        rules.extend([built_rule, built_reverse_rule])
        seq += 10
        reverse_seq += 10
        sleep_counter -= 1
        if sleep_counter <= 0:
            sleep_counter = 500
            sleep(0)

    seq = len(rules) * 10
    for protocol in dvs_const.PROTOCOL.keys():
        rules.append(DropAllRule(None, protocol,
                                 name='drop all').build(seq))
        seq += 10

    return builder.filter_policy(rules, filter_config_key=filter_config_key)


def port_configuration(port_key, sg_rules=None, hashed_rules=None,
                       version=None, filter_config_key=None):
    setting = vim.VMwareDVSPortSetting()
    setting.filterPolicy = compile_filter_policy(
        sg_rules=sg_rules,
        hashed_rules=hashed_rules,
        filter_config_key=filter_config_key)
    spec = builder.port_config_spec(setting=setting, version=version)
    spec.key = port_key

    return spec


def _rule_excepted(rule):
    if rule.direction == 'incomingPackets' and rule.protocol == 'udp':
        if (rule.ethertype == 'IPv4' and rule.port_range == (68, 68) and
                rule.backward_port_range == (67, 67)):
            return True
        if (rule.ethertype == 'IPv6' and rule.port_range == (546, 546) and
                rule.backward_port_range == (547, 547)):
            return True
    return False


def _create_rule(rule_info, ip=None, name=None):
    if rule_info.direction == 'ingress':
        rule_class = IngressRule
        cidr = rule_info.source_ip_prefix
        source_port_range_min_default = 0
    else:
        rule_class = EgressRule
        cidr = rule_info.dest_ip_prefix
        source_port_range_min_default = dvs_const.MIN_EPHEMERAL_PORT

    try:
        rule = rule_class(
            ethertype=rule_info.ethertype,
            protocol=rule_info.protocol,
            name=name
        )
        rule.cidr = ip or cidr

        if rule_info.protocol in ('tcp', 'udp', None):
            rule.port_range = (rule_info.port_range_min,
                               rule_info.port_range_max)
            rule.backward_port_range = (
                rule_info.source_port_range_min or
                source_port_range_min_default,
                rule_info.source_port_range_max or
                dvs_const.MAX_EPHEMERAL_PORT)
    except (AttributeError, KeyError):
        return None

    return rule


def patch_sg_rules(security_group_rules):
    patched_rules = []

    for rule in security_group_rules:
        # Remove data, which is purely informational (at this point)
        rule.pop('security_group_id', None)
        rule.pop('remote_group_id', None)

        if rule.get('direction') == 'egress' \
                and rule.get('ethertype') in ['IPv4', 'IPv6'] \
                and rule.get('dest_ip_prefix') is None:
            rule['dest_ip_prefix'] = _ANY_IPS[rule.get('ethertype')]

        protocol = rule.get('protocol', None)
        if protocol:
            # Filter out unsupported protocols
            if protocol.lower() in dvs_const.PROTOCOL:
                patched_rules.append(Rule(**rule))
        else:
            # We need to multiply the rules here,
            # because we cannot specify a port-range without
            # also specifying the protocol to be either tcp or udp
            for proto in ['icmp', 'udp', 'tcp']:
                new_rule = Rule(**rule)
                new_rule.protocol = proto
                if proto != 'icmp':
                    new_rule.port_range_min = 0
                    new_rule.port_range_max = 65535
                patched_rules.append(new_rule)
        sleep(0)

    return patched_rules


def security_group_set(port):
    """
    Returns the security group set for a port.

    A security group set is a comma-separated,
    sorted list of security group ids
    """
    network_id = port.get('network_id')

    if not network_id:
        LOG.warning("No network for port %s", port['id'])
        return None

    security_groups = port.get('security_groups')
    if not security_groups :
        return network_id

    # There are 36 chars to a uuid, and in the description fits 255 chars
    # The first 37 chars will be used for the network id, though
    security_groups = sorted(security_groups)
    num_groups = len(security_groups)
    if num_groups < 5:  # Up to 5 fit in full length
        sgs = ",".join(security_groups)
    elif num_groups < 12:  # Up to eleven in split in the "middle"
        sgs = ",".join([g[:18] for g in security_groups])
    elif num_groups < 25:
        sgs = ",".join([g[:8] for g in security_groups])
    else:
        LOG.warning("Too many security groups for port %s", port['id'])
        return None

    return ":".join([network_id, sgs])


def _consolidate_rules(rules):
    grouped = defaultdict(list)
    for rule in rules:
        id_ = (rule.direction,
               rule.ethertype,
               rule.protocol,
               rule.port_range_min,
               rule.port_range_max,
               rule.source_port_range_min,
               rule.source_port_range_max)
        grouped[id_].append(rule)

    for rule_set, rules in six.iteritems(grouped):
        collapsed = sorted(collapse_addresses(
            [rule.ip_prefix for rule in rules if rule.ip_prefix]))
        for rule in rules:
            try:
                ip_prefix = rule.ip_prefix
                if not ip_prefix:
                    yield rule
                else:
                    idx = bisect.bisect(collapsed, ip_prefix) - 1
                    collapsed_address = collapsed[idx]
                    if not collapsed_address or collapsed_address == ip_prefix:
                        yield rule
                    elif ip_prefix.network_address == \
                            collapsed_address.network_address:
                        new_rule = copy.copy(rule)
                        new_rule.ip_prefix = collapsed_address
                        yield new_rule
                    else:
                        # Dropping rule, as it is handled by the case before
                        pass
            except IndexError:
                yield rule


def _consolidate_ipv4_6(rules):
    grouped = defaultdict(list)
    for rule in rules:  # Group by anything but the ethertype
        if rule.ip_prefix and rule.ip_prefix.prefixlen > 0:
            yield rule
        else:
            id_ = (rule.direction, rule.protocol, rule.port_range_min,
                   rule.port_range_max,
                   rule.source_port_range_min, rule.source_port_range_max)
            grouped[id_].append(rule)

    for ruleset in six.itervalues(grouped):
        # Cannot be zero
        if len(ruleset) == 1:
            yield ruleset[0]
        else:
            # The only two ethertypes we have are IPv4 and IPv6
            items = attr.asdict(ruleset[0])
            # We drop the ethertype and prefixes, which will result in any
            # IPv4 or IPv6 address
            items.pop('ethertype')
            items.pop('source_ip_prefix')
            items.pop('dest_ip_prefix')
            yield Rule(**items)


def consolidate_rules(rules):
    return sorted(_consolidate_ipv4_6(_consolidate_rules(rules)))


def get_rules(sg_aggr):
    """
    Returns a list of the rules stored in a security group aggregate
    """
    return consolidate_rules(six.iterkeys(sg_aggr.rules))

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
from ipaddress import ip_network, collapse_addresses
from neutron.i18n import _LI
from oslo_log import log

from networking_dvs.common import constants as dvs_const
from networking_dvs.utils import spec_builder

LOG = log.getLogger(__name__)

try:
    from attr.converters import optional as _optional
except ImportError:
    def _optional(converter):
        def wrap(value):
            if value is None:
                return None
            return converter(value)

        return wrap

_ANY_IPS = {
    'IPv4': ip_network(u'0.0.0.0/0'),
    'IPv6': ip_network(u'::/0')
}


@attr.s(cmp=True, hash=True)
class Rule(object):
    direction = attr.ib(default=None)
    ethertype = attr.ib(default=None)
    protocol = attr.ib(default=None)

    dest_ip_prefix = attr.ib(default=None, convert=_optional(lambda x: ip_network(x, strict=False)))
    port_range_min = attr.ib(default=0, convert=int)
    port_range_max = attr.ib(default=0, convert=int)

    source_ip_prefix = attr.ib(default=None, convert=_optional(lambda x: ip_network(x, strict=False)))
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


@attr.s(cmp=True, hash=True)
class SgAggr(object):
    pg_key = attr.ib(default=None)
    vlan = attr.ib(default=None)
    rules = attr.ib(default=attr.Factory(dict))
    ports_to_assign = attr.ib(default=attr.Factory(list))
    dirty = attr.ib(default=True)


class PortConfigSpecBuilder(spec_builder.SpecBuilder):
    def __init__(self, spec_factory):
        super(PortConfigSpecBuilder, self).__init__(spec_factory)
        self.rule_obj = self.factory.create('ns0:DvsTrafficRule')

    def traffic_rule(self):
        return copy.copy(self.rule_obj)

    def create_spec(self, spec_type):
        return self.factory.create(spec_type)


@six.add_metaclass(abc.ABCMeta)
class TrafficRuleBuilder(object):
    action = 'ns0:DvsAcceptNetworkRuleAction'
    direction = 'both'
    reverse_class = None
    _backward_port_range = (None, None)
    _port_range = (None, None)

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        self.spec_builder = spec_builder

        self.rule = spec_builder.traffic_rule()
        self.rule.action = self.spec_builder.create_spec(self.action)

        self.ip_qualifier = self.spec_builder.create_spec(
            'ns0:DvsIpNetworkRuleQualifier')

        self.ethertype = ethertype
        if ethertype:
            self.cidr = _ANY_IPS[ethertype]

        self.protocol = protocol
        if protocol:
            protocol_number = dvs_const.PROTOCOL.get(protocol, None)
            if not protocol_number:
                raise ValueError("Unknown protocol %s", protocol)
            int_exp = self.spec_builder.create_spec('ns0:IntExpression')
            int_exp.value = protocol_number
            self.ip_qualifier.protocol = int_exp

        self.name = name

    def reverse(self, cidr_bool):
        """Returns reversed rule"""
        name = 'reversed ' + (self.name or '')
        rule = self.reverse_class(self.spec_builder, self.ethertype,
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
            result = self.spec_builder.create_spec('ns0:DvsSingleIpPort')
            result.portNumber = begin
        else:
            result = self.spec_builder.create_spec('ns0:DvsIpPortRange')
            result.startPortNumber = begin
            result.endPortNumber = end
        return result

    def _cidr_spec(self, cidr):
        if not cidr:
            return None

        if cidr.prefixlen <= 0:
            cidr = _ANY_IPS[self.ethertype]
            result = self.spec_builder.create_spec('ns0:IpRange')
            result.addressPrefix = str(cidr.network_address)
            result.prefixLength = '0'  # Not just zero, because it evaluates to false and will be dropped
        elif cidr.prefixlen < cidr.max_prefixlen:
            result = self.spec_builder.create_spec('ns0:IpRange')
            result.addressPrefix = str(cidr.network_address)
            result.prefixLength = cidr.prefixlen
        else:
            result = self.spec_builder.create_spec('ns0:SingleIp')
            result.address = str(cidr.network_address)

        return result

    def _has_port(self, min_port):
        if min_port:
            if self.protocol == 'icmp':
                LOG.info(_LI('Vmware dvs driver does not support '
                             '"type" and "code" for ICMP protocol.'))
                return False
            else:
                return True
        else:
            return False


class IngressRule(TrafficRuleBuilder):
    direction = 'incomingPackets'

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        super(IngressRule, self).__init__(
            spec_builder, ethertype, protocol, name)
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

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        super(EgressRule, self).__init__(
            spec_builder, ethertype, protocol, name)
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
    action = 'ns0:DvsDropNetworkRuleAction'


def build_port_rules(builder, ports, hashed_rules=None):
    port_config_list = []
    hashed_rules = hashed_rules or {}
    for port in ports:
        port_desc = port.get('port_desc', None)
        if port_desc:
            key = port_desc.port_key
            filter_config_key = port_desc.filter_config_key
            version = port_desc.config_version
        else:
            key = port.get('binding:vif_details', {}).get('dvs_port_key')
            filter_config_key = None
            version = None

        if key:
            port_config = port_configuration(
                builder, key, port['security_group_rules'], hashed_rules,
                version=version,
                filter_config_key=filter_config_key)
            port_config_list.append(port_config)
    return port_config_list


def get_port_rules(client_factory, ports):
    if not ports:
        return

    builder = PortConfigSpecBuilder(client_factory)
    hashed_rules = {}
    return build_port_rules(builder, ports, hashed_rules)


def filter_policy(builder, sg_rules=None, hashed_rules=None, filter_config_key=None):
    hashed_rules = hashed_rules or {}
    sg_rules = sg_rules or []
    rules = []
    seq = 0
    reverse_seq = len(sg_rules) * 10
    for rule_info in sg_rules:
        if rule_info in hashed_rules:
            rule, reverse_rule = hashed_rules[rule_info]
            built_rule = copy.copy(rule)
            built_reverse_rule = copy.copy(reverse_rule)
            built_rule.description = '%d. regular' % seq
            built_rule.sequence = seq
            built_reverse_rule.description = '%s. reversed %s' % (
                str(reverse_seq), built_rule.description)
            built_reverse_rule.sequence = reverse_seq
        else:
            rule = _create_rule(builder, rule_info, name='regular')
            built_rule = rule.build(seq)
            cidr_revert = not _rule_excepted(rule)
            reverse_rule = rule.reverse(cidr_revert)
            built_reverse_rule = reverse_rule.build(reverse_seq)
            hashed_rules[rule_info] = (built_rule, built_reverse_rule)

        rules.extend([built_rule, built_reverse_rule])
        seq += 10
        reverse_seq += 10

    seq = len(rules) * 10
    for protocol in dvs_const.PROTOCOL.keys():
        rules.append(DropAllRule(builder, None, protocol,
                                 name='drop all').build(seq))
        seq += 10

    return builder.filter_policy(rules, filter_config_key=filter_config_key)


def port_configuration(builder, port_key, sg_rules=None, hashed_rules=None, version=None, filter_config_key=None):
    setting = builder.port_setting()
    setting.filterPolicy = filter_policy(builder, sg_rules=sg_rules, hashed_rules=hashed_rules,
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


def _create_rule(builder, rule_info, ip=None, name=None):
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
            spec_builder=builder,
            ethertype=rule_info.ethertype,
            protocol=rule_info.protocol,
            name=name
        )
        rule.cidr = ip or cidr

        if rule_info.protocol in ('tcp', 'udp', None):
            rule.port_range = (rule_info.port_range_min,
                               rule_info.port_range_max)
            rule.backward_port_range = (
                rule_info.source_port_range_min or source_port_range_min_default,
                rule_info.source_port_range_max or dvs_const.MAX_EPHEMERAL_PORT)
    except KeyError:
        return None

    return rule


def _patch_sg_rules(security_group_rules):
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

    return patched_rules


def security_group_set(port):
    """
    Returns the security group set for a port.

    A security group set is a comma-separated,
    sorted list of security group ids
    """
    return ",".join(sorted(port['security_groups']))


def apply_rules(rules, sg_aggr, decrement=False):
    """
    Apply a set of security group rules to a security group aggregate structure
    {
        "rules": { "comparable_rule": count }
        "dirty": True|False
    """

    for rule in rules:
        if rule in sg_aggr.rules:
            count = sg_aggr.rules[rule]
            if decrement:
                count -= 1
                if count == 0:
                    del sg_aggr.rules[rule]
                    sg_aggr.dirty = True
                    continue
            else:
                count += 1
            sg_aggr.rules[rule] = count
        else:
            sg_aggr.rules[rule] = 1
            sg_aggr.dirty = True


def _consolidate_rules(rules):
    grouped = defaultdict(list)
    for rule in rules:
        id_ = (rule.direction, rule.ethertype, rule.protocol, rule.port_range_min, rule.port_range_max,
               rule.source_port_range_min, rule.source_port_range_max)
        grouped[id_].append(rule)

    for rule_set, rules in six.iteritems(grouped):
        collapsed = sorted(collapse_addresses([rule.ip_prefix for rule in rules if rule.ip_prefix]))

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
                    elif ip_prefix.network_address == collapsed_address.network_address:
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
            id_ = (rule.direction, rule.protocol, rule.port_range_min, rule.port_range_max,
                   rule.source_port_range_min, rule.source_port_range_max)
            grouped[id_].append(rule)

    for ruleset in six.itervalues(grouped):
        # Cannot be zero
        if len(ruleset) == 1:
            yield ruleset[0]
        else:
            # The only two ethertypes we have are IPv4 and IPv6
            items = attr.asdict(ruleset[0])
            # We drop the ethertype and prefixes, which will result in any IPv4 or IPv6 address
            items.pop('ethertype')
            items.pop('source_ip_prefix')
            items.pop('dest_ip_prefix')
            yield Rule(**items)


def get_rules(sg_aggr):
    """
    Returns a list of the rules stored in a security group aggregate
    """
    return sorted(_consolidate_ipv4_6(_consolidate_rules(six.iterkeys(sg_aggr.rules))))

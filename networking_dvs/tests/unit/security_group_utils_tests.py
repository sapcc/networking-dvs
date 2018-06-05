"""Tests for security group utils"""

import mock
import six
import unittest
from oslo_utils import uuidutils
import testtools
from pyVmomi import vim, vmodl
from oslo_config import fixture as fixture_config
from oslo_log import log as logging
from networking_dvs.utils import security_group_utils as sg_utils
from ipaddress import ip_network, IPv4Network, IPv6Network
LOG = logging.getLogger(__name__)

FAKE_SGID = 'fake_sgid'
OTHER_SGID = 'other_sgid'


class SecurityGroupUtilsTest(testtools.TestCase):

    def setUp(self):
        super(SecurityGroupUtilsTest, self).setUp()
        self.ipv4_ethertype = 'IPv4'
        self.ipv6_ethertype = 'IPv6'
        self.FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
                       'IPv6': '2001:db8::/64'}

    def get_fake_ingress_rule(self):
        ingress_rule = sg_utils.IngressRule(self.ipv4_ethertype, 'tcp')
        return ingress_rule

    def get_fake_egress_rule(self):
        egress_rule = sg_utils.EgressRule(self.ipv4_ethertype, 'tcp')
        return egress_rule

    def get_fake_ipv4_network(self, address=None, netmask='255.255.255.255'):
        ip_addr = address or six.u(netmask)
        return ip_network(ip_addr)

    def get_fake_ipv6_network(self, address=None):
        ip_addr = address or six.u('::/0')
        return ip_network(ip_addr)

    def _get_fake_rule(self, rule_id=None,
                      direction=None, ethertype=None,
                      protocol=None, port_range_min=0, port_range_max=0,
                      source_ip_prefix=None,source_port_range_min=0,
                      source_port_range_max=65535):

        rule = sg_utils.Rule(ethertype, protocol)
        rule.ethertype = ethertype
        rule.direction = direction
        rule.protocol = protocol
        rule.source_ip_prefix = source_ip_prefix
        rule.port_range_min = port_range_min
        rule.port_range_max = port_range_max
        rule.source_port_range_min = source_port_range_min
        rule.source_port_range_max = source_port_range_max

        return rule

    def _get_fake_ingress_rule(self, rule_id=None,
                      direction=None, ethertype=None,
                      protocol=None, port_range_min=None, port_range_max=None,
                      source_ip_prefix=None,
                      port_range=None, source_port_range_min=None,
                      source_port_range_max=None,
                      backward_port_range=None, dest_ip_prefix=None,
                      filters=None):
        self.rule = sg_utils.IngressRule(ethertype, protocol)
        self.rule.ethertype = ethertype
        self.rule.direction = direction
        self.rule_id = rule_id or uuidutils.generate_uuid()
        self.rule.port_range = port_range
        self.rule.backward_port_range = backward_port_range
        self.rule.source_ip_prefix = source_ip_prefix
        self.rule.dest_ip_prefix = dest_ip_prefix
        self.rule.port_range_min = port_range_min
        self.rule.port_range_max = port_range_max
        self.rule.source_port_range_min = source_port_range_min
        self.rule.source_port_range_max = source_port_range_max

        return self.rule

    def _rpepare_fake_port(self):

        IDENTIFIER = 'IDENTIFIER'
        fake_port = {
                    'admin_state_up': True,
                    'allowed_address_pairs': [{'2': 2}],
                    'binding:host_id': '3',
                    'binding:profile': {'4': 4},
                    'binding:vif_details': {'5': 5},
                    'binding:vif_type': '6',
                    'binding:vnic_type': '7',
                    'created_at': '2016-03-09T12:14:57.233772',
                    'data_plane_status': '32',
                    'description': '8',
                    'device_id': '9',
                    'device_owner': '10',
                    'dns_assignment': [{'11': 11}],
                    'dns_domain': 'a11',
                    'dns_name': '12',
                    'extra_dhcp_opts': [{'13': 13}],
                    'fixed_ips': [{'14': '14'}],
                    'id': IDENTIFIER,
                    'ip_address': '15',
                    'mac_address': '16',
                    'name': '17',
                    'network_id': '18',
                    'opt_name': '19',
                    'opt_value': '20',
                    'port_security_enabled': True,
                    'qos_policy_id': '21',
                    'revision_number': 22,
                    'security_groups': ['23'],
                    'subnet_id': '24',
                    'status': '25',
                    'tenant_id': '26',
                    'trunk_details': {
                        'trunk_id': '27',
                        'sub_ports': [{
                            'port_id': '28',
                            'segmentation_id': 29,
                            'segmentation_type': '30',
                            'mac_address': '31'}]},
                    'updated_at': '2016-07-09T12:14:57.233772',
                }

        return fake_port

    def _prepare_fake_sg_aggr(self):
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(68, 68),
                                       backward_port_range=(67, 67))
        sg_aggr = sg_utils.SgAggr()
        sg_aggr.rules = [fake_rule]
        return sg_aggr

    def _fake_sg_rule_for_ethertype(self, ethertype=None, remote_group=None):

        return {'direction': 'ingress', 'remote_group_id': remote_group,
                'ethertype': ethertype}

    def _get_fake_filter_policy(self, rules=None, filter_config_key=None, filter_policy=None):
        filter_policy = vim.DvsFilterPolicy()
        if rules:
            traffic_ruleset = vim.DvsTrafficRuleset()
            traffic_ruleset.enabled = True
            traffic_ruleset.rules = rules
            filter_config = vim.DvsTrafficFilterConfig()
            filter_config.agentName = "dvfilter-generic-vmware"
            filter_config.inherited = False
            filter_config.trafficRuleset = traffic_ruleset
            if filter_config_key:
                filter_config.key = filter_config_key
            filter_policy.filterConfig = [filter_config]
            filter_policy.inherited = False
        else:
            filter_policy.inherited = True
        return filter_policy

    def test__to_ip_network_with_ipv4(self):
        result = sg_utils._to_ip_network(self.get_fake_ipv4_network(six.u('0.0.0.0/0')))
        expected = IPv4Network(u'0.0.0.0/0')
        self.assertEqual(result, expected)

    """Scenario with passing text instead of 'IPv4Network', 'IPv6Network' objects"""
    def test__to_ip_network_with_ipv4_text(self):
        result = sg_utils._to_ip_network(six.u('0.0.0.0/0'))
        expected = IPv4Network(u'0.0.0.0/0')
        self.assertEqual(result, expected)


    def test__to_ip_network_with_ipv6(self):
        result = sg_utils._to_ip_network(self.get_fake_ipv6_network())
        expected = IPv6Network(u'::/0')
        self.assertEqual(result, expected)

    """Scenario with passing text instead of 'IPv4Network', 'IPv6Network' objects"""
    def test__to_ip_network_with_ipv6(self):
        result = sg_utils._to_ip_network(six.u('::/0'))
        expected = IPv6Network(u'::/0')
        self.assertEqual(result, expected)

    def test_compile_filter_policy_without_hashed_rules(self):

        fake_rule = self._get_fake_rule(protocol="tcp",
                                                direction='ingress',
                                          port_range_min=0,
                                          port_range_max=65535,
                                          source_port_range_min=0,
                                          source_port_range_max=0)

        rules = [fake_rule]
        #expected = self._get_fake_filter_policy(rules=None)

        result = sg_utils.compile_filter_policy(rules)
        self.assertIsNotNone(result)

    def test_compile_filter_policy_with_hashed_rules(self):
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(68, 68),
                                       backward_port_range=(67, 67))


        fake_hashed1 = vim.DvsTrafficRule()
        fake_hashed2 = vim.DvsTrafficRule()

        rules = [fake_rule]
        hashed_rules = {fake_rule: [fake_hashed1, fake_hashed2]}
        result = sg_utils.compile_filter_policy(rules, hashed_rules=hashed_rules)
        self.assertIsNotNone(result)

    def test__rule_excepted_true(self):
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(68, 68),
                                       backward_port_range=(67, 67))
        result = sg_utils._rule_excepted(fake_rule)
        self.assertTrue(result)


    def test__rule_excepted_false_ipv4(self):
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(546, 546),
                                       backward_port_range=(547, 547))
        result = sg_utils._rule_excepted(fake_rule)
        self.assertFalse(result)

    def test__rule_excepted_true_ipv6(self):
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv6", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(546, 546),
                                       backward_port_range=(547, 547))
        result = sg_utils._rule_excepted(fake_rule)
        self.assertTrue(result)

    def test__create_rule(self):
        source_ip_prefix = self.get_fake_ipv4_network(six.u('10.192.168.11'))
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='ingress', port_range_min=23,
                                       port_range_max=23, source_ip_prefix=source_ip_prefix,
                                       port_range=(546, 546),
                                       backward_port_range=(547, 547))

        result = sg_utils._create_rule(fake_rule)
        self.assertIsNotNone(result)

    def test__create_rule_error(self):
        source_ip_prefix = self.get_fake_ipv4_network(six.u('10.192.168.11'))
        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4",
                                       direction='ingress', port_range_min=23,
                                       port_range_max=23, source_ip_prefix=source_ip_prefix,
                                       port_range=(546, 546),
                                       backward_port_range=(547, 547))

        """
        Simulating missing attribute for raise AttributeError which 
        will result in None    
        """
        del fake_rule.port_range_min

        result = sg_utils._create_rule(fake_rule)
        self.assertIsNone(result)

    def test_patch_sg_rules(self):
        sg_rule = self._fake_sg_rule_for_ethertype(remote_group={'IPv4': [OTHER_SGID, FAKE_SGID],
                           'IPv6': [FAKE_SGID]})

        expected = []
        for key, protocol in enumerate(['icmp', 'udp', 'tcp']):
            fake_rule = self._get_fake_rule(protocol=protocol,
                                                direction='ingress',
                                          port_range_min=0,
                                          port_range_max=65535,
                                          source_port_range_min=0,
                                          source_port_range_max=0)

            if key == 0:
                fake_rule.port_range_max = 0
            expected.append(fake_rule)

        self.maxDiff = None
        result = sg_utils.patch_sg_rules([sg_rule])
        self.assertEqual(result, expected)

    """Test scenario for patch security group rules with empty rules list"""
    def test_patch_sg_rules_empty(self):
        result = sg_utils.patch_sg_rules([])
        expected = []
        self.assertEqual(result, expected)

    def test_security_group_set(self):
        fake_port = self._rpepare_fake_port()

        """Hardcoded value from 'self._prepare_fake_port()' helper function"""
        expected = '23'

        result = sg_utils.security_group_set(fake_port)
        self.assertEqual(result, expected)

    def test_security_group_set_none(self):
        fake_port = self._rpepare_fake_port()

        """Deleting 'security_groups' property to simulate returning None"""
        del fake_port['security_groups']
        result = sg_utils.security_group_set(fake_port)
        self.assertIsNone(result)

    def test_apply_rules(self):

        fake_rule = self._get_fake_ingress_rule(ethertype="IPv4", protocol='udp',
                                       direction='incomingPackets',
                                       port_range=(68, 68),
                                       backward_port_range=(67, 67))
        fake_rules = [fake_rule]
        fake_sg_aggr = self._prepare_fake_sg_aggr()

        sg_utils.apply_rules = mock.Mock()
        sg_utils.apply_rules(fake_rules, fake_sg_aggr)

        sg_utils.apply_rules.assert_called_with(fake_rules, fake_sg_aggr)

    def test__consolidate_rules_success(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                                direction='ingress',
                                          port_range_min=0,
                                          port_range_max=65535,
                                          source_port_range_min=0,
                                          source_port_range_max=0)

        fake_rules = [fake_rule]
        result = sg_utils._consolidate_rules(fake_rules)
        fake_rule.ip_prefix = self.get_fake_ipv4_network()

        for i in result:
            self.assertEqual(i, fake_rule)

    def test__consolidate_rules_without_ip_prefix(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                                direction='ingress',
                                          port_range_min=0,
                                          port_range_max=65535,
                                          source_port_range_min=0,
                                          source_port_range_max=0)


        fake_rules = [fake_rule]
        result = sg_utils._consolidate_rules(fake_rules)

        for i in result:
            self.assertEqual(i, fake_rule)

    def test__consolidate_rules_pass_result(self):
        pass

    """Test case with prefixlen 0"""
    def test__consolidate_ipv4_6(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                        direction='ingress',
                                        port_range_min=0,
                                        port_range_max=65535,
                                        source_port_range_min=0,
                                        source_port_range_max=0)

        fake_rule.ip_prefix = self.get_fake_ipv4_network(netmask='0.0.0.0/0')
        fake_rules = [fake_rule]

        result = sg_utils._consolidate_ipv4_6(fake_rules)
        for i in result:
            self.assertEqual(i, fake_rule)

    """Test case with prefixlen 32"""
    def test__consolidate_ipv4_6_prefixlen32(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                        direction='ingress',
                                        port_range_min=0,
                                        port_range_max=65535,
                                        source_port_range_min=0,
                                        source_port_range_max=0)

        fake_rule.ip_prefix = self.get_fake_ipv4_network()
        fake_rules = [fake_rule]

        result = sg_utils._consolidate_ipv4_6(fake_rules)
        for i in result:
            self.assertEqual(i, fake_rule)

    """Covering the case in which the ethertype and prefixes are dropped"""
    def test__consolidate_ipv4_6_drop(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                        direction='ingress',
                                        port_range_min=0,
                                        port_range_max=65535,
                                        source_port_range_min=0,
                                        source_port_range_max=0)

        fake_rule2 = self._get_fake_rule(protocol="udp",
                                        direction='ingress',
                                        port_range_min=0,
                                        port_range_max=65535,
                                        source_port_range_min=0,
                                        source_port_range_max=0)

        fake_rules = [fake_rule, fake_rule2]

        result = sg_utils._consolidate_ipv4_6(fake_rules)
        for i in result:
            self.assertEqual(i, fake_rule)

    def test_consolidate_rules(self):
        fake_rule = self._get_fake_rule(protocol="udp",
                                        direction='ingress',
                                        port_range_min=0,
                                        port_range_max=65535,
                                        source_port_range_min=0,
                                        source_port_range_max=0)

        fake_rule2 = self._get_fake_rule(protocol="tcp",
                                         direction='ingress',
                                         port_range_min=0,
                                         port_range_max=65535,
                                         source_port_range_min=0,
                                         source_port_range_max=0)

        rules = [fake_rule, fake_rule2]
        expected = sorted([fake_rule, fake_rule2])

        result = sg_utils.consolidate_rules(rules)
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()

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
import attr

VMWARE_HYPERVISOR_TYPE = 'VMware vCenter Server'
DVS = 'dvs'
AGENT_TYPE_DVS = 'DVS Agent'
# protocol number according to RFC 1700
PROTOCOL = {'icmp': 1,
            'tcp': 6,
            'udp': 17,
            }

DVS_PORTGROUP_NAME_MAXLEN = 80

LOGIN_RETRIES = 3

VM_NETWORK_DEVICE_TYPES = [
    'VirtualE1000', 'VirtualE1000e', 'VirtualPCNet32',
    'VirtualSriovEthernetCard', 'VirtualVmxnet']

CONCURRENT_MODIFICATION_TEXT = 'Cannot complete operation due to concurrent ' \
                               'modification by another operation.'

LOGIN_PROBLEM_TEXT = "Cannot complete login due to an incorrect " \
                     "user name or password"

DELETED_TEXT = "The object has already been deleted or has not been " \
               "completely created"

DUPLICATE_NAME = "oslo_vmware.exceptions.DuplicateName"

BULK_FAULT_TEXT = "Cannot complete a vSphere Distributed Switch operation " \
                  "for one or more host members."

MIN_EPHEMERAL_PORT = 32768
MAX_EPHEMERAL_PORT = 65535

ATTR_ARGS = {'cmp': True, 'hash': True}
if attr.__version__ > '16':
    ATTR_ARGS.update(slots=True)

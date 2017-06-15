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

from time import sleep
import hashlib
import uuid
import six
import string

from neutron.i18n import _LI, _LW, _LE
from neutron.common import utils as neutron_utils
from oslo_log import log
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util
from requests.exceptions import ConnectionError

from networking_dvs.common import constants as dvs_const
from networking_dvs.common.util import stats
from networking_dvs.common import exceptions
from networking_dvs.utils import spec_builder

LOG = log.getLogger(__name__)

INIT_PG_PORTS_COUNT = 4


class DVSController(object):
    """Controls one DVS."""

    def __init__(self, dvs_name, connection=None, pool=None):
        self.connection = connection
        self.dvs_name = dvs_name
        self._uuid = None
        self.pool = pool
        self._update_spec_queue = []
        self.ports_by_key = {}
        self._blocked_ports = set()
        self._service_content = connection.vim.retrieve_service_content()
        self.builder = spec_builder.SpecBuilder(
            self.connection.vim.client.factory)
        try:
            self._dvs, self._datacenter = self._get_dvs(dvs_name, connection)
            # (SlOPS) To do release blocked port after use
            self._blocked_ports = set()
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    @property
    def uuid(self):
        if self._uuid:
            return self._uuid
        self._uuid = self._uuid = self.connection.invoke_api(vim_util, 'get_object_property', self.connection.vim, self._dvs, 'uuid')
        return self._uuid

    def create_network(self, network, segment):
        name = self._get_net_name(self.dvs_name, network)
        blocked = not network['admin_state_up']

        try:
            pg_spec = self._build_pg_create_spec(
                name,
                segment['segmentation_id'],
                blocked)
            pg_create_task = self.connection.invoke_api(
                self.connection.vim,
                'CreateDVPortgroup_Task',
                self._dvs, spec=pg_spec)

            result = self.connection.wait_for_task(pg_create_task)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)
        else:
            pg = result.result
            LOG.info(_LI('Network %(name)s created \n%(pg_ref)s'),
                     {'name': name, 'pg_ref': pg})
            return pg

    def update_network(self, network, original=None):
        original_name = self._get_net_name(self.dvs_name, original) if original else None
        current_name = self._get_net_name(self.dvs_name, network)
        blocked = not network['admin_state_up']
        try:
            pg_ref = self._get_pg_by_name(original_name or current_name)
            pg_config_info = self._get_config_by_ref(pg_ref)

            if (pg_config_info.defaultPortConfig.blocked.value != blocked or
                    (original_name and original_name != current_name)):
                # we upgrade only defaultPortConfig, because it is inherited
                # by all ports in PortGroup, unless they are explicitly
                # overwritten on specific port.
                pg_spec = self._build_pg_update_spec(
                    pg_config_info.configVersion,
                    blocked=blocked)
                pg_spec.name = current_name
                pg_update_task = self.connection.invoke_api(
                    self.connection.vim,
                    'ReconfigureDVPortgroup_Task',
                    pg_ref, spec=pg_spec)

                self.connection.wait_for_task(pg_update_task)
                LOG.info(_LI('Network %(name)s updated'),
                         {'name': current_name})
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def delete_network(self, network):
        name = self._get_net_name(self.dvs_name, network)
        try:
            pg_ref = self._get_pg_by_name(name)
        except exceptions.PortGroupNotFound:
            LOG.debug('Network %s is not present in vcenter. '
                      'Nothing to delete.' % name)
            return
        self._delete_port_group(pg_ref, name)

    def delete_networks_without_active_ports(self, pg_keys_with_active_ports):
        for pg_ref in self._get_all_port_groups():
            if pg_ref.value not in pg_keys_with_active_ports:
                # check name
                try:
                    name = self.connection.invoke_api(
                        vim_util, 'get_object_property',
                        self.connection.vim, pg_ref, 'name')
                    name_tokens = name.split(self.dvs_name)
                    if (len(name_tokens) == 2 and not name_tokens[0] and
                            self._valid_uuid(name_tokens[1])):
                        self._delete_port_group(pg_ref, name)
                except vmware_exceptions.VMwareDriverException as e:
                    if dvs_const.DELETED_TEXT in e.message:
                        pass

    def _delete_port_group(self, pg_ref, name, wait=True):
        while True:
            try:
                pg_delete_task = self.connection.invoke_api(
                    self.connection.vim,
                    'Destroy_Task',
                    pg_ref)
                if wait:
                    self.connection.wait_for_task(pg_delete_task)
                else:
                    return pg_delete_task
                LOG.info(_LI('Network %(name)s deleted.') % {'name': name})
                break
            except vmware_exceptions.VimException as e:
                raise exceptions.wrap_wmvare_vim_exception(e)
            except vmware_exceptions.VMwareDriverException as e:
                if dvs_const.DELETED_TEXT in e.message:
                    sleep(0.1)
                else:
                    raise

    def submit_update_ports(self, update_specs):
        return self.connection.invoke_api(
            self.connection.vim, 'ReconfigureDVPort_Task',
            self._dvs, port=update_specs)

    def update_ports(self, update_specs):
        if not update_specs:
            return
        LOG.debug("Update Ports: {} {}".format(update_specs[0].setting.filterPolicy.inherited, sorted([spec.key for spec in update_specs])))
        update_task = self.submit_update_ports(update_specs)
        try:
            return self.connection.wait_for_task(update_task)  # -> May raise DvsOperationBulkFault, when host is down
        except vmware_exceptions.ManagedObjectNotFoundException:
            return

    def queue_update_specs(self, update_specs, callback=None):
        self._update_spec_queue.append((update_specs, [callback]))
        stats.gauge('networking_dvs.update_spec_queue_length', len(self._update_spec_queue))

    def filter_update_specs(self, filter_func):
        self._update_spec_queue = [
            (filter(filter_func, update_specs), callbacks)
            for update_specs, callbacks in self._update_spec_queue]

    @staticmethod
    def _chunked_update_specs(specs, limit=500):
        specs = list(specs)
        countdown = limit
        first = 0
        for i, spec in enumerate(specs):
            try:
                for filter_config in spec.setting.filterPolicy.filterConfig:
                    countdown -= len(filter_config.parameters)
                    try:
                        countdown -= len(filter_config.trafficRuleset)
                    except AttributeError:
                        pass
            except AttributeError:
                pass
            if countdown <= 0:
                last = i + 1
                yield(specs[first:last])
                countdown = limit
                first = last
        yield(specs[first:])

    def apply_queued_update_specs(self):
        callbacks, update_specs_by_key = self._get_queued_update_changes()

        if not update_specs_by_key:
            return

        results = []
        for result in self.pool.starmap(self._apply_queued_update_specs, [(update_spec, callbacks) for update_spec in self._chunked_update_specs(six.itervalues(update_specs_by_key))]):
            if result:
                results.extend(result)

        return results

    def _apply_queued_update_specs(self, update_specs, callbacks, retries=5):
        if not update_specs:
            return

        failed_keys = []
        for i in range(retries):
            try:
                value = self.update_ports(update_specs)

                for spec in update_specs:
                    port = self.ports_by_key[spec.key]
                    port_desc = port.get('port_desc', None)
                    if port_desc and port_desc.config_version:
                        port_desc.config_version = str(int(port_desc.config_version) + 1)

                if callbacks:
                    succeeded_keys = [str(spec.key) for spec in update_specs]
                for callback in callbacks:
                    if callable(callback):
                        callback(self, succeeded_keys, failed_keys)

                return value
            except vmware_exceptions.VimException as e:
                if dvs_const.CONCURRENT_MODIFICATION_TEXT in e.msg:
                    for port_info in self.get_port_info_by_portkey([spec.key for spec in update_specs]):
                        port_key = str(port_info.key)
                        port = self.ports_by_key[port_key]
                        port_desc = port['port_desc']
                        update_spec_index = None
                        update_spec = None

                        for index, item in enumerate(update_specs):
                            if item.key == port_key:
                                update_spec = item
                                update_spec_index = index
                                break

                        connection_cookie = getattr(port_info, "connectionCookie", None)

                        if connection_cookie:
                            connection_cookie = str(connection_cookie)

                        if connection_cookie != port_desc.connection_cookie:
                            LOG.error("Cookie mismatch {} {} {} <> {}".format(port_desc.mac_address, port_desc.port_key,
                                                                              port_desc.connection_cookie,
                                                                              connection_cookie))
                            if update_spec_index:
                                failed_keys.append(port_key)
                                del update_specs[update_spec_index]
                        else:
                            config_version = str(port_info.config.configVersion)
                            port_desc.config_version = config_version
                            if update_spec:
                                LOG.debug("Config version {} {} from {} ({}) to {}".format(port_desc.mac_address,
                                                                                           port_desc.port_key,
                                                                                           port_desc.config_version,
                                                                                           update_spec.configVersion,
                                                                                           config_version))

                                update_spec.configVersion = config_version
                    continue

                raise exceptions.wrap_wmvare_vim_exception(e)

    def _get_queued_update_changes(self):
        callbacks = []
        # First merge the changes for the same port(key)
        # Later changes overwrite earlier ones, non-inherited values take precedence
        # This cannot be called out-of-order
        update_specs_by_key = {}
        update_spec_queue = self._update_spec_queue
        self._update_spec_queue = []
        stats.gauge('networking_dvs.update_spec_queue', len(self._update_spec_queue))

        for _update_specs, _callbacks in update_spec_queue:
            if _callbacks:
                callbacks.extend(_callbacks)

            for spec in _update_specs:
                existing_spec = update_specs_by_key.get(spec.key, None)
                if not existing_spec:
                    update_specs_by_key[spec.key] = spec
                else:
                    for attr in ['configVersion', 'description', 'name']:
                        value = getattr(spec, attr, None)
                        if not value is None and value != getattr(existing_spec, attr, None):
                            setattr(existing_spec, attr, value)
                    for attr in ['blocked', 'filterPolicy', 'vlan']:
                        value = getattr(spec.setting, attr)
                        if not value.inherited is None:
                            setattr(existing_spec.setting, attr, getattr(spec.setting, attr))
        return callbacks, update_specs_by_key

    def get_pg_per_sg_attribute(self, sg_attr_key, max_objects=100):
        vim = self.connection.vim

        traversal_spec = vim_util.build_traversal_spec(
                vim.client.factory,
                "dvs_to_dvpg",
                "DistributedVirtualSwitch",
                "portgroup",
                False,
                [])
        object_spec = vim_util.build_object_spec(
                vim.client.factory,
                self._dvs,
                [traversal_spec])
        property_spec = vim_util.build_property_spec(
                vim.client.factory,
                "DistributedVirtualPortgroup",
                ["key", "name", "config", "customValue", "vm"])

        property_filter_spec = vim_util.build_property_filter_spec(
                vim.client.factory,
                [property_spec],
                [object_spec])
        options = vim.client.factory.create('ns0:RetrieveOptions')
        options.maxObjects = max_objects

        pc_result = vim.RetrievePropertiesEx(
                vim.service_content.propertyCollector,
                specSet=[property_filter_spec],
                options=options)
        result = {}

        while True:
            for objContent in pc_result.objects:
                props = {prop.name : prop.val for prop in objContent.propSet}
                if props["customValue"].__class__.__name__ == "ArrayOfCustomFieldValue":
                    for custom_field_value in props["customValue"]["CustomFieldValue"]:
                        if custom_field_value.key == sg_attr_key:
                            result[custom_field_value.value] = {
                                "key": props["key"],
                                "ref": objContent.obj,
                                "configVersion": props["config"].configVersion,
                                "name": props["name"],
                                "vm": props["vm"],
                            }
                            break

            if getattr(pc_result, 'token', None):
                pc_result = vim.ContinueRetrievePropertiesEx(
                        vim.service_content.propertyCollector, pc_result.token)
            else:
                break

        return result

    def create_dvportgroup(self, sg_attr_key, sg_set, port_config):
        """
        Creates an automatically-named dvportgroup on the dvswitch
        with the specified sg rules and marks it as such through a custom attribute

        Returns a dictionary with "key" and "ref" keys.

        Note, that while a portgroup's key and managed object id have
        the same string format and appear identical under normal use
        it is possible to have them diverge by the use of the backup
        and restore feature of the dvs for example.
        As such, one should not rely on any equivalence between them.
        """
        # There is a create_network method a few lines above
        # which seems to be part of a non-used call path
        # starting from the dvs_agent_rpc_api. TODO - remove it

        # There is an upper limit on managed object names in vCenter
        name = sg_set + "-" + self.dvs_name
        if len(name) > 80:
            # so we use a hash of the security group set
            hex = hashlib.sha224()
            hex.update(self.dvs_name)
            hex.update(sg_set)
            name = hex.hexdigest() + "-" + self.dvs_name[:23]

        try:
            pg_spec = self.builder.pg_config(port_config)
            pg_spec.name = name
            pg_spec.numPorts = 0
            pg_spec.type = 'earlyBinding'
            pg_spec.description = sg_set

            pg_create_task = self.connection.invoke_api(
                self.connection.vim,
                'CreateDVPortgroup_Task',
                self._dvs, spec=pg_spec)

            result = self.connection.wait_for_task(pg_create_task)

            pg_ref = result.result

            self.connection.invoke_api(
                self.connection.vim,
                "SetField",
                self._service_content.customFieldsManager,
                entity=pg_ref,
                key=sg_attr_key,
                value=sg_set)

            key = vim_util.get_object_properties(self.connection.vim, pg_ref, ["key"])[0].propSet[0].val
            return {"key": key, "ref": pg_ref}
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def update_dvportgroup(self, pg_ref, config_version, port_config=None, wait=True):
        if not port_config:
            port_config = self.builder.port_setting()
            port_config.blocked = self.builder.blocked(False)
            port_config.filterPolicy = self.builder.filter_policy([], None)
        try:
            pg_spec = self.builder.pg_config(port_config)
            pg_spec.configVersion = config_version
            pg_update_task = self.connection.invoke_api(
                self.connection.vim,
                'ReconfigureDVPortgroup_Task',
                pg_ref, spec=pg_spec)

            if wait:
                self.connection.wait_for_task(pg_update_task)
            else:
                return pg_update_task
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def switch_port_blocked_state(self, port):
        try:
            port_info = self.get_port_info(port)
            port_settings = self.builder.port_setting()
            state = not port['admin_state_up']
            port_settings.blocked = self.builder.blocked(state)

            update_spec = self.builder.port_config_spec(
                port_info.config.configVersion, port_settings)
            update_spec.key = port_info.key
            self.update_ports([update_spec])
        except exceptions.PortNotFound:
            LOG.debug("Port %s was not found. Nothing to block." % port['id'])
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def _lookup_unbound_port_or_increase_pg(self, pg):
        while True:
            try:
                port_info = self._lookup_unbound_port(pg)
                break
            except exceptions.UnboundPortNotFound:
                try:
                    self._increase_ports_on_portgroup(pg)
                except (vmware_exceptions.VMwareDriverException,
                        exceptions.VMWareDVSException) as e:
                    if dvs_const.CONCURRENT_MODIFICATION_TEXT in e.message:
                        LOG.info(_LI('Concurrent modification on '
                                     'increase port group.'))
                        continue
                    raise e
        return port_info

    def book_port(self, network, port_name, segment, net_name=None):
        try:
            if not net_name:
                net_name = self._get_net_name(self.dvs_name, network)
            pg = self._get_or_create_pg(net_name, network, segment)
            for iter in range(0, 4):
                try:
                    port_info = self._lookup_unbound_port_or_increase_pg(pg)

                    port_settings = self.builder.port_setting()
                    port_settings.blocked = self.builder.blocked(False)
                    update_spec = self.builder.port_config_spec(
                        port_info.config.configVersion, port_settings,
                        name=port_name)
                    update_spec.key = port_info.key
                    update_task = self.connection.invoke_api(
                        self.connection.vim, 'ReconfigureDVPort_Task',
                        self._dvs, port=[update_spec])
                    self.connection.wait_for_task(update_task)
                    return port_info.key
                except vmware_exceptions.VimException as e:
                    sleep(0.1)
            raise exceptions.wrap_wmvare_vim_exception(e)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def release_port(self, port):
        try:
            port_info = self.get_port_info(port)
            update_spec = self.builder.port_config_spec(
                port_info.config.configVersion, name='')
            update_spec.key = port_info.key
            #setting = self.builder.port_setting()
            #setting.filterPolicy = self.builder.filter_policy([])
            #update_spec.setting = setting
            update_spec.operation = 'remove'
            update_task = self.connection.invoke_api(
                self.connection.vim, 'ReconfigureDVPort_Task',
                self._dvs, port=[update_spec])
            self.connection.wait_for_task(update_task)
            self.remove_block(port_info.key)
        except exceptions.PortNotFound:
            LOG.debug("Port %s was not found. Nothing to delete." % port['id'])
        except exceptions.ResourceInUse:
            LOG.debug("Port %s in use. Nothing to delete." % port['id'])
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def remove_block(self, port_key):
        self._blocked_ports.discard(port_key)

    def _build_pg_create_spec(self, name, vlan_tag, blocked):
        port_setting = self.builder.port_setting()

        port_setting.vlan = self.builder.vlan(vlan_tag)
        port_setting.blocked = self.builder.blocked(blocked)

        port_setting.filterPolicy = self.builder.filter_policy([])

        pg = self.builder.pg_config(port_setting)
        pg.name = name
        pg.numPorts = 0

        # Equivalent of vCenter static binding type.
        pg.type = 'earlyBinding'
        pg.description = 'Managed By Neutron'
        return pg

    def _build_pg_update_spec(self, config_version,
                              blocked=None,
                              ports_number=None):
        port = self.builder.port_setting()
        if blocked is not None:
            port.blocked = self.builder.blocked(blocked)
        pg = self.builder.pg_config(port)
        if ports_number:
            pg.numPorts = ports_number
        pg.configVersion = config_version
        return pg

    def _get_dvs(self, dvs_name, connection):
        """Get the dvs by name"""

        dvs_list = {}
        with vim_util.WithRetrieval(connection.vim, connection.invoke_api(
                vim_util, 'get_objects', connection.vim, 'DistributedVirtualSwitch', 100, ['name', 'portgroup']) ) as dvswitches:
                for dvs in dvswitches:
                    p = { p.name: p.val for p in dvs.propSet}
                    if dvs_name == p['name']:
                        return dvs.obj, DVSController._get_datacenter(connection.vim, dvs.obj)
                    dvs_list[dvs.obj] = p['portgroup'].ManagedObjectReference

        for dvs, port_groups in six.iteritems(dvs_list):
            for pg in port_groups:
                try:
                    name = self.connection.invoke_api(
                        vim_util, 'get_object_property',
                        self.connection.vim, pg, 'name')
                    if dvs_name == name:
                        return dvs, DVSController._get_datacenter(connection.vim, dvs)
                except vmware_exceptions.VimException:
                    pass

        raise exceptions.DVSNotFound(dvs_name=dvs_name)

    @staticmethod
    def _get_datacenter(vim, entity_ref, max_objects=100):
        """Get the inventory path of a managed entity.
        :param vim: Vim object
        :param entity_ref: managed entity reference
        :return: the datacenter of the entity_ref
        """
        client_factory = vim.client.factory
        property_collector = vim.service_content.propertyCollector

        prop_spec = vim_util.build_property_spec(client_factory, 'Datacenter', ['name'])
        select_set = vim_util.build_selection_spec(client_factory, 'ParentTraversalSpec')
        select_set = vim_util.build_traversal_spec(
            client_factory, 'ParentTraversalSpec', 'ManagedEntity', 'parent',
            False, [select_set])
        obj_spec = vim_util.build_object_spec(client_factory, entity_ref, select_set)
        prop_filter_spec = vim_util.build_property_filter_spec(client_factory,
                                                               [prop_spec], [obj_spec])
        options = client_factory.create('ns0:RetrieveOptions')
        options.maxObjects = max_objects
        retrieve_result = vim.RetrievePropertiesEx(
            property_collector,
            specSet=[prop_filter_spec],
            options=options)

        with vim_util.WithRetrieval(vim, retrieve_result) as objects:
            for obj in objects:
                if obj.obj._type == 'Datacenter':
                    return obj.obj

    def _get_pg_by_name(self, pg_name):
        """Get the dpg ref by name"""
        for pg in self._get_all_port_groups():
            try:
                name = self.connection.invoke_api(
                    vim_util, 'get_object_property',
                    self.connection.vim, pg, 'name')
                if pg_name == name:
                    return pg
            except vmware_exceptions.VimException:
                pass
        raise exceptions.PortGroupNotFound(pg_name=pg_name)

    def _get_all_port_groups(self):
        net_list = self.connection.invoke_api(
            vim_util, 'get_object_property', self.connection.vim,
            self._datacenter, 'network').ManagedObjectReference
        type_value = 'DistributedVirtualPortgroup'
        return self._get_object_by_type(net_list, type_value)

    def _get_or_create_pg(self, pg_name, network, segment):
        try:
            return self._get_pg_by_name(pg_name)
        except exceptions.PortGroupNotFound:
            LOG.debug(_LI('Network %s is not present in vcenter. '
                          'Perform network creation' % pg_name))
            return self.create_network(network, segment)

    def _get_config_by_ref(self, ref):
        """pg - ManagedObjectReference of Port Group"""
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, ref, 'config')

    @staticmethod
    def _get_net_name(dvs_name, network):
        # TODO(dbogun): check network['bridge'] generation algorithm our
        # must match it

        return dvs_name + network['id']

    @staticmethod
    def _get_object_by_type(results, type_value):
        """Get object by type.

        Get the desired object from the given objects result by the given type.
        """
        return [obj for obj in results if obj._type == type_value]

    def _get_ports_for_pg(self, pg_name):
        pg = self._get_pg_by_name(pg_name)
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, pg, 'portKeys')[0]

    def _get_free_pg_keys(self, port_group):
        criteria = self.builder.port_criteria(
            port_group_key=port_group.value)
        all_port_keys = set(
            self.connection.invoke_api(self.connection.vim,
                                       'FetchDVPortKeys',
                                       self._dvs, criteria=criteria))
        criteria.connected = True
        connected_port_keys = set(
            self.connection.invoke_api(self.connection.vim,
                                       'FetchDVPortKeys',
                                       self._dvs, criteria=criteria))
        return list(all_port_keys - connected_port_keys - self._blocked_ports)

    def _lookup_unbound_port(self, port_group):
        for port_key in self._get_free_pg_keys(port_group):
            self._blocked_ports.add(port_key)
            p_info = self._get_port_info_by_portkey(port_key)
            if not getattr(p_info.config, 'name', None):
                return p_info
        raise exceptions.UnboundPortNotFound()

    def _increase_ports_on_portgroup(self, port_group):
        pg_info = self._get_config_by_ref(port_group)
        #TODO(ekosareva): need to have max size of ports number
        ports_number = max(INIT_PG_PORTS_COUNT, pg_info.numPorts * 2)
        pg_spec = self._build_pg_update_spec(
            pg_info.configVersion, ports_number=ports_number)
        pg_update_task = self.connection.invoke_api(
            self.connection.vim,
            'ReconfigureDVPortgroup_Task',
            port_group, spec=pg_spec)
        self.connection.wait_for_task(pg_update_task)

    def get_port_info(self, port):
        key = port.get('binding:vif_details', {}).get('dvs_port_key')
        if key is not None:
            port_info = self.get_port_info_by_portkey(key)
        else:
            port_info = self._get_port_info_by_name(port['id'])
        return port_info

    def get_port_info_by_portkey(self, port_key):
        """pg - ManagedObjectReference of Port Group"""
        criteria = self.builder.port_criteria(port_key=port_key)
        port_info = self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            self._dvs, criteria=criteria)
        if not port_info:
            raise exceptions.PortNotFound(id=port_key)

        if getattr(port_key, '__iter__', None):
            return port_info
        else:
            return port_info[0]

    def _get_port_info_by_name(self, name, port_list=None):
        if port_list is None:
            port_list = self.get_ports(None)
        ports = [port for port in port_list if port.config.name == name]
        if not ports:
            raise exceptions.PortNotFound(id=name)
        if len(ports) > 1:
            LOG.warn(_LW("Multiple ports found for name %s."), name)
        return ports[0]

    def get_ports(self, connect_flag=True):
        criteria = self.builder.port_criteria(connected=connect_flag)
        ports = self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            self._dvs, criteria=criteria)
        p_ret = []
        for port in ports:
            if (getattr(port.config, 'name', None) is not None and
                    self._valid_uuid(port.config.name)):
                p_ret.append(port)
        return p_ret

    def _get_ports_ids(self):
        return [port.config.name for port in self.get_ports()]

    def _valid_uuid(self, name):
        try:
            uuid.UUID(name, version=4)
        except ValueError:
            return False
        return True


def connect(config, **kwds):
    connection = None
    while not connection:
        try:
            connection = api.VMwareAPISession(
            config.vsphere_hostname,
            config.vsphere_login,
            config.vsphere_password,
            config.api_retry_count,
            config.task_poll_interval,
            cacert=config.ca_certs,
            insecure=False if config.ca_certs else True,
            pool_size=config.connections_pool_size,
            **kwds)
        except ConnectionError:
            LOG.error(_LE("No connection to vSphere"))
            sleep(10)

    return connection


def create_network_map_from_config(config, connection=None, pool=None):
    """Creates physical network to dvs map from config"""
    connection = connection or connect(config)
    network_map = {}
    for network, dvs in six.iteritems(neutron_utils.parse_mappings(config.network_maps)):
        network_map[network] = DVSController(dvs, connection=connection, pool=pool)
    return network_map


def create_port_map(dvs_list, connect_flag=True):
    port_map = {}
    for dvs in dvs_list:
        port_map[dvs] = dict([[port.key, port] for port in dvs.get_ports(connect_flag)])
    return port_map


def get_dvs_and_port_by_id_and_key(dvs_list, port_id, port_key):
    for dvs in dvs_list:
        port = dvs.get_port_info_by_portkey(port_key)
        if port:
            if port.config.name == port_id:
                return dvs, port
    return None, None


def get_dvs_by_id_and_key(dvs_list, port_id, port_key):
    dvs, port = get_dvs_and_port_by_id_and_key(dvs_list, port_id, port_key)
    return dvs


def wrap_retry(func):
    """
    Retry operation on dvs when concurrent modification by another operation
    was discovered
    """
    @six.wraps(func)
    def wrapper(*args, **kwargs):
        login_failures = 0
        while True:
            try:
                return func(*args, **kwargs)
            except (vmware_exceptions.VMwareDriverException,
                    exceptions.VMWareDVSException) as e:
                if dvs_const.CONCURRENT_MODIFICATION_TEXT in str(e):
                    continue
                elif (dvs_const.LOGIN_PROBLEM_TEXT in str(e) and
                        login_failures < dvs_const.LOGIN_RETRIES - 1):
                    login_failures += 1
                    continue
                else:
                    raise
    return wrapper

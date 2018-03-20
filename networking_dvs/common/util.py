import os, six
import logging
from oslo_utils.importutils import try_import
from pyVmomi import vim, vmodl


LOG = logging.getLogger(__name__)


def dict_merge(dct, merge_dct):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None
    """
    for k, v in six.iteritems(merge_dct):
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


dogstatsd = try_import('datadog.dogstatsd')

if not dogstatsd or os.getenv('STATSD_MOCK', False):
    from mock import Mock
    stats = Mock()

    class WithDecorator(object):
        def __enter__(self):
            pass
        def __exit__(self, type, value, traceback):
            pass
        def __call__(self, func):
            def wrapped(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapped

    def timed(*args, **kwargs):
            return WithDecorator()

    stats.timed = timed
else:
    stats = dogstatsd.DogStatsd(host=os.getenv('STATSD_HOST', 'localhost'),
                      port=int(os.getenv('STATSD_PORT', 9125)),
                      namespace=os.getenv('STATSD_PREFIX', 'openstack')
                      )


##
# oslo.vmware.vim_util

def _get_token(retrieve_result):
    """Get token from result to obtain next set of results.
    :retrieve_result: Result of RetrievePropertiesEx API call
    :returns: token to obtain next set of results; None if no more results.
    """
    return getattr(retrieve_result, 'token', None)


def cancel_retrieval(si, retrieve_result):
    """Cancels the retrieve operation if necessary.
    :param si: Vim object
    :param retrieve_result: result of RetrievePropertiesEx API call
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    token = _get_token(retrieve_result)
    if token:
        si.content.propertyCollector.CancelRetrievePropertiesEx(token=token)


def continue_retrieval(si, retrieve_result):
    """Continue retrieving results, if available.
    :param si: Vim object
    :param retrieve_result: result of RetrievePropertiesEx API call
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    token = _get_token(retrieve_result)
    if not token:
        return None

    return si.content.propertyCollector.ContinueRetrievePropertiesEx(token=token)


def build_selection_spec( name):
    """Builds the selection spec.
    :param name: name for the selection spec
    :returns: selection spec
    """
    sel_spec = vmodl.query.PropertyCollector.SelectionSpec()
    sel_spec.name = name
    return sel_spec


def build_traversal_spec(name, type_, path, skip, select_set):
    """Builds the traversal spec.
    :param name: name for the traversal spec
    :param type_: type of the managed object
    :param path: property path of the managed object
    :param skip: whether or not to filter the object identified by param path
    :param select_set: set of selection specs specifying additional objects
                       to filter
    :returns: traversal spec
    """
    traversal_spec = vmodl.query.PropertyCollector.TraversalSpec()
    traversal_spec.name = name
    traversal_spec.type = type_
    traversal_spec.path = path
    traversal_spec.skip = skip
    traversal_spec.selectSet = select_set
    return traversal_spec


def build_recursive_traversal_spec():
    """Builds recursive traversal spec to traverse managed object hierarchy.
    :returns: recursive traversal spec
    """
    visit_folders_select_spec = build_selection_spec('visitFolders')
    # Next hop from Datacenter
    dc_to_hf = build_traversal_spec('dc_to_hf',
                                    vim.Datacenter,
                                    'hostFolder',
                                    False,
                                    [visit_folders_select_spec])
    dc_to_vmf = build_traversal_spec('dc_to_vmf',
                                     vim.Datacenter,
                                     'vmFolder',
                                     False,
                                     [visit_folders_select_spec])
    dc_to_netf = build_traversal_spec('dc_to_netf',
                                      vim.Datacenter,
                                      'networkFolder',
                                      False,
                                      [visit_folders_select_spec])

    # Next hop from HostSystem
    h_to_vm = build_traversal_spec('h_to_vm',
                                   vim.HostSystem,
                                   'vm',
                                   False,
                                   [visit_folders_select_spec])

    # Next hop from ComputeResource
    cr_to_h = build_traversal_spec('cr_to_h',
                                   vim.ComputeResource,
                                   'host',
                                   False,
                                   [])
    cr_to_ds = build_traversal_spec('cr_to_ds',
                                    vim.ComputeResource,
                                    'datastore',
                                    False,
                                    [])

    rp_to_rp_select_spec = build_selection_spec('rp_to_rp')
    rp_to_vm_select_spec = build_selection_spec('rp_to_vm')

    cr_to_rp = build_traversal_spec('cr_to_rp',
                                    vim.ComputeResource,
                                    'resourcePool',
                                    False,
                                    [rp_to_rp_select_spec,
                                     rp_to_vm_select_spec])

    # Next hop from ClusterComputeResource
    ccr_to_h = build_traversal_spec('ccr_to_h',
                                    vim.ClusterComputeResource,
                                    'host',
                                    False,
                                    [])
    ccr_to_ds = build_traversal_spec('ccr_to_ds',
                                     vim.ClusterComputeResource,
                                     'datastore',
                                     False,
                                     [])
    ccr_to_rp = build_traversal_spec('ccr_to_rp',
                                     vim.ClusterComputeResource,
                                     'resourcePool',
                                     False,
                                     [rp_to_rp_select_spec,
                                      rp_to_vm_select_spec])
    # Next hop from ResourcePool
    rp_to_rp = build_traversal_spec('rp_to_rp',
                                    vim.ResourcePool,
                                    'resourcePool',
                                    False,
                                    [rp_to_rp_select_spec,
                                     rp_to_vm_select_spec])
    rp_to_vm = build_traversal_spec('rp_to_vm',
                                    vim.ResourcePool,
                                    'vm',
                                    False,
                                    [rp_to_rp_select_spec,
                                     rp_to_vm_select_spec])

    # Get the assorted traversal spec which takes care of the objects to
    # be searched for from the rootFolder
    traversal_spec = build_traversal_spec('visitFolders',
                                          vim.Folder,
                                          'childEntity',
                                          False,
                                          [visit_folders_select_spec,
                                           h_to_vm,
                                           dc_to_hf,
                                           dc_to_vmf,
                                           dc_to_netf,
                                           cr_to_ds,
                                           cr_to_h,
                                           cr_to_rp,
                                           ccr_to_h,
                                           ccr_to_ds,
                                           ccr_to_rp,
                                           rp_to_rp,
                                           rp_to_vm])
    return traversal_spec


def build_property_spec(type_=vim.VirtualMachine,
                        properties_to_collect=None, all_properties=False):
    """Builds the property spec.
    :param type_: type of the managed object
    :param properties_to_collect: names of the managed object properties to be
                                  collected while traversal filtering
    :param all_properties: whether all properties of the managed object need
                           to be collected
    :returns: property spec
    """
    if not properties_to_collect:
        properties_to_collect = ['name']

    property_spec = vmodl.query.PropertyCollector.PropertySpec()
    property_spec.all = all_properties
    property_spec.pathSet = properties_to_collect
    property_spec.type = type_
    return property_spec


def build_object_spec(root_folder, traversal_specs):
    """Builds the object spec.
    :param root_folder: root folder reference; the starting point of traversal
    :param traversal_specs: filter specs required for traversal
    :returns: object spec
    """
    object_spec = vmodl.query.PropertyCollector.ObjectSpec()
    object_spec.obj = root_folder
    object_spec.skip = False
    object_spec.selectSet = traversal_specs
    return object_spec


def build_property_filter_spec(property_specs, object_specs):
    """Builds the property filter spec.
    :param property_specs: property specs to be collected for filtered objects
    :param object_specs: object specs to identify objects to be filtered
    :returns: property filter spec
    """
    property_filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    property_filter_spec.propSet = property_specs
    property_filter_spec.objectSet = object_specs
    return property_filter_spec


def get_objects(si, type_, max_objects, properties_to_collect=None,
                all_properties=False):
    """Get all managed object references of the given type.
    It is the caller's responsibility to continue or cancel retrieval.
    :param vim: Vim object
    :param type_: type of the managed object
    :param max_objects: maximum number of objects that should be returned in
                        a single call
    :param properties_to_collect: names of the managed object properties to be
                                  collected
    :param all_properties: whether all properties of the managed object need to
                           be collected
    :returns: all managed object references of the given type
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    if not properties_to_collect:
        properties_to_collect = ['name']

    recur_trav_spec = build_recursive_traversal_spec()
    object_spec = build_object_spec(si.content.rootFolder,
                                    [recur_trav_spec])
    property_spec = build_property_spec(
        type_=type_,
        properties_to_collect=properties_to_collect,
        all_properties=all_properties)
    property_filter_spec = build_property_filter_spec([property_spec],
                                                      [object_spec])
    options = vmodl.query.PropertyCollector.RetrieveOptions()
    options.maxObjects = max_objects
    pc = si.content.propertyCollector
    return pc.RetrievePropertiesEx(specSet=[property_filter_spec],
                                   options=options)


def get_object_properties(si, moref, properties_to_collect, skip_op_id=False):
    """Get properties of the given managed object.
    :param si: Vim object
    :param moref: managed object reference
    :param properties_to_collect: names of the managed object properties to be
                                  collected
    :param skip_op_id: whether to skip putting opID in the request
    :returns: properties of the given managed object
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    if moref is None:
        return None

    all_properties = (properties_to_collect is None or
                      len(properties_to_collect) == 0)
    property_spec = build_property_spec(
        type_=moref.__class__,
        properties_to_collect=properties_to_collect,
        all_properties=all_properties)
    object_spec = build_object_spec(moref, [])
    property_filter_spec = build_property_filter_spec([property_spec],
                                                      [object_spec])

    options = vmodl.query.PropertyCollector.RetrieveOptions()
    options.maxObjects = 1
    retrieve_result = si.content.propertyCollector.RetrievePropertiesEx(
        specSet=[property_filter_spec],
        options=options)
    if retrieve_result and retrieve_result.token:
        si.content.propertyCollector.CancelRetrievePropertiesEx(retrieve_result.token)
    return retrieve_result.objects


def get_object_property(si, moref, property_name, skip_op_id=False):
    """Get property of the given managed object.
    :param vim: Vim object
    :param moref: managed object reference
    :param property_name: name of the property to be retrieved
    :param skip_op_id: whether to skip putting opID in the request
    :returns: property of the given managed object
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    props = get_object_properties(si, moref, [property_name],
                                  skip_op_id=skip_op_id)
    prop_val = None
    if props:
        prop = None
        if hasattr(props[0], 'propSet'):
            # propSet will be set only if the server provides value
            # for the field
            prop = props[0].propSet
        if prop:
            prop_val = prop[0].val

    return prop_val


def get_object_properties_dict(si, moref, properties_to_collect):
    """Get properties of the given managed object as a dict.
    :param si: Vim object
    :param moref: managed object reference
    :param properties_to_collect: names of the managed object properties to be
                                  collected
    :returns: a dict of properties of the given managed object
    :raises: VimException, VimFaultException, VimAttributeException,
             VimSessionOverLoadException, VimConnectionException
    """
    obj_contents = get_object_properties(si, moref, properties_to_collect)
    if obj_contents is None:
        return {}
    property_dict = {}
    if hasattr(obj_contents[0], 'propSet'):
        dynamic_properties = obj_contents[0].propSet
        if dynamic_properties:
            for prop in dynamic_properties:
                property_dict[prop.name] = prop.val
    # The object may have information useful for logging
    if hasattr(obj_contents[0], 'missingSet'):
        for m in obj_contents[0].missingSet:
            LOG.warning("Unable to retrieve value for %(path)s "
                        "Reason: %(reason)s",
                        {'path': m.path,
                         'reason': m.faultCause.localizedMessage})
    return property_dict

class WithRetrieval(object):
    def __init__(self, si, retrieve_result):
        super(WithRetrieval, self).__init__()
        self.si = si
        self.retrieve_result = retrieve_result

    def __enter__(self):
        return iter(self)

    def __exit__(self, exc_type, exc_value, traceback):
        cancel_retrieval(self.si, self.retrieve_result)

    def __iter__(self):
        while self.retrieve_result:
            for obj in self.retrieve_result.objects:
                yield obj
            self.retrieve_result = continue_retrieval(self.si, self.retrieve_result)

try:
    from attr.converters import optional as optional_attr
except ImportError:
    def optional_attr(converter):
        def wrap(value):
            if value is None:
                return None
            return converter(value)

        return wrap

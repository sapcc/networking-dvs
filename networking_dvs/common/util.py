import os, six

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

if os.getenv('STATSD_MOCK', False):
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
    from datadog.dogstatsd import DogStatsd
    stats = DogStatsd(host=os.getenv('STATSD_HOST', 'localhost'),
                      port=int(os.getenv('STATSD_PORT', 9125)),
                      namespace=os.getenv('STATSD_PREFIX', 'openstack')
                      )


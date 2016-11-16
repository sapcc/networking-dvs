import suds.version

if suds.version.__version__ < '0.7':
    from logging import getLogger
    import suds.mx.appender

    def _suds_mx_object_appender_append_workaround(self, parent, content):
        object = content.value
        child = self.node(content)
        parent.append(child)
        for item in object:
            cont = suds.mx.Content(tag=item[0], value=item[1])
            suds.mx.appender.Appender.append(self, child, cont)

    suds.mx.appender.ObjectAppender.append = _suds_mx_object_appender_append_workaround

    import eventlet

    def yield_function(function):
        def wrapped(*args, **kwargs):
            eventlet.sleep(0)
            value = function(*args, **kwargs)
            eventlet.sleep(0)

            return value

        setattr(function.im_class, function.__name__, wrapped)

    import suds.sax.parser

    yield_function(suds.sax.parser.Handler.endElement)

    import suds.wsdl

    def _wdsl_definitions_open_import(self):
        for imp in self.imports:
            eventlet.sleep(0)
            imp.load(self)

    suds.wsdl.Definitions.open_imports = _wdsl_definitions_open_import

    yield_function(suds.wsdl.Definitions.add_children)
    yield_function(suds.wsdl.Definitions.set_wrapped)

    import suds.reader

    yield_function(suds.reader.DocumentReader.open)

    import suds.xsd.schema

    yield_function(suds.xsd.schema.Schema.build)
    yield_function(suds.xsd.schema.Schema.merge)
    yield_function(suds.xsd.schema.Schema.instance)
    from suds.xsd.deplist import DepList

    def _suds_xsd_schema_dereference(self):
        """
        Instruct all children to perform dereferencing.
        """
        all = []
        indexes = {}
        for child in self.children:
            eventlet.sleep(0)
            child.content(all)
        deplist = DepList()
        for x in all:
            eventlet.sleep(0)
            x.qualify()
            midx, deps = x.dependencies()
            item = (x, tuple(deps))
            deplist.add(item)
            indexes[x] = midx
        for x, deps in deplist.sort():
            midx = indexes.get(x)
            if midx is None: continue
            d = deps[midx]
            # log.debug('(%s) merging %s <== %s', self.tns[1], repr(x), repr(d))
            x.merge(d)
            eventlet.sleep(0)

    suds.xsd.schema.Schema.dereference = _suds_xsd_schema_dereference

    import suds.umx.core

    yield_function(suds.umx.core.Core.append)

    import suds.xsd.sxbase

    yield_function(suds.xsd.sxbase.Iter.__init__)

    import suds.xsd.deplist

    # Looks crappy, might need actually to be patched, or upgraded to 0.7 where they fixed it
    def _suds_xsd_deplist_sort(self):
        self.sorted = list()
        self.pushed = set()
        for item in self.unsorted:
            popped = []
            eventlet.sleep(0)
            self.push(item)
            while len(self.stack):
                try:
                    top = self.top()
                    ref = top[1].next()
                    refd = self.index.get(ref)
                    if refd is None:
                        continue
                    self.push(refd)
                except StopIteration:
                    popped.append(self.pop())
                    continue
            for p in popped:
                self.sorted.append(p)
        self.unsorted = self.sorted
        return self.sorted

    suds.xsd.deplist.DepList.sort = _suds_xsd_deplist_sort



def apply():
    pass

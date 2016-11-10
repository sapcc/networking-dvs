import suds.version

if suds.version.__version__ < '0.7':
    import suds.mx.appender

    def _suds_mx_object_appender_append_workaround(self, parent, content):
        object = content.value
        child = self.node(content)
        parent.append(child)
        for item in object:
            cont = suds.mx.Content(tag=item[0], value=item[1])
            suds.mx.appender.Appender.append(self, child, cont)

    suds.mx.appender.ObjectAppender.append = _suds_mx_object_appender_append_workaround

    import suds.sax.parser, eventlet

    _original_sax_parser_endElement = suds.sax.parser.Handler.endElement

    def _sax_parser_endElement(self, name):
        _original_sax_parser_endElement(self, name)
        eventlet.sleep(0)

    suds.sax.parser.Handler.endElement = _sax_parser_endElement

    # _original_sax_parser_characters = suds.sax.parser.Handler.characters

    #def _sax_parser_characters(self, characters):
    #    value = _original_sax_parser_endElement(self, content)
    #    eventlet.sleep(0)

    # suds.sax.parser.Handler.characters = _sax_parser_characters

def apply():
    pass

from sqlalchemy.sql.expression import ColumnElement, _literal_as_binds
from sqlalchemy.sql.sqltypes import Text
from sqlalchemy.ext.compiler import compiles


class string_agg(ColumnElement):
    def __init__(self, expr, separator, order_by=None):
        self.type = Text
        self.expr = _literal_as_binds(expr)
        self.separator = _literal_as_binds(separator)
        self.order_by = _literal_as_binds(order_by)

    @property
    def _from_objects(self):
        return self.expr._from_objects


@compiles(string_agg, 'postgresql')
def compile_string_agg(element, compiler, **kwargs):
    head = 'STRING_AGG(%s, %s' % (
        compiler.process(element.expr),
        compiler.process(element.separator)
    )
    if element.order_by is not None:
        tail = ' ORDER BY %s)' % compiler.process(element.order_by)
    else:
        tail = ')'
    return head + tail


@compiles(string_agg, 'mysql')
def compile_string_agg(element, compiler, **kwargs):
    if element.order_by is not None:
        order = ' ORDER BY %s' % compiler.process(element.order_by)
    else:
        order = ''
    return 'GROUP_CONCAT(%s %s SEPARATOR %s)' % (
        compiler.process(element.expr),
        order,
        compiler.process(element.separator)
    )

from kitty.model import Container
from kitty.model import String, Static, Group


def _valuename(name):
    return '%s_value' % name


class XmlNode(Container):
    def __init__(self, tag, value, attributes=None, fuzzable=True):
        if isinstance(value, str):
            value_field = [String(name=_valuename(tag), value=value)]
        else:
            value_field = value
        fields = [
            startTag(tag, attributes, fuzzable),
            Container(name='child_%s' % _valuename(tag), fields=value_field),
            endTag(tag, fuzzable=True)
        ]
        super(XmlNode, self).__init__(name=tag, fields=fields, fuzzable=fuzzable)


class startTag(Container):
    def __init__(self, tag, attributes=None, fuzzable=True):
        name = 'start_tag_%s' % tag
        fields = [
            Group(['<', ''], fuzzable=False),
            String(name=name, value=tag),
        ]
        if attributes is not None:
            fields += attributes
        fields.append(Group(['>', '', ' />'], fuzzable=False))
        super(startTag, self).__init__(name='container_%s' % name, fields=fields, fuzzable=fuzzable)


class endTag(Container):
    def __init__(self, tag, fuzzable=True):
        name = 'end_tag_%s' % tag
        fields = [
            Group(['<', '', '</'], fuzzable=False),
            String(name=name, value=tag),
            Group(['>', '', ' />'], fuzzable=False),
        ]
        super(endTag, self).__init__(name='container_%s' % name, fields=fields, fuzzable=fuzzable)


class xmlAttribute(Container):
    '''
    XML attribute field
    '''

    def __init__(self, key, value, fuzzable=True):
        fields = [
            Static(' '),
            String(name='attribute key', value=key, fuzzable=False),
            Static('="'),
            Container(name='attribute value', fields=value),
            Static('"'),
        ]
        super(xmlAttribute, self).__init__(name=key, fields=fields, fuzzable=fuzzable)


class xmlTextAttribute(xmlAttribute):
    '''
    XML String attribute value
    '''

    def __init__(self, key, value, fuzzable=True):
        value_field = [String(name=_valuename(key), value=value)]
        super(xmlTextAttribute, self).__init__(key, value_field, fuzzable)

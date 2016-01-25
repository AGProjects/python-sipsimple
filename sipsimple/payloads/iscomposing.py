
"""Parses and produces isComposing messages according to RFC3994."""


__all__ = ['namespace', 'IsComposingDocument', 'State', 'LastActive', 'ContentType', 'Refresh', 'IsComposingMessage']


from sipsimple.payloads import XMLDocument, XMLRootElement, XMLStringElement, XMLPositiveIntegerElement, XMLDateTimeElement, XMLElementChild


namespace = 'urn:ietf:params:xml:ns:im-iscomposing'


class IsComposingDocument(XMLDocument):
    content_type = "application/im-iscomposing+xml"

IsComposingDocument.register_namespace(namespace, prefix=None, schema='im-iscomposing.xsd')


# Attribute value types
class StateValue(str):
    def __new__(cls, value):
        if value not in ('active', 'idle'):
            value = 'idle'
        return str.__new__(cls, value)


# Elements
class State(XMLStringElement):
    _xml_tag = 'state'
    _xml_namespace = namespace
    _xml_document = IsComposingDocument
    _xml_value_type = StateValue


class LastActive(XMLDateTimeElement):
    _xml_tag = 'lastactive'
    _xml_namespace = namespace
    _xml_document = IsComposingDocument


class ContentType(XMLStringElement):
    _xml_tag = 'contenttype'
    _xml_namespace = namespace
    _xml_document = IsComposingDocument


class Refresh(XMLPositiveIntegerElement):
    _xml_tag = 'refresh'
    _xml_namespace = namespace
    _xml_document = IsComposingDocument


class IsComposingMessage(XMLRootElement):
    _xml_tag = 'isComposing'
    _xml_namespace = namespace
    _xml_document = IsComposingDocument
    _xml_children_order = {State.qname: 0,
                           LastActive.qname: 1,
                           ContentType.qname: 2,
                           Refresh.qname: 3,
                           None: 4}

    state = XMLElementChild('state', type=State, required=True, test_equal=True)
    last_active = XMLElementChild('last_active', type=LastActive, required=False, test_equal=True)
    content_type = XMLElementChild('content_type', type=ContentType, required=False, test_equal=True)
    refresh = XMLElementChild('refresh', type=Refresh, required=False, test_equal=True)

    def __init__(self, state=None, last_active=None, content_type=None, refresh=None):
        XMLRootElement.__init__(self)
        self.state = state
        self.last_active = last_active
        self.content_type = content_type
        self.refresh = refresh


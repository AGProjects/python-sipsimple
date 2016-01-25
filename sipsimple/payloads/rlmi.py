
"""RLMI document handling as described in RFC 4662"""


__all__ = ['namespace', 'RLMIDocument', 'Name', 'Instance', 'Resource', 'List']


from sipsimple.payloads import XMLDocument, XMLElement, XMLListElement, XMLListRootElement, XMLLocalizedStringElement, XMLElementID, XMLAttribute
from sipsimple.payloads.datatypes import AnyURI, Boolean, UnsignedInt


namespace = 'urn:ietf:params:xml:ns:rlmi'


class RLMIDocument(XMLDocument):
    content_type = 'application/rlmi+xml'

RLMIDocument.register_namespace(namespace, prefix=None, schema='rlmi.xsd')


class StateValue(str):
    def __new__(cls, value):
        if value not in ('active', 'pending', 'terminated'):
            raise ValueError("Invalid state value: %s" % value)
        return str.__new__(cls, value)


class Name(XMLLocalizedStringElement):
    _xml_tag = 'name'
    _xml_namespace = namespace
    _xml_document = RLMIDocument


class Instance(XMLElement):
    _xml_tag = 'instance'
    _xml_namespace = namespace
    _xml_document = RLMIDocument

    id = XMLElementID('id', type=str, required=True, test_equal=True)
    state = XMLAttribute('state', type=StateValue, required=True, test_equal=True)
    reason = XMLAttribute('reason', type=str, required=False, test_equal=True)
    cid = XMLAttribute('cid', type=str, required=False, test_equal=True)

    def __init__(self, id, state, reason=None, cid=None):
        XMLElement.__init__(self)
        self.id = id
        self.state = state
        self.reason = reason
        self.cid = cid

    def __repr__(self):
        return '%s(%r, state=%r, reason=%r, cid=%r)' % (self.__class__.__name__, self.id, self.state, self.reason, self.cid)


class Resource(XMLListElement):
    _xml_tag = 'resource'
    _xml_namespace = namespace
    _xml_document = RLMIDocument
    _xml_item_type = (Name, Instance)

    uri = XMLElementID('uri', type=AnyURI, required=True, test_equal=True)

    def __init__(self, uri, items=[]):
        XMLElement.__init__(self)
        self.uri = uri
        self.update(items)

    def __repr__(self):
        return '%s(%r, items=%r)' % (self.__class__.__name__, self.uri, list(self))


class List(XMLListRootElement):
    _xml_tag = 'list'
    _xml_namespace = namespace
    _xml_document = RLMIDocument
    _xml_item_type = (Name, Resource)

    uri = XMLElementID('uri', type=AnyURI, required=True, test_equal=True)
    version = XMLAttribute('version', type=UnsignedInt, required=True, test_equal=True)
    full_state = XMLAttribute('full_state', xmlname='fullState', type=Boolean, required=True, test_equal=True)
    cid = XMLAttribute('cid', type=str, required=False, test_equal=True)

    def __init__(self, uri, version, full_state, cid=None, items=[]):
        XMLListElement.__init__(self)
        self.uri = uri
        self.version = version
        self.full_state = full_state
        self.cid = cid
        self.update(items)

    def __repr__(self):
        return '%s(%r, version=%r, full_state=%r, cid=%r, items=%r)' % (self.__class__.__name__, self.uri, self.version, self.full_state, self.cid, list(self))



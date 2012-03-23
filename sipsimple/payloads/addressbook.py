# Copyright (C) 2012 AG Projects. See LICENSE for details.
#

"""Addressbook related payload elements"""


__all__ = ['namespace', 'Group', 'Contact', 'ContactURI', 'ContactURIList', 'ElementExtension', 'ElementAttributes']


from lxml import etree

from sipsimple.payloads import XMLElement, XMLListElement, XMLStringElement, XMLBooleanElement, XMLElementID, XMLAttribute, XMLElementChild
from sipsimple.payloads.datatypes import AnyURI
from sipsimple.payloads.resourcelists import ResourceListsDocument, ListElement


namespace = 'urn:ag-projects:xml:ns:addressbook'

ResourceListsDocument.register_namespace(namespace, prefix='addressbook', schema='addressbook.xsd')


class ElementExtension(object): pass


class Name(XMLStringElement):
    _xml_tag = 'name'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)


class Group(XMLElement, ListElement):
    _xml_tag = 'group'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=str, required=True, test_equal=True)
    name = XMLElementChild('name', type=Name, required=True, test_equal=True)

    def __init__(self, id, name):
        XMLElement.__init__(self)
        self.id = id
        self.name = name

    def __unicode__(self):
        return unicode(self.name)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.id, self.name)


class ContactURI(XMLElement):
    _xml_tag = 'uri'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=str, required=True, test_equal=True)
    uri = XMLAttribute('uri', type=AnyURI, required=True, test_equal=True)
    type = XMLAttribute('type', type=unicode, required=False, test_equal=True)

    def __init__(self, id, uri, type=None):
        XMLElement.__init__(self)
        self.id = id
        self.uri = uri
        self.type = type

    def __unicode__(self):
        return unicode(self.uri)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.id, self.uri, self.type)


class ContactURIList(XMLListElement):
    _xml_tag = 'uris'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_item_type = ContactURI

    def __init__(self, uris=[]):
        XMLListElement.__init__(self)
        self.update(uris)


class PolicyValue(str):
    def __new__(cls, value):
        if value not in ('allow', 'block', 'ignore', 'confirm'):
            raise ValueError("Invalid policy value: %s" % value)
        return super(PolicyValue, cls).__new__(cls, value)


class Policy(XMLStringElement):
    _xml_tag = 'policy'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_value_type = PolicyValue


class Subscribe(XMLBooleanElement):
    _xml_tag = 'subscribe'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument


class DialogHandling(XMLElement):
    _xml_tag = 'dialog'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument

    policy    = XMLElementChild('policy',    type=Policy, required=True, test_equal=True)
    subscribe = XMLElementChild('subscribe', type=Subscribe, required=True, test_equal=True)

    def __init__(self, policy, subscribe):
        XMLElement.__init__(self)
        self.policy = policy
        self.subscribe = subscribe

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.policy, self.subscribe)


class PresenceHandling(XMLElement):
    _xml_tag = 'presence'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument

    policy    = XMLElementChild('policy',    type=Policy, required=True, test_equal=True)
    subscribe = XMLElementChild('subscribe', type=Subscribe, required=True, test_equal=True)

    def __init__(self, policy, subscribe):
        XMLElement.__init__(self)
        self.policy = policy
        self.subscribe = subscribe

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.policy, self.subscribe)


class Contact(XMLElement, ListElement):
    _xml_tag = 'contact'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=str, required=True, test_equal=True)
    group_id = XMLAttribute('group_id', type=str, required=True, test_equal=True)

    name = XMLElementChild('name', type=Name, required=True, test_equal=True)
    uris = XMLElementChild('uris', type=ContactURIList, required=True, test_equal=True)
    dialog = XMLElementChild('dialog', type=DialogHandling, required=True, test_equal=True)
    presence = XMLElementChild('presence', type=PresenceHandling, required=True, test_equal=True)

    def __init__(self, id, group_id, name, uris=[], presence_handling=None, dialog_handling=None):
        XMLElement.__init__(self)
        self.id = id
        self.group_id = group_id
        self.name = name
        self.uris = ContactURIList(uris)
        self.dialog = dialog_handling or DialogHandling('confirm', False)
        self.presence = presence_handling or PresenceHandling('confirm', False)

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.group_id, self.name, list(self.uris), self.presence, self.dialog)


#
# Extensions
#

class ElementAttributes(XMLElement, ElementExtension):
    _xml_tag = 'attributes'
    _xml_namespace = 'urn:ag-projects:sipsimple:xml:ns:addressbook'
    _xml_document = ResourceListsDocument

    def __init__(self, attributes={}):
        XMLElement.__init__(self)
        self._attributes = dict()
        self.update(attributes)

    def _parse_element(self, element):
        self._attributes = dict()
        attribute_tag = '{%s}attribute' % self._xml_namespace
        for child in (child for child in element if child.tag == attribute_tag):
            if 'nil' in child.attrib:
                self[child.attrib['name']] = None
            else:
                self[child.attrib['name']] = unicode(child.text or u'')

    def _build_element(self):
        self.element.clear()
        attribute_tag = '{%s}attribute' % self._xml_namespace
        for key, value in self.iteritems():
            child = etree.SubElement(self.element, attribute_tag, nsmap=self._xml_document.nsmap)
            child.attrib['name'] = key
            if value is None:
                child.attrib['nil'] = 'true'
            else:
                child.text = value

    def __contains__(self, key):
        return key in self._attributes

    def __iter__(self):
        return iter(self._attributes)

    def __getitem__(self, key):
        return self._attributes[key]

    def __setitem__(self, key, value):
        if self._attributes.get(key, None) == value:
            return
        self._attributes[key] = value
        self.__dirty__ = True

    def __delitem__(self, key):
        del self._attributes[key]
        self.__dirty__ = True

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, dict(self))

    def clear(self):
        if self._attributes:
            self._attributes.clear()
            self.__dirty__ = True

    def get(self, key, default=None):
        return self._attributes.get(key, default)

    def has_key(self, key):
        return key in self._attributes

    def items(self):
        return self._attributes.items()

    def iteritems(self):
        return self._attributes.iteritems()

    def iterkeys(self):
        return self._attributes.iterkeys()

    def itervalues(self):
        return self._attributes.itervalues()

    def keys(self):
        return self._attributes.keys()

    def pop(self, key, *args):
        value = self._attributes.pop(key, *args)
        if not args or value is not args[0]:
            self.__dirty__ = True
        return value

    def popitem(self):
        value = self._attributes.popitem()
        self.__dirty__ = True
        return value

    def setdefault(self, key, default=None):
        value = self._attributes.setdefault(key, default)
        if value is default:
            self.__dirty__ = True
        return value

    def update(self, attributes=(), **kw):
        self._attributes.update(attributes, **kw)
        if attributes or kw:
            self.__dirty__ = True

ResourceListsDocument.register_namespace(ElementAttributes._xml_namespace, prefix='sipsimple')
Group.register_extension('attributes', ElementAttributes)
Contact.register_extension('attributes', ElementAttributes)
ContactURI.register_extension('attributes', ElementAttributes)



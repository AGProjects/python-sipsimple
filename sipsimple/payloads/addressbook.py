
"""Addressbook related payload elements"""


__all__ = ['namespace', 'Group', 'Contact', 'ContactURI', 'Policy', 'ElementExtension', 'ElementAttributes']


from application.python import Null
from lxml import etree

from sipsimple.payloads import XMLElement, XMLListElement, XMLStringElement, XMLBooleanElement, XMLElementID, XMLAttribute, XMLElementChild
from sipsimple.payloads import IterateIDs, IterateItems, All
from sipsimple.payloads.datatypes import AnyURI, ID
from sipsimple.payloads.resourcelists import ResourceListsDocument, ListElement


namespace = 'urn:ag-projects:xml:ns:addressbook'

ResourceListsDocument.register_namespace(namespace, prefix='addressbook', schema='addressbook.xsd')


class ElementExtension(object): pass


class Name(XMLStringElement):
    _xml_tag = 'name'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument


class ContactID(XMLStringElement):
    _xml_tag = 'contact_id'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_value_type = ID


class ContactList(XMLListElement):
    _xml_tag = 'contacts'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_item_type = ContactID

    def __init__(self, contacts=[]):
        XMLListElement.__init__(self)
        self.update(contacts)

    def __contains__(self, item):
        if isinstance(item, basestring):
            item = ContactID(item)
        return super(ContactList, self).__contains__(item)

    def __iter__(self):
        return (item.value for item in super(ContactList, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            item = ContactID(item)
        super(ContactList, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            try:
                item = (entry for entry in super(ContactList, self).__iter__() if entry.value == item).next()
            except StopIteration:
                raise KeyError(item)
        super(ContactList, self).remove(item)


class Group(XMLElement, ListElement):
    _xml_tag = 'group'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=ID, required=True, test_equal=True)
    name = XMLElementChild('name', type=Name, required=True, test_equal=True)
    contacts = XMLElementChild('contacts', type=ContactList, required=True, test_equal=True)

    def __init__(self, id, name, contacts=[]):
        XMLElement.__init__(self)
        self.id = id
        self.name = name
        self.contacts = ContactList(contacts)

    def __unicode__(self):
        return unicode(self.name)

    def __repr__(self):
        return '%s(%r, %r, contacts=%r)' % (self.__class__.__name__, self.id, self.name, list(self.contacts))


class ContactURI(XMLElement):
    _xml_tag = 'uri'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=ID, required=True, test_equal=True)
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

    default = XMLAttribute('default', type=str, required=False, test_equal=True)

    def __init__(self, uris=[], default=None):
        XMLListElement.__init__(self)
        self.update(uris)
        self.default = default

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[ContactURI].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[ContactURI].itervalues()
        else:
            return self._xmlid_map[ContactURI][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[ContactURI].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[ContactURI][key])

    def get(self, key, default=None):
        return self._xmlid_map[ContactURI].get(key, default)


class PolicyValue(str):
    def __new__(cls, value):
        if value not in ('allow', 'block', 'default'):
            raise ValueError("Invalid policy value: %s" % value)
        return super(PolicyValue, cls).__new__(cls, value)


class PolicyString(XMLStringElement):
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

    policy    = XMLElementChild('policy', type=PolicyString, required=True, test_equal=True)
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

    policy    = XMLElementChild('policy', type=PolicyString, required=True, test_equal=True)
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

    id = XMLElementID('id', type=ID, required=True, test_equal=True)

    name = XMLElementChild('name', type=Name, required=True, test_equal=True)
    uris = XMLElementChild('uris', type=ContactURIList, required=True, test_equal=True)
    dialog = XMLElementChild('dialog', type=DialogHandling, required=True, test_equal=True)
    presence = XMLElementChild('presence', type=PresenceHandling, required=True, test_equal=True)

    def __init__(self, id, name, uris=[], presence_handling=None, dialog_handling=None):
        XMLElement.__init__(self)
        self.id = id
        self.name = name
        self.uris = uris
        self.dialog = dialog_handling or DialogHandling('default', False)
        self.presence = presence_handling or PresenceHandling('default', False)

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.name, list(self.uris), self.presence, self.dialog)


class Policy(XMLElement, ListElement):
    _xml_tag = 'policy-element'
    _xml_namespace = namespace
    _xml_extension_type = ElementExtension
    _xml_document = ResourceListsDocument

    id = XMLElementID('id', type=ID, required=True, test_equal=True)
    uri = XMLAttribute('uri', type=AnyURI, required=True, test_equal=True)

    name = XMLElementChild('name', type=Name, required=True, test_equal=True)
    dialog = XMLElementChild('dialog', type=DialogHandling, required=True, test_equal=True)
    presence = XMLElementChild('presence', type=PresenceHandling, required=True, test_equal=True)

    def __init__(self, id, uri, name='', presence_handling=None, dialog_handling=None):
        XMLElement.__init__(self)
        self.id = id
        self.uri = uri
        self.name = name
        self.dialog = dialog_handling or DialogHandling('default', False)
        self.presence = presence_handling or PresenceHandling('default', False)

    def __unicode__(self):
        return unicode(self.uri)

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.uri, self.name, self.presence, self.dialog)


#
# Extensions
#

class ElementAttributes(XMLElement, ElementExtension):
    _xml_tag = 'attributes'
    _xml_namespace = 'urn:ag-projects:sipsimple:xml:ns:addressbook'
    _xml_document = ResourceListsDocument

    def __init__(self, iterable=(), **attributes):
        XMLElement.__init__(self)
        self._attributes = dict()
        self.update(iterable, **attributes)

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

    def __len__(self):
        return len(self._attributes)

    def __getitem__(self, key):
        return self._attributes[key]

    def __setitem__(self, key, value):
        if self._attributes.get(key, Null) == value:
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

    def update(self, iterable=(), **attributes):
        self._attributes.update(iterable, **attributes)
        if iterable or attributes:
            self.__dirty__ = True

ResourceListsDocument.register_namespace(ElementAttributes._xml_namespace, prefix='sipsimple')
Group.register_extension('attributes', ElementAttributes)
Contact.register_extension('attributes', ElementAttributes)
ContactURI.register_extension('attributes', ElementAttributes)
Policy.register_extension('attributes', ElementAttributes)



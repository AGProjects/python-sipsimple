
"""Resource lists (rfc4826) handling"""


__all__ = ['namespace',
           'ResourceListsDocument',
           'DisplayName',
           'Entry',
           'EntryRef',
           'External',
           'List',
           'ResourceLists',
           # Extensions
           'EntryAttributes']


from collections import deque
from lxml import etree
from xml.sax.saxutils import quoteattr

from application.python import Null

from sipsimple.payloads import XMLDocument, XMLListRootElement, XMLElement, XMLListElement, XMLLocalizedStringElement, XMLElementID, XMLElementChild, ThisClass
from sipsimple.payloads import IterateIDs, IterateItems, All
from sipsimple.payloads.datatypes import AnyURI


namespace = 'urn:ietf:params:xml:ns:resource-lists'

# excerpt from the RFC:

# <list>
# attribute "name" - optional, unique among the same level 
# body: optional <display-name>, the sequence of entry/list/entry-ref/external

# <display-name>
# attribute xml:lang - optional
# body: utf8 string

# <entry>
# attribute "uri" - mandatory, unique among all other <uri> within the same parent
# body: optional <display-name>

# <entry-ref>
# attribute "ref" - mandatory, unique among all other <entry-ref> within the same parent
# body: optional <display-name>
# ref is a relative URI that resolves into <entry>

# <external>
# attribute "anchor" - mandatory, unique among all other anchor in <external> within the same parent
# anchor must be an absolute http uri that resolves into <list>


class ResourceListsDocument(XMLDocument):
    content_type = 'application/resource-lists+xml'

ResourceListsDocument.register_namespace(namespace, prefix='rl', schema='resourcelists.xsd')


## Marker mixins

class ListElement(object): pass
class EntryExtension(object): pass


## Elements

class DisplayName(XMLLocalizedStringElement):
    _xml_tag = 'display-name'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument


class Entry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_extension_type = EntryExtension
    _xml_document = ResourceListsDocument
    _xml_children_order = {DisplayName.qname: 0}

    uri = XMLElementID('uri', type=AnyURI, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)

    def __init__(self, uri, display_name=None):
        XMLElement.__init__(self)
        self.uri = uri
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and u'"%s" <%s>' % (self.display_name, self.uri) or self.uri

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.uri, self.display_name)


class EntryRef(XMLElement):
    _xml_tag = 'entry-ref'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_children_order = {DisplayName.qname: 0}

    ref = XMLElementID('ref', type=AnyURI, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)

    def __init__(self, ref, display_name=None):
        XMLElement.__init__(self)
        self.ref = ref
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.ref) or self.ref

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.ref, self.display_name)


class External(XMLElement):
    _xml_tag = 'external'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_children_order = {DisplayName.qname: 0}

    anchor = XMLElementID('anchor', type=AnyURI, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)

    def __init__(self, anchor, display_name=None):
        XMLElement.__init__(self)
        self.anchor = anchor
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.anchor) or self.anchor

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.anchor, self.display_name)


List = ThisClass # a List can contain items of its own kind

class List(XMLListElement):
    _xml_tag = 'list'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_children_order = {DisplayName.qname: 0,
                           Entry.qname: 1,
                           EntryRef.qname: 1,
                           External.qname: 1}
    _xml_item_type = (Entry, EntryRef, External, List, ListElement)

    name = XMLElementID('name', type=unicode, required=False, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)

    def __init__(self, entries=[], name=None, display_name=None):
        XMLListElement.__init__(self)
        self.name = name
        self.display_name = display_name
        self.update(entries)

    def __repr__(self):
        return '%s(%s, %r, %r)' % (self.__class__.__name__, list(self), self.name, self.display_name)

    def __unicode__(self):
        name = u'List element'
        if self.name is not None:
            name += u' %s' % self.name
        if self.display_name is not None:
            name += u' (%s)' % self.display_name
        return name

List._xml_children_order[List.qname] = 1 # cannot self reference in declaration


class ResourceLists(XMLListRootElement):
    _xml_tag = 'resource-lists'
    _xml_namespace = namespace
    _xml_document = ResourceListsDocument
    _xml_children_order = {List.qname: 0}
    _xml_item_type = List

    def __init__(self, lists=[]):
        XMLListRootElement.__init__(self)
        self.update(lists)

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[List].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[List].itervalues()
        else:
            return self._xmlid_map[List][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[List].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[List][key])

    def get(self, key, default=None):
        return self._xmlid_map[List].get(key, default)

    def get_xpath(self, element):
        if not isinstance(element, (List, Entry, EntryRef, External, ResourceLists)):
            raise ValueError('can only find xpath for List, Entry, EntryRef or External elements')
        nsmap = dict((namespace, prefix) for prefix, namespace in self._xml_document.nsmap.iteritems())
        nsmap[self._xml_namespace] = None
        xpath_nsmap = {}
        root_xpath = '/' + self._xml_tag
        if element is self:
            return root_xpath
        notexpanded = deque([self])
        visited = set(notexpanded)
        parents = {self: None}
        obj = None
        while notexpanded:
            list = notexpanded.popleft()
            for child in list:
                if child is element:
                    parents[child] = list
                    obj = child
                    notexpanded.clear()
                    break
                elif isinstance(child, List) and child not in visited:
                    parents[child] = list
                    notexpanded.append(child)
                    visited.add(child)
        if obj is None:
            return None
        components = []
        while obj is not self:
            prefix = nsmap[obj._xml_namespace]
            if prefix:
                name = '%s:%s' % (prefix, obj._xml_tag)
                xpath_nsmap[obj._xml_namespace] = prefix
            else:
                name = obj._xml_tag
            if isinstance(obj, List):
                if obj.name is not None:
                    components.append('/%s[@%s=%s]' % (name, List.name.xmlname, quoteattr(obj.name)))
                else:
                    siblings = [l for l in parents[obj] if isinstance(l, List)]
                    components.append('/%s[%d]' % (name, siblings.index(obj)+1))
            elif isinstance(obj, Entry):
                components.append('/%s[@%s=%s]' % (name, Entry.uri.xmlname, quoteattr(obj.uri)))
            elif isinstance(obj, EntryRef):
                components.append('/%s[@%s=%s]' % (name, EntryRef.ref.xmlname, quoteattr(obj.ref)))
            elif isinstance(obj, External):
                components.append('/%s[@%s=%s]' % (name, External.anchor.xmlname, quoteattr(obj.anchor)))
            obj = parents[obj]
        components.reverse()
        return root_xpath + ''.join(components) + ('?' + ''.join('xmlns(%s=%s)' % (prefix, namespace) for namespace, prefix in xpath_nsmap.iteritems()) if xpath_nsmap else '')

    def find_parent(self, element):
        if not isinstance(element, (List, Entry, EntryRef, External)):
            raise ValueError('can only find parent for List, Entry, EntryRef or External elements')
        if element is self:
            return None
        notexpanded = deque([self])
        visited = set(notexpanded)
        while notexpanded:
            list = notexpanded.popleft()
            for child in list:
                if child is element:
                    return list
                elif isinstance(child, List) and child not in visited:
                    notexpanded.append(child)
                    visited.add(child)
        return None


#
# Extensions
#

class EntryAttributes(XMLElement, EntryExtension):
    _xml_tag = 'attributes'
    _xml_namespace = 'urn:ag-projects:xml:ns:resource-lists'
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

ResourceListsDocument.register_namespace(EntryAttributes._xml_namespace, prefix='agp-rl')
Entry.register_extension('attributes', EntryAttributes)



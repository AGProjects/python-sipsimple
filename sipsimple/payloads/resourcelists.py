# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Resource lists (rfc4826) handling
"""

from collections import deque
from lxml import etree
from xml.sax.saxutils import quoteattr

from sipsimple.payloads import ValidationError, XMLApplication, XMLListRootElement, XMLElement, XMLListElement, XMLStringElement, XMLAttribute, XMLElementChild, uri_attribute_builder, uri_attribute_parser

__all__ = ['namespace',
           'ResourceListsApplication',
           'DisplayName',
           'Entry',
           'EntryRef',
           'External',
           'List',
           'ResourceLists',
           # Extensions
           'EntryAttributes']

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


class ResourceListsApplication(XMLApplication): pass
ResourceListsApplication.register_namespace(namespace, prefix='rl')


## Marker mixins

class ListElement(object): pass
class EntryExtension(object): pass


## Elements

class DisplayName(XMLStringElement):
    _xml_tag = 'display-name'
    _xml_namespace = namespace
    _xml_application = ResourceListsApplication
    _xml_lang = True


class Entry(XMLElement, ListElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_extension_type = EntryExtension
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    uri = XMLAttribute('uri', type=unicode, required=True, test_equal=True, builder=uri_attribute_builder, parser=uri_attribute_parser)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = uri

    def __init__(self, uri, display_name=None):
        XMLElement.__init__(self)
        self.uri = uri
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and u'"%s" <%s>' % (self.display_name, self.uri) or self.uri

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.uri, self.display_name)


class EntryRef(XMLElement, ListElement):
    _xml_tag = 'entry-ref'
    _xml_namespace = namespace
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    ref = XMLAttribute('ref', type=unicode, required=True, test_equal=True, builder=uri_attribute_builder, parser=uri_attribute_parser)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = ref

    def __init__(self, ref, display_name=None):
        XMLElement.__init__(self)
        self.ref = ref
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.ref) or self.ref

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.ref, self.display_name)


class External(XMLElement, ListElement):
    _xml_tag = 'external'
    _xml_namespace = namespace
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    anchor = XMLAttribute('anchor', type=unicode, required=True, test_equal=True, builder=uri_attribute_builder, parser=uri_attribute_parser)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = anchor

    def __init__(self, anchor, display_name=None):
        XMLElement.__init__(self)
        self.anchor = anchor
        self.display_name = display_name

    def __unicode__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.anchor) or self.anchor

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.anchor, self.display_name)


class List(XMLListElement, ListElement):
    _xml_tag = 'list'
    _xml_namespace = namespace
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0,
                           Entry.qname: 1,
                           EntryRef.qname: 1,
                           External.qname: 1}

    name = XMLAttribute('name', type=unicode, required=False, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = name

    def __init__(self, entries=[], name=None, display_name=None):
        XMLListElement.__init__(self)
        self.name = name
        self.display_name = display_name
        self[0:0] = entries

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag, None)
            if child_cls is not None and issubclass(child_cls, ListElement):
                try:
                    value = child_cls.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    for basetype in (List, Entry, EntryRef, External):
                        if isinstance(value, basetype):
                            break
                    else:
                        list.append(self, value)
                        continue
                    for elem in self:
                        if isinstance(elem, basetype) and value._xml_id == elem._xml_id:
                            element.remove(child)
                            break
                    else:
                        list.append(self, value)

    
    def _build_element(self, *args, **kwargs):
        # build children
        for child in self:
            child.to_element(*args, **kwargs)
    
    def _add_item(self, value):
        for basetype in (List, Entry, EntryRef, External):
            if isinstance(value, basetype):
                break
        else:
            if isinstance(value, ListElement):
                return value
            raise TypeError("cannot add element type %s to List" % value.__class__.__name__)
        for elem in self:
            if isinstance(elem, basetype) and value._xml_id == elem._xml_id:
                raise ValueError("cannot have more than one %s with the same id attribute at this level: %r" % (basetype.__name__, value._xml_id))
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __unicode__(self):
        name = u'List element'
        if self.name is not None:
            name += u' %s' % self.name
        if self.display_name is not None:
            name += u' (%s)' % self.display_name
        return name

    def __repr__(self):
        return '%s(%s, %r, %r)' % (self.__class__.__name__, list.__repr__(self), self.name, self.display_name)

List._xml_children_order[List.qname] = 1 # cannot self reference in declaration


class ResourceLists(XMLListRootElement):
    content_type = 'application/resource-lists+xml'
    
    _xml_tag = 'resource-lists'
    _xml_namespace = namespace
    _xml_application = ResourceListsApplication
    _xml_children_order = {List.qname: 0}
    _xml_schema_file = 'resourcelists.xsd'

    def __init__(self, lists=[]):
        XMLListRootElement.__init__(self)
        self._lists = {}
        self[:] = lists

    def get_xpath(self, element):
        if not isinstance(element, (List, Entry, EntryRef, External, ResourceLists)):
            raise ValueError('can only find xpath for List, Entry, EntryRef or External elements')
        namespaces = dict((namespace, prefix) for prefix, namespace in self._xml_application.xml_nsmap.iteritems())
        namespaces[self._xml_namespace] = ''
        prefix = namespaces[self._xml_namespace]
        root_xpath = '/%s:%s' % (prefix, self._xml_tag) if prefix else '/'+self._xml_tag
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
            prefix = namespaces[obj._xml_namespace]
            name = '%s:%s' % (prefix, obj._xml_tag) if prefix else obj._xml_tag
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
        xpointer = ''.join('xmlns(%s=%s)' % (prefix, namespace) for namespace, prefix in namespaces.iteritems() if prefix)
        return root_xpath + ''.join(components) + ('?'+xpointer if xpointer else '')

    def find_parent(self, element):
        if not isinstance(element, (List, Entry, EntryRef, External)):
            raise ValueError('can obly find parent for List, Entry, EntryRef or External elements')
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

    def _parse_element(self, element, *args, **kwargs):
        self._lists = {}
        for child in element:
            if child.tag == List.qname:
                try:
                    rlist = List.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    if rlist.name in self._lists:
                        element.remove(child)
                        continue
                    list.append(self, rlist)
                    self._lists[rlist.name] = rlist
            else:
                element.remove(child)

    def _build_element(self, *args, **kwargs):
        for rlist in self:
            rlist.to_element(*args, **kwargs)

    def _add_item(self, rlist):
        if not isinstance(rlist, List):
            raise TypeError("found %s, expected %s" % (rlist.__class__.__name__, List.__name__))
        if rlist.name in self._lists:
            raise ValueError("cannot have more than one list with the same name at this level: %s" % rlist.name)
        self._lists[rlist.name] = rlist
        self._insert_element(rlist.element)
        return rlist

    def _del_item(self, rlist):
        del self._lists[rlist.name]
        self.element.remove(rlist.element)

    # it also makes sense to be able to get a List by its name
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._lists[key]
        else:
            return super(ResourceLists, self).__getitem__(key)


#
# Extensions
#

class EntryAttributes(XMLElement, EntryExtension):
    _xml_tag = 'attributes'
    _xml_namespace = 'urn:ag-projects:xml:ns:resource-lists'
    _xml_application = ResourceListsApplication

    def __init__(self, attributes={}):
        XMLElement.__init__(self)
        self._attributes = dict()
        self.update(attributes)

    def _parse_element(self, element, *args, **kwargs):
        self._attributes = dict()
        attribute_tag = '{%s}attribute' % self._xml_namespace
        for child in (child for child in element if child.tag == attribute_tag):
            if 'nil' in child.attrib:
                self[child.attrib['name']] = None
            else:
                self[child.attrib['name']] = unicode(child.text or u'')

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        attribute_tag = '{%s}attribute' % self._xml_namespace
        for key, value in self.iteritems():
            child = etree.SubElement(self.element, attribute_tag, nsmap=self._xml_application.xml_nsmap)
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
        self._attributes[key] = value

    def __delitem__(self, key):
        del self._attributes[key]

    def clear(self):
        self._attributes.clear()

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
        return self._attributes.pop(key, *args)

    def popitem(self):
        return self._attributes.popitem()

    def setdefault(self, key, default=None):
        return self._attributes.setdefault(key, default)

    def update(self, attributes):
        self._attributes.update(attributes)

ResourceListsApplication.register_namespace(EntryAttributes._xml_namespace, prefix='agp-rl')
Entry.register_extension('attributes', EntryAttributes)



"""Resource lists (rfc4826) handling

This module provides convenient classes to parse and generate
resource-lists documents as described in RFC 4826.

Generation
----------

>>> bill = Entry('sip:bill@example.com', display_name = 'Bill Doe')
>>> petri = EntryRef('some/ref')
>>> friends = List([bill, petri])
>>> rl = ResourceLists([friends])
>>> print rl.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">
  <list>
    <entry uri="sip:bill@example.com">
      <display-name>Bill Doe</display-name>
    </entry>
    <entry-ref ref="some/ref"/>
  </list>
</resource-lists>
<BLANKLINE>

toxml() wraps etree.tostring() and accepts all its arguments (like pretty_print).


Parsing
-------

>>> r = ResourceLists.parse(example_from_section_3_3_rfc)
>>> len(r)
1

>>> friends = r[0]
>>> friends.name
'friends'

>>> bill = friends[0]
>>> bill.uri
'sip:bill@example.com'
>>> print bill.display_name
Bill Doe

>>> close_friends = friends[2]
>>> print close_friends[0]
"Joe Smith" <sip:joe@example.com>
>>> print close_friends[2].display_name
Marketing
"""

import sys
from lxml import etree
from sipsimple.applications import ParserError, XMLMeta, XMLListApplication, XMLElement, XMLListElement, XMLStringElement

__all__ = ['_namespace_',
           'ResourceListsMeta',
           'DisplayName',
           'Entry',
           'EntryRef',
           'External',
           'List',
           'ResourceLists']

_namespace_ = 'urn:ietf:params:xml:ns:resource-lists'

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


class ResourceListsMeta(XMLMeta): pass

class DisplayName(XMLStringElement):
    _xml_tag = 'display-name'
    _xml_namespace = _namespace_
    _xml_meta = ResourceListsMeta
    _xml_lang = True

ResourceListsMeta.register(DisplayName)

class Entry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = _namespace_
    _xml_attrs = {'uri': {'id_attribute': True}}
    _xml_meta = ResourceListsMeta

    def __init__(self, uri, display_name=None):
        if uri is None:
            raise ValueError("Entry element's uri must not be None")
        self.uri = uri
        self.display_name = display_name is not None and DisplayName(display_name) or None

    def _parse_element(self, element):
        display_name = element.find(DisplayName.qname)
        self.display_name = display_name is not None and DisplayName.from_element(display_name) or None

    def _build_element(self, element, nsmap):
        # add display_name
        if self.display_name:
            self.display_name.to_element(parent=element, nsmap=nsmap)

    def __str__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.uri) or self.uri

ResourceListsMeta.register(Entry)

class EntryRef(XMLElement):
    _xml_tag = 'entry-ref'
    _xml_namespace = _namespace_
    _xml_attrs = {'ref': {'id_attribute': True}}
    _xml_meta = ResourceListsMeta

    def __init__(self, ref, display_name=None):
        if ref is None:
            raise ValueError("EntryRef element's ref must not be None")
        self.ref = ref
        self.display_name = display_name is not None and DisplayName(display_name) or None

    def _parse_element(self, element):
        display_name = element.find(DisplayName.qname)
        self.display_name = display_name is not None and DisplayName.from_element(display_name) or None

    def _build_element(self, element, nsmap):
        # add display_name
        if self.display_name:
            self.display_name.to_element(parent=element, nsmap=nsmap)

ResourceListsMeta.register(EntryRef)

class External(XMLElement):
    _xml_tag = 'external'
    _xml_namespace = _namespace_
    _xml_attrs = {'anchor': {'id_attribute': True}}
    _xml_meta = ResourceListsMeta

    def __init__(self, anchor, display_name=None):
        if anchor is None:
            raise ValueError("External element's anchor must not be None")
        self.anchor = anchor
        self.display_name = display_name is not None and DisplayName(display_name) or None

    def _parse_element(self, element):
        display_name = element.find(DisplayName.qname)
        self.display_name = display_name is not None and DisplayName.from_element(display_name) or None

    def _build_element(self, element, nsmap):
        # add display_name
        if self.display_name:
            self.display_name.to_element(parent=element, nsmap=nsmap)

ResourceListsMeta.register(External)

class List(XMLListElement):
    _xml_tag = 'list'
    _xml_namespace = _namespace_
    _xml_attrs = {'name': {'id_attribute': True}}
    _xml_meta = ResourceListsMeta

    def __init__(self, entries=[], name=None, display_name=None):
        self.name = name
        self.display_name = display_name is not None and DisplayName(display_name) or None
        self[0:0] = entries

    def _parse_element(self, element):
        self.display_name = None
        for child in element:
            if child.tag == DisplayName.qname:
                self.display_name = DisplayName.from_element(child)
            else:
                child_cls = self._xml_meta.get(child.tag)
                if child_cls is not None:
                    self.append(child_cls.from_element(child, xml_meta=self._xml_meta))
    
    def _build_element(self, element, nsmap):
        # add display name
        if self.display_name:
            self.display_name.to_element(parent=element, nsmap=nsmap)
        # add children
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)
    
    def _before_add(self, value):
        for basetype in (List, Entry, EntryRef, External):
            if isinstance(value, basetype):
                break
        else:
            raise TypeError("Cannot add element type %s to List" % value.__class__.__name__)
        for elem in self:
            if isinstance(elem, basetype) and value == elem:
                raise ValueError("Cannot have more than one %s with the same id attribute at this level: %s" % (basetype.__name__, str(elem)))
        return value

    def __str__(self):
        return self.display_name and str(self.display_name) or str(self.name)

ResourceListsMeta.register(List)

class ResourceLists(XMLListApplication):
    accept_types = ['application/resource-lists+xml']
    build_types = ['application/resource-lists+xml']
    
    _xml_tag = 'resource-lists'
    _xml_namespace = _namespace_
    _xml_meta = ResourceListsMeta
    _xml_schema_file = 'resourcelists.xsd'
    _xml_nsmap = {None: _namespace_}

    _parser_opts = {'remove_blank_text': True}

    def __init__(self, lists=[]):
        self._lists = {}
        self[:] = lists

    def _parse_element(self, element):
        self._lists = {}
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for rlist in self:
            rlist.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, rlist):
        if not isinstance(rlist, List):
            raise TypeError("found %s, expected %s" % (rlist.__class__.__name__, List.__name__))
        if rlist.name in self._lists:
            raise ValueError("Cannot have more than one list with the same name at this level: %s" % rlist.name)
        self._lists[rlist.name] = rlist
        return rlist

    def _before_del(self, rlist):
        del self._lists[rlist.name]

    # it also makes sense to be able to get a List by its name
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._lists[key]
        else:
            return super(ResourceLists, self).__getitem__(key)

ResourceListsMeta.register(ResourceLists)


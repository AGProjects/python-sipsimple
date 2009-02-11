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
<rl:resource-lists xmlns:rl="urn:ietf:params:xml:ns:resource-lists">
  <rl:list>
    <rl:entry uri="sip:bill@example.com">
      <rl:display-name>Bill Doe</rl:display-name>
    </rl:entry>
    <rl:entry-ref ref="some/ref"/>
  </rl:list>
</rl:resource-lists>
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
from sipsimple.applications import ValidationError, XMLApplication, XMLListRootElement, XMLElement, XMLListElement, XMLStringElement, XMLAttribute, XMLElementChild
from sipsimple.applications.util import SIPURI

__all__ = ['_namespace_',
           'ResourceListsApplication',
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


class ResourceListsApplication(XMLApplication): pass
ResourceListsApplication.register_namespace(_namespace_, prefix='rl')


## Marker mixins

class ListElement(object): pass


## Elements

class DisplayName(XMLStringElement):
    _xml_tag = 'display-name'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_lang = True


class Entry(XMLElement, ListElement):
    _xml_tag = 'entry'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    uri = XMLAttribute('uri', type=SIPURI, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = uri

    def __init__(self, uri, display_name=None):
        XMLElement.__init__(self)
        self.uri = uri
        self.display_name = display_name

    def __str__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.uri) or self.uri

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.uri, self.display_name)


class EntryRef(XMLElement, ListElement):
    _xml_tag = 'entry-ref'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    ref = XMLAttribute('ref', type=str, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = ref

    def __init__(self, ref, display_name=None):
        XMLElement.__init__(self)
        self.ref = ref
        self.display_name = display_name

    def __str__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.ref) or self.ref

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.ref, self.display_name)


class External(XMLElement, ListElement):
    _xml_tag = 'external'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0}

    anchor = XMLAttribute('anchor', type=str, required=True, test_equal=True)
    display_name = XMLElementChild('display_name', type=DisplayName, required=False, test_equal=False)
    _xml_id = anchor

    def __init__(self, anchor, display_name=None):
        XMLElement.__init__(self)
        self.anchor = anchor
        self.display_name = display_name

    def __str__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.anchor) or self.anchor

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.anchor, self.display_name)


class List(XMLListElement, ListElement):
    _xml_tag = 'list'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_children_order = {DisplayName.qname: 0,
                           Entry.qname: 1,
                           EntryRef.qname: 1,
                           External.qname: 1}

    name = XMLAttribute('name', type=str, required=False, test_equal=True)
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

    def __str__(self):
        name = 'List element'
        if self.name is not None:
            name += ' %s' % str(self.name)
        if self.display_name is not None:
            name += ' (%s)' % str(self.display_name)
        return name

    def __repr__(self):
        return '%s(%s, %r, %r)' % (self.__class__.__name__, list.__repr__(self), self.name, self.display_name)

List._xml_children_order[List.qname] = 1 # cannot self reference in declaration


class ResourceLists(XMLListRootElement):
    content_type = 'application/resource-lists+xml'
    
    _xml_tag = 'resource-lists'
    _xml_namespace = _namespace_
    _xml_application = ResourceListsApplication
    _xml_children_order = {List.qname: 0}
    _xml_schema_file = 'resourcelists.xsd'

    def __init__(self, lists=[]):
        XMLListRootElement.__init__(self)
        self._lists = {}
        self[:] = lists

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



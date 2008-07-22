"""Resource lists (rfc4826) handling

This module provides convenient classes to parse and generate
<resource-lists> and <rls-services> documents as described in RFC 4826.

Generation
----------

>>> bill = Entry('sip:bill@example.com', display_name = 'Bill Doe')
>>> petri = EntryRef('some/ref')
>>> friends = List([bill, petri])
>>> rl = ResourceLists([friends])
>>> print rl.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<ns0:resource-lists xmlns:ns0="urn:ietf:params:xml:ns:resource-lists">
  <ns0:list>
    <ns0:entry uri="sip:bill@example.com">
      <ns0:display-name>Bill Doe</ns0:display-name>
    </ns0:entry>
    <ns0:entry-ref ref="some/ref"/>
  </ns0:list>
</ns0:resource-lists>
<BLANKLINE>

toxml() wraps etree.tostring() and accepts all its arguments (like pretty_print).

>>> buddies = Service('sip:mybuddies@example.com', 'http://xcap.example.com/xxx', ['presence'])
>>> marketing = Service('sip:marketing@example.com')
>>> marketing.list = List([Entry('sip:joe@example.com'), Entry('sip:sudhir@example.com')])
>>> marketing.packages = ['presence']
>>> rls = RLSServices([buddies, marketing])
>>> print rls.toxml(validate=False, pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<ns0:rls-services xmlns:ns0="urn:ietf:params:xml:ns:rls-services">
  <ns0:service uri="sip:mybuddies@example.com">
    <ns0:resource-list>http://xcap.example.com/xxx</ns0:resource-list>
    <ns0:packages>
      <ns0:package>presence</ns0:package>
    </ns0:packages>
  </ns0:service>
  <ns0:service uri="sip:marketing@example.com">
    <ns1:list xmlns:ns1="urn:ietf:params:xml:ns:resource-lists">
      <ns1:entry uri="sip:joe@example.com"/>
      <ns1:entry uri="sip:sudhir@example.com"/>
    </ns1:list>
    <ns0:packages>
      <ns0:package>presence</ns0:package>
    </ns0:packages>
  </ns0:service>
</ns0:rls-services>
<BLANKLINE>

XXX validation fails when there're one or more List elements (i.e. from imported namespace)
XXX when there are no Lists, validations passes:
>>> _ = RLSServices([buddies]).toxml(validate=True)


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
>>> close_friends[0]
Entry('sip:joe@example.com', display_name=DisplayName('Joe Smith'))
>>> print close_friends[2].display_name
Marketing


>>> rls = RLSServices.parse(example_from_section_4_3_rfc)
>>> len(rls)
2

>>> rls[0].uri
'sip:mybuddies@example.com'

>>> rls[0].list
ResourceList(u'http://xcap.example.com/xxx')

>>> rls[0].packages
Packages([Package(u'presence')])


>>> rls[1].uri
'sip:marketing@example.com'

>>> rls[1].list
List([Entry('sip:joe@example.com'), Entry('sip:sudhir@example.com')], name='marketing')

>>> assert rls[1].packages == ['presence']

"""


import sys
from lxml import etree
from pypjua.applications import XMLParser, ParserError
from hlist import TypedList, HookedList

__all__ = ['List',
           'DisplayName',
           'Entry',
           'EntryRef',
           'External',
           'ResourceLists',
           'Package',
           'Packages',
           'ResourceList',
           'Service',
           'RLSServices']

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

# <rls-services>
# body: sequence of <service> elements

# <service>
# attribute "uri": mandatory, unique among all <service> in any document
# body: List or ResourceList, then optional Packages

# <resource-list>
# body: http uri that references <list>

# <packages>
# body: sequence of <package>

# <package>
# body: name of SIP event package

# XXX currently there are no consistency checks in the classes (i.e. that name is unique, etc)
# you'll get an error at validation, but you should get it earlier, at object construction.

class ResourceListsParser(XMLParser):
    accept_types = ['application/resource-lists+xml']
    _namespace = 'urn:ietf:params:xml:ns:resource-lists'
    _schema_file = 'resourcelists.xsd'
    _parser = etree.XMLParser(remove_blank_text=True)

class RLSServicesParser(XMLParser):
    accept_types = ['application/rls-services+xml']
    _namespace = 'urn:ietf:params:xml:ns:rls-services'
    _schema_file = 'rlsservices.xsd'
    _parser = etree.XMLParser(remove_blank_text=True)

_resource_lists_prefix = '{%s}' % ResourceListsParser._namespace
_rls_services_prefix = '{%s}' % RLSServicesParser._namespace


class ToElementMixin(object):
    _xml_tag = None
    default_encoding = 'UTF-8'

    def to_element(self, parent = None):
        if parent is None:
            element = etree.Element(self._xml_tag)
        else:
            element = etree.SubElement(parent, self._xml_tag)
        self.set_element(element)
        return element

    def set_element(self, element):
        raise NotImplementedError

    def toxml(self, *args, **kwargs):
        """Shortcut that generates Element and calls etree.tostring"""
        element = self.to_element()
        kwargs.setdefault('encoding', self.default_encoding)
        return etree.tostring(element, *args, **kwargs)


class DisplayNameMixin(object):
    "adds display_name attribute to the class"

    def _get_display_name(self):
        return self._display_name

    def _set_display_name(self, value):
        if value is not None and not isinstance(value, DisplayName):
            value = DisplayName(value)
        self._display_name = value

    display_name = property(_get_display_name,
                            _set_display_name)


class DisplayName(ToElementMixin):
    _xml_tag = _resource_lists_prefix + 'display-name'

    def __init__(self, text, lang = None):
        self.text = text
        self.lang = lang

    @classmethod
    def from_element(cls, element):
        lang = element.get('xml:lang', None)
        return cls(element.text, lang = lang)

    def set_element(self, element):
        element.text = self.text
        if self.lang is not None:
            element.set('xml:lang', self.lang)

    def __repr__(self):
        if self.lang is not None:
            lang = ', lang=%r' % self.lang
        else:
            lang = ''
        return 'DisplayName(%r%s)' % (self.text, lang)

    def __str__(self):
        return str(self.text)

    def __unicode__(self):
        return unicode(self.text)

    def __cmp__(self, other):
        return cmp(self.text, other.text) or cmp(self.lang, other.lang)


def find_display_name(element):
    for child in element:
        if child.tag == '{urn:ietf:params:xml:ns:resource-lists}display-name':
            return DisplayName.from_element(child)


class ElementWithDisplayName(ToElementMixin, DisplayNameMixin):
    _arg = None

    @classmethod
    def from_element(cls, element):
        arg = element.attrib[cls._arg]
        display_name = find_display_name(element)
        return cls(arg, display_name)

    def set_element(self, element):
        element.set(self._arg, getattr(self, self._arg))
        if self.display_name:
            self.display_name.to_element(element)

    def __init__(self, arg, display_name = None):
        setattr(self, self._arg, arg)
        self.display_name = display_name

    def __repr__(self):
        if self.display_name is not None:
            display_name = ', display_name=%r' % self.display_name
        else:
            display_name = ''
        return '%s(%r%s)' % (self.__class__.__name__,
                             getattr(self, self._arg),
                             display_name)

    def __cmp__(self, other):
        arg = self._arg
        return cmp(getattr(self, arg), getattr(other, arg)) or \
               cmp(self.display_name, other.display_name)

    def __hash__(self):
        return hash((getattr(self, self._arg), self.display_name))


class Entry(ElementWithDisplayName):
    _xml_tag = _resource_lists_prefix + 'entry'
    _arg = 'uri'


class EntryRef(ElementWithDisplayName):
    _xml_tag = _resource_lists_prefix + 'entry-ref'
    _arg = 'ref'


class External(ElementWithDisplayName):
    _xml_tag = _resource_lists_prefix + 'external'
    _arg = 'anchor'


class List(TypedList, ToElementMixin, DisplayNameMixin):
    "list of List/Entry/EntryRef/External objects"
    _xml_tag = _resource_lists_prefix + 'list'

    def __init__(self, iterable = [], name = None, display_name = None):
        assert not isinstance(iterable, basestring), 'have you passed name as first argument?'
        list.__init__(self, iterable)
        self.name = name
        self.display_name = display_name

    @classmethod
    def from_element(cls, element):
        display_name = None
        lst = []
        for child in element:
            klass = _mapping_.get(child.tag)
            if klass is DisplayName:
                display_name = DisplayName.from_element(child)
            elif klass is not None:
                obj = klass.from_element(child)
                lst.append(obj)
        return cls(lst, element.get('name'), display_name)

    def set_element(self, element):
        if self.name is not None:
            element.set('name', self.name)
        if self.display_name:
            self.display_name.to_element(element)
        for child in self:
            child.to_element(element)

    def __repr__(self):
        if self.name is not None:
            name = ', name=%r' % self.name
        else:
            name = ''
        if self.display_name is not None:
            display_name = ', display_name=%r' % self.display_name
        else:
            display_name = ''            
        return '%s(%s%s%s)' % (self.__class__.__name__,
                               list.__repr__(self),
                               name,
                               display_name)

    def entries(self):
        return [x for x in self if isinstance(x, Entry)]

    def lists(self):
        return [x for x in self if isinstance(x, List)]

    def entryrefs(self):
        return [x for x in self if isinstance(x, EntryRef)]

    def externals(self):
        return [x for x in self if isinstance(x, External)]

List._items_types_ = (Entry, EntryRef, External, List)

# possible List members
_mapping_ = { Entry._xml_tag       : Entry,
              EntryRef._xml_tag    : EntryRef,
              List._xml_tag        : List,
              External._xml_tag    : External,
              DisplayName._xml_tag : DisplayName }


class MainListElement(TypedList):

    # default parameters for toxml()
    default_validate = True
    default_encoding = 'UTF-8'
    default_xml_declaration = True

    @classmethod
    def from_element(cls, element):
        self = cls()
        for x in element:
            assert x.tag == cls._items_types_._xml_tag, x.tag
            l = cls._items_types_.from_element(x)
            self.append(l)
        return self

    def to_element(self):
        element = etree.Element(self._xml_tag)
        for child in self:
            child.to_element(element)
        return element

    @classmethod
    def parse(cls, document):
        root = cls.parser._parse(document)
        return cls.from_element(root)

    def toxml(self, *args, **kwargs):
        """Shortcut that generates Element and calls etree.tostring.

        If `validate' keyword arg is present and evaluates to True, method
        also does schema validation.
        """
        element = self.to_element()
        kwargs.setdefault('encoding', self.default_encoding)
        kwargs.setdefault('xml_declaration', self.default_xml_declaration)
        validate = kwargs.pop('validate', self.default_validate)
        res = etree.tostring(element, *args, **kwargs)
        if validate:
            try:
                self.parser._validate(element)
            except ParserError:
                sys.stderr.write('Failed to validate:\n%s\n' % res)
                raise
        return res


class ResourceLists(MainListElement):
    "list of Lists"
    _xml_tag = _resource_lists_prefix + 'resource-lists'
    _items_types_ = List
    parser = ResourceListsParser()


class StringElement(unicode, ToElementMixin):

    def __new__(cls, name):
        return unicode.__new__(cls, name)

    @classmethod
    def from_element(cls, element):
        return cls(element.text)

    def set_element(self, element):
        element.text = self

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, unicode.__repr__(self))


class Package(StringElement):
    _xml_tag = _rls_services_prefix + 'package'


class Packages(HookedList, ToElementMixin):
    _xml_tag = _rls_services_prefix + 'packages'

    @classmethod
    def from_element(cls, element):
        self = cls()
        for child in element:
            assert child.tag == Package._xml_tag
            self.append(Package.from_element(child))
        return self

    def set_element(self, element):
        for child in self:
            child.to_element(element)

    def _before_insert(self, value):
        if isinstance(value, basestring):
            return Package(value)
        elif isinstance(value, Package):
            return value
        else:
            raise TypeError('value must be Package, str or unicode')


class ResourceList(StringElement):
    _xml_tag = _rls_services_prefix + 'resource-list'


class Service(ToElementMixin):
    _xml_tag = _rls_services_prefix + 'service'

    list_classes = { ResourceList._xml_tag : ResourceList,
                     _rls_services_prefix + 'list' : List, # QQQ why this is needed?
                     List._xml_tag : List }

    def __init__(self, uri, list = List(), packages = Packages()):
        self.uri = uri
        self.list = list
        self.packages = packages

    def _get_list(self):
        return self._list

    def _set_list(self, list):
        if isinstance(list, (List, ResourceList)):
            self._list = list
        else:
            self._list = ResourceList(list)

    list = property(_get_list, _set_list)

    def _get_packages(self):
        return self._packages

    def _set_packages(self, packages):
        if isinstance(packages, Packages):
            self._packages = packages
        else:
            self._packages = Packages(packages)

    packages = property(_get_packages, _set_packages)

    @classmethod
    def from_element(cls, element):
        uri = element.attrib['uri']
        children = element.iterchildren()
        x = children.next()
        lst = cls.list_classes[x.tag].from_element(x)
        try:
            x = children.next()
        except StopIteration:
            packages = None
        else:
            packages = Packages.from_element(x)
        return Service(uri, lst, packages)

    def set_element(self, element):
        element.set('uri', self.uri)
        self.list.to_element(element)
        if self.packages:
            self.packages.to_element(element)

    def __cmp__(self, other):
        return cmp(self.uri, other.uri) or \
               cmp(self._list, other._list) or \
               cmp(self._packages, other._packages)


class RLSServices(MainListElement):
    _xml_tag = _rls_services_prefix + 'rls-services'
    _items_types_ = Service
    parser = RLSServicesParser()


def __test():

    def clone(obj):
        element = obj.to_element()
        return obj.__class__.from_element(element)

    bill = Entry('sip:bill@example.com', display_name = 'Bill Doe')
    bill2 = clone(bill)
    assert bill.uri == bill2.uri
    assert bill.display_name == bill2.display_name
    assert bill == bill2

    bill2.display_name = 'Just Bill'
    assert bill != bill2

    ref = EntryRef('a/b/c', display_name = u'Unicode')
    ref2 = clone(ref)
    assert ref.ref == ref2.ref
    assert ref.display_name == ref2.display_name
    assert ref == ref2

    ext = External('http://localhost')
    ext2 = clone(ext)
    assert ext.anchor == ext2.anchor
    assert ext.display_name == ext2.display_name
    assert ext == ext2

    #name = DisplayName('ABC', lang = 'en')
    #name2 = clone(name)
    #assert name == name2
    #XXX ValueError: Invalid attribute name u'xml:lang'

    lst = List([bill, ref, ext, List(name='inside')], display_name = 'mylist')
    lst2 = clone(lst)
    assert lst == lst2

    rls = ResourceLists()
    rls.append(lst)
    rls2 = clone(rls)
    assert rls == rls2

    xml = rls.toxml(pretty_print=True)
    assert xml  == '''<?xml version='1.0' encoding='UTF-8'?>
<ns0:resource-lists xmlns:ns0="urn:ietf:params:xml:ns:resource-lists">
  <ns0:list>
    <ns0:display-name>mylist</ns0:display-name>
    <ns0:entry uri="sip:bill@example.com">
      <ns0:display-name>Bill Doe</ns0:display-name>
    </ns0:entry>
    <ns0:entry-ref ref="a/b/c">
      <ns0:display-name>Unicode</ns0:display-name>
    </ns0:entry-ref>
    <ns0:external anchor="http://localhost"/>
    <ns0:list name="inside"/>
  </ns0:list>
</ns0:resource-lists>
''', xml

    assert DisplayName('123') == DisplayName ('123')
    assert not DisplayName('123') == DisplayName ('123', lang = 'en')

    package = Package('presence')
    package2 = clone(package)
    assert package == package2

    packages = Packages([package, package2])
    packages2 = clone(package)
    assert packages == packages

    rl = ResourceList('http://localhost')
    rl2 = clone(rl)
    assert rl == rl2

    s = Service('sip:service@service.com', rl, packages)
    s2 = clone(s)
    assert s.uri == s2.uri
    assert s.list == s2.list, (s.list, s2.list)
    assert s.packages == s2.packages
    assert s == s2, (s, s2)

    rls = RLSServices([s])

    s = Service('sip:service@service.com', lst, packages)
    s2 = clone(s)
    assert s.uri == s2.uri
    assert s.list == s2.list
    assert s.packages == s2.packages
    assert s == s2

    s.packages = [package, package2]
    assert s.packages == s2.packages
    assert s == s2

    rls.append(s)
    rls.toxml(validate=False, pretty_print=True)

if __name__ == '__main__':
    example_from_section_3_3_rfc = """<?xml version="1.0" encoding="UTF-8"?>
<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <list name="friends">
  <entry uri="sip:bill@example.com">
   <display-name>Bill Doe</display-name>
  </entry>
  <entry-ref ref="resource-lists/users..."/>
  <list name="close-friends">
   <display-name>Close Friends</display-name>
   <entry uri="sip:joe@example.com">
    <display-name>Joe Smith</display-name>
   </entry>
   <entry uri="sip:nancy@example.com">
    <display-name>Nancy Gross</display-name>
   </entry>
   <external anchor="http://xcap.example.org/resource-lists...">
    <display-name>Marketing</display-name>
   </external>
  </list>
 </list>
</resource-lists>"""

    example_from_section_4_3_rfc = """<?xml version="1.0" encoding="UTF-8"?>
<rls-services xmlns="urn:ietf:params:xml:ns:rls-services"
   xmlns:rl="urn:ietf:params:xml:ns:resource-lists"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <service uri="sip:mybuddies@example.com">
  <resource-list>http://xcap.example.com/xxx</resource-list>
  <packages>
   <package>presence</package>
  </packages>
 </service>
 <service uri="sip:marketing@example.com">
   <list name="marketing">
     <rl:entry uri="sip:joe@example.com"/>
     <rl:entry uri="sip:sudhir@example.com"/>
   </list>
   <packages>
     <package>presence</package>
   </packages>
 </service>
</rls-services>"""

    import doctest
    doctest.testmod(extraglobs = locals())
    __test()

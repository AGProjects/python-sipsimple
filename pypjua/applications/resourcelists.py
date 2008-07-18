"""<resource-lists> (rfc4826) handling

This module provides convenient classes to parse and generate
<resource-lists> documents as described in RFC 4826.

TODO: schema isn't enforced at object construction

The module implements following classes which map one-to-one to the
corresponding xml elements:

 * ResourceLists
 * List
 * Entry
 * EntryRef
 * External
 * DisplayName

ResourceLists is a list of List objects.
List is a list of List/Entry/EntryRef/External objects.
List may have additional name attribute.
List, Entry, EntryRef and External may have display_name attribute.
Entry, EntryRef and External each have one mandatory attribute:
uri, ref and anchor respectively.

Create a simple document:

>>> bill = Entry('sip:bill@example.com', display_name = 'Bill Doe')
>>> petri = EntryRef('some/ref')
>>> friends = List([bill, petri])
>>> rls = ResourceLists([friends])
>>> print rls.toxml(pretty_print=True)
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

toxml() passes all the arguments (like pretty_print) to etree.tostring()

Parse a document:

>>> rls = ResourceLists.parse(example_from_section_3_3_of_rfc)
>>> len(rls)
1

>>> friends = rls[0]
>>> friends.name
'friends'

>>> bill = friends[0]
>>> bill.uri
'sip:bill@example.com'
>>> print bill.display_name
Bill Doe

>>> close_friends = friends[2]
>>> close_friends[0]
Entry(uri='sip:joe@example.com', display_name=DisplayName('Joe Smith'))
>>> print close_friends[2].display_name
Marketing

"""


import sys
from lxml import etree
from pypjua.applications import XMLParser, ParserError

__all__ = ['List',
           'DisplayName',
           'Entry',
           'EntryRef',
           'External',
           'ResourceLists']

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

# XXX currently there are no consistency checks in the classes (i.e. that name is unique, etc)
# you'll get an error at validation, but you should get it earlier, at object construction.

class Parser(XMLParser):
    accept_types = ['application/resource-lists+xml']
    _namespace = 'urn:ietf:params:xml:ns:resource-lists'
    _schema_file = 'resourcelists.xsd'
    _parser = etree.XMLParser(remove_blank_text=True)

_parser_ = Parser()
_prefix_ = '{%s}' % Parser._namespace


def class_to_str(klass):
    return klass.__name__
    return '%s.%s' % (klass.__module__, klass.__name__)


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

    def _get_display_name(self):
        return self._display_name

    def _set_display_name(self, value):
        if value is not None and not isinstance(value, DisplayName):
            value = DisplayName(value)
        self._display_name = value

    display_name = property(_get_display_name,
                            _set_display_name)


class List(list, ToElementMixin, DisplayNameMixin):
    _xml_tag = _prefix_ + 'list'

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
        return '%s(%s%s%s)' % (class_to_str(self.__class__),
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


class DisplayName(ToElementMixin):
    _xml_tag = _prefix_ + 'display-name'

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
        return '%s(%s=%r%s)' % (class_to_str(self.__class__),
                                self._arg,
                                getattr(self, self._arg),
                                display_name)

    def __cmp__(self, other):
        arg = self._arg
        return cmp(getattr(self, arg), getattr(other, arg)) or \
               cmp(self.display_name, other.display_name)

    def __hash__(self, other):
        return hash((getattr(self, arg), self.display_name))


class Entry(ElementWithDisplayName):
    _xml_tag = _prefix_ + 'entry'
    _arg = 'uri'


class EntryRef(ElementWithDisplayName):
    _xml_tag = _prefix_ + 'entry-ref'
    _arg = 'ref'


class External(ElementWithDisplayName):
    _xml_tag = _prefix_ + 'external'
    _arg = 'anchor'


class ResourceLists(list):
    _xml_tag = _prefix_ + 'resource-lists'

    # default parameters for toxml()
    default_validate = True
    default_encoding = 'UTF-8'
    default_xml_declaration = True

    @classmethod
    def from_element(cls, element):
        self = cls()
        for x in element:
            assert x.tag == List._xml_tag, x.tag
            l = List.from_element(x)
            self.append(l)
        return self

    def to_element(self):
        element = etree.Element(self._xml_tag)
        for child in self:
            child.to_element(element)
        return element

    @classmethod
    def parse(cls, document):
        root = _parser_._parse(document)
        return cls.from_element(root)

    def toxml(self, *args, **kwargs):
        """Shortcut that generates Element and calls etree.tostring.

        If `validate' keyword arg is present and evaluates to True, method
        also does schema validation.
        """
        element = self.to_element()
        kwargs.setdefault('encoding', self.default_encoding)
        kwargs.setdefault('xml_declaration', self.default_xml_declaration)
        res = etree.tostring(element, *args, **kwargs)
        if kwargs.pop('validate', self.default_validate):
            try:
                _parser_._validate(element)
            except ParserError:
                sys.stderr.write('Failed to validate:\n%s\n' % res)
                raise
        return res


# possible List members
_mapping_ = { Entry._xml_tag       : Entry,
              EntryRef._xml_tag    : EntryRef,
              List._xml_tag        : List,
              External._xml_tag    : External,
              DisplayName._xml_tag : DisplayName }


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


if __name__ == '__main__':
    demo_xml = """<?xml version="1.0" encoding="UTF-8"?>
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
    import doctest
    doctest.testmod(extraglobs = {'example_from_section_3_3_of_rfc' : demo_xml})
    __test()

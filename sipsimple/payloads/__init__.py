# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

import os
import sys
import urllib
from collections import deque

from lxml import etree

from sipsimple.util import classproperty

__all__ = ['ParserError',
           'BuilderError',
           'ValidationError',
           'parse_qname',
           'XMLApplication', 
           'XMLElement',
           'XMLRootElement',
           'XMLStringElement',
           'XMLEmptyElement',
           'XMLListElement',
           'XMLListRootElement',
           'uri_attribute_builder',
           'uri_attribute_parser']


## Exceptions

class ParserError(Exception): pass
class BuilderError(Exception): pass
class ValidationError(ParserError): pass


## Utilities

def parse_qname(qname):
    if qname[0] == '{':
        qname = qname[1:]
        return qname.split('}')
    else:
        return None, qname


## XMLApplication

class XMLApplicationType(type):
    def __init__(cls, name, bases, dct):
        cls._children_applications = []
        cls._xml_classes = {}
        cls.xml_nsmap = {}
        for base in reversed(bases):
            if hasattr(base, '_xml_classes'):
                cls._xml_classes.update(base._xml_classes)
            if hasattr(base, 'xml_nsmap'):
                cls.xml_nsmap.update(base.xml_nsmap)
        # register this application as child of its basses
        if dct['__module__'] != XMLApplicationType.__module__:
            for base in bases:
                if issubclass(base, XMLApplication):
                    base.add_child(cls)


class XMLApplication(object):
    __metaclass__ = XMLApplicationType

    @classmethod
    def register_element(cls, xml_class):
        cls._xml_classes[xml_class.qname] = xml_class
        for child in cls._children_applications:
            child.register_element(xml_class)

    @classmethod
    def register_namespace(cls, namespace, prefix=None):
        if prefix in cls.xml_nsmap:
            raise ValueError("prefix %s is already registered in %s" % (prefix, cls.__name__))
        if namespace in cls.xml_nsmap.itervalues():
            raise ValueError("namespace %s is already registered in %s" % (namespace, cls.__name__))
        cls.xml_nsmap[prefix] = namespace
        for child in cls._children_applications:
            child.register_namespace(namespace, prefix)

    @classmethod
    def get_element(cls, qname, default=None):
        return cls._xml_classes.get(qname, default)

    @classmethod
    def add_child(cls, application):
        cls._children_applications.append(application)


## Children descriptors

class XMLAttribute(object):
    def __init__(self, name, xmlname=None, type=unicode, default=None, parser=None, builder=None, required=False, test_equal=True, onset=None, ondel=None):
        self.name = name
        self.xmlname = xmlname or name
        self.type = type
        self.default = default
        self.parser = parser or (lambda value: value)
        self.builder = builder or (lambda value: unicode(value))
        self.required = required
        self.test_equal = test_equal
        self.onset = onset
        self.ondel = ondel
        self.values = {}
    
    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[id(obj)]
        except KeyError:
            value = self.default
            if value is not None:
                obj.element.set(self.xmlname, self.builder(value))
            self.values[id(obj)] = value
            return value
    
    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        if value is not None:
            obj.element.set(self.xmlname, self.builder(value))
        else:
            obj.element.attrib.pop(self.xmlname, None)
        self.values[id(obj)] = value
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        obj.element.attrib.pop(self.xmlname, None)
        try:
            del self.values[id(obj)]
        except KeyError:
            pass
        if self.ondel:
            self.ondel(obj, self)

    def parse(self, xmlvalue):
        return self.parser(xmlvalue)

    def build(self, value):
        return self.builder(value)


class XMLElementChild(object):
    def __init__(self, name, type, required=False, test_equal=True, onset=None, ondel=None):
        self.name = name
        self.type = type
        self.required = required
        self.test_equal = test_equal
        self.onset = onset
        self.ondel = ondel
        self.values = {}

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[id(obj)]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        old_value = self.values.get(id(obj), None)
        if old_value is not None:
            obj.element.remove(old_value.element)
        self.values[id(obj)] = value
        if value is not None:
            obj._insert_element(value.element)
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            del self.values[id(obj)]
        except KeyError:
            pass
        if self.ondel:
            self.ondel(obj, self)


class XMLElementChoiceChild(object):
    def __init__(self, name, types, required=False, test_equal=True, onset=None, ondel=None):
        self.name = name
        self.types = types
        self.required = required
        self.test_equal = test_equal
        self.onset = onset
        self.ondel = ondel
        self.values = {}

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[id(obj)]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.types):
            value = self.types[0](value)
        old_value = self.values.get(id(obj), None)
        if old_value is not None:
            obj.element.remove(old_value.element)
        self.values[id(obj)] = value
        if value is not None:
            obj._insert_element(value.element)
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            del self.values[id(obj)]
        except KeyError:
            pass
        if self.ondel:
            self.ondel(obj, self)


## XMLElement base classes

# This is needed for the hack employed in XMLElement.__del__ because of a bug in
# libxml2. Please see XMLElement.__del__ for more information.
fakeroot = etree.Element('fakeroot')

class XMLElementType(type):
    def __init__(cls, name, bases, dct):
        # set dictionary of xml attributes and xml child elements
        cls._xml_attributes = {}
        cls._xml_element_children = {}
        cls._xml_children_qname_map = {}
        for base in reversed(bases):
            if hasattr(base, '_xml_attributes'):
                cls._xml_attributes.update(base._xml_attributes)
            if hasattr(base, '_xml_element_children') and hasattr(base, '_xml_children_qname_map'):
                cls._xml_element_children.update(base._xml_element_children)
                cls._xml_children_qname_map.update(base._xml_children_qname_map)
        for name, value in dct.items():
            if isinstance(value, XMLAttribute):
                cls._xml_attributes[value.name] = value
            elif isinstance(value, XMLElementChild):
                cls._xml_element_children[value.name] = value
                cls._xml_children_qname_map[value.type.qname] = (value, value.type)
            elif isinstance(value, XMLElementChoiceChild):
                cls._xml_element_children[value.name] = value
                for type in value.types:
                    cls._xml_children_qname_map[type.qname] = (value, type)

        # register class in its XMLApplication
        if cls._xml_application is not None:
            cls._xml_application.register_element(cls)

class XMLElement(object):
    __metaclass__ = XMLElementType
    
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_application = None # To be defined in subclass
    _xml_extension_type = None # Can be defined in subclass
    _xml_id = None # Can be defined in subclass
    _xml_children_order = {} # Can be defined in subclass

    # dynamically generated
    _xml_attributes = {}
    _xml_element_children = {}
    _xml_children_qname_map = {}

    qname = classproperty(lambda cls: '{%s}%s' % (cls._xml_namespace, cls._xml_tag))

    def __init__(self):
        self.element = etree.Element(self.qname, nsmap=self._xml_application.xml_nsmap)

    def check_validity(self):
        # check attributes
        for name, attribute in self._xml_attributes.items():
            # if attribute has default but it was not set, will also be added with this occasion
            value = getattr(self, name, None)
            if attribute.required and value is None:
                raise ValidationError("required attribute %s of %s is not set" % (name, self.__class__.__name__))
        # check element children
        for name, element_child in self._xml_element_children.items():
            # if child has default but it was not set, will also be added with this occasion
            child = getattr(self, name, None)
            if child is None and element_child.required:
                raise ValidationError("element child %s of %s is not set" % (name, self.__class__.__name__))

    def to_element(self, *args, **kwargs):
        try:
            self.check_validity()
        except ValidationError, e:
            raise BuilderError(str(e))
        # build element children
        for name in self._xml_element_children:
            child = getattr(self, name, None)
            if child is not None:
                child.to_element(*args, **kwargs)
        self._build_element(*args, **kwargs)
        return self.element
    
    # To be defined in subclass
    def _build_element(self, *args, **kwargs):
        pass

    @classmethod
    def from_element(cls, element, *args, **kwargs):
        obj = cls.__new__(cls)
        if 'xml_application' in kwargs:
            obj._xml_application = kwargs['xml_application']
        else:
            kwargs['xml_application'] = cls._xml_application
        obj.element = element
        # set known attributes
        for name, attribute in cls._xml_attributes.items():
            xmlvalue = element.get(attribute.xmlname, None)
            if xmlvalue is not None:
                try:
                    setattr(obj, name, attribute.parse(xmlvalue))
                except (ValueError, TypeError):
                    raise ValidationError("got illegal value for attribute %s of %s: %s" % (name, cls.__name__, xmlvalue))
            elif attribute.required:
                raise ValidationError("attribute %s of %s is required but is not present" % (name, cls.__name__))
        # set element children
        required_children = set(child for child in cls._xml_element_children.itervalues() if child.required)
        for child in element:
            element_child, type = cls._xml_children_qname_map.get(child.tag, (None, None))
            if element_child is not None:
                try:
                    value = type.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass # we should accept partially valid documents
                else:
                    if element_child.required:
                        required_children.remove(element_child)
                    setattr(obj, element_child.name, value)
        if required_children:
            raise ValidationError("not all required sub elements exist in %s element" % cls.__name__)
        obj._parse_element(element, *args, **kwargs)
        obj.check_validity()
        return obj
    
    # To be defined in subclass
    def _parse_element(self, element, *args, **kwargs):
        pass
    
    @classmethod
    def register_extension(cls, attribute, type, test_equal=True):
        if cls._xml_extension_type is None:
            raise ValueError("XMLElement type %s does not support extensions (requested extension type %s)" % (cls.__name__, type.__name__))
        elif not issubclass(type, cls._xml_extension_type):
            raise TypeError("XMLElement type %s only supports extensions of type %s (requested extension type %s)" % (cls.__name__, cls._xml_extension_type, type.__name__))
        elif hasattr(cls, attribute):
            raise ValueError("XMLElement type %s already has an attribute named %s (requested extension type %s)" % (cls.__name__, attribute, type.__name__))
        extension = XMLElementChild(attribute, type=type, required=False, test_equal=test_equal)
        setattr(cls, attribute, extension)
        cls._xml_element_children[attribute] = extension
        cls._xml_children_qname_map[type.qname] = (extension, type)

    def _insert_element(self, element):
        if element in self.element:
            return
        order = self._xml_children_order.get(element.tag, self._xml_children_order.get(None, sys.maxint))
        for i in xrange(len(self.element)):
            child_order = self._xml_children_order.get(self.element[i].tag, self._xml_children_order.get(None, sys.maxint))
            if child_order > order:
                position = i
                break
        else:
            position = len(self.element)
        self.element.insert(position, element)
    
    def __eq__(self, obj):
        if not isinstance(obj, XMLElement):
            if self.__class__._xml_id is None:
                return False
            else:
                return self._xml_id == obj
        else:
            for name, attribute in self._xml_attributes.items():
                if attribute.test_equal:
                    if not hasattr(obj, name) or getattr(self, name) != getattr(obj, name):
                        return False
            for name, element_child in self._xml_element_children.items():
                if element_child.test_equal:
                    if not hasattr(obj, name) or getattr(self, name) != getattr(obj, name):
                        return False
            try:
                return super(XMLElement, self).__eq__(obj)
            except AttributeError:
                return True

    def __hash__(self):
        if self.__class__._xml_id is not None:
            return hash(self._xml_id)
        else:
            hashes = [hash(getattr(self, name)) for name, child in self._xml_attributes.items() + self._xml_element_children.items() if child.test_equal]
            if len(hashes) == 0:
                return hash((self._xml_tag, self._xml_namespace))
            return sum(hashes)

    def __del__(self):
        # Ugly hack needed because of bug in libxml2. It seems that libxml2
        # keeps a reference to the XML tree an element belongs to even after
        # the element is removed from its parent. This causes a problem when
        # the element is about to be freed. So we simply change the XML tree
        # an element belongs to by explicitly adding it to a fake root, and
        # then removing it.
        fakeroot.append(self.element)
        fakeroot.remove(self.element)
        for name in self._xml_attributes.keys() + self._xml_element_children.keys():
            delattr(self, name)


class XMLRootElementType(XMLElementType):
    def __init__(cls, name, bases, dct):
        XMLElementType.__init__(cls, name, bases, dct)
        if cls._xml_schema is None and cls._xml_schema_file is not None:
            cls._xml_schema = etree.XMLSchema(etree.parse(open(os.path.join(cls._xml_schema_dir, cls._xml_schema_file), 'r')))
        if cls._xml_parser is None:
            if cls._xml_schema is not None and cls._validate_input:
                cls._xml_parser = etree.XMLParser(schema=cls._xml_schema, remove_blank_text=True)
            else:
                cls._xml_parser = etree.XMLParser(remove_blank_text=True)

class XMLRootElement(XMLElement):
    __metaclass__ = XMLRootElementType
    
    encoding = 'UTF-8'
    content_type = None
    
    _validate_input = True
    _validate_output = True
    
    _xml_nsmap = {}
    _xml_schema_file = None
    _xml_schema_dir = os.path.join(os.path.dirname(__file__), 'xml-schemas')
    _xml_declaration = True
    
    # dinamically generated
    _xml_parser = None
    _xml_schema = None

    def __init__(self):
        XMLElement.__init__(self)
        self.cache = {self.element: self}

    @classmethod
    def from_element(cls, element, *args, **kwargs):
        obj = super(XMLRootElement, cls).from_element(element, *args, **kwargs)
        obj.cache = {obj.element: obj}
        return obj
    
    @classmethod
    def parse(cls, document, *args, **kwargs):
        try:
            if isinstance(document, str):
                xml = etree.XML(document, parser=cls._xml_parser)
            else:
                xml = etree.parse(document, parser=cls._xml_parser).getroot()
        except etree.XMLSyntaxError, e:
            raise ParserError(str(e))
        else:
            kwargs.setdefault('xml_application', cls._xml_application)
            return cls.from_element(xml, *args, **kwargs)
    
    def toxml(self, *args, **kwargs):
        element = self.to_element(*args, **kwargs)
        if kwargs.pop('validate', self._validate_output) and self._xml_schema is not None:
            self._xml_schema.assertValid(element)
        
        kwargs.setdefault('encoding', self.encoding)
        kwargs.setdefault('xml_declaration', self._xml_declaration)
        return etree.tostring(element, *args, **kwargs)

    def xpath(self, xpath, namespaces=None):
        result = []
        try:
            nodes = self.element.xpath(xpath, namespaces=namespaces)
        except etree.XPathError:
            raise ValueError("illegal XPath expression")
        for element in (node for node in nodes if isinstance(node, etree._Element)):
            if element in self.cache:
                result.append(self.cache[element])
                continue
            if element is self.element:
                self.cache[element] = self
                result.append(self)
                continue
            for ancestor in element.iterancestors():
                if ancestor in self.cache:
                    container = self.cache[ancestor]
                    break
            else:
                container = self
            notvisited = deque([container])
            visited = set()
            while notvisited:
                container = notvisited.popleft()
                self.cache[container.element] = container
                if isinstance(container, XMLListMixin):
                    children = set(child for child in container if isinstance(child, XMLElement) and child not in visited)
                    visited.update(children)
                    notvisited.extend(children)
                for child in container._xml_element_children:
                    value = getattr(container, child)
                    if value is not None and value not in visited:
                        visited.add(value)
                        notvisited.append(value)
            if element in self.cache:
                result.append(self.cache[element])
        return result

    def get_xpath(self, element):
        raise NotImplementedError


## Mixin classes

class XMLListMixin(list):
    """A mixin representing a list of other XML elements
    that allows to setup hooks on element insertion/removal
    """

    def _add_item(self, value):
        """Called for every value that is about to be inserted into the list.
        The returned value will be inserted into the list"""
        return value

#    def _get_item(self, value):
#        """Called for every value that is about to be get from the list.
#        The returned value will be the one returned
#        
#        Must not throw!
#        """
#        return value

    def _del_item(self, value):
        """Called for every value that is about to be removed from the list."""

    def __setitem__(self, key, items):
        if isinstance(key, slice):
            for value in self.__getitem__(key):
                self._del_item(value)
            values = []
            count = 0
            for value in items:
                try:
                    values.append(self._add_item(value))
                    count += 1
                except:
                    exc = sys.exc_info()
                    for value in items[:count]:
                        self._del_item(value)
                    raise exc[0], exc[1], exc[2]
            list.__setitem__(self, key, values)
        else:
            old_value = self.__getitem__(key)
            self._del_item(value)
            # items is actually only one item
            try:
                value = self._add_item(items)
            except:
                self._add_item(old_value)
                raise
            else:
                list.__setitem__(self, key, value)

    def __setslice__(self, start, stop, sequence):
        return self.__setitem__(slice(start, stop), sequence)

#    def __getitem__(self, key):
#        if isinstance(key, slice):
#            values = []
#            for value in list.__getitem__(self, key):
#                values.append(self._get_item(value))
#            return values
#        else:
#            return self._get_item(list.__getitem__(self, key))
#
#    def __getslice__(self, start, stop):
#        return self.__getitem__(slice(start, stop))

    def __delitem__(self, key):
        if isinstance(key, slice):
            for value in self.__getitem__(key):
                self._del_item(value)
        else:
            self._del_item(self.__getitem__(key))
        list.__delitem__(self, key)

    def __delslice__(self, start, stop):
        return self.__delitem__(slice(start, stop))

    def append(self, item):
        self[len(self):len(self)] = [item]

    def extend(self, sequence):
        self[len(self):len(self)] = sequence

    def insert(self, index, value):
        self[index:index] = [value]

    def pop(self, index = -1):
        value = self[index];
        del self[index];
        return value

    def remove(self, value):
        del self[self.index(value)]

    def clear(self):
        self[:] = []

    def __iadd__(self, sequence):
        self.extend(sequence)
        return self
    
    def __imul__(self, n):
        values = self[:]
        for i in xrange(n):
            self += values

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, list.__repr__(self))

    __str__ = __repr__


## Element types

class XMLStringElement(XMLElement):
    _xml_lang = False # To be defined in subclass
    _xml_value_type = unicode # To be defined in subclass

    lang = XMLAttribute('lang', xmlname='{http://www.w3.org/XML/1998/namespace}lang', type=str, required=False, test_equal=True)
    
    def __init__(self, value, lang=None):
        XMLElement.__init__(self)
        self.value = value
        self.lang = lang

    def _parse_element(self, element, *args, **kwargs):
        self.value = element.text
        if self._xml_lang:
            self.lang = element.get('{http://www.w3.org/XML/1998/namespace}lang', None)
        else:
            self.lang = None

    def _build_element(self, *args, **kwargs):
        if self.value is not None:
            self.element.text = unicode(self.value)
        else:
            self.element.text = None
        if not self._xml_lang and self.lang is not None:
            del self.element.attrib[self.__class__.lang.xmlname]

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        if value is not None and not isinstance(value, self._xml_value_type):
            value = self._xml_value_type(value)
        self._value = value

    value = property(_get_value, _set_value)
    del _get_value, _set_value

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.value, self.lang)

    def __unicode__(self):
        return unicode(self.value)

    def __eq__(self, obj):
        if self._xml_lang and not (hasattr(obj, 'lang') and self.lang == obj.lang):
            return False
        return self.value == unicode(obj)

    def __hash__(self):
        return hash(self.value)


class XMLEmptyElement(XMLElement):
    def __init__(self):
        XMLElement.__init__(self)
    def __repr__(self):
        return '%s()' % self.__class__.__name__
    def __eq__(self, obj):
        return type(self) == type(obj)
    def __hash__(self):
        return hash(type(self))


## Created using mixins

class XMLListElement(XMLElement, XMLListMixin): pass
class XMLListRootElement(XMLRootElement, XMLListMixin): pass


## Useful attribute builders/parser

def uri_attribute_builder(value):
    return urllib.quote(value.encode('utf-8'))

def uri_attribute_parser(value):
    return urllib.unquote(value).decode('utf-8')



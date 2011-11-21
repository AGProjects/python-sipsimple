# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#


__all__ = ['ParserError',
           'BuilderError',
           'ValidationError',
           'parse_qname',
           'XMLDocument',
           'XMLAttribute',
           'XMLElementID',
           'XMLElementChild',
           'XMLElementChoiceChild',
           'XMLStringChoiceChild',
           'XMLElement',
           'XMLRootElement',
           'XMLStringElement',
           'XMLEmptyElement',
           'XMLEmptyElementRegistryType',
           'XMLListElement',
           'XMLListRootElement',
           'XMLStringListElement',
           'uri_attribute_builder',
           'uri_attribute_parser']


import os
import sys
import urllib
import weakref
from collections import defaultdict, deque

from application.python.descriptor import classproperty
from lxml import etree


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


## XMLDocument

class XMLDocumentType(type):
    def __init__(cls, name, bases, dct):
        cls._xml_root_element = None
        cls._xml_classes = {}
        cls._xml_schema_map = {}
        cls.xml_nsmap = {}
        for base in reversed(bases):
            if hasattr(base, '_xml_classes'):
                cls._xml_classes.update(base._xml_classes)
            if hasattr(base, '_xml_schema_map'):
                cls._xml_schema_map.update(base._xml_schema_map)
            if hasattr(base, 'xml_nsmap'):
                cls.xml_nsmap.update(base.xml_nsmap)


class XMLDocument(object):
    __metaclass__ = XMLDocumentType

    _validate_input = True
    _validate_output = True
    
    _xml_schema_dir = os.path.join(os.path.dirname(__file__), 'xml-schemas')

    # dinamically generated
    _xml_parser = None
    _xml_schema = None

    @classmethod
    def _build_schema(cls):
        schema = """<?xml version="1.0"?>
            <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
                %s
            </xs:schema>
        """ % '\r\n'.join('<xs:import namespace="%s" schemaLocation="%s"/>' % (ns, urllib.quote(os.path.join(cls._xml_schema_dir, file))) for ns, file in cls._xml_schema_map.iteritems())
        cls._xml_schema = etree.XMLSchema(etree.XML(schema))
        if cls._validate_input:
            cls._xml_parser = etree.XMLParser(schema=cls._xml_schema, remove_blank_text=True)
        else:
            cls._xml_parser = etree.XMLParser(remove_blank_text=True)

    @classmethod
    def register_element(cls, xml_class):
        cls._xml_classes[xml_class.qname] = xml_class
        for child in cls.__subclasses__():
            child.register_element(xml_class)

    @classmethod
    def get_element(cls, qname, default=None):
        return cls._xml_classes.get(qname, default)

    @classmethod
    def register_namespace(cls, namespace, prefix=None, schema=None):
        if prefix in cls.xml_nsmap:
            raise ValueError("prefix %s is already registered in %s" % (prefix, cls.__name__))
        if namespace in cls.xml_nsmap.itervalues():
            raise ValueError("namespace %s is already registered in %s" % (namespace, cls.__name__))
        cls.xml_nsmap[prefix] = namespace
        if schema is not None:
            cls._xml_schema_map[namespace] = schema
            cls._build_schema()
        for child in cls.__subclasses__():
            child.register_namespace(namespace, prefix, schema)

    @classmethod
    def unregister_namespace(cls, namespace):
        try:
            prefix = (prefix for prefix in cls.xml_nsmap if cls.xml_nsmap[prefix]==namespace).next()
        except StopIteration:
            raise KeyError("namespace %s is not registered in %s" % (namespace, cls.__name__))
        del cls.xml_nsmap[prefix]
        cls._xml_schema_map.pop(namespace, None)
        cls._build_schema()
        for child in cls.__subclasses__():
            try:
                child.unregister_namespace(namespace)
            except KeyError:
                pass


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
            return self.values[id(obj)][0]
        except KeyError:
            value = self.default
            if value is not None:
                obj.element.set(self.xmlname, self.builder(value))
            obj_id = id(obj)
            self.values[obj_id] = (value, weakref.ref(obj, lambda weak_ref: self.values.pop(obj_id)))
            return value
    
    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        if value is not None:
            obj.element.set(self.xmlname, self.builder(value))
        else:
            obj.element.attrib.pop(self.xmlname, None)
        obj_id = id(obj)
        self.values[obj_id] = (value, weakref.ref(obj, lambda weak_ref: self.values.pop(obj_id)))
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


class XMLElementID(XMLAttribute):
    """An XMLAttribute that represents the ID of an element (immutable)."""

    def __set__(self, obj, value):
        obj_id = id(obj)
        if obj_id in self.values:
            raise AttributeError("An XML element ID cannot be changed")
        super(XMLElementID, self).__set__(obj, value)

    def __delete__(self, obj):
        raise AttributeError("An XML element ID cannot be deleted")


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
            return self.values[id(obj)][0]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        obj_id = id(obj)
        try:
            old_value = self.values[obj_id][0]
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
        self.values[obj_id] = (value, weakref.ref(obj, lambda weak_ref: self.values.pop(obj_id)))
        if value is not None:
            obj._insert_element(value.element)
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            old_value = self.values.pop(id(obj))[0]
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
        if self.ondel:
            self.ondel(obj, self)


class XMLElementChoiceChildWrapper(object):
    __slots__ = ('descriptor', 'type')

    def __init__(self, descriptor, type):
        self.descriptor = descriptor
        self.type = type

    def __getattribute__(self, name):
        if name in ('descriptor', 'type', 'register_extension', 'unregister_extension'):
            return super(XMLElementChoiceChildWrapper, self).__getattribute__(name)
        else:
            return self.descriptor.__getattribute__(name)

    def __setattr__(self, name, value):
        if name in ('descriptor', 'type'):
            super(XMLElementChoiceChildWrapper, self).__setattr__(name, value)
        else:
            setattr(self.descriptor, name, value)

    def __dir__(self):
        return dir(self.descriptor) + ['descriptor', 'type', 'register_extension', 'unregister_extension']

    def register_extension(self, type):
        if self.extension_type is None:
            raise ValueError("The %s XML choice element of %s does not support extensions" % (self.name, self.type.__name__))
        if not issubclass(type, XMLElement) or not issubclass(type, self.extension_type):
            raise TypeError("type is not a subclass of XMLElement and/or %s: %s" % (self.extension_type.__name__, type.__name__))
        if type in self.types:
            raise ValueError("%s is already registered as a choice extension" % type.__name__)
        self.types.add(type)
        self.type._xml_children_qname_map[type.qname] = (self.descriptor, type)
        for child_class in self.type.__subclasses__():
            child_class._xml_children_qname_map[type.qname] = (self.descriptor, type)

    def unregister_extension(self, type):
        if self.extension_type is None:
            raise ValueError("The %s XML choice element of %s does not support extensions" % (self.name, self.type.__name__))
        try:
            self.types.remove(type)
        except ValueError:
            raise ValueError("%s is not a registered choice extension on %s" % (type.__name__, self.type.__name__))
        del self.type._xml_children_qname_map[type.qname]
        for child_class in self.type.__subclasses__():
            del child_class._xml_children_qname_map[type.qname]


class XMLElementChoiceChild(object):
    def __init__(self, name, types, extension_type=None, required=False, test_equal=True, onset=None, ondel=None):
        self.name = name
        self.types = set(types)
        self.extension_type = extension_type
        self.required = required
        self.test_equal = test_equal
        self.onset = onset
        self.ondel = ondel
        self.values = {}

    def __get__(self, obj, objtype):
        if obj is None:
            return XMLElementChoiceChildWrapper(self, objtype)
        try:
            return self.values[id(obj)][0]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and type(value) not in self.types:
            raise TypeError("%s is not an acceptable type for %s" % (value.__class__.__name__, obj.__class__.__name__))
        obj_id = id(obj)
        try:
            old_value = self.values[obj_id][0]
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
        self.values[obj_id] = (value, weakref.ref(obj, lambda weak_ref: self.values.pop(obj_id)))
        if value is not None:
            obj._insert_element(value.element)
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            old_value = self.values.pop(id(obj))[0]
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
        if self.ondel:
            self.ondel(obj, self)


class XMLStringChoiceChild(XMLElementChoiceChild):
    """
    A choice between keyword strings from a registry, custom strings from the
    other type and custom extensions. This descriptor will accept and return
    strings instead of requiring XMLElement instances for the values in the
    registry and the other type. Check XMLEmptyElementRegistryType for a
    metaclass for building registries of XMLEmptyElement classes for keywords.
    """

    def __init__(self, name, registry=None, other_type=None, extension_type=None):
        self.registry = registry
        self.other_type = other_type
        self.extension_type = extension_type
        types  = registry.classes if registry is not None else ()
        types += (other_type,) if other_type is not None else ()
        super(XMLStringChoiceChild, self).__init__(name, types, extension_type=extension_type, required=True, test_equal=True)

    def __get__(self, obj, objtype):
        value = super(XMLStringChoiceChild, self).__get__(obj, objtype)
        if obj is None or value is None or isinstance(value, self.extension_type or ()):
            return value
        else:
            return unicode(value)

    def __set__(self, obj, value):
        if isinstance(value, basestring):
            if self.registry is not None and value in self.registry.names:
                value = self.registry.class_map[value]()
            elif self.other_type is not None:
                value = self.other_type.from_string(value)
        super(XMLStringChoiceChild, self).__set__(obj, value)


## XMLElement base classes

class XMLElementType(type):
    def __init__(cls, name, bases, dct):
        super(XMLElementType, cls).__init__(name, bases, dct)

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
        for name, value in dct.iteritems():
            if isinstance(value, XMLElementID):
                if cls._xml_id is not None:
                    raise AttributeError("Only one XMLElementID attribute can be defined in the %s class" % cls.__name__)
                cls._xml_id = value
                cls._xml_attributes[value.name] = value
            elif isinstance(value, XMLAttribute):
                cls._xml_attributes[value.name] = value
            elif isinstance(value, XMLElementChild):
                cls._xml_element_children[value.name] = value
                cls._xml_children_qname_map[value.type.qname] = (value, value.type)
            elif isinstance(value, XMLElementChoiceChild):
                cls._xml_element_children[value.name] = value
                for type in value.types:
                    cls._xml_children_qname_map[type.qname] = (value, type)

        # register class in its XMLDocument
        if cls._xml_document is not None:
            cls._xml_document.register_element(cls)

class XMLElement(object):
    __metaclass__ = XMLElementType
    
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_document = None # To be defined in subclass
    _xml_extension_type = None # Can be defined in subclass
    _xml_id = None # Can be defined in subclass, or will be set by the metaclass to the XMLElementID attribute (if present)
    _xml_children_order = {} # Can be defined in subclass

    # dynamically generated
    _xml_attributes = {}
    _xml_element_children = {}
    _xml_children_qname_map = {}

    qname = classproperty(lambda cls: '{%s}%s' % (cls._xml_namespace, cls._xml_tag))

    def __init__(self):
        self.element = etree.Element(self.qname, nsmap=self._xml_document.xml_nsmap)

    def check_validity(self):
        # check attributes
        for name, attribute in self._xml_attributes.iteritems():
            # if attribute has default but it was not set, will also be added with this occasion
            value = getattr(self, name, None)
            if attribute.required and value is None:
                raise ValidationError("required attribute %s of %s is not set" % (name, self.__class__.__name__))
        # check element children
        for name, element_child in self._xml_element_children.iteritems():
            # if child has default but it was not set, will also be added with this occasion
            child = getattr(self, name, None)
            if child is None and element_child.required:
                raise ValidationError("element child %s of %s is not set" % (name, self.__class__.__name__))

    def to_element(self):
        try:
            self.check_validity()
        except ValidationError, e:
            raise BuilderError(str(e))
        # build element children
        for name in self._xml_element_children:
            child = getattr(self, name, None)
            if child is not None:
                child.to_element()
        self._build_element()
        return self.element
    
    # To be defined in subclass
    def _build_element(self):
        try:
            build_element = super(XMLElement, self)._build_element
        except AttributeError:
            pass
        else:
            build_element()

    @classmethod
    def from_element(cls, element):
        obj = cls.__new__(cls)
        obj.element = element
        # set known attributes
        for name, attribute in cls._xml_attributes.iteritems():
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
                    value = type.from_element(child)
                except ValidationError:
                    pass # we should accept partially valid documents
                else:
                    if element_child.required:
                        required_children.remove(element_child)
                    setattr(obj, element_child.name, value)
        if required_children:
            raise ValidationError("not all required sub elements exist in %s element" % cls.__name__)
        obj._parse_element(element)
        obj.check_validity()
        return obj
    
    # To be defined in subclass
    def _parse_element(self, element):
        try:
            parse_element = super(XMLElement, self)._parse_element
        except AttributeError:
            pass
        else:
            parse_element(element)
    
    @classmethod
    def _register_xml_attribute(cls, attribute, element):
        cls._xml_element_children[attribute] = element
        cls._xml_children_qname_map[element.type.qname] = (element, element.type)
        for subclass in cls.__subclasses__():
            subclass._register_xml_attribute(attribute, element)

    @classmethod
    def _unregister_xml_attribute(cls, attribute):
        element = cls._xml_element_children.pop(attribute)
        del cls._xml_children_qname_map[element.type.qname]
        for subclass in cls.__subclasses__():
            subclass._unregister_xml_attribute(attribute)

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
        cls._register_xml_attribute(attribute, extension)

    @classmethod
    def unregister_extension(cls, attribute):
        if cls._xml_extension_type is None:
            raise ValueError("XMLElement type %s does not support extensions" % cls.__name__)
        cls._unregister_xml_attribute(attribute)
        delattr(cls, attribute)

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
    
    def __eq__(self, other):
        if isinstance(other, XMLElement):
            for name, attribute in self._xml_attributes.iteritems():
                if attribute.test_equal:
                    if not hasattr(other, name) or getattr(self, name) != getattr(other, name):
                        return False
            for name, element_child in self._xml_element_children.iteritems():
                if element_child.test_equal:
                    if not hasattr(other, name) or getattr(self, name) != getattr(other, name):
                        return False
            try:
                __eq__ = super(XMLElement, self).__eq__
            except AttributeError:
                return True
            else:
                return __eq__(other)
        elif self.__class__._xml_id is not None:
            return self._xml_id == other
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __hash__(self):
        if self.__class__._xml_id is not None:
            return hash(self._xml_id)
        else:
            return object.__hash__(self)


class XMLRootElementType(XMLElementType):
    def __init__(cls, name, bases, dct):
        super(XMLRootElementType, cls).__init__(name, bases, dct)
        if cls._xml_document is not None:
            if cls._xml_document._xml_root_element is not None:
                raise TypeError('there is already another root element registered for %s application' % cls.__name__)
            cls._xml_document._xml_root_element = cls

class XMLRootElement(XMLElement):
    __metaclass__ = XMLRootElementType
    
    encoding = 'UTF-8'
    content_type = None
    
    def __init__(self):
        XMLElement.__init__(self)
        self.cache = weakref.WeakValueDictionary({self.element: self})

    @classmethod
    def from_element(cls, element):
        obj = super(XMLRootElement, cls).from_element(element)
        obj.cache = weakref.WeakValueDictionary({obj.element: obj})
        return obj
    
    @classmethod
    def parse(cls, document):
        parser = cls._xml_document._xml_parser
        try:
            if isinstance(document, str):
                xml = etree.XML(document, parser=parser)
            elif isinstance(document, unicode):
                xml = etree.XML(document.encode('utf-8'), parser=parser)
            else:
                xml = etree.parse(document, parser=parser).getroot()
        except etree.XMLSyntaxError, e:
            raise ParserError(str(e))
        else:
            return cls.from_element(xml)

    def toxml(self, encoding=None, pretty_print=False, validate=True):
        element = self.to_element()
        if validate and self._xml_document._xml_schema is not None:
            self._xml_document._xml_schema.assertValid(element)
        if encoding is None:
            encoding = self.encoding
        return etree.tostring(element, encoding=encoding, method='xml', xml_declaration=True, pretty_print=pretty_print)

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

    def find_parent(self, element):
        raise NotImplementedError


## Mixin classes

class ThisClass(object):
    """
    Special marker class that is used to indicate that an XMLListElement
    subclass can be an item of itself. This is necessary because a class
    cannot reference itself when defining _xml_item_type
    """


class XMLListMixinType(type):
    def __init__(cls, name, bases, dct):
        super(XMLListMixinType, cls).__init__(name, bases, dct)
        if '_xml_item_type' in dct:
            cls._xml_item_type = cls._xml_item_type # trigger __setattr__

    def __setattr__(cls, name, value):
        if name == '_xml_item_type':
            if value is ThisClass:
                value = cls
            elif isinstance(value, tuple) and ThisClass in value:
                value = tuple(cls if type is ThisClass else type for type in value)
            if value is None:
                cls._xml_item_element_types = ()
                cls._xml_item_extension_types = ()
            else:
                item_types = value if isinstance(value, tuple) else (value,)
                cls._xml_item_element_types = tuple(type for type in item_types if issubclass(type, XMLElement))
                cls._xml_item_extension_types = tuple(type for type in item_types if not issubclass(type, XMLElement))
        super(XMLListMixinType, cls).__setattr__(name, value)


class XMLListMixin(object):
    """A mixin representing a list of other XML elements"""

    __metaclass__ = XMLListMixinType

    _xml_item_type = None

    def __new__(cls, *args, **kw):
        if cls._xml_item_type is None:
            raise TypeError("The %s class cannot be instantiated because it doesn't define the _xml_item_type attribute" % cls.__name__)
        instance = super(XMLListMixin, cls).__new__(cls)
        instance._element_map = {}
        instance._xmlid_map = defaultdict(dict)
        return instance

    def __contains__(self, item):
        return item in self._element_map.itervalues()

    def __iter__(self):
        return (self._element_map[element] for element in self.element if element in self._element_map)

    def __len__(self):
        return len(self._element_map)

    def __nonzero__(self):
        return bool(self._element_map)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def _parse_element(self, element):
        self._element_map.clear()
        self._xmlid_map.clear()
        for child in element[:]:
            child_class = self._xml_document.get_element(child.tag, type(None))
            if child_class in self._xml_item_element_types or issubclass(child_class, self._xml_item_extension_types):
                try:
                    value = child_class.from_element(child)
                except ValidationError:
                    pass
                else:
                    if value._xml_id is not None and value._xml_id in self._xmlid_map[child_class]:
                        element.remove(child)
                    else:
                        if value._xml_id is not None:
                            self._xmlid_map[child_class][value._xml_id] = value
                        self._element_map[value.element] = value

    def _build_element(self):
        for child in self._element_map.itervalues():
            child.to_element()

    def add(self, item):
        if not (item.__class__ in self._xml_item_element_types or isinstance(item, self._xml_item_extension_types)):
            raise TypeError("%s cannot add items of type %s" % (self.__class__.__name__, item.__class__.__name__))
        if item._xml_id is not None and item._xml_id in self._xmlid_map[item.__class__]:
            self.remove(self._xmlid_map[item.__class__][item._xml_id])
        self._insert_element(item.element)
        if item._xml_id is not None:
            self._xmlid_map[item.__class__][item._xml_id] = item
        self._element_map[item.element] = item

    def remove(self, item):
        self.element.remove(item.element)
        if item._xml_id is not None:
            del self._xmlid_map[item.__class__][item._xml_id]
        del self._element_map[item.element]

    def update(self, sequence):
        for item in sequence:
            self.add(item)

    def clear(self):
        for item in self._element_map.values():
            self.remove(item)


## Element types

class XMLStringElement(XMLElement):
    _xml_lang = False # To be defined in subclass
    _xml_value_type = unicode # To be defined in subclass

    lang = XMLAttribute('lang', xmlname='{http://www.w3.org/XML/1998/namespace}lang', type=str, required=False, test_equal=True)

    def __init__(self, value, lang=None):
        XMLElement.__init__(self)
        self.value = value
        self.lang = lang

    def __eq__(self, other):
        if isinstance(other, XMLStringElement):
            return self.lang == other.lang and self.value == other.value
        elif isinstance(other, basestring) and (self._xml_lang is False or self.lang is None):
            return self.value == other
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.value, self.lang)

    def __str__(self):
        return str(self.value)

    def __unicode__(self):
        return unicode(self.value)

    def _get_value(self):
        return self.__dict__['value']

    def _set_value(self, value):
        if value is not None and not isinstance(value, self._xml_value_type):
            value = self._xml_value_type(value)
        self.__dict__['value'] = value

    value = property(_get_value, _set_value)
    del _get_value, _set_value

    def _parse_element(self, element):
        self.value = element.text
        if self._xml_lang:
            self.lang = element.get('{http://www.w3.org/XML/1998/namespace}lang', None)
        else:
            self.lang = None

    def _build_element(self):
        if self.value is not None:
            self.element.text = unicode(self.value)
        else:
            self.element.text = None
        if not self._xml_lang and self.lang is not None:
            del self.element.attrib[self.__class__.lang.xmlname]


class XMLEmptyElement(XMLElement):
    def __init__(self):
        XMLElement.__init__(self)
    def __repr__(self):
        return '%s()' % self.__class__.__name__
    def __eq__(self, other):
        return type(self) is type(other) or NotImplemented
    def __hash__(self):
        return hash(self.__class__)


class XMLEmptyElementRegistryType(type):
    """A metaclass for building registries of XMLEmptyElement subclasses from names"""

    def __init__(cls, name, bases, dct):
        super(XMLEmptyElementRegistryType, cls).__init__(name, bases, dct)
        typename = getattr(cls, '__typename__', name.partition('Registry')[0]).capitalize()
        class BaseElementType(XMLEmptyElement):
            def __str__(self): return self._xml_tag
            def __unicode__(self): return unicode(self._xml_tag)
        cls.__basetype__ = BaseElementType
        cls.__basetype__.__name__ = 'Base%sType' % typename
        cls.class_map = {}
        for name in cls.names:
            class ElementType(BaseElementType):
                _xml_tag = name
                _xml_namespace = cls._xml_namespace
                _xml_document = cls._xml_document
                _xml_id = name
            ElementType.__name__ = typename + name.title().translate(None, '-_')
            cls.class_map[name] = ElementType
        cls.classes = tuple(cls.class_map[name] for name in cls.names)


## Created using mixins

class XMLListElementType(XMLElementType, XMLListMixinType): pass

class XMLListRootElementType(XMLRootElementType, XMLListMixinType): pass

class XMLListElement(XMLElement, XMLListMixin):
    __metaclass__ = XMLListElementType

class XMLListRootElement(XMLRootElement, XMLListMixin):
    __metaclass__ = XMLListRootElementType


class XMLStringListElementType(XMLListElementType):
    def __init__(cls, name, bases, dct):
        if cls._xml_item_type is not None:
            raise TypeError("The %s class should not define _xml_item_type, but define _xml_item_registry, _xml_item_other_type and _xml_item_extension_type instead" % cls.__name__)
        types = cls._xml_item_registry.classes if cls._xml_item_registry is not None else ()
        types += tuple(type for type in (cls._xml_item_other_type, cls._xml_item_extension_type) if type is not None)
        cls._xml_item_type = types or None
        super(XMLStringListElementType, cls).__init__(name, bases, dct)


class XMLStringListElement(XMLListElement):
    __metaclass__ = XMLStringListElementType

    _xml_item_registry = None
    _xml_item_other_type = None
    _xml_item_extension_type = None

    def __contains__(self, item):
        if isinstance(item, basestring):
            if self._xml_item_registry is not None and item in self._xml_item_registry.names:
                item = self._xml_item_registry.class_map[item]()
            elif self._xml_item_other_type is not None:
                item = self._xml_item_other_type.from_string(item)
        return item in self._element_map.itervalues()

    def __iter__(self):
        return (item if isinstance(item, self._xml_item_extension_types) else unicode(item) for item in super(XMLStringListElement, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            if self._xml_item_registry is not None and item in self._xml_item_registry.names:
                item = self._xml_item_registry.class_map[item]()
            elif self._xml_item_other_type is not None:
                item = self._xml_item_other_type.from_string(item)
        super(XMLStringListElement, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            if self._xml_item_registry is not None and item in self._xml_item_registry.names:
                xmlitem = self._xml_item_registry.class_map[item]()
                try:
                    item = (entry for entry in super(XMLStringListElement, self).__iter__() if entry == xmlitem).next()
                except StopIteration:
                    raise KeyError(item)
            elif self._xml_item_other_type is not None:
                xmlitem = self._xml_item_other_type.from_string(item)
                try:
                    item = (entry for entry in super(XMLStringListElement, self).__iter__() if entry == xmlitem).next()
                except StopIteration:
                    raise KeyError(item)
        super(XMLStringListElement, self).remove(item)


## Useful attribute builders/parser

def uri_attribute_builder(value):
    return urllib.quote(value.encode('utf-8'))

def uri_attribute_parser(value):
    return urllib.unquote(value).decode('utf-8')




__all__ = ['ParserError',
           'BuilderError',
           'ValidationError',
           'IterateTypes',
           'IterateIDs',
           'IterateItems',
           'All',
           'parse_qname',
           'XMLDocument',
           'XMLAttribute',
           'XMLElementID',
           'XMLElementChild',
           'XMLElementChoiceChild',
           'XMLStringChoiceChild',
           'XMLElement',
           'XMLRootElement',
           'XMLSimpleElement',
           'XMLStringElement',
           'XMLLocalizedStringElement',
           'XMLBooleanElement',
           'XMLByteElement',
           'XMLUnsignedByteElement',
           'XMLShortElement',
           'XMLUnsignedShortElement',
           'XMLIntElement',
           'XMLUnsignedIntElement',
           'XMLLongElement',
           'XMLUnsignedLongElement',
           'XMLIntegerElement',
           'XMLPositiveIntegerElement',
           'XMLNegativeIntegerElement',
           'XMLNonNegativeIntegerElement',
           'XMLNonPositiveIntegerElement',
           'XMLDecimalElement',
           'XMLDateTimeElement',
           'XMLAnyURIElement',
           'XMLEmptyElement',
           'XMLEmptyElementRegistryType',
           'XMLListElement',
           'XMLListRootElement',
           'XMLStringListElement']


import os
import sys
import urllib
from collections import defaultdict, deque
from copy import deepcopy
from decimal import Decimal
from itertools import chain, izip
from weakref import WeakValueDictionary

from application.python import Null
from application.python.descriptor import classproperty
from application.python.types import MarkerType
from application.python.weakref import weakobjectmap
from lxml import etree

from sipsimple.payloads.datatypes import Boolean, Byte, UnsignedByte, Short, UnsignedShort, Int, UnsignedInt, Long, UnsignedLong
from sipsimple.payloads.datatypes import PositiveInteger, NegativeInteger, NonNegativeInteger, NonPositiveInteger, DateTime, AnyURI
from sipsimple.util import All


## Exceptions

class ParserError(Exception): pass
class BuilderError(Exception): pass
class ValidationError(ParserError): pass


## Markers

class IterateTypes: __metaclass__ = MarkerType
class IterateIDs:   __metaclass__ = MarkerType
class IterateItems: __metaclass__ = MarkerType

class StoredAttribute: __metaclass__ = MarkerType


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
        cls.nsmap = {}
        cls.schema_map = {}
        cls.element_map = {}
        cls.root_element = None
        cls.schema = None
        cls.parser = None
        for base in reversed(bases):
            if hasattr(base, 'element_map'):
                cls.element_map.update(base.element_map)
            if hasattr(base, 'schema_map'):
                cls.schema_map.update(base.schema_map)
            if hasattr(base, 'nsmap'):
                cls.nsmap.update(base.nsmap)
        cls._update_schema()

    def __setattr__(cls, name, value):
        if name == 'schema_path':
            if cls is not XMLDocument:
                raise AttributeError("%s can only be changed on XMLDocument" % name)
            super(XMLDocumentType, cls).__setattr__(name, value)
            def update_schema(document_class):
                document_class._update_schema()
                for document_subclass in document_class.__subclasses__():
                    update_schema(document_subclass)
            update_schema(XMLDocument)
        else:
            super(XMLDocumentType, cls).__setattr__(name, value)

    def _update_schema(cls):
        if cls.schema_map:
            location_map = {ns: urllib.quote(os.path.abspath(os.path.join(cls.schema_path, schema_file)).replace('\\', '//')) for ns, schema_file in cls.schema_map.iteritems()}
            schema = """<?xml version="1.0"?>
                <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
                    %s
                </xs:schema>
            """ % '\r\n'.join('<xs:import namespace="%s" schemaLocation="%s"/>' % (namespace, schema_location) for namespace, schema_location in location_map.iteritems())
            cls.schema = etree.XMLSchema(etree.XML(schema))
            cls.parser = etree.XMLParser(schema=cls.schema, remove_blank_text=True)
        else:
            cls.schema = None
            cls.parser = etree.XMLParser(remove_blank_text=True)


class XMLDocument(object):
    __metaclass__ = XMLDocumentType

    encoding = 'UTF-8'
    content_type = None
    schema_path = os.path.join(os.path.dirname(__file__), 'xml-schemas')

    @classmethod
    def parse(cls, document):
        try:
            if isinstance(document, str):
                xml = etree.XML(document, parser=cls.parser)
            elif isinstance(document, unicode):
                xml = etree.XML(document.encode('utf-8'), parser=cls.parser)
            else:
                xml = etree.parse(document, parser=cls.parser).getroot()
            if cls.schema is not None:
                cls.schema.assertValid(xml)
            return cls.root_element.from_element(xml, xml_document=cls)
        except (etree.DocumentInvalid, etree.XMLSyntaxError, ValueError), e:
            raise ParserError(str(e))

    @classmethod
    def build(cls, root_element, encoding=None, pretty_print=False, validate=True):
        if type(root_element) is not cls.root_element:
            raise TypeError("can only build XML documents from root elements of type %s" % cls.root_element.__name__)
        element = root_element.to_element()
        if validate and cls.schema is not None:
            cls.schema.assertValid(element)
        # Cleanup namespaces and move element NS mappings to the global scope.
        normalized_element = etree.Element(element.tag, attrib=element.attrib, nsmap=dict(chain(element.nsmap.iteritems(), cls.nsmap.iteritems())))
        normalized_element.text = element.text
        normalized_element.tail = element.tail
        normalized_element.extend(deepcopy(child) for child in element)
        etree.cleanup_namespaces(normalized_element)
        return etree.tostring(normalized_element, encoding=encoding or cls.encoding, method='xml', xml_declaration=True, pretty_print=pretty_print)

    @classmethod
    def create(cls, build_kw={}, **kw):
        return cls.build(cls.root_element(**kw), **build_kw)

    @classmethod
    def register_element(cls, xml_class):
        cls.element_map[xml_class.qname] = xml_class
        for child in cls.__subclasses__():
            child.register_element(xml_class)

    @classmethod
    def get_element(cls, qname, default=None):
        return cls.element_map.get(qname, default)

    @classmethod
    def register_namespace(cls, namespace, prefix=None, schema=None):
        if prefix in cls.nsmap:
            raise ValueError("prefix %s is already registered in %s" % (prefix, cls.__name__))
        if namespace in cls.nsmap.itervalues():
            raise ValueError("namespace %s is already registered in %s" % (namespace, cls.__name__))
        cls.nsmap[prefix] = namespace
        if schema is not None:
            cls.schema_map[namespace] = schema
            cls._update_schema()
        for child in cls.__subclasses__():
            child.register_namespace(namespace, prefix, schema)

    @classmethod
    def unregister_namespace(cls, namespace):
        try:
            prefix = (prefix for prefix in cls.nsmap if cls.nsmap[prefix]==namespace).next()
        except StopIteration:
            raise KeyError("namespace %s is not registered in %s" % (namespace, cls.__name__))
        del cls.nsmap[prefix]
        schema = cls.schema_map.pop(namespace, None)
        if schema is not None:
            cls._update_schema()
        for child in cls.__subclasses__():
            try:
                child.unregister_namespace(namespace)
            except KeyError:
                pass


## Children descriptors

class XMLAttribute(object):
    def __init__(self, name, xmlname=None, type=unicode, default=None, required=False, test_equal=True, onset=None, ondel=None):
        self.name = name
        self.xmlname = xmlname or name
        self.type = type
        self.default = default
        self.__xmlparse__ = getattr(type, '__xmlparse__', lambda value: value)
        self.__xmlbuild__ = getattr(type, '__xmlbuild__', unicode)
        self.required = required
        self.test_equal = test_equal
        self.onset = onset
        self.ondel = ondel
        self.values = weakobjectmap()
    
    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[obj]
        except KeyError:
            value = self.values.setdefault(obj, self.default)
            if value is not None:
                obj.element.set(self.xmlname, self.build(value))
            return value
    
    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        old_value = self.values.get(obj, self.default)
        if value == old_value:
            return
        if value is not None:
            obj.element.set(self.xmlname, self.build(value))
        else:
            obj.element.attrib.pop(self.xmlname, None)
        self.values[obj] = value
        obj.__dirty__ = True
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        obj.element.attrib.pop(self.xmlname, None)
        try:
            value = self.values.pop(obj)
        except KeyError:
            pass
        else:
            if value != self.default:
                obj.__dirty__ = True
        if self.ondel:
            self.ondel(obj, self)

    def parse(self, xmlvalue):
        return self.__xmlparse__(xmlvalue)

    def build(self, value):
        return self.__xmlbuild__(value)


class XMLElementID(XMLAttribute):
    """An XMLAttribute that represents the ID of an element (immutable)."""

    def __set__(self, obj, value):
        if obj in self.values:
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
        self.values = weakobjectmap()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[obj]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        same_value = False
        old_value = self.values.get(obj)
        if value is old_value:
            return
        elif value is not None and value == old_value:
            value.__dirty__ = old_value.__dirty__
            same_value = True
        if old_value is not None:
            obj.element.remove(old_value.element)
        if value is not None:
            obj._insert_element(value.element)
        self.values[obj] = value
        if not same_value:
            obj.__dirty__ = True
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            old_value = self.values.pop(obj)
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
                obj.__dirty__ = True
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
        self.values = weakobjectmap()

    def __get__(self, obj, objtype):
        if obj is None:
            return XMLElementChoiceChildWrapper(self, objtype)
        try:
            return self.values[obj]
        except KeyError:
            return None

    def __set__(self, obj, value):
        if value is not None and type(value) not in self.types:
            raise TypeError("%s is not an acceptable type for %s" % (value.__class__.__name__, obj.__class__.__name__))
        same_value = False
        old_value = self.values.get(obj)
        if value is old_value:
            return
        elif value is not None and value == old_value:
            value.__dirty__ = old_value.__dirty__
            same_value = True
        if old_value is not None:
            obj.element.remove(old_value.element)
        if value is not None:
            obj._insert_element(value.element)
        self.values[obj] = value
        if not same_value:
            obj.__dirty__ = True
        if self.onset:
            self.onset(obj, self, value)

    def __delete__(self, obj):
        try:
            old_value = self.values.pop(obj)
        except KeyError:
            pass
        else:
            if old_value is not None:
                obj.element.remove(old_value.element)
                obj.__dirty__ = True
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
        if obj is None or objtype is StoredAttribute or value is None or isinstance(value, self.extension_type or ()):
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

class XMLElementBase(object):
    """
    This class is used as a common ancestor for XML elements and provides
    the means for super() to find at least dummy implementations for the
    methods that are supposed to be implemented by subclasses, even when
    they are not implemented by any other ancestor class. This is necessary
    in order to simplify access to these methods when multiple inheritance
    is involved and none or only some of the classes implement them.
    The methods declared here should to be implemented in subclasses as
    necessary.
    """

    def __get_dirty__(self):
        return False

    def __set_dirty__(self, dirty):
        return

    def _build_element(self):
        return

    def _parse_element(self, element):
        return


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

class XMLElement(XMLElementBase):
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
        self.element = etree.Element(self.qname, nsmap=self._xml_document.nsmap)
        self.__dirty__ = True

    def __get_dirty__(self):
        return (self.__dict__['__dirty__']
                or any(child.__dirty__ for child in (getattr(self, name) for name in self._xml_element_children) if child is not None)
                or super(XMLElement, self).__get_dirty__())

    def __set_dirty__(self, dirty):
        super(XMLElement, self).__set_dirty__(dirty)
        if not dirty:
            for child in (child for child in (getattr(self, name) for name in self._xml_element_children) if child is not None):
                child.__dirty__ = dirty
        self.__dict__['__dirty__'] = dirty

    __dirty__ = property(__get_dirty__, __set_dirty__)

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
            descriptor = getattr(self.__class__, name)
            child = descriptor.__get__(self, StoredAttribute)
            if child is not None:
                child.to_element()
        self._build_element()
        return self.element

    @classmethod
    def from_element(cls, element, xml_document=None):
        obj = cls.__new__(cls)
        obj._xml_document = xml_document if xml_document is not None else cls._xml_document
        obj.element = element
        # set known attributes
        for name, attribute in cls._xml_attributes.iteritems():
            xmlvalue = element.get(attribute.xmlname, None)
            if xmlvalue is not None:
                try:
                    setattr(obj, name, attribute.parse(xmlvalue))
                except (ValueError, TypeError):
                    raise ValidationError("got illegal value for attribute %s of %s: %s" % (name, cls.__name__, xmlvalue))
        # set element children
        for child in element:
            element_child, type = cls._xml_children_qname_map.get(child.tag, (None, None))
            if element_child is not None:
                try:
                    value = type.from_element(child, xml_document=obj._xml_document)
                except ValidationError:
                    pass # we should accept partially valid documents
                else:
                    setattr(obj, element_child.name, value)
        obj._parse_element(element)
        obj.check_validity()
        obj.__dirty__ = False
        return obj

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
            if self is other:
                return True
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
        elif self._xml_id is not None:
            return self._xml_id == other
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __hash__(self):
        if self._xml_id is not None:
            return hash(self._xml_id)
        else:
            return object.__hash__(self)


class XMLRootElementType(XMLElementType):
    def __init__(cls, name, bases, dct):
        super(XMLRootElementType, cls).__init__(name, bases, dct)
        if cls._xml_document is not None:
            if cls._xml_document.root_element is not None:
                raise TypeError('there is already a root element registered for %s' % cls.__name__)
            cls._xml_document.root_element = cls

class XMLRootElement(XMLElement):
    __metaclass__ = XMLRootElementType

    def __init__(self):
        XMLElement.__init__(self)
        self.__cache__ = WeakValueDictionary({self.element: self})

    @classmethod
    def from_element(cls, element, xml_document=None):
        obj = super(XMLRootElement, cls).from_element(element, xml_document)
        obj.__cache__ = WeakValueDictionary({obj.element: obj})
        return obj

    @classmethod
    def parse(cls, document):
        return cls._xml_document.parse(document)

    def toxml(self, encoding=None, pretty_print=False, validate=True):
        return self._xml_document.build(self, encoding=encoding, pretty_print=pretty_print, validate=validate)

    def xpath(self, xpath, namespaces=None):
        result = []
        try:
            nodes = self.element.xpath(xpath, namespaces=namespaces)
        except etree.XPathError:
            raise ValueError("illegal XPath expression")
        for element in (node for node in nodes if isinstance(node, etree._Element)):
            if element in self.__cache__:
                result.append(self.__cache__[element])
                continue
            if element is self.element:
                self.__cache__[element] = self
                result.append(self)
                continue
            for ancestor in element.iterancestors():
                if ancestor in self.__cache__:
                    container = self.__cache__[ancestor]
                    break
            else:
                container = self
            notvisited = deque([container])
            visited = set()
            while notvisited:
                container = notvisited.popleft()
                self.__cache__[container.element] = container
                if isinstance(container, XMLListMixin):
                    children = set(child for child in container if isinstance(child, XMLElement) and child not in visited)
                    visited.update(children)
                    notvisited.extend(children)
                for child in container._xml_element_children:
                    value = getattr(container, child)
                    if value is not None and value not in visited:
                        visited.add(value)
                        notvisited.append(value)
            if element in self.__cache__:
                result.append(self.__cache__[element])
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


class XMLListMixin(XMLElementBase):
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

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, XMLListMixin):
            return self is other or (len(self) == len(other) and all(self_item == other_item for self_item, other_item in izip(self, other)))
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __getitem__(self, key):
        if key is IterateTypes:
            return (cls for cls, mapping in self._xmlid_map.iteritems() if mapping)
        if not isinstance(key, tuple):
            raise KeyError(key)
        try:
            cls, id = key
        except ValueError:
            raise KeyError(key)
        if id is IterateIDs:
            return self._xmlid_map[cls].iterkeys()
        elif id is IterateItems:
            return self._xmlid_map[cls].itervalues()
        else:
            return self._xmlid_map[cls][id]

    def __delitem__(self, key):
        if not isinstance(key, tuple):
            raise KeyError(key)
        try:
            cls, id = key
        except ValueError:
            raise KeyError(key)
        if id is All:
            for item in self._xmlid_map[cls].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[cls][id])

    def __get_dirty__(self):
        return any(item.__dirty__ for item in self._element_map.itervalues()) or super(XMLListMixin, self).__get_dirty__()

    def __set_dirty__(self, dirty):
        super(XMLListMixin, self).__set_dirty__(dirty)
        if not dirty:
            for item in self._element_map.itervalues():
                item.__dirty__ = dirty

    def _parse_element(self, element):
        super(XMLListMixin, self)._parse_element(element)
        self._element_map.clear()
        self._xmlid_map.clear()
        for child in element[:]:
            child_class = self._xml_document.get_element(child.tag, type(None))
            if child_class in self._xml_item_element_types or issubclass(child_class, self._xml_item_extension_types):
                try:
                    value = child_class.from_element(child, xml_document=self._xml_document)
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
        super(XMLListMixin, self)._build_element()
        for child in self._element_map.itervalues():
            child.to_element()

    def add(self, item):
        if not (item.__class__ in self._xml_item_element_types or isinstance(item, self._xml_item_extension_types)):
            raise TypeError("%s cannot add items of type %s" % (self.__class__.__name__, item.__class__.__name__))
        same_value = False
        if item._xml_id is not None and item._xml_id in self._xmlid_map[item.__class__]:
            old_item = self._xmlid_map[item.__class__][item._xml_id]
            if item is old_item:
                return
            elif item == old_item:
                item.__dirty__ = old_item.__dirty__
                same_value = True
            self.element.remove(old_item.element)
            del self._xmlid_map[item.__class__][item._xml_id]
            del self._element_map[old_item.element]
        self._insert_element(item.element)
        if item._xml_id is not None:
            self._xmlid_map[item.__class__][item._xml_id] = item
        self._element_map[item.element] = item
        if not same_value:
            self.__dirty__ = True

    def remove(self, item):
        self.element.remove(item.element)
        if item._xml_id is not None:
            del self._xmlid_map[item.__class__][item._xml_id]
        del self._element_map[item.element]
        self.__dirty__ = True

    def update(self, sequence):
        for item in sequence:
            self.add(item)

    def clear(self):
        for item in self._element_map.values():
            self.remove(item)


## Element types

class XMLSimpleElement(XMLElement):
    _xml_value_type = None # To be defined in subclass

    def __new__(cls, *args, **kw):
        if cls._xml_value_type is None:
            raise TypeError("The %s class cannot be instantiated because it doesn't define the _xml_value_type attribute" % cls.__name__)
        return super(XMLSimpleElement, cls).__new__(cls)

    def __init__(self, value):
        XMLElement.__init__(self)
        self.value = value

    def __eq__(self, other):
        if isinstance(other, XMLSimpleElement):
            return self is other or self.value == other.value
        else:
            return self.value == other

    def __nonzero__(self):
        return bool(self.value)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)

    def __str__(self):
        return str(self.value)

    def __unicode__(self):
        return unicode(self.value)

    def _get_value(self):
        return self.__dict__['value']

    def _set_value(self, value):
        if not isinstance(value, self._xml_value_type):
            value = self._xml_value_type(value)
        if self.__dict__.get('value', Null) == value:
            return
        self.__dict__['value'] = value
        self.__dirty__ = True

    value = property(_get_value, _set_value)
    del _get_value, _set_value

    def _parse_element(self, element):
        super(XMLSimpleElement, self)._parse_element(element)
        value = element.text or u''
        if hasattr(self._xml_value_type, '__xmlparse__'):
            self.value = self._xml_value_type.__xmlparse__(value)
        else:
            self.value = self._xml_value_type(value)

    def _build_element(self):
        super(XMLSimpleElement, self)._build_element()
        if hasattr(self.value, '__xmlbuild__'):
            self.element.text = self.value.__xmlbuild__()
        else:
            self.element.text = unicode(self.value)


class XMLStringElement(XMLSimpleElement):
    _xml_value_type = unicode # Can be overwritten in subclasses

    def __len__(self):
        return len(self.value)


class XMLLocalizedStringElement(XMLStringElement):
    lang = XMLAttribute('lang', xmlname='{http://www.w3.org/XML/1998/namespace}lang', type=str, required=False, test_equal=True)

    def __init__(self, value, lang=None):
        XMLStringElement.__init__(self, value)
        self.lang = lang

    def __eq__(self, other):
        if isinstance(other, XMLLocalizedStringElement):
            return self is other or (self.lang == other.lang and self.value == other.value)
        elif self.lang is None:
            return XMLStringElement.__eq__(self, other)
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.value, self.lang)

    def _parse_element(self, element):
        super(XMLLocalizedStringElement, self)._parse_element(element)
        self.lang = element.get('{http://www.w3.org/XML/1998/namespace}lang', None)


class XMLBooleanElement(XMLSimpleElement):
    _xml_value_type = Boolean


class XMLByteElement(XMLSimpleElement):
    _xml_value_type = Byte


class XMLUnsignedByteElement(XMLSimpleElement):
    _xml_value_type = UnsignedByte


class XMLShortElement(XMLSimpleElement):
    _xml_value_type = Short


class XMLUnsignedShortElement(XMLSimpleElement):
    _xml_value_type = UnsignedShort


class XMLIntElement(XMLSimpleElement):
    _xml_value_type = Int


class XMLUnsignedIntElement(XMLSimpleElement):
    _xml_value_type = UnsignedInt


class XMLLongElement(XMLSimpleElement):
    _xml_value_type = Long


class XMLUnsignedLongElement(XMLSimpleElement):
    _xml_value_type = UnsignedLong


class XMLIntegerElement(XMLSimpleElement):
    _xml_value_type = int


class XMLPositiveIntegerElement(XMLSimpleElement):
    _xml_value_type = PositiveInteger


class XMLNegativeIntegerElement(XMLSimpleElement):
    _xml_value_type = NegativeInteger


class XMLNonNegativeIntegerElement(XMLSimpleElement):
    _xml_value_type = NonNegativeInteger


class XMLNonPositiveIntegerElement(XMLSimpleElement):
    _xml_value_type = NonPositiveInteger


class XMLDecimalElement(XMLSimpleElement):
    _xml_value_type = Decimal


class XMLDateTimeElement(XMLSimpleElement):
    _xml_value_type = DateTime


class XMLAnyURIElement(XMLStringElement):
    _xml_value_type = AnyURI


class XMLEmptyElement(XMLElement):
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

    def __nonzero__(self):
        if self._xml_attributes or self._xml_element_children:
            return True
        else:
            return len(self._element_map) != 0

class XMLListRootElement(XMLRootElement, XMLListMixin):
    __metaclass__ = XMLListRootElementType

    def __nonzero__(self):
        if self._xml_attributes or self._xml_element_children:
            return True
        else:
            return len(self._element_map) != 0


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



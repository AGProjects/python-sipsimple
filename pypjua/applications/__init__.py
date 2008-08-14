import os

from lxml import etree

__all__ = ["ParserError", "BuilderError", "XMLElement", "XMLApplication"]


_schema_dir_ = os.path.join(os.path.dirname(__file__), 'xml-schemas')

class ParserError(Exception): pass
class BuilderError(Exception): pass

def classproperty(function):
    class Descriptor(object):
        def __get__(self, instance, owner):
            return function(owner)
    return Descriptor()

class XMLElement(object):
    encoding = 'UTF-8'
    
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_attrs = {} # Not necessarily defined in subclass

    qname = classproperty(lambda cls: '{%s}%s' % (cls._xml_namespace, cls._xml_tag))

    def to_element(self, parent=None, nsmap=None):
        if parent is None:
            element = etree.Element(self.qname, nsmap=nsmap)
        else:
            element = etree.SubElement(parent, self.qname, nsmap=nsmap)
        for attr, definition in cls._xml_attrs.items():
            if hasattr(obj, attr):
                element.set(definition.get('xml_attribute', attr), getattr(obj, attr))
        self._build_element(element)
        return element
    
    # To be defined in subclass
    def _build_element(self, element):
        pass

    @classmethod
    def from_element(cls, element, *args, **kwargs):
        obj = cls.__new__(cls)
        for attr, definition in cls._xml_attrs.items():
            setattr(obj, attr, element.get(definition.get('xml_attribute', attr)))
        obj._parse_element(element, *args, **kwargs)
        return obj
    
    # To be defined in subclass
    def _parse_element(self, element, *args, **kwargs):
        pass
    
    def __eq__(self, obj):
        ids = [getattr(self, attr) for attr, definition in self._xml_attrs.items() if definition.get('id_attribute', False)]
        if isinstance(obj, basestring):
            if len(ids) != 1 or ids[0] != obj:
                return False
        elif isinstance(obj, (tuple, list)):
            if ids != list(obj) and ids != []:
                return False
        else:
            has_test = False
            for attr, definition in self._xml_attrs.items():
                if definition.get('test_equal', True) or definition.get('id_attribute', False):
                    if not hasattr(obj, attr) or getattr(self, attr) != getattr(obj, attr):
                        return False
                    has_test = True
            if not has_test:
                try:
                    return super(XMLElement, self).__eq__(obj)
                except AttributeError:
                    return self is obj
        return True

    def __hash__(self):
        id_hashes = [hash(getattr(self, attr)) for attr, definition in self._xml_attrs.items() if definition.get('id_attribute', False)]
        if len(id_hashes) == 0:
            return super(XMLElement, self).__hash__()
        return sum(id_hashes)

class XMLApplicationMeta(type):
    def __init__(cls, name, bases, dct):
        if cls._xml_schema is None and cls._xml_schema_file is not None:
            cls._xml_schema = etree.XMLSchema(etree.parse(open(os.path.join(cls._xml_schema_dir, cls._xml_schema_file), 'r')))
        if cls._parser is None:
            if cls._xml_schema is not None and cls._validate_input:
                cls._parser = etree.XMLParser(schema=cls._xml_schema, **cls._parser_opts)
            else:
                cls._parser = etree.XMLParser(**cls._parser_opts)

class XMLApplication(XMLElement):
    __metaclass__ = XMLApplicationMeta
    
    accept_types = []
    build_types = []
    
    _validate_input = True
    _validate_output = True
    _parser_opts = {}
    _parser = None
    
    _xml_nsmap = {}
    _xml_schema = None
    _xml_schema_file = None
    _xml_schema_dir = _schema_dir_
    _xml_declaration = False
    
    def to_element(self, nsmap=None):
        nsmap = nsmap or self._xml_nsmap
        return super(XMLApplication, self).to_element(nsmap)

    @classmethod
    def parse(cls, document):
        return cls.from_element(etree.XML(document, cls._parser))
    
    def toxml(self, *args, **kwargs):
        element = self.to_element()
        if kwargs.pop('validate', self._validate_output):
            self._xml_schema.assertValid(element)
        
        kwargs.setdefault('encoding', self.encoding)
        kwargs.setdefault('xml_declaration', self._xml_declaration)
        return etree.tostring(element, *args, **kwargs)
    
    @classmethod
    def _check_qname(cls, element, name, namespace=None):
        namespace = namespace or cls._xml_namespace
        if namespace is not None:
            qname = '{%s}%s' % (namespace, name)
        if element.tag != qname:
            raise ParserError("Wrong XML element in XML application %s: expected %s, got %s" %
                    (self.__class__.__name__, qname, element.tag))

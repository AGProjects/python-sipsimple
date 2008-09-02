import os
import sys
import traceback

from lxml import etree

__all__ = ['ParserError',
           'BuilderError',
           'XMLMeta', 
           'XMLElement', 
           'XMLListElement',
           'XMLStringElement',
           'XMLEmptyElement',
           'XMLApplication']


_schema_dir_ = os.path.join(os.path.dirname(__file__), 'xml-schemas')

class ParserError(Exception): pass
class BuilderError(Exception): pass

def classproperty(function):
    class Descriptor(object):
        def __get__(self, instance, owner):
            return function(owner)
    return Descriptor()


class XMLMetaType(type):
    def __init__(cls, name, bases, dct):
        cls_dct = {}
        for base in reversed(bases):
            if hasattr(base, '_xml_classes'):
                cls_dct.update(base._xml_classes)
        if '_xml_classes' in dct:
            cls_dct.update(dict((xml_cls.qname, xml_cls) for xml_cls in dct['_xml_classes']))
        cls._xml_classes = cls_dct

class XMLMeta(object):
    __metaclass__ = XMLMetaType

    @classmethod
    def register(cls, xml_cls):
        cls._xml_classes[xml_cls.qname] = xml_cls

    @classmethod
    def get(cls, qname, default=None):
        return cls._xml_classes.get(qname, default)

class XMLElement(object):
    encoding = 'UTF-8'
    
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_attrs = {} # Not necessarily defined in subclass
    _xml_meta = None # To be defined in subclass

    qname = classproperty(lambda cls: '{%s}%s' % (cls._xml_namespace, cls._xml_tag))

    def __init__(self):
        raise NotImplementedError("XML Element type %s cannot be directly instantiated" % self.__class__.__name__)

    def to_element(self, parent=None, nsmap=None):
        if parent is None:
            element = etree.Element(self.qname, nsmap=nsmap)
        else:
            element = etree.SubElement(parent, self.qname, nsmap=nsmap)
        for attr, definition in self._xml_attrs.items():
            value = hasattr(self, attr) and getattr(self, attr) or None
            if value is not None:
                element.set(definition.get('xml_attribute', attr), value)
        self._build_element(element, nsmap)
        return element
    
    # To be defined in subclass
    def _build_element(self, element, nsmap):
        raise NotImplementedError("%s does not support building to XML" % self.__class__.__name__)

    @classmethod
    def from_element(cls, element, *args, **kwargs):
        obj = cls.__new__(cls)
        obj._xml_meta = kwargs.pop('xml_meta', cls._xml_meta)
        for attr, definition in cls._xml_attrs.items():
            setattr(obj, attr, element.get(definition.get('xml_attribute', attr)))
        obj._parse_element(element, *args, **kwargs)
        return obj
    
    # To be defined in subclass
    def _parse_element(self, element, *args, **kwargs):
        raise NotImplementedError("%s does not support parsing from XML" % self.__class__.__name__)

    
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

class XMLListElement(XMLElement, list):
    """An XMLElement representing a list of other XML elmeents
    that allows to setup hooks on element insertion/removal
    """

    def _before_add(self, value):
        """Called for every value that is about to be inserted into the list.
        The returned value will be inserted into the list"""
        return value

    def _before_get(self, value):
        """Called for every value that is about to be get from the list.
        The returned value will be the one returned
        
        Must not throw!
        """
        return value

    def _before_del(self, value):
        """Called for every value that is about to be removed from the list.

        Must not throw!
        """

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, list.__repr__(self))

    def __setitem__(self, key, value_or_lst):
        if isinstance(key, slice):
            values = []
            count = 0
            for value in value_or_lst:
                try:
                    values.append(self._before_add(value))
                    count += 1
                except:
                    exc = sys.exc_info()
                    for value in value_or_lst[:count]:
                        try:
                            self._before_remove(value)
                        except:
                            traceback.print_exc() #FIXME
                    raise exc[0], exc[1], exc[2]
            return list.__setitem__(self, key, values)
        else:
            value = self._before_insert(value_or_lst)
            return list.__setitem__(self, key, value)

    def __setslice__(self, i, j, sequence):
        return self.__setitem__(slice(i,j), sequence)

    def __getitem__(self, key):
        if isinstance(key, slice):
            values = []
            for value in list.__getitem__(self, key):
                try:
                    values.append(self._before_get(value))
                except:
                    traceback.print_exc() #FIXME
            return values
        else:
            return self._before_get(list.__getitem__(self, key))

    def __getslice__(self, i, j):
        return self.__getitem__(slice(i, j))

    def __delitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.start, key.stop, key.step
            if start is None:
                start = 0
            if stop is None:
                stop = len(self)
            if step is None:
                step = 1
            for k in xrange(start, stop, step):
                try:
                    self._before_del(list.__getitem__(self, k))
                except:
                    traceback.print_exc() #FIXME
        else:
            try:
                self._before_del(self[key])
            except:
                traceback.print_exc() #FIXME
        return list.__delitem__(self, key)

    def __delslice__(self, i, j):
        return self.__delitem__(slice(i,j))

    def append(self, item):
        self[len(self):len(self)] = [item]

    def extend(self, lst):
        self[len(self):len(self)] = lst

    def insert(self, i, x):
        self[i:i] = [x]

    def pop(self, i = -1):
        x = self[i];
        del self[i];
        return x

    def remove(self, x):
        del self[self.index(x)]

    def __iadd__(self, sequence):
        self.extend(sequence)
        return self
    
    def __imul__(self, n):
        values = self[:]
        for i in xrange(n):
            self += values

    def __str__(self):
        return '['+', '.join("'%s'" % elem for elem in self)+']'

class XMLStringElement(XMLElement):
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_attrs = {} # Not necessarily defined in subclass
    _xml_meta = None # To be defined in subclass
    _xml_lang = False # To be defined in subclass
    _xml_values = None # Not necessarily defined in subclass
    
    def __init__(self, value, lang=None):
        self.value = str(value)
        if not self._xml_lang:
            lang = None
        self.lang = lang

    def _parse_element(self, element):
        self.value = element.text
        if self._xml_lang:
            self.lang = element.get('xml:lang', None)

    def _build_element(self, element, nsmap):
        element.text = self.value
        if self._xml_lang and self.lang is not None:
            element.set('xml:lang', self.lang)

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        if self._xml_values is not None and value not in self._xml_values:
            raise ValueError("%s can only have values [%s]" % (self.__class__.__name__, ', '.join("`%s'" % val for val in self._xml_values)))
        self._value = value

    value = property(_get_value, _set_value)

    def __str__(self):
        return self.value

    def __eq__(self, obj):
        if self._xml_lang and not (hasattr(obj, 'lang') and self.lang == obj.lang):
            return False
        return self.value == str(obj)

    def __hash__(self):
        selfhash = hash(self.value)
        if self._xml_lang:
            selfhash += hash(self.lang)
        return selfhash

class XMLEmptyElement(XMLElement):
    _xml_tag = None # To be defined in subclass
    _xml_namespace = None # To be defined in subclass
    _xml_attrs = {} # Not necessarily defined in subclass
    _xml_meta = None # To be defined in subclass

    def __init__(self):
        pass
    
    def _parse_element(self, element):
        pass

    def _build_element(self, element, nsmap):
        pass

    def __str__(self):
        return self.__class__.__name__

    def __eq__(self, obj):
        return self is obj

    def __hash__(self):
        return object.__hash__(self)

class XMLApplicationType(type):
    def __init__(cls, name, bases, dct):
        if cls._xml_schema is None and cls._xml_schema_file is not None:
            cls._xml_schema = etree.XMLSchema(etree.parse(open(os.path.join(cls._xml_schema_dir, cls._xml_schema_file), 'r')))
        if cls._parser is None:
            if cls._xml_schema is not None and cls._validate_input:
                cls._parser = etree.XMLParser(schema=cls._xml_schema, **cls._parser_opts)
            else:
                cls._parser = etree.XMLParser(**cls._parser_opts)

class XMLApplication(XMLElement):
    __metaclass__ = XMLApplicationType
    
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
    _xml_declaration = True
    
    def to_element(self, nsmap=None):
        nsmap = nsmap or self._xml_nsmap
        return super(XMLApplication, self).to_element(nsmap=nsmap)

    @classmethod
    def parse(cls, document):
        return cls.from_element(etree.XML(document, cls._parser))
    
    def toxml(self, *args, **kwargs):
        nsmap = kwargs.pop('nsmap', None)
        element = self.to_element(nsmap=nsmap)
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

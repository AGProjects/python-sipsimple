import os

from lxml import etree

_schema_dir_ = os.path.join(os.path.dirname(__file__), 'xml-schemas')


class ParserError(Exception): pass


class Parser(object):
    accept_types = []

class XMLElementMapping(object):
    _xml_attrs = {}
    def __init__(self, element, *args, **kwargs):
        for attr, definition in self._xml_attrs.items():
            setattr(self, attr, element.get(definition.get('xml_attribute', attr)))
        self._parse_element(element, *args, **kwargs)
    
    def __eq__(self, obj):
        ids = [getattr(self, attr) for attr, definition in self._xml_attrs.items() if definition.get('id_attribute', False)]
        if isinstance(obj, basestring):
            if len(ids) != 1 or ids[0] != obj:
                return False
        elif isinstance(obj, (tuple, list)):
            if ids != list(obj):
                return False
        else:
            for attr, definition in self._xml_attrs.items():
                if definition.get('testequal', True) and (not hasattr(obj, attr) or getattr(self, attr) != getattr(obj, attr)):
                    return False
        return True

    def __hash__(self):
        return sum(hash(getattr(self, attr)) for attr, definition in self._xml_attrs.items() if definition.get('id_attribute', False))
    
    def _parse_element(self, element, *args, **kwargs):
        pass

def parse_schema(filename, dir = _schema_dir_):
    return etree.XMLSchema(etree.parse(open(os.path.join(dir, filename), 'r')))

class XMLParserMeta(type):
    def __init__(cls, name, bases, dct):
        if cls._schema is None and cls._schema_file is not None:
            cls._schema = parse_schema(cls._schema_file, cls._schema_dir)

class XMLParser(Parser):
    __metaclass__ = XMLParserMeta

    _namespace = None
    _schema = None
    _schema_file = None
    _parser = etree.XMLParser()

    _schema_dir = _schema_dir_

    def assertValid(self, element):
        if self._schema is not None:
            self._schema.assertValid(element)

    def _parse(self, document):
        if self._parser is not None:
            try:
                root = etree.XML(document, self._parser)
                self.assertValid(root)
            except Exception, e:
                raise ParserError("Cannot load XML document: %s" % e)
            return root
        else:
            raise ParserError("No XML parser defined")

    def _check_qname(self, element, name, namespace=None):
        namespace = namespace or self._namespace
        try:
            if namespace is not None:
                name = '{%s}%s' % (namespace, name)
            if element.tag != name:
                raise ParserError("Wrong XML element in XML parser %s: expected %s, got %s" %
                        (self.__class__.__name__, name, element.tag))
        except KeyError:
            raise ParserError("Cannot find namespace for XML element %s:%s" % (element.prefix, element.tag))

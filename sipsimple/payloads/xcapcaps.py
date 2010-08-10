# Copyright (C) 2010 AG Projects. See LICENSE for details
#

"""
Support for parsing and building xcap-caps documents, as defined by RFC4825.
"""

__all__ = ['XCAPCapabilitiesApplication', 'AUIDS', 'Extensions', 'Namespaces', 'XCAPCapabilities']

from lxml import etree

from sipsimple.payloads import XMLApplication, XMLElementChild, XMLListElement, XMLRootElement


namespace = 'urn:ietf:params:xml:ns:xcap-caps'


class XCAPCapabilitiesApplication(XMLApplication): pass
XCAPCapabilitiesApplication.register_namespace(namespace, prefix=None)


## Elements

class AUIDS(XMLListElement):
    _xml_tag = 'auids'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self[0:0] = children

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == '{%s}auid' % self._xml_namespace:
                try:
                    self.append(child.text)
                except:
                    pass

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        for auid in self:
            child = etree.SubElement(self.element, '{%s}auid' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            child.text = auid

    def _add_item(self, auid):
        return unicode(auid)


class Extensions(XMLListElement):
    _xml_tag = 'extensions'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self[0:0] = children

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == '{%s}extension' % self._xml_namespace:
                try:
                    self.append(child.text)
                except:
                    pass

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        for extension in self:
            child = etree.SubElement(self.element, '{%s}extension' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            child.text = extension

    def _add_item(self, extension):
        return unicode(extension)


class Namespaces(XMLListElement):
    _xml_tag = 'namespaces'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self[:] = children

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == '{%s}namespace' % self._xml_namespace:
                try:
                    self.append(child.text)
                except:
                    pass

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        for namespace in self:
            child = etree.SubElement(self.element, '{%s}namespace' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            child.text = namespace

    def _add_item(self, namespace):
        return unicode(namespace)


class XCAPCapabilities(XMLRootElement):
    content_type = 'application/xcap-caps+xml'
    _xml_tag = 'xcap-caps'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication
    _xml_schema_file = 'xcap-caps.xsd'
    _xml_children_order = {AUIDS.qname: 0,
                           Extensions.qname: 1,
                           Namespaces.qname: 2}

    auids = XMLElementChild('auids', type=AUIDS, required=True, test_equal=True)
    extensions = XMLElementChild('extensions', type=Extensions, required=False, test_equal=True)
    namespaces = XMLElementChild('namespaces', type=Namespaces, required=True, test_equal=True)

    def __init__(self, auids=[], extensions=[], namespaces=[]):
        XMLRootElement.__init__(self)
        self.auids = AUIDS(auids)
        self.extensions = Extensions(extensions)
        self.namespaces = Namespaces(namespaces)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.auids, self.extensions, self.namespaces)

    __str__ = __repr__



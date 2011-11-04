# Copyright (C) 2010-2011 AG Projects. See LICENSE for details
#


"""Support for parsing and building xcap-caps documents, as defined by RFC4825."""


__all__ = ['XCAPCapabilitiesApplication', 'AUIDS', 'Extensions', 'Namespaces', 'XCAPCapabilities']


from sipsimple.payloads import XMLApplication, XMLElementChild, XMLListElement, XMLRootElement, XMLStringElement


namespace = 'urn:ietf:params:xml:ns:xcap-caps'


class XCAPCapabilitiesApplication(XMLApplication): pass
XCAPCapabilitiesApplication.register_namespace(namespace, prefix=None)


## Elements

class AUID(XMLStringElement):
    _xml_tag = 'auid'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication


class AUIDS(XMLListElement):
    _xml_tag = 'auids'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication
    _xml_item_type = AUID

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self.update(children)

    def __iter__(self):
        return (unicode(item) for item in super(AUIDS, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            item = AUID(item)
        super(AUIDS, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            try:
                item = (entry for entry in super(AUIDS, self).__iter__() if entry == item).next()
            except StopIteration:
                raise KeyError(item)
        super(AUIDS, self).remove(item)


class Extension(XMLStringElement):
    _xml_tag = 'extension'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication


class Extensions(XMLListElement):
    _xml_tag = 'extensions'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication
    _xml_item_type = Extension

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self.update(children)

    def __iter__(self):
        return (unicode(item) for item in super(Extensions, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            item = Extension(item)
        super(Extensions, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            try:
                item = (entry for entry in super(Extensions, self).__iter__() if entry == item).next()
            except StopIteration:
                raise KeyError(item)
        super(Extensions, self).remove(item)


class Namespace(XMLStringElement):
    _xml_tag = 'extension'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication


class Namespaces(XMLListElement):
    _xml_tag = 'namespaces'
    _xml_namespace = namespace
    _xml_application = XCAPCapabilitiesApplication
    _xml_item_type = Namespace

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self.update(children)

    def __iter__(self):
        return (unicode(item) for item in super(Namespaces, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            item = Namespace(item)
        super(Namespaces, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            try:
                item = (entry for entry in super(Namespaces, self).__iter__() if entry == item).next()
            except StopIteration:
                raise KeyError(item)
        super(Namespaces, self).remove(item)


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




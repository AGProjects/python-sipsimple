# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and builds application/rls-services+xml documents according to
RFC4826.
"""

import urllib

from sipsimple.payloads import ValidationError, XMLListRootElement, XMLElement, XMLListElement, XMLStringElement, XMLAttribute, XMLElementChild, XMLElementChoiceChild
from sipsimple.payloads.resourcelists import namespace as rl_namespace, List, ResourceListsApplication

__all__ = ['rl_namespace',
           'rls_namespace',
           'RLSServicesApplication',
           'Package',
           'Packages',
           'ResourceList',
           'RLSList',
           'Service',
           'RLSServices']


rls_namespace = 'urn:ietf:params:xml:ns:rls-services'


class RLSServicesApplication(ResourceListsApplication): pass
RLSServicesApplication.register_namespace(rls_namespace, prefix=None)

## Marker mixins

class PackagesElement(object): pass


## Elements

class Package(XMLStringElement, PackagesElement):
    _xml_tag = 'package'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication
    _xml_lang = False


class Packages(XMLListElement):
    _xml_tag = 'packages'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication
    _xml_children_order = {Package.qname: 0}

    def __init__(self, packages=[]):
        XMLListElement.__init__(self)
        self[:] = packages

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag, None)
            if child_cls is not None and issubclass(child_cls, PackagesElement):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    
    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, PackagesElement):
            if isinstance(value, XMLElement):
                raise TypeError("expected PackagesElement instace, got %s instead" % value.__class__.__name__)
            value = Package(value)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


class ResourceList(XMLElement):
    _xml_tag = 'resource-list'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication

    def __init__(self, value):
        XMLElement.__init__(self)
        self.value = value

    def _parse_element(self, element, *args, **kw):
        self.value = urllib.unquote(element.text).decode('utf-8')

    def _build_element(self, *args, **kw):
        self.element.text = urllib.quote(self.value.encode('utf-8'))

    def _get_value(self):
        return self.__dict__['value']

    def _set_value(self, value):
        self.__dict__['value'] = unicode(value)

    value = property(_get_value, _set_value)
    del _get_value, _set_value


# This is identical to the list element in resourcelists, accept for the
# namespace. We'll redefine the xml tag just for readability purposes.
class RLSList(List):
    _xml_tag = 'list'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication


class Service(XMLElement):
    _xml_tag = 'service'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication
    _xml_children_order = {RLSList.qname: 0,
                           ResourceList.qname: 0,
                           Packages.qname: 1}

    uri = XMLAttribute('uri', type=str, required=True, test_equal=True)
    list = XMLElementChoiceChild('list', types=(ResourceList, RLSList), required=True, test_equal=True)
    packages = XMLElementChild('packages', type=Packages, required=False, test_equal=True)
    _xml_id = uri
    
    def __init__(self, uri, list=RLSList(), packages=Packages()):
        XMLElement.__init__(self)
        self.uri = uri
        self.list = list
        self.packages = packages

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.uri, self.list, self.packages)

    __str__ = __repr__


class RLSServices(XMLListRootElement):
    content_type = 'application/rls-services+xml'

    _xml_tag = 'rls-services'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication
    _xml_children_order = {Service.qname: 0}
    _xml_schema_file = 'rlsservices.xsd'

    def __init__(self, services=[]):
        XMLListRootElement.__init__(self)
        self._services = {}
        self[:] = services

    def _parse_element(self, element, *args, **kwargs):
        self._services = {}
        for child in element:
            if child.tag == Service.qname:
                try:
                    service = Service.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    if service in self:
                        element.remove(child)
                        continue
                    self._services[service.uri] = service
                    list.append(self, service)
    
    def _build_element(self, *args, **kwargs):
        for service in self:
            service.to_element(*args, **kwargs)

    def _add_item(self, service):
        if not isinstance(service, Service):
            raise TypeError("found %s, expected %s" % (service.__class__.__name__, Service.__name__))
        if service.uri in self._services:
            raise ValueError("cannot have more than one service with the same uri: %s" % service.uri)
        self._services[service.uri] = service
        self._insert_element(service.element)
        return service
    
    def _del_item(self, service):
        del self._services[service.uri]
        self.element.remove(service.element)

    # it also makes sense to be able to get a Service by its uri
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._services[key]
        else:
            return super(RLSServices, self).__getitem__(key)



# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and builds application/rls-services+xml documents according to
RFC4826.

See RLSServices class for more information.

>>> buddies = Service('sip:mybuddies@example.com', 'http://xcap.example.com/xxx', ['presence'])
>>> marketing = Service('sip:marketing@example.com')
>>> marketing.list = RLSList([Entry('sip:joe@example.com'), Entry('sip:sudhir@example.com')])
>>> marketing.packages = ['presence']
>>> rls = RLSServices([buddies, marketing])
>>> print rls.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<rls-services xmlns:rl="urn:ietf:params:xml:ns:resource-lists" xmlns="urn:ietf:params:xml:ns:rls-services">
  <service uri="sip:mybuddies@example.com">
    <resource-list>http://xcap.example.com/xxx</resource-list>
    <packages>
      <package>presence</package>
    </packages>
  </service>
  <service uri="sip:marketing@example.com">
    <list>
      <rl:entry uri="sip:joe@example.com"/>
      <rl:entry uri="sip:sudhir@example.com"/>
    </list>
    <packages>
      <package>presence</package>
    </packages>
  </service>
</rls-services>
<BLANKLINE>


>>> rls = RLSServices.parse(example_from_section_4_3_rfc)
>>> len(rls)
2

>>> rls[0].uri
'sip:mybuddies@example.com'

>>> print rls[0].list
http://xcap.example.com/xxx

>>> print rls[0].packages[0]
presence


>>> rls[1].uri
'sip:marketing@example.com'

>>> assert len(rls[1].packages) == 1 and rls[1].packages[0] == 'presence'

"""

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

# excerpt from the RFC:

# <rls-services>
# body: sequence of <service> elements

# <service>
# attribute "uri": mandatory, unique among all <service> in any document
# body: List or ResourceList, then optional Packages

# <resource-list>
# body: http uri that references <list>

# <packages>
# body: sequence of <package>

# <package>
# body: name of SIP event package


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


class ResourceList(XMLStringElement):
    _xml_tag = 'resource-list'
    _xml_namespace = rls_namespace
    _xml_application = RLSServicesApplication
    _xml_lang = False


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



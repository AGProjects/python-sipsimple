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

>>> assert rls[1].packages == ['presence']

"""

from lxml import etree

from pypjua.applications import XMLMeta, XMLApplication, XMLElement, XMLListElement, XMLStringElement
from pypjua.applications.resourcelists import _namespace_ as _rl_namespace_, List, ResourceListsMeta

__all__ = ['_rl_namespace_',
           '_rls_namespace_',
           'RLSServicesMeta',
           'Package',
           'Packages',
           'ResourceList',
           'RLSList',
           'Service',
           'RLSServices']


_rls_namespace_ = 'urn:ietf:params:xml:ns:rls-services'

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


class RLSServicesMeta(ResourceListsMeta): pass

class Package(XMLStringElement):
    _xml_tag = 'package'
    _xml_namespace = _rls_namespace_
    _xml_meta = RLSServicesMeta
    _xml_lang = False

RLSServicesMeta.register(Package)

class Packages(XMLListElement):
    _xml_tag = 'packages'
    _xml_namespace = _rls_namespace_
    _xml_meta = RLSServicesMeta

    def __init__(self, packages=[]):
        self[:] = packages

    def _parse_element(self, element):
        for child in element:
            if child.tag == Package.qname:
                self.append(Package.from_element(child))
    
    def _build_element(self, element, nsmap):
        for package in self:
            package.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, package):
        if not isinstance(package, Package):
            package = Package(package)
        return package

RLSServicesMeta.register(Packages)

class ResourceList(XMLStringElement):
    _xml_tag = 'resource-list'
    _xml_namespace = _rls_namespace_
    _xml_meta = RLSServicesMeta
    _xml_lang = False

RLSServicesMeta.register(ResourceList)

# This is identical to the list element in resourcelists, accept for the
# namespace. We'll redefine the xml tag just for readability purposes.
class RLSList(List):
    _xml_tag = 'list'
    _xml_namespace = _rls_namespace_
    _xml_meta = RLSServicesMeta

RLSServicesMeta.register(RLSList)

class Service(XMLElement):
    _xml_tag = 'service'
    _xml_namespace = _rls_namespace_
    _xml_attrs = {'uri': {'id_attribute': True}}
    _xml_meta = RLSServicesMeta
    
    def __init__(self, uri, list=RLSList(), packages=Packages()):
        self.uri = uri
        self.list = list
        self.packages = packages

    def _get_list(self):
        return self.__list
    
    def _set_list(self, list):
        if isinstance(list, (RLSList, ResourceList)):
            self.__list = list
        else:
            # we'll simply add a ResourceList
            self.__list = ResourceList(list)

    list = property(_get_list, _set_list)
    del _get_list, _set_list

    def _get_packages(self):
        return self.__packages

    def _set_packages(self, packages):
        if isinstance(packages, Packages):
            self.__packages = packages
        else:
            self.__packages = Packages(packages)

    packages = property(_get_packages, _set_packages)
    del _get_packages, _set_packages

    def _parse_element(self, element):
        for child in element:
            if child.tag == RLSList.qname:
                self.list = RLSList.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == ResourceList.qname:
                self.list = ResourceList.from_element(child)
            elif child.tag == Packages.qname:
                self.packages = Packages.from_element(child)

    def _build_element(self, element, nsmap):
        self.list.to_element(parent=element, nsmap=nsmap)
        self.packages.to_element(parent=element, nsmap=nsmap)

class RLSServices(XMLApplication, XMLListElement):
    accept_types = ['application/rls-services+xml']
    build_types = ['application/rls-services+xml']

    _xml_tag = 'rls-services'
    _xml_namespace = _rls_namespace_
    _xml_schema_file = 'rlsservices.xsd'
    _xml_nsmap = {
            None: _rls_namespace_,
            'rl': _rl_namespace_}
    _xml_meta = RLSServicesMeta

    _parser_opts = {'remove_blank_text': True}

    def __init__(self, services=[]):
        self[:] = services

    def _parse_element(self, element):
        for child in element:
            if child.tag == Service.qname:
                self.append(Service.from_element(child, xml_meta=self._xml_meta))
    
    def _build_element(self, element, nsmap):
        for service in self:
            service.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, service):
        if not isinstance(service, Service):
            raise TypeError("found %s, expected %s" % (service.__class__.__name__, Service.__name__))
        return service

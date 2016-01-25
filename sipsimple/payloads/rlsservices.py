
"""RFC4826 compliant parser/builder for application/rls-services+xml documents."""


__all__ = ['namespace',
           'RLSServicesDocument',
           'Packages',
           'ResourceList',
           'List',
           'Service',
           'RLSServices']


from sipsimple.payloads import XMLListRootElement, XMLElement, XMLListElement, XMLStringElement, XMLAnyURIElement, XMLElementID, XMLElementChild, XMLElementChoiceChild
from sipsimple.payloads import IterateIDs, IterateItems, All
from sipsimple.payloads import resourcelists
from sipsimple.payloads.datatypes import AnyURI


namespace = 'urn:ietf:params:xml:ns:rls-services'


class RLSServicesDocument(resourcelists.ResourceListsDocument):
    content_type = 'application/rls-services+xml'

RLSServicesDocument.register_namespace(namespace, prefix=None, schema='rlsservices.xsd')

## Marker mixins

class PackagesElement(object): pass


## Elements

class Package(XMLStringElement):
    _xml_tag = 'package'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument


class Packages(XMLListElement):
    _xml_tag = 'packages'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument
    _xml_children_order = {Package.qname: 0}
    _xml_item_type = (Package, PackagesElement)

    def __init__(self, packages=[]):
        XMLListElement.__init__(self)
        self.update(packages)

    def __iter__(self):
        return (unicode(item) if type(item) is Package else item for item in super(Packages, self).__iter__())

    def add(self, item):
        if isinstance(item, basestring):
            item = Package(item)
        super(Packages, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            package = Package(item)
            try:
                item = (entry for entry in super(Packages, self).__iter__() if entry == package).next()
            except StopIteration:
                raise KeyError(item)
        super(Packages, self).remove(item)


class ResourceList(XMLAnyURIElement):
    _xml_tag = 'resource-list'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument


# This is identical to the list element in resourcelists, except for the
# namespace. We'll redefine the xml tag just for readability purposes.
class List(resourcelists.List):
    _xml_tag = 'list'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument


class Service(XMLElement):
    _xml_tag = 'service'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument
    _xml_children_order = {List.qname: 0,
                           ResourceList.qname: 0,
                           Packages.qname: 1}

    uri = XMLElementID('uri', type=AnyURI, required=True, test_equal=True)
    list = XMLElementChoiceChild('list', types=(ResourceList, List), required=True, test_equal=True)
    packages = XMLElementChild('packages', type=Packages, required=False, test_equal=True)

    def __init__(self, uri, list=None, packages=None):
        XMLElement.__init__(self)
        self.uri = uri
        self.list = list if list is not None else List()
        self.packages = packages if packages is not None else Packages()

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.uri, self.list, self.packages)


class RLSServices(XMLListRootElement):
    _xml_tag = 'rls-services'
    _xml_namespace = namespace
    _xml_document = RLSServicesDocument
    _xml_children_order = {Service.qname: 0}
    _xml_item_type = Service

    def __init__(self, services=[]):
        XMLListRootElement.__init__(self)
        self.update(services)

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[Service].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[Service].itervalues()
        else:
            return self._xmlid_map[Service][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[Service].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[Service][key])

    def get(self, key, default=None):
        return self._xmlid_map[Service].get(key, default)



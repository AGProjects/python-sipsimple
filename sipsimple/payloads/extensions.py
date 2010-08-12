# Copyright (C) 2010 AG Projects. See LICENSE for details.
#

"""
Proprietary extensions to IETF and OMA defined documents.
"""

__all__ = ['rl_namespace', 'EntryAttributes']

from lxml import etree

from sipsimple.payloads import XMLElement
from sipsimple.payloads.resourcelists import Entry, EntryExtension, ResourceListsApplication


rl_namespace = 'urn:ag-projects:xml:ns:resource-lists'
ResourceListsApplication.register_namespace(rl_namespace, prefix='agp-rl')


class EntryAttributes(XMLElement, EntryExtension):
    _xml_tag = 'attributes'
    _xml_namespace = rl_namespace
    _xml_application = ResourceListsApplication

    def __init__(self, attributes={}):
        XMLElement.__init__(self)
        self._attributes = dict()
        self.update(attributes)

    def _parse_element(self, element, *args, **kwargs):
        self._attributes = dict()
        for child in element:
            if child.tag == '{%s}attribute' % self._xml_namespace:
                try:
                    self[child.attrib['name']] = child.attrib['value']
                except:
                    pass

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        for key in self:
            child = etree.SubElement(self.element, '{%s}attribute' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            child.attrib['name'] = key
            child.attrib['value'] = self[key]

    def __contains__(self, key):
        return key in self._attributes

    def __iter__(self):
        return iter(self._attributes)

    def __getitem__(self, key):
        return self._attributes[key]

    def __setitem__(self, key, value):
        self._attributes[key] = value

    def __delitem__(self, key):
        del self._attributes[key]

    def clear(self):
        self._attributes.clear()

    def get(self, key, default=None):
        return self._attributes.get(key, default)

    def has_key(self, key):
        return key in self._attributes

    def items(self):
        return self._attributes.items()

    def iteritems(self):
        return self._attributes.iteritems()

    def iterkeys(self):
        return self._attributes.iterkeys()

    def itervalues(self):
        return self._attributes.itervalues()

    def keys(self):
        return self._attributes.keys()

    def pop(self, key, *args):
        return self._attributes.pop(key, *args)

    def popitem(self):
        return self._attributes.popitem()

    def setdefault(self, key, default=None):
        return self._attributes.setdefault(key, default)

    def update(self, attributes):
        self._attributes.update(attributes)

Entry.register_extension('attributes', EntryAttributes)



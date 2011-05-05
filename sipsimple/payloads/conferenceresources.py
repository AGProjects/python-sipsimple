# Copyright (C) 2011 AG Projects. See LICENSE for details.
#

"""
Custom extensions to RFC 4575 to add a list of resources to the conference descriptuion
"""

__all__ = ['namespace', 'FileResource', 'FileResources', 'Resources']

from sipsimple.payloads import ValidationError, XMLAttribute, XMLElement, XMLElementChild, XMLListElement
from sipsimple.payloads.conference import ConferenceApplication, ConferenceDescription, ConferenceDescriptionExtension


namespace = 'urn:ag-projects:xml:ns:conference-info'
ConferenceApplication.register_namespace(namespace, prefix='agp-conf')


class FileResource(XMLElement):
    _xml_tag = 'file'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    name = XMLAttribute('name', type=unicode, required=True, test_equal=False)
    hash = XMLAttribute('hash', type=str, required=True, test_equal=False)
    size = XMLAttribute('size', type=int, required=True, test_equal=False)
    sender = XMLAttribute('sender', type=str, required=True, test_equal=False)
    status = XMLAttribute('status', type=str, required=True, test_equal=False)

    def __init__(self, name, hash, size, sender, status):
        XMLElement.__init__(self)
        self.name = name
        self.hash = hash
        self.size = size
        self.sender = sender
        self.status = status

class FileResources(XMLListElement):
    _xml_tag = 'files'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    def __init__(self, files=[]):
        XMLListElement.__init__(self)
        self[0:0] = files

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is FileResource:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, FileResource):
            raise TypeError("Element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Resources(XMLElement, ConferenceDescriptionExtension):
    _xml_tag = 'resources'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    files = XMLElementChild('files', type=FileResources, required=False, test_equal=True)

    def __init__(self, files=None):
        XMLElement.__init__(self)
        self.files = files

ConferenceDescription.register_extension('resources', Resources)


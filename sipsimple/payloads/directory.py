# Copyright (C) 2009 AG Projects. See LICENSE for details.
#

"""Parses xcap-directory messages according to OMA TS XDM Core 1.1"""


__all__ = ['namespace', 'XCAPDirectoryApplication', 'Folder', 'Entry', 'ErrorCode']


from sipsimple.payloads import ValidationError, XMLApplication, XMLListRootElement, XMLStringElement, XMLListElement, XMLAttribute
from sipsimple.util import Timestamp


namespace = 'urn:oma:xml:xdm:xcap-directory'


class XCAPDirectoryApplication(XMLApplication): pass
XCAPDirectoryApplication.register_namespace(namespace, prefix=None)


# Attribute value types
class SizeValue(int):
    def __new__(cls, value):
        value = int.__new__(cls, value)
        if value <= 0:
            raise ValueError("illegal value for size")
        return value


# Elements
class Entry(XMLStringElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_application = XCAPDirectoryApplication

    uri = XMLAttribute('uri', type=str, required=True, test_equal=True)
    etag = XMLAttribute('etag', type=str, required=True, test_equal=True)
    last_modified = XMLAttribute('last_modified', xmlname='last-modified', type=Timestamp, required=False, test_equal=True)
    size = XMLAttribute('size', type=SizeValue, required=False, test_equal=True)

class ErrorCode(XMLStringElement):
    _xml_tag = 'error-code'
    _xml_namespace = namespace
    _xml_application = XCAPDirectoryApplication

class Folder(XMLListElement):
    _xml_tag = 'folder'
    _xml_namespace = namespace
    _xml_application = XCAPDirectoryApplication
    _xml_children_order = {Entry.qname: 0,
                           ErrorCode.qname: 1}

    auid = XMLAttribute('auid', type=str, required=True, test_equal=True)

    def __init__(self, auid, folder=[]):
        XMLListElement.__init__(self)
        self.auid = auid
        self[0:0] = folder

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (child_cls is Entry or child_cls is ErrorCode):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, (Entry, ErrorCode)):
            raise TypeError("Folder element can only contain Entry or ErrorCode children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


class XCAPDirectory(XMLListRootElement):
    content_type = "application/vnd.oma.xcap-directory+xml"

    _xml_tag = 'xcap-directory'
    _xml_namespace = namespace
    _xml_application = XCAPDirectoryApplication
    _xml_schema_file = 'xcap-directory.xsd'

    def __init__(self, folders=[]):
        XMLListRootElement.__init__(self)
        self[0:0] = folders

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is Folder:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, Folder):
            raise TypeError("xcap-directory can only contain Folder children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


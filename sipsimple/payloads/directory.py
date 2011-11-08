# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""Parses xcap-directory messages according to OMA TS XDM Core 1.1"""


__all__ = ['namespace', 'XCAPDirectoryApplication', 'Folder', 'Entry', 'ErrorCode']


from sipsimple.payloads import XMLApplication, XMLListRootElement, XMLStringElement, XMLListElement, XMLAttribute, XMLElementChild
from sipsimple.util import Timestamp


namespace = 'urn:oma:xml:xdm:xcap-directory'


class XCAPDirectoryApplication(XMLApplication): pass
XCAPDirectoryApplication.register_namespace(namespace, prefix=None, schema='xcap-directory.xsd')


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
    _xml_item_type = Entry

    auid = XMLAttribute('auid', type=str, required=True, test_equal=True)
    error_code = XMLElementChild('error_code', type=ErrorCode, retuired=False, test_equal=True, onset=lambda self, descriptor, value: self.clear() if value is not None else None)

    def __init__(self, auid, entries=[], error_code=None):
        if error_code is not None and entries:
            raise ValueError("Cannot set both an error code and add entries at the same time")
        XMLListElement.__init__(self)
        self.auid = auid
        self.error_code = error_code
        self.update(entries)

    def add(self, entry):
        if self.error_code is not None:
            raise ValueError("Cannot add an entry when error_code is set")
        super(Folder, self).add(entry)


class XCAPDirectory(XMLListRootElement):
    content_type = "application/vnd.oma.xcap-directory+xml"

    _xml_tag = 'xcap-directory'
    _xml_namespace = namespace
    _xml_application = XCAPDirectoryApplication
    _xml_item_type = Folder

    def __init__(self, folders=[]):
        XMLListRootElement.__init__(self)
        self.update(folders)



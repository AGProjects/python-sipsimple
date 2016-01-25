
"""
This module allows parsing and building xcap-diff documents according to
RFC 5874.
"""


__all__ = ['namespace', 'XCAPDiffDocument', 'BodyNotChanged', 'Document', 'Element', 'Attribute', 'XCAPDiff']


from sipsimple.payloads import XMLDocument, XMLElement, XMLListRootElement, XMLStringElement, XMLEmptyElement, XMLAttribute, XMLElementID, XMLElementChild
from sipsimple.payloads.datatypes import Boolean, XCAPURI


namespace = 'urn:ietf:params:xml:ns:xcap-diff'


class XCAPDiffDocument(XMLDocument):
    content_type = 'application/xcap-diff+xml'

XCAPDiffDocument.register_namespace(namespace, prefix=None, schema='xcapdiff.xsd')


class BodyNotChanged(XMLEmptyElement):
    _xml_tag = 'body-not-changed'
    _xml_namespace = namespace
    _xml_document = XCAPDiffDocument


class Document(XMLElement):
    _xml_tag = 'document'
    _xml_namespace = namespace
    _xml_document = XCAPDiffDocument

    selector = XMLElementID('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    new_etag = XMLAttribute('new_etag', xmlname='new-etag', type=str, required=False, test_equal=True)
    previous_etag = XMLAttribute('previous_etag', xmlname='previous-etag', type=str, required=False, test_equal=True)
    body_not_changed = XMLElementChild('body_not_changed', type=BodyNotChanged, required=False, test_equal=True)

    def __init__(self, selector, new_etag=None, previous_etag=None):
        XMLElement.__init__(self)
        self.selector = selector
        self.new_etag = new_etag
        self.previous_etag = previous_etag

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.selector, self.new_etag, self.previous_etag)

    def _get_empty_body(self):
        return self.body_not_changed is not None

    def _set_empty_body(self, body_not_changed):
        if body_not_changed:
            self.body_not_changed = BodyNotChanged()
        else:
            self.body_not_changed = None
    empty_body = property(_get_empty_body, _set_empty_body)
    del _get_empty_body, _set_empty_body


class Element(XMLElement):
    _xml_tag = 'element'
    _xml_namespace = namespace
    _xml_document = XCAPDiffDocument

    selector = XMLElementID('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    exists = XMLAttribute('exists', type=Boolean, required=False, test_equal=True)

    def __init__(self, selector, exists=None):
        XMLElement.__init__(self)
        self.selector = selector
        self.exists = exists

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.selector, self.exists)


class Attribute(XMLStringElement):
    _xml_tag = 'attribute'
    _xml_namespace = namespace
    _xml_document = XCAPDiffDocument

    selector = XMLElementID('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    exists = XMLAttribute('exists', type=Boolean, required=False, test_equal=True)

    def __init__(self, selector, exists=None):
        XMLStringElement.__init__(self)
        self.selector = selector
        self.exists = exists

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.selector, self.exists)


class XCAPDiff(XMLListRootElement):
    _xml_tag = 'xcap-diff'
    _xml_namespace = namespace
    _xml_document = XCAPDiffDocument
    _xml_item_type = (Document, Element, Attribute)

    xcap_root = XMLElementID('xcap_root', xmlname='xcap-root', type=str, required=True, test_equal=True)

    def __init__(self, xcap_root, children=[]):
        XMLListRootElement.__init__(self)
        self.xcap_root = xcap_root
        self.update(children)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.xcap_root, list(self))



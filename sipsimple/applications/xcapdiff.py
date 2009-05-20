# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
This module allows parsing and building xcap-diff documents according to
draft-ietf-simple-xcap-diff.
"""

from sipsimple.applications import XMLApplication, XMLElement, XMLListRootElement, XMLStringElement, XMLEmptyElement, XMLAttribute, XMLElementChild
from sipsimple.applications.util import XCAPURI, Boolean

__all__ = ['_namespace_', 'XCAPDiffApplication', 'BodyNotChanged', 'Document', 'Element', 'Attribute', 'XCAPDiff']


_namespace_ = 'urn:ietf:params:xml:ns:xcap-diff'

class XCAPDiffApplication(XMLApplication): pass
XCAPDiffApplication.register_namespace(_namespace_, prefix=None)


class BodyNotChanged(XMLEmptyElement):
    _xml_tag = 'body-not-changed'
    _xml_namespace = _namespace_
    _xml_application = XCAPDiffApplication


class Document(XMLElement):
    _xml_tag = 'document'
    _xml_namespace = _namespace_
    _xml_application = XCAPDiffApplication

    selector = XMLAttribute('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    new_etag = XMLAttribute('new_etag', xmlname='new-etag', type=str, required=False, test_equal=True)
    previous_etag = XMLAttribute('previous_etag', xmlname='previous-etag', type=str, required=False, test_equal=True)
    body_not_changed = XMLElementChild('body_not_changed', type=BodyNotChanged, required=False, test_equal=True)
    _xml_id = selector

    def __init__(self, selector, new_etag=None, previous_etag=None):
        XMLElement.__init__(self)
        self.selector = selector
        self.new_etag = new_etag
        self.previous_etag = previous_etag

    def _parse_element(self, element, *args, **kwargs):
        pass

    def _build_element(self, *args, **kwargs):
        pass

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.selector, self.new_etag, self.previous_etag)

    __str__ = __repr__

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
    _xml_namespace = _namespace_
    _xml_application = XCAPDiffApplication

    selector = XMLAttribute('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    exists = XMLAttribute('exists', type=Boolean, required=False, test_equal=True)
    _xml_id = selector

    def __init__(self, selector, exists=None):
        XMLElement.__init__(self)
        self.selector = selector
        self.exists = exists

    def _parse_element(self, element, *args, **kwargs):
        pass

    def _build_element(self, *args, **kwargs):
        pass

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.selector, self.exists)

    __str__ = __repr__


class Attribute(XMLStringElement):
    _xml_tag = 'attribute'
    _xml_namespace = _namespace_
    _xml_application = XCAPDiffApplication

    selector = XMLAttribute('selector', xmlname='sel', type=XCAPURI, required=True, test_equal=True)
    exists = XMLAttribute('exists', type=Boolean, required=False, test_equal=True)
    _xml_id = selector
    
    def __init__(self, selector, exists=None):
        XMLStringElement.__init__(self)
        self.selector = selector
        self.exists = exists

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.selector, self.exists)

    __str__ = __repr__


class XCAPDiff(XMLListRootElement):
    content_type = 'application/xcap-diff+xml'

    _xml_tag = 'xcap-diff'
    _xml_namespace = _namespace_
    _xml_application = XCAPDiffApplication

    xcap_root = XMLAttribute('xcap_root', xmlname='xcap-root', type=str, required=True, test_equal=True)
    _xml_id = xcap_root

    def __init__(self, xcap_root, children=[]):
        XMLListRootElement.__init__(self)
        self.xcap_root = xcap_root
        self[:] = children

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == Document.qname:
                list.append(self, Document.from_element(child, *args, **kwargs))
            elif child.tag == Element.qname:
                list.append(self, Element.from_element(child, *args, **kwargs))
            elif child.tag == Attribute.qname:
                list.append(self, Attribute.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, (Document, Element, Attribute)):
            raise TypeError("XCAPDiff can only contain Document, Element or Attribute children")
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, [%s])' % (self.__class__.__name__, self.xcap_root, ', '.join('%r' % child for child in self))

    __str__ = __repr__



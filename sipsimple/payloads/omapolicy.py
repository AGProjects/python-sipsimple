# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""
Conditions extension handling according to OMA-TS-XDM_Core-V1_1

This module provides an extension to RFC4745 (Common Policy) to
support condition extensions defined by OMA.
"""

import urllib

from lxml import etree

from sipsimple.payloads import XMLAttribute, XMLElement, XMLEmptyElement, XMLListElement, ValidationError
from sipsimple.payloads.policy import ConditionElement
from sipsimple.payloads.presrules import PresRulesApplication

__all__ = ['OtherIdentity',
           'ExternalList',
           'AnonymousRequest']

oma_cp_namespace = 'urn:oma:xml:xdm:common-policy'
PresRulesApplication.register_namespace(oma_cp_namespace, prefix='ocp')


class OtherIdentity(XMLEmptyElement, ConditionElement):
    _xml_tag = 'other-identity'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication


class ExternalList(XMLListElement, ConditionElement):
    _xml_tag = 'external-list'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self[0:0] = entries

    def _parse_element(self, element, *args, **kw):
        for child in element:
            if child.tag == '{%s}entry' % self._xml_namespace:
                try:
                    self.append(urllib.unquote(child.attrib['anc']).decode('utf-8'))
                except:
                    pass

    def _build_element(self, *args, **kw):
        self.element.clear()
        for entry in self:
            child = etree.SubElement(self.element, '{%s}entry' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            child.attrib['anc'] = urllib.quote(entry.encode('utf-8'))

    def _add_item(self, entry):
        return unicode(entry)


class AnonymousRequest(XMLEmptyElement, ConditionElement):
    _xml_tag = 'anonymous-request'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication


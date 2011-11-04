# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Conditions extension handling according to OMA-TS-XDM_Core-V1_1

This module provides an extension to RFC4745 (Common Policy) to
support condition extensions defined by OMA.
"""


__all__ = ['OtherIdentity', 'ExternalList', 'AnonymousRequest']


from sipsimple.payloads import XMLElement, XMLEmptyElement, XMLListElement, XMLAttribute, uri_attribute_builder, uri_attribute_parser
from sipsimple.payloads.policy import ConditionElement
from sipsimple.payloads.presrules import PresRulesApplication


oma_cp_namespace = 'urn:oma:xml:xdm:common-policy'
PresRulesApplication.register_namespace(oma_cp_namespace, prefix='ocp')


class OtherIdentity(XMLEmptyElement, ConditionElement):
    _xml_tag = 'other-identity'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication


class Entry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication

    uri = XMLAttribute('uri', xmlname='anc', type=unicode, required=True, test_equal=True, parser=uri_attribute_parser, builder=uri_attribute_builder)
    _xml_id = uri

    def __init__(self, uri):
        XMLElement.__init__(self)
        self.uri = uri

    def __unicode__(self):
        return self.uri

    def __str__(self):
        return str(self.uri)


class ExternalList(XMLListElement, ConditionElement):
    _xml_tag = 'external-list'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication
    _xml_item_type = Entry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)

    def __iter__(self):
        return (unicode(item) for item in super(ExternalList, self).__iter__())

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def add(self, item):
        if isinstance(item, basestring):
            item = Entry(item)
        super(ExternalList, self).add(item)

    def remove(self, item):
        if isinstance(item, basestring):
            try:
                item = (entry for entry in super(ExternalList, self).__iter__() if entry == item).next()
            except StopIteration:
                raise KeyError(item)
        super(ExternalList, self).remove(item)


class AnonymousRequest(XMLEmptyElement, ConditionElement):
    _xml_tag = 'anonymous-request'
    _xml_namespace = oma_cp_namespace
    _xml_application = PresRulesApplication


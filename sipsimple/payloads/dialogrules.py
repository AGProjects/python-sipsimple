# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Parses and produces Dialog Authorization Rules documents. As there is no
RFC for this we'll use common-policy format (RFC 4745).

NOTE: Subscription Handling has been taken from RFC 5025.
"""


__all__ = ['cp_namespace', 'dlg_namespace', 'DialogRulesApplication', 'ExternalList', 'SubHandling', 'DialogRules']


from sipsimple.payloads import XMLElementID, XMLElement, XMLListElement, XMLStringElement, uri_attribute_builder, uri_attribute_parser
from sipsimple.payloads.policy import namespace as cp_namespace, CommonPolicyApplication, ActionElement, ConditionElement, RuleSet


dlg_namespace = 'http://openxcap.org/ns/dialog-rules'

class DialogRulesApplication(CommonPolicyApplication): pass
DialogRulesApplication.register_namespace(dlg_namespace, prefix='dr')


## Attribute value types
class SubHandlingValue(str):
    def __new__(cls, value):
        if value not in ('block', 'confirm', 'polite-block', 'allow'):
            raise ValueError("illegal value for SubHandling element")
        return str.__new__(cls, value)


## Action Elements
class SubHandling(XMLStringElement, ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    _xml_lang = False
    _xml_value_type = SubHandlingValue


## Condition Elements
class Entry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication

    uri = XMLElementID('uri', xmlname='anc', type=unicode, required=True, test_equal=True, parser=uri_attribute_parser, builder=uri_attribute_builder)

    def __init__(self, uri):
        XMLElement.__init__(self)
        self.uri = uri

    def __unicode__(self):
        return self.uri

    def __str__(self):
        return str(self.uri)


class ExternalList(XMLListElement, ConditionElement):
    _xml_tag = 'external-list'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
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


class DialogRules(RuleSet):
    _xml_application = DialogRulesApplication


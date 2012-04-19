# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Parses and produces Dialog Authorization Rules documents. As there is no
RFC for this we'll use common-policy format (RFC 4745).

NOTE: Subscription Handling has been taken from RFC 5025.
"""


__all__ = ['cp_namespace', 'dlg_namespace', 'DialogRulesDocument', 'SubHandling', 'DialogRules']


from sipsimple.payloads import omapolicy
from sipsimple.payloads import XMLStringElement
from sipsimple.payloads.policy import namespace as cp_namespace, CommonPolicyDocument, ActionElement, RuleSet


dlg_namespace = 'http://openxcap.org/ns/dialog-rules'


class DialogRulesDocument(CommonPolicyDocument): pass
DialogRulesDocument.register_namespace(dlg_namespace, prefix='dr', schema='dialog-rules.xsd')
DialogRulesDocument.register_namespace(omapolicy.oma_cp_namespace, prefix='ocp', schema='oma-common-policy.xsd')
DialogRulesDocument.register_element(omapolicy.AnonymousRequest)
DialogRulesDocument.register_element(omapolicy.OtherIdentity)
DialogRulesDocument.register_element(omapolicy.Entry)
DialogRulesDocument.register_element(omapolicy.ExternalList)


class SubHandlingValue(str):
    __prioritymap__ = {'block': 0, 'confirm': 10, 'polite-block': 20, 'allow': 30}

    def __new__(cls, value):
        if value not in ('block', 'confirm', 'polite-block', 'allow'):
            raise ValueError("illegal value for SubHandling element")
        return str.__new__(cls, value)

    @property
    def priority(self):
        return self.__prioritymap__[self]


class SubHandling(XMLStringElement, ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = dlg_namespace
    _xml_document = DialogRulesDocument
    _xml_value_type = SubHandlingValue


class DialogRules(RuleSet):
    _xml_document = DialogRulesDocument


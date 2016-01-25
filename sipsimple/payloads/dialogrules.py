
"""
Parses and produces Dialog Authorization Rules documents. As there is no
RFC for this we'll use common-policy format (RFC 4745).

NOTE: Subscription Handling has been taken from RFC 5025.
"""


__all__ = ['namespace', 'DialogRulesDocument', 'SubHandling', 'DialogRules']


from sipsimple.payloads import commonpolicy, omapolicy
from sipsimple.payloads import XMLStringElement


namespace = 'urn:ag-projects:xml:ns:dialog-rules'


class DialogRulesDocument(commonpolicy.CommonPolicyDocument): pass
DialogRulesDocument.register_namespace(namespace, prefix='dr', schema='dialog-rules.xsd')
DialogRulesDocument.register_namespace(omapolicy.namespace, prefix='ocp', schema='oma-common-policy.xsd')
DialogRulesDocument.register_element(omapolicy.AnonymousRequest)
DialogRulesDocument.register_element(omapolicy.OtherIdentity)
DialogRulesDocument.register_element(omapolicy.Entry)
DialogRulesDocument.register_element(omapolicy.ExternalList)


class SubHandlingValue(str):
    __prioritymap__ = {'block': 0, 'confirm': 10, 'polite-block': 20, 'allow': 30}

    def __new__(cls, value):
        if value not in cls.__prioritymap__:
            raise ValueError("illegal value for SubHandling element")
        return str.__new__(cls, value)

    @property
    def priority(self):
        return self.__prioritymap__[self]


class SubHandling(XMLStringElement, commonpolicy.ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = namespace
    _xml_document = DialogRulesDocument
    _xml_value_type = SubHandlingValue


class DialogRules(commonpolicy.RuleSet):
    _xml_document = DialogRulesDocument


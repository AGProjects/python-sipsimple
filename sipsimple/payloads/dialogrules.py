# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and produces Dialog Authorization Rules documents. As there is no
RFC for this we'll use common-policy format (RFC 4745).

NOTE: Subscription Handling has been taken from RFC 5025. 
"""

from sipsimple.payloads import XMLStringElement
from sipsimple.payloads.policy import namespace as cp_namespace, CommonPolicyApplication, ActionElement, RuleSet

__all__ = ['cp_namespace',
           'dlg_namespace',
           'DialogRulesApplication',
           'SubHandling',
           'DialogRules']


dlg_namespace = 'urn:ietf:params:xml:ns:dialog-rules'

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


class DialogRules(RuleSet):
    _xml_application = DialogRulesApplication
    _xml_schema_file = 'common-policy.xsd'
    _xml_nsmap = {'dr': dlg_namespace,
                  'cr': cp_namespace}



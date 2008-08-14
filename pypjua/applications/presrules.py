"""
Parses and produces Presence Authorization Rules documents according to
RFC5025.
"""

from lxml import etree

from pypjua.applications import XMLElementMapping, XMLApplication
from pypjua.applications.policy import _namespace_ as _cp_namespace_, RuleSet

_pr_namespace_ = 'urn:ietf:params:xml:ns:pres-rules'

class PresRules(RuleSet):
    _xml_schema_file = 'pres-rules.xsd'

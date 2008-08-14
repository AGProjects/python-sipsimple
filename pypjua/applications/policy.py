"""
Generic data types to be used in policy applications, according to
RFC475.
"""

from pypjua.applications import XMLElementMapping


_namespace_ = 'urn:ietf:params:xml:ns:common-policy'

class IdentityOne(XMLElementMapping):
    _xml_tag = 'one'
    _xml_namespace = _namespace_
    _xml_attr = {'id': {'id_attribute': True}}

    def __init__(self, id=None):
        self.id = id

class IdentityMany(XMLElementMapping):
    _xml_tag = 'many'
    _xml_namespace = _namespace_
    _xml_attr = {'domain': {'test_equal': False}}

    def __init__(self):
        self._excepts = []


class Identity(XMLElementMapping):
    _xml_tag = 'identity'
    _xml_namespace = _namespace_

    def __init__(self):
        self._one = []
        self._many = []

    def _parse_element(self, element):
        for child in element:
            if child.tag == IndetityOne.tag():
                self._one.append(IdentityOne.from_element(child))
            elif child.tag == IdentityMany.tag():
                self._many.append(IdentityMany.from_element(child))

class Conditions(XMLElementMapping):
    _xml_tag = 'conditions'
    _xml_namespace = _namespace_

    def __init__(self):
        self._conditions = []
    
    def _parse_element(self, element):
        for child in element:
            if child.tag == Identity.tag():
                self._conditions.append(Identity.from_element(child))

class Actions(XMLElementMapping):
    _xml_tag = 'actions'
    _xml_namespace = _namespace_

class Transformations(XMLElementMapping):
    _xml_tag = 'transformations'
    _xml_namespace = _namespace_

class Rule(XMLElementMapping):
    _xml_tag = 'rule'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}

class RuleSet(XMLApplication):
    accept_types = ['application/auth-policy+xml']
    build_types = ['application/auth-policy+xml']
    
    _xml_tag = 'ruleset'
    _xml_namespace = _namespace_

    _parser_opts = {'remove_blank_text': True}

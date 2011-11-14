# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Generic data types to be used in policy applications, according to
RFC4745.
"""


__all__ = ['namespace',
           'CommonPolicyApplication',
           'ConditionElement',
           'ActionElement',
           'TransformationElement',
           'RuleExtension',
           'IdentityOne',
           'IdentityExcept',
           'IdentityMany',
           'Identity',
           'Validity',
           'Conditions',
           'Actions',
           'Transformations',
           'Rule',
           'RuleSet',
           # Extensions
           'FalseCondition',
           'RuleDisplayName']


import datetime

from sipsimple.payloads import ValidationError, XMLApplication, XMLElement, XMLListElement, XMLListRootElement, XMLAttribute, XMLElementID, XMLElementChild, XMLStringElement
from sipsimple.util import Timestamp


namespace = 'urn:ietf:params:xml:ns:common-policy'


class CommonPolicyApplication(XMLApplication): pass
CommonPolicyApplication.register_namespace(namespace, prefix='cp', schema='common-policy.xsd')


## Mixin types for extensibility

class ConditionElement(object): pass
class ActionElement(object): pass
class TransformationElement(object): pass
class RuleExtension(object): pass


## Elements

class IdentityOne(XMLElement):
    _xml_tag = 'one'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    id = XMLElementID('id', type=str, required=True, test_equal=True)

    def __init__(self, id):
        XMLElement.__init__(self)
        self.id = id

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.id)

    def __str__(self):
        return self.id

    def matches(self, uri):
        return self.id == uri


class IdentityExcept(XMLElement):
    _xml_tag = 'except'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def _onset_id(self, attribute, value):
        if value is not None:
            self.domain = None
    id = XMLAttribute('id', type=str, required=False, test_equal=True, onset=_onset_id)
    del _onset_id

    def _onset_domain(self, attribute, value):
        if value is not None:
            self.id = None
    domain = XMLAttribute('domain', type=str, required=False, test_equal=True, onset=_onset_domain)
    del _onset_domain

    def __init__(self, id=None, domain=None):
        XMLElement.__init__(self)
        self.id = id
        self.domain = domain

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.id, self.domain)

    def __str__(self):
        if self.id is not None:
            return self.id
        else:
            return self.domain

    def matches(self, uri):
        if self.id is not None:
            return self.id != uri
        else:
            return [self.domain] != uri.split('@', 1)[1:]


class IdentityMany(XMLListElement):
    _xml_tag = 'many'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_children_order = {IdentityExcept.qname: 0}
    _xml_item_type = IdentityExcept

    domain = XMLAttribute('domain', type=str, required=False, test_equal=True)

    def __init__(self, domain=None, exceptions=[]):
        XMLListElement.__init__(self)
        self.domain = domain
        self.update(exceptions)

    def __repr__(self):
        return '%s(%r, %s)' % (self.__class__.__name__, self.domain, list(self))

    def matches(self, uri):
        if self.domain is not None:
            if self.domain != uri.partition('@')[2]:
                return False
        for child in self:
            if not child.matches(uri):
                return False
        return True


class Identity(XMLListElement):
    _xml_tag = 'identity'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_item_type = (IdentityOne, IdentityMany)

    def __init__(self, identities=[]):
        XMLListElement.__init__(self)
        self.update(identities)

    def matches(self, uri):
        for child in self:
            if child.matches(uri):
                return True
        return False


class Sphere(XMLElement):
    _xml_tag = 'sphere'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    value = XMLAttribute('value', type=str, required=True, test_equal=True)

    def __init__(self, value):
        XMLElement.__init__(self)
        self.value = value

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)


class ValidFrom(XMLElement):
    _xml_tag = 'from'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, timestamp):
        if isinstance(timestamp, (datetime.datetime, str)):
            timestamp = Timestamp(timestamp)
        if not isinstance(timestamp, Timestamp):
            raise TypeError("Validity element can only be a Timestamp, datetime or string")
        XMLElement.__init__(self)
        self.element.text = str(timestamp)


class ValidUntil(XMLElement):
    _xml_tag = 'until'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, timestamp):
        if isinstance(timestamp, (datetime.datetime, str)):
            timestamp = Timestamp(timestamp)
        if not isinstance(timestamp, Timestamp):
            raise TypeError("Validity element can only be a Timestamp, datetime or string")
        XMLElement.__init__(self)
        self.element.text = str(timestamp)


class ValidityInterval(object):
    def __init__(self, from_timestamp, until_timestamp):
        self.valid_from = ValidFrom(from_timestamp)
        self.valid_until = ValidUntil(until_timestamp)

    def __eq__(self, other):
        if isinstance(other, ValidityInterval):
            return self.valid_from.text==other.valid_from.text and self.valid_until.text==other.valid_until.text
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ValidityInterval):
            return self.valid_from.text!=other.valid_from.text or self.valid_until.text!=other.valid_until.text
        return NotImplemented

    @classmethod
    def from_elements(cls, from_element, until_element):
        instance = object.__new__(cls)
        instance.valid_from = ValidFrom.from_element(from_element)
        instance.valid_until = ValidUntil.from_element(until_element)
        return instance


class Validity(XMLListElement):
    _xml_tag = 'validity'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_item_type = ValidityInterval

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self.update(children)

    def _parse_element(self, element, *args, **kwargs):
        iterator = iter(element)
        for first_child in iterator:
            second_child = iterator.next()
            if first_child.tag == '{%s}from' % self._xml_namespace and second_child.tag == '{%s}until' % self._xml_namespace:
                try:
                    item = ValidityInterval.from_elements(first_child, second_child)
                except:
                    pass
                else:
                    self._element_map[item.valid_from.element] = item

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.valid_from.to_element(*args, **kwargs)
            child.valid_until.to_element(*args, **kwargs)

    def add(self, item):
        if not isinstance(item, ValidityInterval):
            raise TypeError("Validity element must be a ValidityInterval instance")
        self._insert_element(item.valid_from.element)
        self._insert_element(item.valid_until.element)
        self._element_map[item.valid_from.element] = item

    def remove(self, item):
        self.element.remove(item.valid_from.element)
        self.element.remove(item.valid_until.element)
        del self._element_map[item.valid_from.element]

    def check_validity(self):
        if not self:
            raise ValidationError("cannot have Validity element without any children")
        XMLListElement.check_validity(self)


class Conditions(XMLListElement):
    _xml_tag = 'conditions'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_children_order = {Identity.qname: 0,
                           Sphere.qname: 1,
                           Validity.qname: 2}
    _xml_item_type = (Identity, Sphere, Validity, ConditionElement)

    def __init__(self, conditions=[]):
        XMLListElement.__init__(self)
        self.update(conditions)


class Actions(XMLListElement):
    _xml_tag = 'actions'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_item_type = ActionElement

    def __init__(self, actions=[]):
        XMLListElement.__init__(self)
        self.update(actions)


class Transformations(XMLListElement):
    _xml_tag = 'transformations'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_item_type = TransformationElement

    def __init__(self, transformations=[]):
        XMLListElement.__init__(self)
        self.update(transformations)


class Rule(XMLElement):
    _xml_tag = 'rule'
    _xml_namespace = namespace
    _xml_extension_type = RuleExtension
    _xml_application = CommonPolicyApplication
    _xml_children_order = {Conditions.qname: 0,
                           Actions.qname: 1,
                           Transformations.qname: 2}

    id = XMLElementID('id', type=unicode, required=True, test_equal=True)

    conditions = XMLElementChild('conditions', type=Conditions, required=False, test_equal=True)
    actions = XMLElementChild('actions', type=Actions, required=False, test_equal=True)
    transformations = XMLElementChild('transformations', type=Transformations, required=False, test_equal=True)

    def __init__(self, id, conditions=None, actions=None, transformations=None):
        XMLElement.__init__(self)
        self.id = id
        self.conditions = conditions
        self.actions = actions
        self.transformations = transformations

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.conditions, self.actions, self.transformations)


class RuleSet(XMLListRootElement):
    content_type = 'application/auth-policy+xml'

    _xml_tag = 'ruleset'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_item_type = Rule

    def __init__(self, rules=[]):
        XMLListRootElement.__init__(self)
        self.update(rules)

    def __getitem__(self, key):
        return self._xmlid_map[Rule][key]

    def __delitem__(self, key):
        self.remove(self._xmlid_map[Rule][key])


#
# Extensions
#

agp_cp_namespace = 'urn:ag-projects:xml:ns:common-policy'
CommonPolicyApplication.register_namespace(agp_cp_namespace, prefix='agp-cp')

# A condition element in the AG Projects namespace, it will always be evaluated to false
# because it's not understood by servers
class FalseCondition(XMLElement, ConditionElement):
    _xml_tag = 'false-condition'
    _xml_namespace = agp_cp_namespace
    _xml_application = CommonPolicyApplication


class RuleDisplayName(XMLStringElement, RuleExtension):
    _xml_tag = 'display-name'
    _xml_namespace = agp_cp_namespace
    _xml_application = CommonPolicyApplication
    _xml_lang = True

Rule.register_extension('display_name', RuleDisplayName)


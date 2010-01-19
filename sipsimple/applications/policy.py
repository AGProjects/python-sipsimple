# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Generic data types to be used in policy applications, according to
RFC4745.

Example usage:

>>> alice = IdentityOne('sip:alice@example.com')
>>> carol = IdentityOne('tel:+1-212-555-1234')
>>> bob = IdentityOne('mailto:bob@example.net')
>>> print carol
tel:+1-212-555-1234
>>> id = Identity([alice, bob])
>>> print id
Identity([IdentityOne('sip:alice@example.com'), IdentityOne('mailto:bob@example.net')])
>>> id[1:1] = [carol]
>>> print id
Identity([IdentityOne('sip:alice@example.com'), IdentityOne('tel:+1-212-555-1234'), IdentityOne('mailto:bob@example.net')])
>>> conditions = Conditions([id])
>>> rule = Rule(id='f3g44r1', conditions=conditions, actions=Actions(), transformations=Transformations())
>>> ruleset = RuleSet()
>>> ruleset.append(rule)
>>> print ruleset.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<cp:ruleset xmlns:cp="urn:ietf:params:xml:ns:common-policy">
  <cp:rule id="f3g44r1">
    <cp:conditions>
      <cp:identity>
        <cp:one id="sip:alice@example.com"/>
        <cp:one id="mailto:bob@example.net"/>
        <cp:one id="tel:+1-212-555-1234"/>
      </cp:identity>
    </cp:conditions>
    <cp:actions/>
    <cp:transformations/>
  </cp:rule>
</cp:ruleset>
<BLANKLINE>

"""

import datetime
from lxml import etree

from sipsimple.applications import ValidationError, XMLApplication, XMLElement, XMLListElement, XMLListRootElement, XMLAttribute, XMLElementChild
from sipsimple.util import Timestamp


__all__ = ['namespace',
           'CommonPolicyApplication',
           'ConditionElement',
           'ActionElement',
           'TransformationElement',
           'IdentityOne',
           'IdentityExcept',
           'IdentityMany',
           'Identity',
           'Validity',
           'Conditions',
           'Actions',
           'Transformations',
           'Rule',
           'RuleSet']


namespace = 'urn:ietf:params:xml:ns:common-policy'


class CommonPolicyApplication(XMLApplication): pass
CommonPolicyApplication.register_namespace(namespace, prefix='cp')


## Mixin types for extensibility

class ConditionElement(object): pass
class ActionElement(object): pass
class TransformationElement(object): pass


## Elements

class IdentityOne(XMLElement):
    _xml_tag = 'one'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    _xml_id = id

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
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True, onset=(lambda self, attr: setattr(self, 'domain', None)))
    domain = XMLAttribute('domain', type=str, required=False, test_equal=True, onset=(lambda self, attr: setattr(self, 'id', None)))

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

    domain = XMLAttribute('domain', type=str, required=False, test_equal=True)

    def __init__(self, domain=None, excepts=[]):
        XMLListElement.__init__(self)
        self.domain = domain
        self[0:0] = excepts

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == IdentityExcept.qname:
                try:
                    list.append(self, IdentityExcept.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, IdentityExcept):
            raise TypeError("Identity elements can only have IdentityExcept children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def matches(self, uri):
        if self.domain is not None:
            if [self.domain] != uri.split('@', 1)[1:]:
                return False
        for child in self:
            if not child.matches(uri):
                return False
        return True

    def __repr__(self):
        return '%s(%r, %s)' % (self.__class__.__name__, self.domain, list.__repr__(self))

    __str__ = __repr__


class Identity(XMLListElement, ConditionElement):
    _xml_tag = 'identity'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, identities=[]):
        XMLListElement.__init__(self)
        self[0:0] = identities

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and issubclass(child_cls, (IdentityOne, IdentityMany)):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, (IdentityOne, IdentityMany)):
            raise TypeError("Identity elements can only have IdentityOne or IdentityMany children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def matches(self, uri):
        for child in self:
            if child.matches(uri):
                return True
        return False


class Sphere(XMLElement, ConditionElement):
    _xml_tag = 'sphere'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    value = XMLAttribute('value', type=str, required=True, test_equal=True)

    def __init__(self, value):
        XMLElement.__init__(self)
        self.value = value

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)

    __str__ = __repr__


class Validity(XMLListElement, ConditionElement):
    _xml_tag = 'validity'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, children=[]):
        XMLListElement.__init__(self)
        self[0:0] = children

    def _parse_element(self, element, *args, **kwargs):
        iterator = iter(element)
        for child in iterator:
            if child.tag == '{%s}from' % self._xml_namespace:
                try:
                    self.append((child.text, iterator.next().text))
                except:
                    pass

    def _build_element(self, *args, **kwargs):
        self.element.clear()
        for child in self:
            from_elem = etree.SubElement(self.element, '{%s}from' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
            until_elem = etree.SubElement(self.element, '{%s}until' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)

    def check_validity(self):
        if not self:
            raise ValidationError("cannot have Validity element without any children")
        XMLListElement.check_validity(self)

    def _add_item(self, (from_valid, until_valid)):
        if isinstance(from_valid, (datetime.datetime, str)):
            from_valid = Timestamp(from_valid)
        if isinstance(until_valid, (datetime.datetime, str)):
            until_valid = Timestamp(until_valid)
        if not isinstance(from_valid, Timestamp) or not isinstance(until_valid, Timestamp):
            raise TypeError("Validity element can only contain Timestamp 2-tuples")
        return (from_valid, until_valid)


class Conditions(XMLListElement):
    _xml_tag = 'conditions'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_children_order = {Identity.qname: 0,
                           Sphere.qname: 1,
                           Validity.qname: 2}

    def __init__(self, conditions=[]):
        XMLListElement.__init__(self)
        self[0:0] = conditions
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and issubclass(child_cls, ConditionElement):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, ConditionElement):
            raise TypeError("Conditions element can only contain ConditionElement children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


class Actions(XMLListElement):
    _xml_tag = 'actions'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, actions=[]):
        XMLListElement.__init__(self)
        self[0:0] = actions

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and issubclass(child_cls, ActionElement):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, ActionElement):
            raise TypeError("Actions element can only contain ActionElement children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


class Transformations(XMLListElement):
    _xml_tag = 'transformations'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication

    def __init__(self, transformations=[]):
        XMLListElement.__init__(self)
        self[0:0] = transformations
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and issubclass(child_cls, TransformationElement):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, TransformationElement):
            raise TypeError("Transformations element can only contain TransformationElement children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)


class Rule(XMLElement):
    _xml_tag = 'rule'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_children_order = {Conditions.qname: 0,
                           Actions.qname: 1,
                           Transformations.qname: 2}

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    conditions = XMLElementChild('conditions', type=Conditions, required=False, test_equal=True)
    actions = XMLElementChild('actions', type=Actions, required=False, test_equal=True)
    transformations = XMLElementChild('transformations', type=Transformations, required=False, test_equal=True)
    _xml_id = id

    def __init__(self, id, conditions=None, actions=None, transformations=None):
        XMLElement.__init__(self)
        self.id = id
        self.conditions = conditions
        self.actions = actions
        self.transformations = transformations

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.conditions, self.actions, self.transformations)

    __str__ = __repr__


class RuleSet(XMLListRootElement):
    content_type = 'application/auth-policy+xml'
    
    _xml_tag = 'ruleset'
    _xml_namespace = namespace
    _xml_application = CommonPolicyApplication
    _xml_schema_file = 'common-policy.xsd'

    def __init__(self, rules=[]):
        XMLListRootElement.__init__(self)
        self._rules = {}
        self[0:0] = rules

    def _parse_element(self, element, *args, **kwargs):
        self._rules = {}
        for child in element:
            if child.tag == Rule.qname:
                rule =  Rule.from_element(child, *args, **kwargs)
                list.append(self, rule)
                if not rule.id in self._rules:
                    self._rules[rule.id] = rule

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, rule):
        if not isinstance(rule, Rule):
            raise TypeError("found %s, expected %s" % (rule.__class__.__name__, Rule.__name__))
        if rule.id in self._rules:
            raise ValueError("Cannot have more than one Rule with the same id: %s" % rule.id)
        self._rules[rule.id] = rule
        self._insert_element(rule.element)
        return rule

    def _del_item(self, rule):
        del self._rules[rule.id]
        self.element.remove(rule.element)

    # it also makes sense to be able to get a Rule by its id
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._rules[key]
        else:
            return super(RuleSet, self).__getitem__(key)



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
['sip:alice@example.com', 'mailto:bob@example.net']
>>> id[1:1] = [carol]
>>> print id
['sip:alice@example.com', 'tel:+1-212-555-1234', 'mailto:bob@example.net']
>>> conditions = Conditions([id])
>>> rule = Rule(id='f3g44r1', conditions=conditions, actions=Actions(), transformations=Transformations())
>>> ruleset = RuleSet()
>>> ruleset.append(rule)
>>> print ruleset.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<ruleset xmlns="urn:ietf:params:xml:ns:common-policy">
  <rule id="f3g44r1">
    <conditions>
      <identity>
        <one id="sip:alice@example.com"/>
        <one id="tel:+1-212-555-1234"/>
        <one id="mailto:bob@example.net"/>
      </identity>
    </conditions>
    <actions/>
    <transformations/>
  </rule>
</ruleset>
<BLANKLINE>

"""

from pypjua.applications import XMLMeta, XMLElement, XMLListElement, XMLStringElement, XMLApplication

__all__ = ['_namespace_',
           'ConditionElement',
           'ActionElement',
           'TransformationElement',
           'IdentityOne',
           'IdentityExcept',
           'IdentityMany',
           'Identity',
           'ValidityFrom',
           'ValidityUntil',
           'Validity',
           'Conditions',
           'Actions',
           'Transformations',
           'Rule',
           'RuleSet']


_namespace_ = 'urn:ietf:params:xml:ns:common-policy'

class CommonPolicyMeta(XMLMeta): pass

# Mixin types for extensibility
class ConditionElement(object): pass
class ActionElement(object): pass
class TransformationElement(object): pass


class IdentityOne(XMLElement):
    _xml_tag = 'one'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = CommonPolicyMeta

    def __init__(self, id):
        self.id = id

    def _parse_element(self, element):
        pass

    def _build_element(self, element, nsmap):
        pass

    def __str__(self):
        return self.id

CommonPolicyMeta.register(IdentityOne)

class IdentityExcept(XMLElement):
    _xml_tag = 'except'
    _xml_namespace = _namespace_
    _xml_attrs = {
            'id': {},
            'domain': {}}
    _xml_meta = CommonPolicyMeta

    def __init__(self, id=None, domain=None):
        self.id = id
        self.domain = domain
        if (self.id is not None and self.domain is not None) or \
                (self.id is None and self.domain is None):
            raise ValueError("Only one of id or domain can be set")

    def _parse_element(self, element):
        pass

    def _build_element(self, element, nsmap):
        pass

    def __str__(self):
        if self.id is not None:
            return self.id
        else:
            return self.domain

CommonPolicyMeta.register(IdentityExcept)

class IdentityMany(XMLListElement):
    _xml_tag = 'many'
    _xml_namespace = _namespace_
    _xml_attrs = {'domain': {'test_equal': False}}
    _xml_meta = CommonPolicyMeta

    def __init__(self, domain=None, excepts=[]):
        self.domain = domain
        self[0:0] = excepts

    def _parse_element(self, element):
        for child in element:
            if child.tag == IdentityExcept.qname:
                self.append(IdentityExcept.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, IdentityExcept):
            raise TypeError("Identity elements can only have IdentityExcept children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(IdentityMany)

class Identity(XMLListElement, ConditionElement):
    _xml_tag = 'identity'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta

    def __init__(self, identities=[]):
        self[0:0] = identities

    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, (IdentityOne, IdentityMany)):
            raise TypeError("Identity elements can only have IdentityOne or IdentityMany children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(Identity)

class Sphere(XMLElement, ConditionElement):
    _xml_tag = 'sphere'
    _xml_namespace = _namespace_
    _xml_attrs = {'value': {'id_attribute': True}}
    _xml_meta = CommonPolicyMeta

    def __init__(self, value):
        self.value = value

    def _parse_element(self, element):
        pass

    def _build_element(self, element, nsmap):
        pass

CommonPolicyMeta.register(Sphere)

class ValidityFrom(XMLStringElement):
    _xml_tag = 'from'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta
    _xml_lang = False

CommonPolicyMeta.register(ValidityFrom)

class ValidityUntil(XMLStringElement):
    _xml_tag = 'until'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta
    _xml_lang = False

CommonPolicyMeta.register(ValidityUntil)

class Validity(XMLListElement, ConditionElement):
    _xml_tag = 'validity'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta

    def __init__(self, children=[]):
        self[0:0] = children

    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, (ValidityFrom, ValidityUntil)):
            raise TypeError("Validity elements can only contain ValidityFrom or ValidityUntil children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(Validity)

class Conditions(XMLListElement):
    _xml_tag = 'conditions'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta

    def __init__(self, conditions=[]):
        self[0:0] = conditions
    
    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, ConditionElement):
            raise TypeError("Conditions element can only contain ConditionElement children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(Conditions)

class Actions(XMLListElement):
    _xml_tag = 'actions'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta

    def __init__(self, actions=[]):
        self[0:0] = actions

    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, ActionElement):
            raise TypeError("Actions element can only contain ActionElement children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(Actions)

class Transformations(XMLListElement):
    _xml_tag = 'transformations'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta

    def __init__(self, transformations=[]):
        self[0:0] = transformations
    
    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, TransformationElement):
            raise TypeError("Transformations element can only contain TransformationElement children, got %s instead" % value.__class__.__name__)
        return value

CommonPolicyMeta.register(Transformations)

class Rule(XMLElement):
    _xml_tag = 'rule'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = CommonPolicyMeta

    def __init__(self, id, conditions=None, actions=None, transformations=None):
        self.id = id
        self.conditions = conditions
        self.actions = actions
        self.transformations = transformations

    def _parse_element(self, element):
        for child in element:
            if child.tag == Conditions.qname:
                self.conditions = Conditions.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Actions.qname:
                self.actions = Actions.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Transformations.qname:
                self.transformations = Transformations.from_element(child, xml_meta=self._xml_meta)

    def _build_element(self, element, nsmap):
        if self.conditions is not None:
            self.conditions.to_element(parent=element, nsmap=nsmap)
        if self.actions is not None:
            self.actions.to_element(parent=element, nsmap=nsmap)
        if self.transformations is not None:
            self.transformations.to_element(parent=element, nsmap=nsmap)

CommonPolicyMeta.register(Rule)

class RuleSet(XMLListApplication):
    accept_types = ['application/auth-policy+xml']
    build_types = ['application/auth-policy+xml']
    
    _xml_tag = 'ruleset'
    _xml_namespace = _namespace_
    _xml_meta = CommonPolicyMeta
    _xml_schema_file = 'common-policy.xsd'
    _xml_nsmap = {None: _namespace_}

    _parser_opts = {'remove_blank_text': True}

    def __init__(self, rules=[]):
        self._rules = {}
        for rule in rules:
            self.append(rule)

    def _parse_element(self, element):
        self._rules = {}
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, rule):
        if self._rules.get(rule.id) is None:
            self._rules[rule.id] = rule
        else:
            raise ValueError("Cannot have more than one Rule with the same id: %s" % rule.id)
        return rule

    def _before_del(self, rule):
        del self._rules[rule.id]

    # it also makes sense to be able to get a Rule by its id
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._rules[key]
        else:
            return super(RuleSet, self).__getitem__(key)

CommonPolicyMeta.register(RuleSet)

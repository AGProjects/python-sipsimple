# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and produces Presence Authorization Rules documents according to
RFC5025.

Example usage:
>>> conditions = Conditions([Identity([IdentityOne('sip:user@example.com')])])
>>> actions = Actions([SubHandling('allow')])
>>> transformations = Transformations()
>>> psrv = ProvideServices(provides=[ServiceURIScheme('sip'), ServiceURIScheme('mailto')])
>>> ppers = ProvidePersons(all=True)
>>> transformations[0:0] = [psrv, ppers]
>>> transformations.append(ProvideActivities('true'))
>>> transformations.append(ProvideUserInput('bare'))
>>> transformations.append(ProvideUnknownAttribute(ns='urn:vendor-specific:foo-namespace', name='foo', value='true'))
>>> rule = Rule(id='a', conditions=conditions, actions=actions, transformations=transformations)
>>> prules = PresRules([rule])
>>> print prules.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<cp:ruleset xmlns:pr="urn:ietf:params:xml:ns:pres-rules" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
  <cp:rule id="a">
    <cp:conditions>
      <cp:identity>
        <cp:one id="sip:user@example.com"/>
      </cp:identity>
    </cp:conditions>
    <cp:actions>
      <pr:sub-handling>allow</pr:sub-handling>
    </cp:actions>
    <cp:transformations>
      <pr:provide-services>
        <pr:service-uri-scheme>sip</pr:service-uri-scheme>
        <pr:service-uri-scheme>mailto</pr:service-uri-scheme>
      </pr:provide-services>
      <pr:provide-persons>
        <pr:all-persons/>
      </pr:provide-persons>
      <pr:provide-activities>true</pr:provide-activities>
      <pr:provide-user-input>bare</pr:provide-user-input>
      <pr:provide-unknown-attribute ns="urn:vendor-specific:foo-namespace" name="foo">true</pr:provide-unknown-attribute>
    </cp:transformations>
  </cp:rule>
</cp:ruleset>
<BLANKLINE>

"""

from sipsimple.payloads import XMLElement, XMLListElement, XMLStringElement, XMLEmptyElement, XMLAttribute, XMLElementChild
from sipsimple.payloads.policy import namespace as cp_namespace, CommonPolicyApplication, ActionElement, TransformationElement, RuleSet

__all__ = ['cp_namespace',
           'pr_namespace',
           'PresRulesApplication',
           'SubHandling',
           'DeviceID',
           'Class',
           'AllDevices',
           'ProvideDevices',
           'OccurenceID',
           'AllPersons',
           'ProvidePersons',
           'ServiceURI',
           'ServiceURIScheme',
           'AllServices',
           'ProvideServices',
           'BooleanProvideElement',
           'ProvideActivities',
           'ProvideClass',
           'ProvideDeviceID',
           'ProvideMood',
           'ProvidePlaceIs',
           'ProvidePlaceType',
           'ProvidePrivacy',
           'ProvideRelationship',
           'ProvideStatusIcon',
           'ProvideSphere',
           'ProvideTimeOffset',
           'ProvideUserInput',
           'ProvideUnknownAttribute',
           'ProvideAllAttributes',
           'PresRules']


pr_namespace = 'urn:ietf:params:xml:ns:pres-rules'

class PresRulesApplication(CommonPolicyApplication): pass
PresRulesApplication.register_namespace(pr_namespace, prefix='pr')


## Marker mixins

class ProvideDeviceElement(object): pass
class ProvidePersonElement(object): pass
class ProvideServiceElement(object): pass


## Attribute value types

class SubHandlingValue(str):
    def __new__(cls, value):
        if value not in ('block', 'confirm', 'polite-block', 'allow'):
            raise ValueError("illegal value for SubHandling element")
        return str.__new__(cls, value)


class ProvideUserInputValue(str):
    def __new__(cls, value):
        if value not in ('false', 'bare', 'thresholds', 'full'):
            raise ValueError("illega value for ProvideUserInput element")
        return str.__new__(cls, value)


## Action Elements

class SubHandling(XMLStringElement, ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    _xml_lang = False
    _xml_value_type = SubHandlingValue


## Transformation Elements

class Class(XMLStringElement, ProvideDeviceElement, ProvidePersonElement, ProvideServiceElement):
    _xml_tag = 'class'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    _xml_lang = False


class OccurenceID(XMLStringElement, ProvideDeviceElement, ProvidePersonElement, ProvideServiceElement):
    _xml_tag = 'occurence-id'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


## Devices element


class DeviceID(XMLStringElement, ProvideDeviceElement):
    _xml_tag = 'deviceID'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    _xml_lang = False

class AllDevices(XMLEmptyElement):
    _xml_tag = 'all-devices'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvideDevices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-devices'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication

    def _on_all_set(self, attribute):
        if getattr(self, attribute.name) is not None:
            self.clear()
    all = XMLElementChild('all', type=AllDevices, required=False, test_equal=True, onset=_on_all_set)
    del _on_all_set

    def __init__(self, all=False, provides=[]):
        XMLListElement.__init__(self)
        self.all = all
        self[0:0] = provides
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == AllDevices.qname:
                continue
            elif self.all:
                element.remove(child)
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, ProvideDeviceElement):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        if self.all:
            self.clear()
        else:
            for child in self:
                child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, ProvideDeviceElement):
            raise TypeError("ProvideDevices elements can only have ProvideDeviceElement instances as children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %s)' % (self.__class__.__name__, self.all, list.__repr__(self))

    __str__ = __repr__


## Persons elmeent

class AllPersons(XMLEmptyElement):
    _xml_tag = 'all-persons'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvidePersons(XMLListElement, TransformationElement):
    _xml_tag = 'provide-persons'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    
    def _on_all_set(self, attribute):
        if getattr(self, attribute.name) is not None:
            self.clear()
    all = XMLElementChild('all', type=AllPersons, required=False, test_equal=True, onset=_on_all_set)
    del _on_all_set

    def __init__(self, all=False, provides=[]):
        XMLListElement.__init__(self)
        self.all = all
        self[0:0] = provides
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == AllPersons.qname:
                continue
            elif self.all:
                element.remove(child)
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, ProvidePersonElement):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        if self.all:
            self.clear()
        else:
            for child in self:
                child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, ProvidePersonElement):
            raise TypeError("ProvidePersons elements can only have ProvidePersonElement instances as children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %s)' % (self.__class__.__name__, self.all, list.__repr__(self))

    __str__ = __repr__


## Service elements

class ServiceURI(XMLStringElement, ProvideServiceElement):
    _xml_tag = 'service-uri'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ServiceURIScheme(XMLStringElement, ProvideServiceElement):
    _xml_tag = 'service-uri-scheme'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class AllServices(XMLEmptyElement):
    _xml_tag = 'all-services'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvideServices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-services'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication

    def _on_all_set(self, attribute):
        if getattr(self, attribute.name) is not None:
            self.clear()
    all = XMLElementChild('all', type=AllServices, required=False, test_equal=True, onset=_on_all_set)
    del _on_all_set

    def __init__(self, all=False, provides=[]):
        XMLListElement.__init__(self)
        self.all = all
        self[0:0] = provides
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == AllServices.qname:
                continue
            elif self.all:
                element.remove(child)
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, ProvideServiceElement):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        if self.all:
            self.clear()
        else:
            for child in self:
                child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, ProvideServiceElement):
            raise TypeError("ProvideServices elements can only have ProvideServiceElement instances as children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %s)' % (self.__class__.__name__, self.all, list.__repr__(self))

    __str__ = __repr__


## Transformation elements

class BooleanProvideElement(XMLElement):
    def __init__(self, value=True):
        XMLElement.__init__(self)
        self.value = value

    def _parse_element(self, element, *args, **kwargs):
        if element.text.lower() == 'true':
            self.value = True
        else:
            self.value = False

    def _build_element(self, *args, **kwargs):
        self.element.text = str(self.value).lower()
    
    def __nonzero__(self):
        return self.value

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)

    __str__ = __repr__


class ProvideActivities(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-activities'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideClass(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-class'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideDeviceID(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-deviceID'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideMood(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-mood'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvidePlaceIs(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-is'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvidePlaceType(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-type'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvidePrivacy(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-privacy'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideRelationship(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-relationship'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideStatusIcon(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-status-icon'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideSphere(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-sphere'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideTimeOffset(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-time-offset'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class ProvideUserInput(XMLStringElement, TransformationElement):
    _xml_tag = 'provide-user-input'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication
    _xml_lang = False
    _xml_value_type = ProvideUserInputValue


class ProvideUnknownAttribute(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-unknown-attribute'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication

    name = XMLAttribute('name', type=str, required=True, test_equal=True)
    ns = XMLAttribute('ns', type=str, required=True, test_equal=True)

    def __init__(self, ns, name, value):
        BooleanProvideElement.__init__(self, value)
        self.ns = ns
        self.name = name

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.ns, self.name, self.value)

    __str__ = __repr__


class ProvideAllAttributes(XMLEmptyElement, TransformationElement):
    _xml_tag = 'provide-all-attributes'
    _xml_namespace = pr_namespace
    _xml_application = PresRulesApplication


class PresRules(RuleSet):
    _xml_application = PresRulesApplication
    _xml_schema_file = 'pres-rules.xsd'
    _xml_nsmap = {'pr': pr_namespace,
                  'cr': cp_namespace}



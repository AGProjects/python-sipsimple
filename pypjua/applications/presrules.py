"""
Parses and produces Presence Authorization Rules documents according to
RFC5025.

Example usage:
>>> conditions = Conditions([Identity([IdentityOne('sip:user@example.com')])])
>>> actions = Actions([SubHandling('allow')])
>>> transformations = Transformations()
>>> psrv = ProvideServices([ServiceURIScheme('sip'), ServiceURIScheme('mailto')])
>>> ppers = ProvidePersons([AllPersons()])
>>> transformations[0:0] = [psrv, ppers]
>>> transformations.append(ProvideActivities('true'))
>>> transformations.append(ProvideUserInput('bare'))
>>> transformations.append(ProvideUnknownAttribute(ns='urn:vendor-specific:foo-namespace', name='foo', value='true'))
>>> rule = Rule(id='a', conditions=conditions, actions=actions, transformations=transformations)
>>> prules = PresRules([rule])
>>> print prules.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<cr:ruleset xmlns:pr="urn:ietf:params:xml:ns:pres-rules" xmlns:cr="urn:ietf:params:xml:ns:common-policy">
  <cr:rule id="a">
    <cr:conditions>
      <cr:identity>
        <cr:one id="sip:user@example.com"/>
      </cr:identity>
    </cr:conditions>
    <cr:actions>
      <pr:sub-handling>allow</pr:sub-handling>
    </cr:actions>
    <cr:transformations>
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
    </cr:transformations>
  </cr:rule>
</cr:ruleset>
<BLANKLINE>

"""

from lxml import etree

from pypjua.applications import XMLMeta, XMLElement, XMLListElement, XMLStringElement, XMLEmptyElement, XMLApplication
from pypjua.applications.policy import _namespace_ as _cp_namespace_, CommonPolicyMeta, ActionElement, TransformationElement, RuleSet

__all__ = ['_cp_namespace_',
           '_pr_namespace_',
           'PresRulesMeta',
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


_pr_namespace_ = 'urn:ietf:params:xml:ns:pres-rules'

class PresRulesMeta(CommonPolicyMeta): pass

class SubHandling(XMLStringElement, ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta
    _xml_lang = False
    _xml_values = ('block', 'confirm', 'polite-block', 'allow')

PresRulesMeta.register(SubHandling)

class DeviceID(XMLStringElement):
    _xml_tag = 'deviceID'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta
    _xml_lang = False

PresRulesMeta.register(DeviceID)

class Class(XMLStringElement):
    _xml_tag = 'class'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta
    _xml_lang = False

PresRulesMeta.register(Class)

class AllDevices(XMLEmptyElement):
    _xml_tag = 'all-devices'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(AllDevices)

class ProvideDevices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-devices'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

    def __init__(self, provides=[]):
        self[0:0] = provides
    
    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

PresRulesMeta.register(ProvideDevices)

class OccurenceID(XMLStringElement):
    _xml_tag = 'occurence-id'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(OccurenceID)

class AllPersons(XMLEmptyElement):
    _xml_tag = 'all-persons'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(AllPersons)

class ProvidePersons(XMLListElement, TransformationElement):
    _xml_tag = 'provide-persons'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

    def __init__(self, provides=[]):
        self[0:0] = provides
    
    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

PresRulesMeta.register(ProvidePersons)

class ServiceURI(XMLStringElement):
    _xml_tag = 'service-uri'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ServiceURI)

class ServiceURIScheme(XMLStringElement):
    _xml_tag = 'service-uri-scheme'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ServiceURIScheme)

class AllServices(XMLEmptyElement):
    _xml_tag = 'all-services'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(AllServices)

class ProvideServices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-services'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

    def __init__(self, provides=[]):
        self[0:0] = provides
    
    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

PresRulesMeta.register(ProvideServices)

class BooleanProvideElement(XMLStringElement):
    class BooleanString(str):
        def __eq__(self, obj):
            return str(self).lower() == str(obj).lower()

        def __hash__(self):
            return hash(str(self).lower())

    _xml_tag = None # to be defined
    _xml_namespace = None # to be defined
    _xml_attrs = {} # can be defined
    _xml_meta = None # to be defined
    _xml_values = (BooleanString('True'), BooleanString('False'))

class ProvideActivities(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-activities'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideActivities)

class ProvideClass(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-class'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideClass)

class ProvideDeviceID(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-deviceID'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideDeviceID)

class ProvideMood(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-mood'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideMood)

class ProvidePlaceIs(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-is'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePlaceIs)

class ProvidePlaceType(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-type'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePlaceType)

class ProvidePrivacy(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-privacy'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePrivacy)

class ProvideRelationship(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-relationship'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideRelationship)

class ProvideStatusIcon(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-status-icon'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideStatusIcon)

class ProvideSphere(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-sphere'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideSphere)

class ProvideTimeOffset(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-time-offset'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideTimeOffset)

class ProvideUserInput(XMLStringElement, TransformationElement):
    _xml_tag = 'provide-user-input'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta
    _xml_lang = False
    _xml_values = ('false', 'bare', 'thresholds', 'full')

PresRulesMeta.register(ProvideUserInput)

class ProvideUnknownAttribute(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-unknown-attribute'
    _xml_namespace = _pr_namespace_
    _xml_attrs = {'name': {},
                 'ns': {}}
    _xml_meta = PresRulesMeta

    def __init__(self, ns, name, value):
        BooleanProvideElement.__init__(self, value)
        self.ns = ns
        self.name = name

PresRulesMeta.register(ProvideUnknownAttribute)

class ProvideAllAttributes(XMLEmptyElement, TransformationElement):
    _xml_tag = 'provide-all-attributes'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideAllAttributes)

class PresRules(RuleSet):
    _xml_meta = PresRulesMeta
    _xml_schema_file = 'pres-rules.xsd'
    _xml_nsmap = {'pr': _pr_namespace_,
                  'cr': _cp_namespace_}

PresRulesMeta.register(PresRules)

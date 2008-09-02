"""
Parses and produces Presence Authorization Rules documents according to
RFC5025.
"""

from lxml import etree

from pypjua.applications import XMLMeta, XMLElement, XMLListElement, XMLStringElement, XMLEmptyElement, XMLApplication
from pypjua.applications.policy import _namespace_ as _cp_namespace_, CommonPolicyMeta, RuleSet

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

class SubHandling(XMLStringElement):
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

class ProvideDevices(XMLListElement):
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

class ProvidePersons(XMLListElement):
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

class ProvideServices(XMLListElement):
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

class ProvideActivities(BooleanProvideElement):
    _xml_tag = 'provide-activities'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideActivities)

class ProvideClass(BooleanProvideElement):
    _xml_tag = 'provide-class'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideClass)

class ProvideDeviceID(BooleanProvideElement):
    _xml_tag = 'provide-deviceID'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideDeviceID)

class ProvideMood(BooleanProvideElement):
    _xml_tag = 'provide-mood'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideMood)

class ProvidePlaceIs(BooleanProvideElement):
    _xml_tag = 'provide-place-is'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePlaceIs)

class ProvidePlaceType(BooleanProvideElement):
    _xml_tag = 'provide-place-type'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePlaceType)

class ProvidePrivacy(BooleanProvideElement):
    _xml_tag = 'provide-privacy'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvidePrivacy)

class ProvideRelationship(BooleanProvideElement):
    _xml_tag = 'provide-relationship'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideRelationship)

class ProvideStatusIcon(BooleanProvideElement):
    _xml_tag = 'provide-status-icon'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideStatusIcon)

class ProvideSphere(BooleanProvideElement):
    _xml_tag = 'provide-sphere'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideSphere)

class ProvideTimeOffset(BooleanProvideElement):
    _xml_tag = 'provide-time-offset'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideTimeOffset)

class ProvideUserInput(XMLStringElement):
    _xml_tag = 'provide-user-input'
    _xml_namespace = _pr_namespace_
    _xml_meta = PresRulesMeta
    _xml_lang = False
    _xml_values = ('false', 'bare', 'thresholds', 'full')

PresRulesMeta.register(ProvideUserInput)

class ProvideUnknownAttribute(BooleanProvideElement):
    _xml_tag = 'provide-unknown-attribute'
    _xml_namespace = _pr_namespace_
    _xml_attrs = {'name': {},
                 'ns': {}}
    _xml_meta = PresRulesMeta

PresRulesMeta.register(ProvideUnknownAttribute)

class ProvideAllAttributes(XMLEmptyElement):
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

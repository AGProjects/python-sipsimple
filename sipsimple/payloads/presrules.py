
"""Parses and produces Presence Authorization Rules documents according to RFC5025."""


__all__ = ['namespace',
           'PresRulesDocument',
           'SubHandling',
           'DeviceID',
           'Class',
           'All',
           'ProvideDevices',
           'OccurenceID',
           'ProvidePersons',
           'ServiceURI',
           'ServiceURIScheme',
           'ProvideServices',
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


from sipsimple.payloads import XMLListElement, XMLStringElement, XMLBooleanElement, XMLEmptyElement, XMLAttribute
from sipsimple.payloads import commonpolicy
from sipsimple.util import All


namespace = 'urn:ietf:params:xml:ns:pres-rules'

class PresRulesDocument(commonpolicy.CommonPolicyDocument): pass
PresRulesDocument.register_namespace(namespace, prefix='pr', schema='pres-rules.xsd')


## Marker mixins

class ProvideDeviceElement(object): pass
class ProvidePersonElement(object): pass
class ProvideServiceElement(object): pass


## Attribute value types

class SubHandlingValue(str):
    __prioritymap__ = {'block': 0, 'confirm': 10, 'polite-block': 20, 'allow': 30}

    def __new__(cls, value):
        if value not in cls.__prioritymap__:
            raise ValueError("illegal value for SubHandling element")
        return str.__new__(cls, value)

    @property
    def priority(self):
        return self.__prioritymap__[self]


class ProvideUserInputValue(str):
    def __new__(cls, value):
        if value not in ('false', 'bare', 'thresholds', 'full'):
            raise ValueError("illegal value for ProvideUserInput element")
        return str.__new__(cls, value)


## Action Elements

class SubHandling(XMLStringElement, commonpolicy.ActionElement):
    _xml_tag = 'sub-handling'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument
    _xml_value_type = SubHandlingValue


## Transformation Elements

class Class(XMLStringElement):
    _xml_tag = 'class'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class OccurenceID(XMLStringElement):
    _xml_tag = 'occurence-id'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


## Devices element


class DeviceID(XMLStringElement):
    _xml_tag = 'deviceID'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class AllDevices(XMLEmptyElement):
    _xml_tag = 'all-devices'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideDevices(XMLListElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-devices'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument
    _xml_item_type = (DeviceID, OccurenceID, Class, AllDevices, ProvideDeviceElement)

    def __init__(self, provides=[]):
        XMLListElement.__init__(self)
        self.update(provides)

    def __contains__(self, item):
        if item == All:
            item = AllDevices()
        return super(ProvideDevices, self).__contains__(item)

    def __iter__(self):
        return (All if type(item) is AllDevices else item for item in super(ProvideDevices, self).__iter__())

    def add(self, item):
        if item == All:
            item = AllDevices()
        if type(item) is AllDevices:
            self.clear()
        else:
            try:
                self.remove(All)
            except KeyError:
                pass
        super(ProvideDevices, self).add(item)

    def remove(self, item):
        if item == All:
            try:
                item = (item for item in super(ProvideDevices, self).__iter__() if type(item) is AllDevices).next()
            except StopIteration:
                raise KeyError(item)
        super(ProvideDevices, self).remove(item)


## Persons elmeent

class AllPersons(XMLEmptyElement):
    _xml_tag = 'all-persons'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvidePersons(XMLListElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-persons'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument
    _xml_item_type = (OccurenceID, Class, AllPersons, ProvidePersonElement)

    def __init__(self, provides=[]):
        XMLListElement.__init__(self)
        self.update(provides)

    def __contains__(self, item):
        if item == All:
            item = AllPersons()
        return super(ProvidePersons, self).__contains__(item)

    def __iter__(self):
        return (All if type(item) is AllPersons else item for item in super(ProvidePersons, self).__iter__())

    def add(self, item):
        if item == All:
            item = AllPersons()
        if type(item) is AllPersons:
            self.clear()
        else:
            try:
                self.remove(All)
            except KeyError:
                pass
        super(ProvidePersons, self).add(item)

    def remove(self, item):
        if item == All:
            try:
                item = (item for item in super(ProvidePersons, self).__iter__() if type(item) is AllPersons).next()
            except StopIteration:
                raise KeyError(item)
        super(ProvidePersons, self).remove(item)


## Service elements

class ServiceURI(XMLStringElement):
    _xml_tag = 'service-uri'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ServiceURIScheme(XMLStringElement):
    _xml_tag = 'service-uri-scheme'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class AllServices(XMLEmptyElement):
    _xml_tag = 'all-services'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideServices(XMLListElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-services'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument
    _xml_item_type = (ServiceURI, ServiceURIScheme, OccurenceID, Class, AllServices, ProvideServiceElement)

    def __init__(self, provides=[]):
        XMLListElement.__init__(self)
        self.update(provides)

    def __contains__(self, item):
        if item == All:
            item = AllServices()
        return super(ProvideServices, self).__contains__(item)

    def __iter__(self):
        return (All if type(item) is AllServices else item for item in super(ProvideServices, self).__iter__())

    def add(self, item):
        if item == All:
            item = AllServices()
        if type(item) is AllServices:
            self.clear()
        else:
            try:
                self.remove(All)
            except KeyError:
                pass
        super(ProvideServices, self).add(item)

    def remove(self, item):
        if item == All:
            try:
                item = (item for item in super(ProvideServices, self).__iter__() if type(item) is AllServices).next()
            except StopIteration:
                raise KeyError(item)
        super(ProvideServices, self).remove(item)


## Transformation elements

class ProvideActivities(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-activities'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideClass(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-class'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideDeviceID(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-deviceID'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideMood(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-mood'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvidePlaceIs(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-place-is'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvidePlaceType(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-place-type'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvidePrivacy(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-privacy'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideRelationship(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-relationship'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideStatusIcon(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-status-icon'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideSphere(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-sphere'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideTimeOffset(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-time-offset'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class ProvideUserInput(XMLStringElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-user-input'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument
    _xml_value_type = ProvideUserInputValue


class ProvideUnknownAttribute(XMLBooleanElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-unknown-attribute'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument

    name = XMLAttribute('name', type=str, required=True, test_equal=True)
    ns = XMLAttribute('ns', type=str, required=True, test_equal=True)

    def __init__(self, ns, name, value):
        XMLBooleanElement.__init__(self, value)
        self.ns = ns
        self.name = name

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.ns, self.name, self.value)


class ProvideAllAttributes(XMLEmptyElement, commonpolicy.TransformationElement):
    _xml_tag = 'provide-all-attributes'
    _xml_namespace = namespace
    _xml_document = PresRulesDocument


class PresRules(commonpolicy.RuleSet):
    _xml_document = PresRulesDocument



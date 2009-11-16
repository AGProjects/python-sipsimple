# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and produces Dialog Authorization Rules documents. As there is no
RFC for this RFC5025 (pres-rules) will be used.
"""

from sipsimple.applications import XMLElement, XMLListElement, XMLStringElement, XMLEmptyElement, XMLAttribute, XMLElementChild
from sipsimple.applications.policy import namespace as cp_namespace, CommonPolicyApplication, ActionElement, TransformationElement, RuleSet

__all__ = ['cp_namespace',
           'dlg_namespace',
           'DialogRulesApplication',
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
           'DialogRules']


dlg_namespace = 'urn:ietf:params:xml:ns:dialog-rules'

class DialogRulesApplication(CommonPolicyApplication): pass
DialogRulesApplication.register_namespace(dlg_namespace, prefix='pr')


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
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    _xml_lang = False
    _xml_value_type = SubHandlingValue


## Transformation Elements

class Class(XMLStringElement, ProvideDeviceElement, ProvidePersonElement, ProvideServiceElement):
    _xml_tag = 'class'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    _xml_lang = False


class OccurenceID(XMLStringElement, ProvideDeviceElement, ProvidePersonElement, ProvideServiceElement):
    _xml_tag = 'occurence-id'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


## Devices element


class DeviceID(XMLStringElement, ProvideDeviceElement):
    _xml_tag = 'deviceID'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    _xml_lang = False

class AllDevices(XMLEmptyElement):
    _xml_tag = 'all-devices'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvideDevices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-devices'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication

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
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvidePersons(XMLListElement, TransformationElement):
    _xml_tag = 'provide-persons'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    
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
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ServiceURIScheme(XMLStringElement, ProvideServiceElement):
    _xml_tag = 'service-uri-scheme'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class AllServices(XMLEmptyElement):
    _xml_tag = 'all-services'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    
    def __init__(self, provide_all=True):
        XMLEmptyElement.__init__(self)
    
    def __new__(cls, provide_all=True):
        if not provide_all:
            return None
        return XMLEmptyElement.__new__(cls)


class ProvideServices(XMLListElement, TransformationElement):
    _xml_tag = 'provide-services'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication

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
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideClass(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-class'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideDeviceID(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-deviceID'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideMood(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-mood'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvidePlaceIs(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-is'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvidePlaceType(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-place-type'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvidePrivacy(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-privacy'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideRelationship(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-relationship'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideStatusIcon(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-status-icon'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideSphere(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-sphere'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideTimeOffset(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-time-offset'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class ProvideUserInput(XMLStringElement, TransformationElement):
    _xml_tag = 'provide-user-input'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication
    _xml_lang = False
    _xml_value_type = ProvideUserInputValue


class ProvideUnknownAttribute(BooleanProvideElement, TransformationElement):
    _xml_tag = 'provide-unknown-attribute'
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication

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
    _xml_namespace = dlg_namespace
    _xml_application = DialogRulesApplication


class DialogRules(RuleSet):
    _xml_application = DialogRulesApplication
    _xml_schema_file = 'dialog-rules.xsd'
    _xml_nsmap = {'pr': dlg_namespace,
                  'cr': cp_namespace}



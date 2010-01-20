# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""User Agent Capability Extension  handling according to RFC5196

This module provides an extension to PIDF (module sipsimple.payloads.presdm) to
describe a user-agent capabilities in the PIDF documents.
"""

from sipsimple.payloads import XMLStringElement, XMLElement, XMLElementChild, XMLEmptyElement, XMLListElement, XMLAttribute
from sipsimple.payloads.presdm import PIDFApplication, ServiceExtension, Service, DeviceExtension, Device

__all__ = ['caps_namespace',
            'Audio', 
            'Application',
            'Data',
            'Control',
            'Video',
            'Video',
            'Text',
            'Message',
            'Type',
            'Automata',
            'Class',
            'ClassPersonal',
            'ClassBusiness',
            'Duplex',
            'DuplexFull',
            'DuplexHalf',
            'DuplexReceiveOnly',
            'DuplexSendOnly',
            'Description',
            'EventPackages',
            'EventConference',
            'EventDialog',
            'EventKpml',
            'EventMessageSummary',
            'EventPocSettings',
            'EventPresence',
            'EventReg',
            'EventRefer',
            'EventSiemensRtpStats',
            'EventSpiritsIndps',
            'EventSpiritsUserProf',
            'EventWinfo',
            'Priority',
            'PriorityLowerthan',
            'PriorityHigherthan',
            'PriorityEquals',
            'PriorityRange',
            'Methods',
            'MethodAck',
            'MethodBye',
            'MethodCancel',
            'MethodInfo',
            'MethodInvite',
            'MethodMessage',
            'MethodNotify',
            'MethodOptions',
            'MethodPrack',
            'MethodPublish',
            'MethodRefer',
            'MethodRegister',
            'MethodSubscribe',
            'MethodUpdate',
            'Extensions',
            'ExtensionRel100',
            'ExtensionEarlySession',
            'ExtensionEventList',
            'ExtensionFromChange',
            'ExtensionGruu',
            'ExtensionHistinfo',
            'ExtensionJoin',
            'ExtensionNoRefSub',
            'ExtensionPath',
            'ExtensionPrecondition',
            'ExtensionPref',
            'ExtensionPrivacy',
            'ExtensionRecipientListInvite',
            'ExtensionRecipientListSubscribe',
            'ExtensionReplaces',
            'ExtensionResourcePriority',
            'ExtensionSdpAnat',
            'ExtensionSecAgree',
            'ExtensionTdialog',
            'ExtensionTimer',
            'Schemes',
            'Scheme',
            'Actor',
            'ActorPrincipal',
            'ActorAttendant',
            'ActorMsgTaker',
            'ActorInformation',
            'IsFocus',
            'Languages',
            'Language',
            'Servcaps',
            'Mobility',
            'MobilityFixed',
            'MobilityMobile',
            'Devcaps',
            'ServcapsExtension',
            'EventPackagesExtension',
            'PriorityExtension',
            'MethodsExtension',
            'ExtensionsExtension',
            'DevcapsExtension',
            'MobilityExtension']

caps_namespace = "urn:ietf:params:xml:ns:pidf:caps"
PIDFApplication.register_namespace(caps_namespace, prefix='caps')

# Marker mixins
class ServcapsExtension(object): pass
class EventPackagesExtension(object): pass
class PriorityExtension(object): pass
class MethodsExtension(object): pass
class ExtensionsExtension(object): pass
class DevcapsExtension(object): pass
class MobilityExtension(object): pass


class BooleanValue(object):
    def __new__(cls, value):
        if type(value) is str and value in ('true', 'false'):
            return str.__new__(str, value)
        if type(value) is not bool:
            raise ValueError("illegal value for boolean type")
        if value:
            return str.__new__(str, 'true')
        else:
            return str.__new__(str, 'false')

class ContentTypeValue(str):
    def __new__(cls, value):
        if len(value.split('/')) != 2:
            raise ValueError("illegal value for Content-Type: %s" % value)
        return str.__new__(cls, value)


class Supported(XMLListElement):
    _xml_tag = 'supported'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    def __init__(self, supported=[]):
        XMLListElement.__init__(self)
        self[0:0] = supported

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

class NotSupported(XMLListElement):
    _xml_tag = 'notsupported'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    def __init__(self, not_supported=[]):
        XMLListElement.__init__(self)
        self[0:0] = not_supported

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

class Audio(XMLStringElement):
    _xml_tag = 'audio'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Application(XMLStringElement):
    _xml_tag = 'application'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Data(XMLStringElement):
    _xml_tag = 'data'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Control(XMLStringElement):
    _xml_tag = 'control'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Video(XMLStringElement):
    _xml_tag = 'video'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Text(XMLStringElement):
    _xml_tag = 'text'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Message(XMLStringElement):
    _xml_tag = 'message'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Type(XMLStringElement):
    _xml_tag = 'type'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = ContentTypeValue

class Automata(XMLStringElement):
    _xml_tag = 'automata'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class ClassBusiness(XMLEmptyElement):
    _xml_tag = 'business'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ClassPersonal(XMLEmptyElement):
    _xml_tag = 'personal'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ClassElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [ClassPersonal, ClassBusiness]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (ClassPersonal, ClassBusiness)):
            raise TypeError("Class element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class ClassSupported(Supported, ClassElementList): pass
class ClassNotSupported(NotSupported, ClassElementList): pass

class Class(XMLElement):
    _xml_tag = 'class'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    supported = XMLElementChild('supported', type=ClassSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=ClassNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = ClassSupported()
        if not_supported:
            self.not_supported = ClassNotSupported()

class DuplexFull(XMLEmptyElement):
    _xml_tag = 'full'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class DuplexHalf(XMLEmptyElement):
    _xml_tag = 'half'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class DuplexReceiveOnly(XMLEmptyElement):
    _xml_tag = 'receive-only'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class DuplexSendOnly(XMLEmptyElement):
    _xml_tag = 'send-only'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class DuplexElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [DuplexFull, DuplexHalf, DuplexReceiveOnly, DuplexSendOnly]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (DuplexFull, DuplexHalf, DuplexReceiveOnly, DuplexSendOnly)):
            raise TypeError("Duplex element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class DuplexSupported(Supported, DuplexElementList): pass
class DuplexNotSupported(NotSupported, DuplexElementList): pass

class Duplex(XMLElement):
    _xml_tag = 'duplex'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    supported = XMLElementChild('supported', type=DuplexSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=DuplexNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = DuplexSupported()
        if not_supported:
            self.not_supported = DuplexNotSupported()

class Description(XMLStringElement):
    _xml_tag = 'description'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_lang = True

class EventConference(XMLEmptyElement):
    _xml_tag = 'conference'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventDialog(XMLEmptyElement):
    _xml_tag = 'dialog'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventKpml(XMLEmptyElement):
    _xml_tag = 'kpml'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventMessageSummary(XMLEmptyElement):
    _xml_tag = 'message-summary'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventPocSettings(XMLEmptyElement):
    _xml_tag = 'poc-settings'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventPresence(XMLEmptyElement):
    _xml_tag = 'presence'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventReg(XMLEmptyElement):
    _xml_tag = 'reg'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventRefer(XMLEmptyElement):
    _xml_tag = 'refer'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventSiemensRtpStats(XMLEmptyElement):
    _xml_tag = 'Siemens-RTP-Stats'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventSpiritsIndps(XMLEmptyElement):
    _xml_tag = 'spirits-INDPs'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventSpiritsUserProf(XMLEmptyElement):
    _xml_tag = 'spirits-user-prof'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventWinfo(XMLEmptyElement):
    _xml_tag = 'winfo'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class EventElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [EventConference, EventDialog, EventKpml, EventMessageSummary, EventPocSettings, EventPresence, EventReg, EventRefer, EventSiemensRtpStats, EventSpiritsIndps, EventSpiritsUserProf, EventWinfo]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (EventConference, EventDialog, EventKpml, EventMessageSummary, EventPocSettings, EventPresence, EventReg, EventRefer, EventSiemensRtpStats, EventSpiritsIndps, EventSpiritsUserProf, EventWinfo)):
            raise TypeError("Event element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class EventSupported(Supported, EventElementList): pass
class EventNotSupported(NotSupported, EventElementList): pass

class EventPackages(XMLElement):
    _xml_tag = 'event-packages'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = EventPackagesExtension

    supported = XMLElementChild('supported', type=EventSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=EventNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = EventSupported()
        if not_supported:
            self.not_supported = EventNotSupported()

class PriorityLowerthan(XMLEmptyElement):
    _xml_tag = 'lowerthan'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    
    maxvalue = XMLAttribute('maxvalue', type=int, required=True, test_equal=True)

    def __init__(self, maxvalue):
        XMLEmptyElement.__init__(self)
        self.maxvalue = maxvalue

class PriorityHigherthan(XMLEmptyElement):
    _xml_tag = 'higherthan'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    
    minvalue = XMLAttribute('minvalue', type=int, required=True, test_equal=True)

    def __init__(self, minvalue):
        XMLEmptyElement.__init__(self)
        self.minvalue = minvalue

class PriorityEquals(XMLEmptyElement):
    _xml_tag = 'equals'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    
    value = XMLAttribute('value', type=int, required=True, test_equal=True)

    def __init__(self, value):
        XMLEmptyElement.__init__(self)
        self.value = value

class PriorityRange(XMLEmptyElement):
    _xml_tag = 'range'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    
    maxvalue = XMLAttribute('maxvalue', type=int, required=True, test_equal=True)
    minvalue = XMLAttribute('minvalue', type=int, required=True, test_equal=True)

    def __init__(self, maxvalue, minvalue):
        XMLEmptyElement.__init__(self)
        self.maxvalue = maxvalue
        self.minvalue = minvalue

class PriorityElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [PriorityLowerthan, PriorityHigherthan, PriorityEquals, PriorityRange]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (PriorityLowerthan, PriorityHigherthan, PriorityEquals, PriorityRange)):
            raise TypeError("Priority element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class PrioritySupported(Supported, PriorityElementList): pass
class PriorityNotSupported(NotSupported, PriorityElementList): pass

class Priority(XMLElement):
    _xml_tag = 'priority'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = PriorityExtension

    supported = XMLElementChild('supported', type=PrioritySupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=PriorityNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = PrioritySupported()
        if not_supported:
            self.not_supported = PriorityNotSupported()

class MethodAck(XMLEmptyElement):
    _xml_tag = 'ACK'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodBye(XMLEmptyElement):
    _xml_tag = 'BYE'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodCancel(XMLEmptyElement):
    _xml_tag = 'CANCEL'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodInfo(XMLEmptyElement):
    _xml_tag = 'INFO'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodInvite(XMLEmptyElement):
    _xml_tag = 'INVITE'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodMessage(XMLEmptyElement):
    _xml_tag = 'MESSAGE'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodNotify(XMLEmptyElement):
    _xml_tag = 'NOTIFY'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodOptions(XMLEmptyElement):
    _xml_tag = 'OPTIONS'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodPrack(XMLEmptyElement):
    _xml_tag = 'PRACK'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodPublish(XMLEmptyElement):
    _xml_tag = 'PUBLISH'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodRefer(XMLEmptyElement):
    _xml_tag = 'REFER'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodRegister(XMLEmptyElement):
    _xml_tag = 'REGISTER'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodSubscribe(XMLEmptyElement):
    _xml_tag = 'SUBSCRIBE'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodUpdate(XMLEmptyElement):
    _xml_tag = 'UPDATE'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MethodsElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [MethodAck, MethodBye, MethodCancel, MethodInfo, MethodInvite, MethodMessage, MethodNotify, MethodOptions, MethodPrack, MethodPublish, MethodRefer, MethodRegister, MethodSubscribe, MethodUpdate]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (MethodAck, MethodBye, MethodCancel, MethodInfo, MethodInvite, MethodMessage, MethodNotify, MethodOptions, MethodPrack, MethodPublish, MethodRefer, MethodRegister, MethodSubscribe, MethodUpdate)):
            raise TypeError("Method element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class MethodsSupported(Supported, MethodsElementList): pass
class MethodsNotSupported(NotSupported, MethodsElementList): pass

class Methods(XMLElement):
    _xml_tag = 'methods'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = MethodsExtension

    supported = XMLElementChild('supported', type=MethodsSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=MethodsNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = MethodsSupported()
        if not_supported:
            self.not_supported = MethodsNotSupported()

class ExtensionRel100(XMLEmptyElement):
    _xml_tag = 'rel100'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionEarlySession(XMLEmptyElement):
    _xml_tag = 'early-session'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionEventList(XMLEmptyElement):
    _xml_tag = 'eventlist'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionFromChange(XMLEmptyElement):
    _xml_tag = 'from-change'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionGruu(XMLEmptyElement):
    _xml_tag = 'gruu'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionHistinfo(XMLEmptyElement):
    _xml_tag = 'histinfo'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionJoin(XMLEmptyElement):
    _xml_tag = 'join'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionNoRefSub(XMLEmptyElement):
    _xml_tag = 'norefsub'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionPath(XMLEmptyElement):
    _xml_tag = 'path'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionPrecondition(XMLEmptyElement):
    _xml_tag = 'precondition'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionPref(XMLEmptyElement):
    _xml_tag = 'pref'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionPrivacy(XMLEmptyElement):
    _xml_tag = 'privacy'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionRecipientListInvite(XMLEmptyElement):
    _xml_tag = 'recipient-list-invite'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionRecipientListSubscribe(XMLEmptyElement):
    _xml_tag = 'recipient-list-subscribe'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionReplaces(XMLEmptyElement):
    _xml_tag = 'replaces'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionResourcePriority(XMLEmptyElement):
    _xml_tag = 'resource-priority'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionSdpAnat(XMLEmptyElement):
    _xml_tag = 'sdp-anat'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionSecAgree(XMLEmptyElement):
    _xml_tag = 'sec-agree'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionTdialog(XMLEmptyElement):
    _xml_tag = 'tdialog'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionTimer(XMLEmptyElement):
    _xml_tag = 'timer'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ExtensionsElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [ExtensionRel100, ExtensionEarlySession, ExtensionEventList, ExtensionFromChange, ExtensionGruu, ExtensionHistinfo, ExtensionJoin, ExtensionNoRefSub, ExtensionPath, ExtensionPrecondition, ExtensionPref, ExtensionPrivacy, ExtensionRecipientListInvite, ExtensionRecipientListSubscribe, ExtensionReplaces, ExtensionResourcePriority, ExtensionSdpAnat, ExtensionSecAgree, ExtensionTdialog, ExtensionTimer]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (ExtensionRel100, ExtensionEarlySession, ExtensionEventList, ExtensionFromChange, ExtensionGruu, ExtensionHistinfo, ExtensionJoin, ExtensionNoRefSub, ExtensionPath, ExtensionPrecondition, ExtensionPref, ExtensionPrivacy, ExtensionRecipientListInvite, ExtensionRecipientListSubscribe, ExtensionReplaces, ExtensionResourcePriority, ExtensionSdpAnat, ExtensionSecAgree, ExtensionTdialog, ExtensionTimer)):
            raise TypeError("Extension element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class ExtensionsSupported(Supported, ExtensionsElementList): pass
class ExtensionsNotSupported(NotSupported, ExtensionsElementList): pass

class Extensions(XMLElement):
    _xml_tag = 'extensions'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = ExtensionsExtension

    supported = XMLElementChild('supported', type=ExtensionsSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=ExtensionsNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = ExtensionsSupported()
        if not_supported:
            self.not_supported = ExtensionsNotSupported()

class Scheme(XMLStringElement):
    _xml_tag = 's'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class SchemesElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Scheme]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (Scheme)):
            raise TypeError("Scheme element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class SchemesSupported(Supported, SchemesElementList): pass
class SchemesNotSupported(NotSupported, SchemesElementList): pass

class Schemes(XMLElement):
    _xml_tag = 'schemes'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    supported = XMLElementChild('supported', type=SchemesSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=SchemesNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = SchemesSupported()
        if not_supported:
            self.not_supported = SchemesNotSupported()

class ActorPrincipal(XMLEmptyElement):
    _xml_tag = 'principal'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ActorAttendant(XMLEmptyElement):
    _xml_tag = 'attendant'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ActorMsgTaker(XMLEmptyElement):
    _xml_tag = 'msg-taker'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ActorInformation(XMLEmptyElement):
    _xml_tag = 'information'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class ActorElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [ActorPrincipal, ActorAttendant, ActorMsgTaker, ActorInformation]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (ActorPrincipal, ActorAttendant, ActorMsgTaker, ActorInformation)):
            raise TypeError("Actor element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class ActorSupported(Supported, ActorElementList): pass
class ActorNotSupported(NotSupported, ActorElementList): pass

class Actor(XMLElement):
    _xml_tag = 'actor'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    supported = XMLElementChild('supported', type=ActorSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=ActorNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = ActorSupported()
        if not_supported:
            self.not_supported = ActorNotSupported()

class IsFocus(XMLStringElement):
    _xml_tag = 'isfocus'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_value_type = BooleanValue

class Language(XMLStringElement):
    _xml_tag = 'l'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class LanguagesElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Language]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (Language)):
            raise TypeError("Language element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class LanguagesSupported(Supported, LanguagesElementList): pass
class LanguagesNotSupported(NotSupported, LanguagesElementList): pass

class Languages(XMLElement):
    _xml_tag = 'languages'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

    supported = XMLElementChild('supported', type=LanguagesSupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=LanguagesNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = LanguagesSupported()
        if not_supported:
            self.not_supported = LanguagesNotSupported()

class Servcaps(XMLListElement, ServiceExtension):
    _xml_tag = 'servcaps'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = ServcapsExtension

    audio = XMLElementChild('audio', type=Audio, required=False, test_equal=True)
    application = XMLElementChild('application', type=Application, required=False, test_equal=True)
    data = XMLElementChild('data', type=Data, required=False, test_equal=True)
    control = XMLElementChild('control', type=Control, required=False, test_equal=True)
    video = XMLElementChild('video', type=Video, required=False, test_equal=True)
    text = XMLElementChild('text', type=Text, required=False, test_equal=True)
    message = XMLElementChild('message', type=Message, required=False, test_equal=True)
    mime_type = XMLElementChild('mime_type', type=Type, required=False, test_equal=True)
    automata = XMLElementChild('automata', type=Automata, required=False, test_equal=True)
    communication_class = XMLElementChild('communication_class', type=Class, required=False, test_equal=True)
    duplex = XMLElementChild('duplex', type=Duplex, required=False, test_equal=True)
    event_packages = XMLElementChild('event_packages', type=EventPackages, required=False, test_equal=True)
    priority = XMLElementChild('priority', type=Priority, required=False, test_equal=True)
    methods = XMLElementChild('methods', type=Methods, required=False, test_equal=True)
    extensions = XMLElementChild('extensions', type=Extensions, required=False, test_equal=True)
    schemes = XMLElementChild('schemes', type=Schemes, required=False, test_equal=True)
    actor = XMLElementChild('actor', type=Actor, required=False, test_equal=True)
    is_focus = XMLElementChild('is_focus', type=IsFocus, required=False, test_equal=True)
    languages = XMLElementChild('languages', type=Languages, required=False, test_equal=True)

    def __init__(self, audio=None, application=None, data=None, control=None, video=None, text=None, message=None, mime_type=None, automata=None, communication_class=None, duplex=None, event_packages=None, priority=None, methods=None, extensions=None, schemes=None, actor=None, is_focus=None, languages=None, descriptions=[]):
        XMLListElement.__init__(self)
        self.audio = audio
        self.application = application
        self.data = data
        self.control = control
        self.video = video
        self.text = text
        self.message = message
        self.mime_type = mime_type
        self.automata = automata
        self.communication_class = communication_class
        self.duplex = duplex
        self.event_packages = event_packages
        self.priority = priority
        self.methods = methods
        self.extensions = extensions
        self.schemes = schemes
        self.actor = actor
        self.is_focus = is_focus
        self.languages = languages
        self[0:0] = descriptions
        
    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Description]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Description)):
            raise TypeError("Servcaps element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    
Service.register_extension('servcaps', type=Servcaps)


class MobilityFixed(XMLEmptyElement):
    _xml_tag = 'fixed'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MobilityMobile(XMLEmptyElement):
    _xml_tag = 'mobile'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication

class MobilityElementList(XMLListElement):
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [MobilityFixed, MobilityMobile]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass
    def _add_item(self, value):
        if not isinstance(value, (MobilityFixed, MobilityMobile)):
            raise TypeError("Mobility element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class MobilitySupported(Supported, MobilityElementList): pass
class MobilityNotSupported(NotSupported, MobilityElementList): pass

class Mobility(XMLElement):
    _xml_tag = 'mobility'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = MobilityExtension

    supported = XMLElementChild('supported', type=MobilitySupported, required=False, test_equal=True)
    not_supported = XMLElementChild('not_supported', type=MobilityNotSupported, required=False, test_equal=True)

    def __init__(self, supported=True, not_supported=True):
        XMLElement.__init__(self)
        if supported:
            self.supported = MobilitySupported()
        if not_supported:
            self.not_supported = MobilityNotSupported()

class Devcaps(XMLListElement, DeviceExtension):
    _xml_tag = 'devcaps'
    _xml_namespace = caps_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = DevcapsExtension

    mobility = XMLElementChild('mobility', type=Mobility, required=False, test_equal=True)

    def __init__(self, mobility=None, descriptions=[]):
        XMLListElement.__init__(self)
        self.mobility = mobility
        self[0:0] = descriptions

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Description]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Description)):
            raise TypeError("Devcaps element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

Device.register_extension('devcaps', type=Devcaps)


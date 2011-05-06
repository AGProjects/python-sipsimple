# Copyright (C) 2010-2011 AG Projects. See LICENSE for details.
#

"""Parses and produces conference-info messages according to RFC4575."""


__all__ = ['namespace', 
        'ConferenceApplication',
        'ConferenceDescription',
        'ConfUris',
        'ConfUrisEntry',
        'ServiceUris',
        'ServiceUrisEntry',
        'UrisTypeModified',
        'UrisTypeEntry',
        'AvailableMedia',
        'AvailableMediaEntry',
        'Users',
        'User',
        'AssociatedAors',
        'Roles',
        'Role',
        'Endpoint',
        'CallInfo',
        'Sip',
        'Referred',
        'JoiningInfo',
        'DisconnectionInfo',
        'HostInfo',
        'HostInfoUris',
        'ConferenceState',
        'SidebarsByRef',
        'SidebarsByVal',
        'Conference',
        'ConferenceDescriptionExtension',
        # Extensions
        'FileResource',
        'FileResources',
        'Resources']


from sipsimple.payloads import ValidationError, XMLApplication, XMLRootElement, XMLStringElement, XMLElementChild, XMLElement, XMLListElement, XMLAttribute
from sipsimple.util import Timestamp


namespace = 'urn:ietf:params:xml:ns:conference-info'


class ConferenceApplication(XMLApplication): pass
ConferenceApplication.register_namespace(namespace, prefix=None)


# Marker mixins
class ConferenceDescriptionExtension(object): pass


class State(str):
    def __new__(cls, value):
        if value not in ('full', 'partial', 'deleted'):
            raise ValueError("illegal value for state")
        return str.__new__(cls, value)

class Version(str):
    def __new__(cls, value):
        return str.__new__(cls, int(value))

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

class When(XMLStringElement):
    _xml_tag = 'when'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = Timestamp

class Reason(XMLStringElement):
    _xml_tag = 'reason'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class By(XMLStringElement):
    _xml_tag = 'by'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class ExecutionType(XMLElement):
    _xml_tag = None     # To be set by the subclass
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    when = XMLElementChild('when', type=When, required=False, test_equal=True)
    reason = XMLElementChild('reason', type=Reason, required=False, test_equal=True)
    by = XMLElementChild('by', type=By, required=False, test_equal=True)

    def __init__(self, when=None, reason=None, by=None):
        XMLElement.__init__(self)
        self.when = when
        self.reason = reason
        self.by = by

class Uri(XMLStringElement):
    _xml_tag = 'uri'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class DisplayText(XMLStringElement):
    _xml_tag = 'display-text'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class UrisTypePurpose(XMLStringElement):
    _xml_tag = 'purpose'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class UrisTypeModified(ExecutionType):
    _xml_tag = 'modified'

class UrisTypeEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    uri = XMLElementChild('uri', type=Uri, required=True, test_equal=True)
    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    purpose = XMLElementChild('purpose', type=UrisTypePurpose, required=False, test_equal=True)
    modified = XMLElementChild('modified', type=UrisTypeModified, required=False, test_equal=True)

    def __init__(self, uri, state=None, display_text=None, purpose=None, modified=None):
        XMLElement.__init__(self)
        self.uri = uri
        self.state = state
        self.display_text = display_text
        self.purpose = purpose
        self.modified = modified

class UrisTypeList(XMLListElement):
    _xml_tag = None     # Needs to be specified in a subclass
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self[0:0] = entries

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is UrisTypeEntry:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (UrisTypeEntry)):
            raise TypeError("Element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Subject(XMLStringElement):
    _xml_tag = 'subject'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class FreeText(XMLStringElement):
    _xml_tag = 'free-text'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class Keywords(XMLStringElement):
    _xml_tag = 'keywords'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class ConfUrisPurposeValue(str):
    def __new__(cls, value):
        if value not in ('participation', 'streaming'):
            raise ValueError("illegal value for purpose element")
        return str.__new__(cls, value)

class ConfUrisPurpose(UrisTypePurpose):
    _xml_value_type = ConfUrisPurposeValue

class ConfUrisEntry(UrisTypeEntry):
    purpose = XMLElementChild('purpose', type=ConfUrisPurpose, required=False, test_equal=True)

class ConfUris(UrisTypeList):
    _xml_tag = 'conf-uris'

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is ConfUrisEntry:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (ConfUrisEntry)):
            raise TypeError("Conf URIs element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class ServiceUrisPurposeValue(str):
    def __new__(cls, value):
        if value not in ('web-page', 'recording', 'event'):
            raise ValueError("illegal value for purpose element")
        return str.__new__(cls, value)

class ServiceUrisPurpose(UrisTypePurpose):
    _xml_value_type = ServiceUrisPurposeValue

class ServiceUrisEntry(UrisTypeEntry):
    purpose = XMLElementChild('purpose', type=ServiceUrisPurpose, required=False, test_equal=True)

class ServiceUris(UrisTypeList):
    _xml_tag = 'service-uris'

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is ServiceUrisEntry:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (ServiceUrisEntry)):
            raise TypeError("Service URIs element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class MaximumUserCount(XMLStringElement):
    _xml_tag = 'maximum-user-count'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = int

class MediaTypeValue(str):
    def __new__(cls, value):
        if value not in ('audio', 'video', 'text', 'message'):
            raise ValueError("illegal value for type element")
        return str.__new__(cls, value)

class MediaType(XMLStringElement):
    _xml_tag = 'type'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = MediaTypeValue

class MediaTypeStatusValue(str):
    def __new__(cls, value):
        if value not in ('sendrecv', 'sendonly', 'recvonly', 'inactive'):
            raise ValueError("illegal value for status element")
        return str.__new__(cls, value)

class MediaTypeStatus(XMLStringElement):
    _xml_tag = 'status'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = MediaTypeStatusValue

class AvailableMediaEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_children_order = {DisplayText.qname: 0,
                           MediaType.qname: 1,
                           MediaTypeStatus.qname: 2,
                           None: 3}

    label = XMLAttribute('label', type=str, required=True, test_equal=False)

    media_type = XMLElementChild('media_type', type=MediaType, required=True, test_equal=True)
    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    status = XMLElementChild('status', type=MediaTypeStatus, required=False, test_equal=True)

    def __init__(self, label, media_type, display_text=None, status=None):
        XMLElement.__init__(self)
        self.label = label
        self.media_type = media_type
        self.display_text = display_text
        self.status = status

class AvailableMedia(XMLListElement):
    _xml_tag = 'available-media'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self[0:0] = entries

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is AvailableMediaEntry:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (AvailableMediaEntry)):
            raise TypeError("Available media element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class ConferenceDescription(XMLElement):
    _xml_tag = 'conference-description'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_extension_type = ConferenceDescriptionExtension

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    subject = XMLElementChild('subject', type=Subject, required=False, test_equal=True)
    free_text = XMLElementChild('free_text', type=FreeText, required=False, test_equal=True)
    keywords = XMLElementChild('keywords', type=Keywords, required=False, test_equal=True)
    conf_uris = XMLElementChild('conf_uris', type=ConfUris, required=False, test_equal=True)
    service_uris = XMLElementChild('service_uris', type=ServiceUris, required=False, test_equal=True)
    maximum_user_count = XMLElementChild('maximum_user_count', type=MaximumUserCount, required=False, test_equal=True)
    available_media = XMLElementChild('available_media', type=AvailableMedia, required=False, test_equal=True)

    def __init__(self, display_text=None, subject=None, free_text=None, keywords=None, conf_uris=None, service_uris=None, maximum_user_count=None, available_media=None):
        XMLElement.__init__(self)
        self.display_text = display_text
        self.subject = subject
        self.free_text = free_text
        self.keywords = keywords
        self.conf_uris = conf_uris
        self.service_uris = service_uris
        self.maximum_user_count = maximum_user_count
        self.available_media = available_media

class WebPage(XMLStringElement):
    _xml_tag = 'web-page'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class HostInfoUris(UrisTypeList):
    _xml_tag = 'uris'

class HostInfo(XMLElement):
    _xml_tag = 'host-info'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    web_page = XMLElementChild('web_page', type=WebPage, required=False, test_equal=True)
    uris = XMLElementChild('uris', type=HostInfoUris, required=False, test_equal=True)

    def __init__(self, display_text=None, web_page=None, uris=None):
        XMLElement.__init__(self)
        self.display_text = display_text
        self.web_page = web_page
        self.uris = uris

class UserCount(XMLStringElement):
    _xml_tag = 'user-count'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = int

class Active(XMLStringElement):
    _xml_tag = 'active'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = BooleanValue

class Locked(XMLStringElement):
    _xml_tag = 'locked'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = BooleanValue

class ConferenceState(XMLElement):
    _xml_tag = 'conference-state'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    user_count = XMLElementChild('user_count', type=UserCount, required=False, test_equal=True)
    active = XMLElementChild('active', type=Active, required=False, test_equal=True)
    locked = XMLElementChild('locked', type=Locked, required=False, test_equal=True)

    def __init__(self, user_count=None, active=None, locked=None):
        XMLElement.__init__(self)
        self.user_count = user_count
        self.active = active
        self.locked = locked

class AssociatedAors(UrisTypeList):
    _xml_tag = 'associated-aors'

class Role(XMLStringElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class Roles(XMLListElement):
    _xml_tag = 'roles'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    def __init__(self, roles=[]):
        XMLListElement.__init__(self)
        self[0:0] = roles

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is Role:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Role)):
            raise TypeError("Roles element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Languages(XMLStringElement):
    _xml_tag = 'languages'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class CascadedFocus(XMLStringElement):
    _xml_tag = 'cascaded-focus'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class Referred(ExecutionType):
    _xml_tag = 'referred'

class EndpointStatusValue(str):
    def __new__(cls, value):
        if value not in ('connected', 'disconnected', 'on-hold', 'muted-via-focus', 'pending', 'alerting', 'dialing-in', 'dialing-out', 'disconnecting'):
            raise ValueError("illegal value for status element")
        return str.__new__(cls, value)

class EndpointStatus(XMLStringElement):
    _xml_tag = 'status'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = EndpointStatusValue

class JoiningMethodValue(str):
    def __new__(cls, value):
        if value not in ('dialed-in', 'dialed-out', 'focus-owner'):
            raise ValueError("illegal value for joining method element")
        return str.__new__(cls, value)

class JoiningMethod(XMLStringElement):
    _xml_tag = 'joining-method'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = JoiningMethodValue

class JoiningInfo(ExecutionType):
    _xml_tag = 'joining-info'

class DisconnectionMethodValue(str):
    def __new__(cls, value):
        if value not in ('departed', 'booted', 'failed', 'busy'):
            raise ValueError("illegal value for disconnection method element")
        return str.__new__(cls, value)

class DisconnectionMethod(XMLStringElement):
    _xml_tag = 'disconnection-method'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_value_type = DisconnectionMethodValue

class DisconnectionInfo(ExecutionType):
    _xml_tag = 'disconnection-info'

class Label(XMLStringElement):
    _xml_tag = 'label'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class SrcId(XMLStringElement):
    _xml_tag = 'src-id'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class Media(XMLElement):
    _xml_tag = 'media'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    id = XMLAttribute('id', type=str, required=True, test_equal=False)

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    media_type = XMLElementChild('media_type', type=MediaType, required=False, test_equal=True)
    label = XMLElementChild('label', type=Label, required=False, test_equal=True)
    src_id = XMLElementChild('src_id', type=SrcId, required=False, test_equal=True)
    status = XMLElementChild('status', type=MediaTypeStatus, required=False, test_equal=True)

    def __init__(self, id, display_text=None, media_type=None, label=None, src_id=None, status=None):
        XMLElement.__init__(self)
        self.id = id
        self.display_text = display_text
        self.media_type = media_type
        self.label = label
        self.src_id = src_id
        self.status = status

class CallId(XMLStringElement):
    _xml_tag = 'call-id'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class FromTag(XMLStringElement):
    _xml_tag = 'from-tag'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class ToTag(XMLStringElement):
    _xml_tag = 'to-tag'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

class Sip(XMLElement):
    _xml_tag = 'sip'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    call_id = XMLElementChild('call_id', type=CallId, required=False, test_equal=True)
    from_tag = XMLElementChild('from_tag', type=FromTag, required=False, test_equal=True)
    to_tag = XMLElementChild('to_tag', type=ToTag, required=False, test_equal=True)

    def __init__(self, display_text=None, call_id=None, from_tag=None, to_tag=None):
        XMLElement.__init__(self)
        self.display_text = display_text
        self.call_id = call_id
        self.from_tag = from_tag
        self.to_tag = to_tag

class CallInfo(XMLElement):
    _xml_tag = 'call-info'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    sip = XMLElementChild('sip', type=Sip, required=False, test_equal=True)

    def __init__(self, sip=None):
        XMLElement.__init__(self)
        self.sip = sip

class Endpoint(XMLListElement):
    _xml_tag = 'endpoint'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    entity = XMLAttribute('entity', type=str, required=True, test_equal=False)
    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    referred = XMLElementChild('referred', type=Referred, required=False, test_equal=True)
    status = XMLElementChild('status', type=EndpointStatus, required=False, test_equal=True)
    joining_method = XMLElementChild('joining_method', type=JoiningMethod, required=False, test_equal=True)
    joining_info = XMLElementChild('joining_info', type=JoiningInfo, required=False, test_equal=True)
    disconnection_method = XMLElementChild('disconnection_method', type=DisconnectionMethod, required=False, test_equal=True)
    disconnection_info = XMLElementChild('disconnection_info', type=DisconnectionInfo, required=False, test_equal=True)
    call_info = XMLElementChild('call_info', type=CallInfo, required=False, test_equal=True)

    def __init__(self, entity, state='full', display_text=None, referred=None, status=None, joining_method=None, joining_info=None, disconnection_method=None, disconnection_info=None, call_info=None, media=[]):
        XMLListElement.__init__(self)
        self.entity = entity
        self.state = state
        self.display_text = display_text
        self.referred = referred
        self.status = status
        self.joining_method = joining_method
        self.joining_info = joining_info
        self.disconnection_method = disconnection_method
        self.disconnection_info = disconnection_info
        self.call_info = call_info
        self[0:0] = media

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is Media:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Media)):
            raise TypeError("User element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class User(XMLListElement):
    _xml_tag = 'user'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    entity = XMLAttribute('entity', type=str, required=True, test_equal=False)
    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    associated_aors = XMLElementChild('associated_aors', type=AssociatedAors, required=False, test_equal=True)
    roles = XMLElementChild('roles', type=Roles, required=False, test_equal=True)
    languages = XMLElementChild('languages', type=Languages, required=False, test_equal=True)
    cascaded_focus = XMLElementChild('cascaded_focus', type=CascadedFocus, required=False, test_equal=True)

    def __init__(self, entity, state='full', display_text=None, associated_aors=None, roles=None, languages=None, cascaded_focus=None, endpoints=[]):
        XMLListElement.__init__(self)
        self.entity = entity
        self.state = state
        self.display_text = display_text
        self.associated_aors = associated_aors
        self.roles = roles
        self.languages = languages
        self.cascaded_focus = cascaded_focus
        self[0:0] = endpoints

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is Endpoint:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Endpoint)):
            raise TypeError("User element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Users(XMLListElement):
    _xml_tag = 'users'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    def __init__(self, state='full', entries=[]):
        XMLListElement.__init__(self)
        self.state = state
        self[0:0] = entries

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is User:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (User)):
            raise TypeError("Users element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class SidebarsByRef(UrisTypeList):
    _xml_tag = 'sidebars-by-ref'

class SidebarsByVal(XMLListElement):
    _xml_tag = 'sidebars-by-val'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    def __init__(self, state='full', entries=[]):
        XMLListElement.__init__(self)
        self.state = state
        self[0:0] = entries

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and child_cls is SidebarsByValEntry:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (SidebarsByValEntry)):
            raise TypeError("Sidebars-by-val element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class SidebarsByValEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication

    entity = XMLAttribute('entity', type=str, required=True, test_equal=False)
    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    conference_description = XMLElementChild('conference_description', type=ConferenceDescription, required=False, test_equal=True)
    host_info = XMLElementChild('host_info', type=HostInfo, required=False, test_equal=True)
    conference_state = XMLElementChild('conference_state', type=ConferenceState, required=False, test_equal=True)
    users = XMLElementChild('users', type=Users, required=False, test_equal=True)
    sidebars_by_ref = XMLElementChild('sidebars_by_ref', type=SidebarsByRef, required=False, test_equal=True)
    sidebars_by_val = XMLElementChild('sidebars_by_val', type=SidebarsByVal, required=False, test_equal=True)
    
    def __init__(self, entity, state='full', version=None, conference_description=None, host_info=None, conference_state=None, users=None, sidebars_by_ref=None, sidebars_by_val=None):
        XMLElement.__init__(self)
        self.entity = entity
        self.state = state
        self.version = version
        self.conference_description = conference_description
        self.host_info = host_info
        self.conference_state = conference_state
        self.users = users
        self.sidebars_by_ref = sidebars_by_ref
        self.sidebars_by_val = sidebars_by_val
        if self.state == "full" and (self.conference_description is None or self.users is None):
            raise ValidationError("A full conference document must at least include the <conference-description> and <users> child elements.")

class Conference(XMLRootElement):
    content_type = "application/conference-info+xml"

    _xml_tag = 'conference-info'
    _xml_namespace = namespace
    _xml_application = ConferenceApplication
    _xml_schema_file = 'conference.xsd'
    _xml_children_order = {ConferenceDescription.qname: 0,
                           HostInfo.qname: 1,
                           ConferenceState.qname: 2,
                           Users.qname: 3,
                           SidebarsByRef.qname: 4,
                           SidebarsByVal.qname: 5,
                           None: 6}

    entity = XMLAttribute('entity', type=str, required=True, test_equal=False)
    state = XMLAttribute('state', type=State, required=False, test_equal=False)
    version = XMLAttribute('version', type=Version, required=False, test_equal=False)

    conference_description = XMLElementChild('conference_description', type=ConferenceDescription, required=False, test_equal=True)
    host_info = XMLElementChild('host_info', type=HostInfo, required=False, test_equal=True)
    conference_state = XMLElementChild('conference_state', type=ConferenceState, required=False, test_equal=True)
    users = XMLElementChild('users', type=Users, required=False, test_equal=True)
    sidebars_by_ref = XMLElementChild('sidebars_by_ref', type=SidebarsByRef, required=False, test_equal=True)
    sidebars_by_val = XMLElementChild('sidebars_by_val', type=SidebarsByVal, required=False, test_equal=True)
    
    def __init__(self, entity, state='full', version=None, conference_description=None, host_info=None, conference_state=None, users=None, sidebars_by_ref=None, sidebars_by_val=None):
        XMLRootElement.__init__(self)
        self.entity = entity
        self.state = state
        self.version = version
        self.conference_description = conference_description
        self.host_info = host_info
        self.conference_state = conference_state
        self.users = users
        self.sidebars_by_ref = sidebars_by_ref
        self.sidebars_by_val = sidebars_by_val
        if self.state == "full" and (self.conference_description is None or self.users is None):
            raise ValidationError("A full conference document must at least include the <conference-description> and <users> child elements.")


#
# Extensions
#

agp_conf_namespace = 'urn:ag-projects:xml:ns:conference-info'
ConferenceApplication.register_namespace(agp_conf_namespace, prefix='agp-conf')

class FileResource(XMLElement):
    _xml_tag = 'file'
    _xml_namespace = agp_conf_namespace
    _xml_application = ConferenceApplication

    name = XMLAttribute('name', type=unicode, required=True, test_equal=False)
    hash = XMLAttribute('hash', type=str, required=True, test_equal=False)
    size = XMLAttribute('size', type=int, required=True, test_equal=False)
    sender = XMLAttribute('sender', type=str, required=True, test_equal=False)
    status = XMLAttribute('status', type=str, required=True, test_equal=False)

    def __init__(self, name, hash, size, sender, status):
        XMLElement.__init__(self)
        self.name = name
        self.hash = hash
        self.size = size
        self.sender = sender
        self.status = status

class FileResources(XMLListElement):
    _xml_tag = 'files'
    _xml_namespace = agp_conf_namespace
    _xml_application = ConferenceApplication

    def __init__(self, files=[]):
        XMLListElement.__init__(self)
        self[0:0] = files

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is FileResource:
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, FileResource):
            raise TypeError("Element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Resources(XMLElement, ConferenceDescriptionExtension):
    _xml_tag = 'resources'
    _xml_namespace = agp_conf_namespace
    _xml_application = ConferenceApplication

    files = XMLElementChild('files', type=FileResources, required=False, test_equal=True)

    def __init__(self, files=None):
        XMLElement.__init__(self)
        self.files = files

ConferenceDescription.register_extension('resources', Resources)



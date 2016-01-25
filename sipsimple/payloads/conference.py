
# This module is currently broken. It breaks the core assumption of the
# payloads infrastructure, that there is only one element with a given qname
# for every given application.
# Currently this module defines at least 2 different elements with the same
# qname (tag=entry) which are used inside list elements. As a result, when
# the list element tries to lookup the class to use for a given qname, only
# one list element will get the class right, the other will get a wrong class
# because the list element uses the application qname map to determine the
# class and that mapping can only contain 1 mapping from a given qname to a
# class. Since the class it obtains is not the right one, it will be ignored
# as it doesn't match the known item types for that list element and the
# corresponding xml data will also be ignored.
#
# To make matters even worse, this module subclasses XMLElement classes
# without changing their qname, which in turn generates even more overlapping
# classes for a given qname. At least according to the xml schema, all these
# subclasses (which seem to be defined in order to impose some restrictions
# in different cases), seem to be unnecessary. The schema only defines one
# type with a string element that has no resctrictions and is to be used
# in all the places. The code however tries to use a variation of the type
# with restrictions in different places and fails as the correct class cannot
# be identified anymore (see for example all the UrisType subclasses or the
# multiple classes to define purpose elements).
#
# -Dan
#

"""Parses and produces conference-info messages according to RFC4575."""


__all__ = ['namespace', 
        'ConferenceDocument',
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
        'UserExtension',
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


from sipsimple.payloads import ValidationError, XMLDocument, XMLRootElement, XMLStringElement, XMLBooleanElement, XMLDateTimeElement, XMLUnsignedIntElement, XMLAnyURIElement
from sipsimple.payloads import XMLElementChild, XMLElement, XMLListElement, XMLAttribute


namespace = 'urn:ietf:params:xml:ns:conference-info'


class ConferenceDocument(XMLDocument):
    content_type = "application/conference-info+xml"

ConferenceDocument.register_namespace(namespace, prefix=None, schema='conference.xsd')


# Marker mixins
class UserExtension(object): pass

class ConferenceDescriptionExtension(object): pass


class State(str):
    def __new__(cls, value):
        if value not in ('full', 'partial', 'deleted'):
            raise ValueError("illegal value for state")
        return str.__new__(cls, value)


class Version(str):
    def __new__(cls, value):
        return str.__new__(cls, int(value))


class When(XMLDateTimeElement):
    _xml_tag = 'when'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Reason(XMLStringElement):
    _xml_tag = 'reason'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class By(XMLStringElement):
    _xml_tag = 'by'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class ExecutionType(XMLElement):
    _xml_tag = None     # To be set by the subclass
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

    when = XMLElementChild('when', type=When, required=False, test_equal=True)
    reason = XMLElementChild('reason', type=Reason, required=False, test_equal=True)
    by = XMLElementChild('by', type=By, required=False, test_equal=True)

    def __init__(self, when=None, reason=None, by=None):
        XMLElement.__init__(self)
        self.when = when
        self.reason = reason
        self.by = by


class URI(XMLAnyURIElement):
    _xml_tag = 'uri'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class DisplayText(XMLStringElement):
    _xml_tag = 'display-text'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class UrisTypePurpose(XMLStringElement):
    _xml_tag = 'purpose'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class UrisTypeModified(ExecutionType):
    _xml_tag = 'modified'


class UrisTypeEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    uri = XMLElementChild('uri', type=URI, required=True, test_equal=True)
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


class Subject(XMLStringElement):
    _xml_tag = 'subject'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class FreeText(XMLStringElement):
    _xml_tag = 'free-text'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Keywords(XMLStringElement):
    _xml_tag = 'keywords'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class ConfUrisPurposeValue(str):
    def __new__(cls, value):
        if value not in ('participation', 'streaming'):
            raise ValueError("illegal value for purpose element")
        return str.__new__(cls, value)


class ConfUrisPurpose(UrisTypePurpose):
    _xml_value_type = ConfUrisPurposeValue


class ConfUrisEntry(UrisTypeEntry):
    purpose = XMLElementChild('purpose', type=ConfUrisPurpose, required=False, test_equal=True)


class ConfUris(XMLListElement):
    _xml_tag = 'conf-uris'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = ConfUrisEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class ServiceUrisPurposeValue(str):
    def __new__(cls, value):
        if value not in ('web-page', 'recording', 'event'):
            raise ValueError("illegal value for purpose element")
        return str.__new__(cls, value)


class ServiceUrisPurpose(UrisTypePurpose):
    _xml_value_type = ServiceUrisPurposeValue


class ServiceUrisEntry(UrisTypeEntry):
    purpose = XMLElementChild('purpose', type=ServiceUrisPurpose, required=False, test_equal=True)


class ServiceUris(XMLListElement):
    _xml_tag = 'service-uris'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = ServiceUrisEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class MaximumUserCount(XMLUnsignedIntElement):
    _xml_tag = 'maximum-user-count'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class MediaTypeValue(str):
    def __new__(cls, value):
        if value not in ('audio', 'video', 'text', 'message'):
            raise ValueError("illegal value for type element")
        return str.__new__(cls, value)


class MediaType(XMLStringElement):
    _xml_tag = 'type'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_value_type = MediaTypeValue


class MediaTypeStatusValue(str):
    def __new__(cls, value):
        if value not in ('sendrecv', 'sendonly', 'recvonly', 'inactive'):
            raise ValueError("illegal value for status element")
        return str.__new__(cls, value)


class MediaTypeStatus(XMLStringElement):
    _xml_tag = 'status'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_value_type = MediaTypeStatusValue


class AvailableMediaEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
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
    _xml_document = ConferenceDocument
    _xml_item_type = AvailableMediaEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class ConferenceDescription(XMLElement):
    _xml_tag = 'conference-description'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
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
    _xml_document = ConferenceDocument


class HostInfoUris(XMLListElement):
    _xml_tag = 'uris'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = UrisTypeEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class HostInfo(XMLElement):
    _xml_tag = 'host-info'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

    display_text = XMLElementChild('display_text', type=DisplayText, required=False, test_equal=True)
    web_page = XMLElementChild('web_page', type=WebPage, required=False, test_equal=True)
    uris = XMLElementChild('uris', type=HostInfoUris, required=False, test_equal=True)

    def __init__(self, display_text=None, web_page=None, uris=None):
        XMLElement.__init__(self)
        self.display_text = display_text
        self.web_page = web_page
        self.uris = uris


class UserCount(XMLUnsignedIntElement):
    _xml_tag = 'user-count'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Active(XMLBooleanElement):
    _xml_tag = 'active'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Locked(XMLBooleanElement):
    _xml_tag = 'locked'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class ConferenceState(XMLElement):
    _xml_tag = 'conference-state'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

    user_count = XMLElementChild('user_count', type=UserCount, required=False, test_equal=True)
    active = XMLElementChild('active', type=Active, required=False, test_equal=True)
    locked = XMLElementChild('locked', type=Locked, required=False, test_equal=True)

    def __init__(self, user_count=None, active=None, locked=None):
        XMLElement.__init__(self)
        self.user_count = user_count
        self.active = active
        self.locked = locked


class AssociatedAors(XMLListElement):
    _xml_tag = 'associated-aors'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = UrisTypeEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class Role(XMLStringElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Roles(XMLListElement):
    _xml_tag = 'roles'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = Role

    def __init__(self, roles=[]):
        XMLListElement.__init__(self)
        self.update(roles)


class Languages(XMLStringElement):
    _xml_tag = 'languages'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class CascadedFocus(XMLStringElement):
    _xml_tag = 'cascaded-focus'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


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
    _xml_document = ConferenceDocument
    _xml_value_type = EndpointStatusValue


class JoiningMethodValue(str):
    def __new__(cls, value):
        if value not in ('dialed-in', 'dialed-out', 'focus-owner'):
            raise ValueError("illegal value for joining method element")
        return str.__new__(cls, value)


class JoiningMethod(XMLStringElement):
    _xml_tag = 'joining-method'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
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
    _xml_document = ConferenceDocument
    _xml_value_type = DisconnectionMethodValue


class DisconnectionInfo(ExecutionType):
    _xml_tag = 'disconnection-info'


class Label(XMLStringElement):
    _xml_tag = 'label'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class SrcId(XMLStringElement):
    _xml_tag = 'src-id'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Media(XMLElement):
    _xml_tag = 'media'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

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
    _xml_document = ConferenceDocument


class FromTag(XMLStringElement):
    _xml_tag = 'from-tag'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class ToTag(XMLStringElement):
    _xml_tag = 'to-tag'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument


class Sip(XMLElement):
    _xml_tag = 'sip'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

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
    _xml_document = ConferenceDocument

    sip = XMLElementChild('sip', type=Sip, required=False, test_equal=True)

    def __init__(self, sip=None):
        XMLElement.__init__(self)
        self.sip = sip


class Endpoint(XMLListElement):
    _xml_tag = 'endpoint'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = Media

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
        self.update(media)

    def __repr__(self):
        args = ('entity', 'state', 'display_text', 'referred', 'status', 'joining_method', 'joining_info', 'disconnection_method', 'disconnection_info', 'call_info')
        return "%s(%s, media=%r)" % (self.__class__.__name__, ', '.join("%s=%r" % (name, getattr(self, name)) for name in args), list(self))


class User(XMLListElement):
    _xml_tag = 'user'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = Endpoint
    _xml_extension_type = UserExtension

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
        self.update(endpoints)

    def __repr__(self):
        args = ('entity', 'state', 'display_text', 'associated_aors', 'roles', 'languages', 'cascaded_focus')
        return "%s(%s, endpoints=%r)" % (self.__class__.__name__, ', '.join("%s=%r" % (name, getattr(self, name)) for name in args), list(self))


class Users(XMLListElement):
    _xml_tag = 'users'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = User

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    def __init__(self, state='full', users=[]):
        XMLListElement.__init__(self)
        self.state = state
        self.update(users)

    def __repr__(self):
        return "%s(state=%r, users=%r)" % (self.__class__.__name__, self.state, list(self))


class SidebarsByRef(XMLListElement):
    _xml_tag = 'sidebars-by-ref'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = UrisTypeEntry

    def __init__(self, entries=[]):
        XMLListElement.__init__(self)
        self.update(entries)


class SidebarsByVal(XMLListElement):
    _xml_tag = 'sidebars-by-val'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
    _xml_item_type = None # will be set later, after the item type is defined below

    state = XMLAttribute('state', type=State, required=False, test_equal=False)

    def __init__(self, state='full', entries=[]):
        XMLListElement.__init__(self)
        self.state = state
        self.update(entries)

    def __repr__(self):
        return "%s(state=%r, entries=%r)" % (self.__class__.__name__, self.state, list(self))


class SidebarsByValEntry(XMLElement):
    _xml_tag = 'entry'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument

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

SidebarsByVal._xml_item_type = SidebarsByValEntry


class Conference(XMLRootElement):
    _xml_tag = 'conference-info'
    _xml_namespace = namespace
    _xml_document = ConferenceDocument
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
ConferenceDocument.register_namespace(agp_conf_namespace, prefix='agp-conf')


class FileResource(XMLElement):
    _xml_tag = 'file'
    _xml_namespace = agp_conf_namespace
    _xml_document = ConferenceDocument

    name = XMLAttribute('name', type=unicode, required=True, test_equal=False)
    hash = XMLAttribute('hash', type=str, required=True, test_equal=False)
    size = XMLAttribute('size', type=int, required=True, test_equal=False)
    sender = XMLAttribute('sender', type=unicode, required=True, test_equal=False)
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
    _xml_document = ConferenceDocument
    _xml_item_type = FileResource

    def __init__(self, files=[]):
        XMLListElement.__init__(self)
        self.update(files)


class Resources(XMLElement, ConferenceDescriptionExtension):
    _xml_tag = 'resources'
    _xml_namespace = agp_conf_namespace
    _xml_document = ConferenceDocument

    files = XMLElementChild('files', type=FileResources, required=False, test_equal=True)

    def __init__(self, files=None):
        XMLElement.__init__(self)
        self.files = files

ConferenceDescription.register_extension('resources', Resources)


class ScreenImageURL(XMLStringElement, UserExtension):
    _xml_tag = 'screen_image_url'
    _xml_namespace = agp_conf_namespace
    _xml_document = ConferenceDocument

User.register_extension('screen_image_url', ScreenImageURL)




"""
RPID handling according to RFC4480

This module provides an extension to PIDF to support rich presence.
"""


__all__ = ['namespace',
           'ActivityElement',
           'MoodElement',
           'PlaceTypeElement',
           'PrivacyElement',
           'RelationshipElement',
           'ServiceClassElement',
           'SphereElement',
           'Note',
           'Other',
           'Activities',
           'Mood',
           'PlaceIs',
           'AudioPlaceInformation',
           'VideoPlaceInformation',
           'TextPlaceInformation',
           'PlaceType',
           'AudioPrivacy',
           'TextPrivacy',
           'VideoPrivacy',
           'Privacy',
           'Relationship',
           'ServiceClass',
           'Sphere',
           'StatusIcon',
           'TimeOffset',
           'UserInput',
           'Class']


from lxml import etree

from sipsimple.payloads import ValidationError, XMLElementType, XMLEmptyElementRegistryType, XMLAttribute, XMLElementChild, XMLStringChoiceChild
from sipsimple.payloads import XMLElement, XMLEmptyElement, XMLStringElement, XMLLocalizedStringElement, XMLStringListElement
from sipsimple.payloads.pidf import PIDFDocument, ServiceExtension, PersonExtension, DeviceExtension, Note, NoteMap, NoteList, Service, Person, Device
from sipsimple.payloads.datatypes import UnsignedLong, DateTime, ID


namespace = 'urn:ietf:params:xml:ns:pidf:rpid'
PIDFDocument.register_namespace(namespace, prefix='rpid', schema='rpid.xsd')


## Marker mixins

class ActivityElement(object): pass
class MoodElement(object): pass
class PlaceTypeElement(object): pass
class PrivacyElement(object): pass
class RelationshipElement(object): pass
class ServiceClassElement(object): pass
class SphereElement(object): pass


## Attribute value types

class AudioPlaceValue(str):
    def __new__(cls, value):
        if value not in ('noisy', 'ok', 'quiet', 'unknown'):
            raise ValueError("illegal value for audio place-is")
        return str.__new__(cls, value)


class VideoPlaceValue(str):
    def __new__(cls, value):
        if value not in ('toobright', 'ok', 'dark', 'unknown'):
            raise ValueError("illegal value for video place-is")
        return str.__new__(cls, value)


class TextPlaceValue(str):
    def __new__(cls, value):
        if value not in ('uncomfortable', 'inappropriate', 'ok', 'unknown'):
            raise ValueError("illegal value for text place-is")
        return str.__new__(cls, value)


class UserInputValue(str):
    def __new__(cls, value):
        if value not in ('active', 'idle'):
            raise ValueError("illegal value for user-input")
        return str.__new__(cls, value)


## Elements

class RPIDNote(XMLLocalizedStringElement):
    _xml_tag = 'note'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    def __unicode__(self):
        return Note(self.value, self.lang)

    @classmethod
    def from_string(cls, value):
        if isinstance(value, Note):
            return cls(value, value.lang)
        elif isinstance(value, basestring):
            return cls(value)
        else:
            raise ValueError("expected str/unicode instance, got %s instead" % value.__class__.__name__)


class RPIDOther(XMLLocalizedStringElement):
    _xml_tag = 'other'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    def __unicode__(self):
        return Other(self.value, self.lang)

    @classmethod
    def from_string(cls, value):
        if isinstance(value, Other):
            return cls(value, value.lang)
        elif isinstance(value, basestring):
            return cls(value)
        else:
            raise ValueError("expected str/unicode instance, got %s instead" % value.__class__.__name__)


class Other(Note): pass


class ActivityRegistry(object):
    __metaclass__ = XMLEmptyElementRegistryType

    _xml_namespace = namespace
    _xml_document = PIDFDocument

    names = ('appointment', 'away', 'breakfast', 'busy', 'dinner',
             'holiday', 'in-transit', 'looking-for-work', 'meal', 'meeting',
             'on-the-phone', 'performance', 'permanent-absence', 'playing',
             'presentation', 'shopping', 'sleeping', 'spectator', 'steering',
             'travel', 'tv', 'vacation', 'working', 'worship', 'unknown')


class Activities(XMLStringListElement, PersonExtension):
    _xml_tag = 'activities'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_children_order = {RPIDNote.qname: 0}
    _xml_item_registry = ActivityRegistry
    _xml_item_other_type = RPIDOther
    _xml_item_extension_type = ActivityElement

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)

    _note_map = NoteMap()

    def __init__(self, id=None, since=None, until=None, activities=[], notes=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        self.update(activities)
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, Activities):
            return super(Activities, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.since, self.until, list(self), list(self.notes))

    def _parse_element(self, element):
        super(Activities, self)._parse_element(element)
        self.notes._parse_element(element)

    def _build_element(self):
        super(Activities, self)._build_element()
        self.notes._build_element()

    def add(self, activity):
        if isinstance(activity, basestring):
            if activity in self._xml_item_registry.names:
                activity = self._xml_item_registry.class_map[activity]()
            else:
                activity = self._xml_item_other_type.from_string(activity)
        unknown_activity = self._xml_item_registry.class_map['unknown']()
        if activity == unknown_activity or unknown_activity in self._element_map.itervalues():
            self.clear()
        super(Activities, self).add(activity)

    def check_validity(self):
        if not self:
            raise ValidationError("Activity element must have at least one value")
        super(Activities, self).check_validity()

Person.register_extension('activities', type=Activities)


class MoodRegistry(object):
    __metaclass__ = XMLEmptyElementRegistryType

    _xml_namespace = namespace
    _xml_document = PIDFDocument

    names = ('afraid', 'amazed', 'angry', 'annoyed', 'anxious', 'ashamed',
             'bored', 'brave', 'calm', 'cold', 'confused', 'contended',
             'cranky', 'curious', 'depressed', 'disappointed', 'disgusted',
             'distracted', 'embarrassed', 'excited', 'flirtatious',
             'frustrated', 'grumpy', 'guilty', 'happy', 'hot', 'humbled',
             'humiliated', 'hungry', 'hurt', 'impressed', 'in_awe', 'in_love',
             'indignant', 'interested', 'invisible', 'jealous', 'lonely',
             'mean', 'moody', 'nervous', 'neutral', 'offended', 'playful',
             'proud', 'relieved', 'remorseful', 'restless', 'sad',
             'sarcastic', 'serious', 'shocked', 'shy', 'sick', 'sleepy',
             'stressed', 'surprised', 'thirsty', 'worried', 'unknown')


class Mood(XMLStringListElement, PersonExtension):
    _xml_tag = 'mood'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_extension_type = MoodElement
    _xml_children_order = {RPIDNote.qname: 0}
    _xml_item_registry = MoodRegistry
    _xml_item_other_type = RPIDOther
    _xml_item_extension_type = MoodElement

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)

    _note_map = NoteMap()

    def __init__(self, id=None, since=None, until=None, moods=[], notes=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        self.update(moods)
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, Mood):
            return super(Mood, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.since, self.until, list(self), list(self.notes))

    def _parse_element(self, element):
        super(Mood, self)._parse_element(element)
        self.notes._parse_element(element)

    def _build_element(self):
        super(Mood, self)._build_element()
        self.notes._build_element()

    def add(self, mood):
        if isinstance(mood, basestring):
            if mood in self._xml_item_registry.names:
                mood = self._xml_item_registry.class_map[mood]()
            else:
                mood = self._xml_item_other_type.from_string(mood)
        unknown_mood = self._xml_item_registry.class_map['unknown']()
        if mood == unknown_mood or unknown_mood in self._element_map.itervalues():
            self.clear()
        super(Mood, self).add(mood)

    def check_validity(self):
        if not self:
            raise ValidationError("Mood element must have at least one value")
        super(Mood, self).check_validity()

Person.register_extension('mood', type=Mood)


class AudioPlaceInformation(XMLStringElement):
    _xml_tag = 'audio'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_value_type = AudioPlaceValue


class VideoPlaceInformation(XMLStringElement):
    _xml_tag = 'video'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_value_type = VideoPlaceValue


class TextPlaceInformation(XMLStringElement):
    _xml_tag = 'text'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_value_type = TextPlaceValue


class PlaceIs(XMLElement, PersonExtension):
    _xml_tag = 'place-is'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_children_order = {RPIDNote.qname: 0,
                           AudioPlaceInformation.qname: 1,
                           VideoPlaceInformation.qname: 2,
                           TextPlaceInformation.qname: 3}

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)
    audio = XMLElementChild('audio', type=AudioPlaceInformation, required=False, test_equal=True)
    video = XMLElementChild('video', type=VideoPlaceInformation, required=False, test_equal=True)
    text = XMLElementChild('text', type=TextPlaceInformation, required=False, test_equal=True)

    _note_map = NoteMap()

    def __init__(self, id=None, since=None, until=None, audio=None, video=None, text=None, notes=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        self.audio = audio
        self.video = video
        self.text = text
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, PlaceIs):
            return super(PlaceIs, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.since, self.until, self.audio, self.video, self.text, list(self.notes))

    def _parse_element(self, element):
        self.notes._parse_element(element)

    def _build_element(self):
        self.notes._build_element()

Person.register_extension('place_is', type=PlaceIs)


class PlaceType(XMLElement, PersonExtension):
    _xml_tag = 'place-type'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_children_order = {RPIDNote.qname: 0}

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)
    value = XMLStringChoiceChild('value', other_type=RPIDOther, extension_type=PlaceTypeElement)

    _note_map = NoteMap()

    def __init__(self, id=None, since=None, until=None, placetype=None, notes=[]):
        super(PlaceType, self).__init__()
        self.id = id
        self.since = since
        self.until = until
        self.value = placetype
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, PlaceType):
            return super(PlaceType, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.since, self.until, self.value, list(self.notes))

    def _parse_element(self, element):
        self.notes._parse_element(element)

    def _build_element(self):
        self.notes._build_element()

Person.register_extension('place_type', type=PlaceType)


class AudioPrivacy(XMLEmptyElement):
    _xml_tag = 'audio'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class TextPrivacy(XMLEmptyElement):
    _xml_tag = 'text'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class VideoPrivacy(XMLEmptyElement):
    _xml_tag = 'video'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class PrivacyType(XMLElementType):
    def __init__(cls, name, bases, dct):
        super(PrivacyType, cls).__init__(name, bases, dct)
        child_attributes = (getattr(cls, name) for name in dir(cls) if type(getattr(cls, name)) is XMLElementChild)
        cls._privacy_attributes = tuple(attr.name for attr in child_attributes if attr.name in ('audio', 'text', 'video') or issubclass(attr.type, PrivacyElement))

class Privacy(XMLElement, PersonExtension):
    __metaclass__ = PrivacyType

    _xml_tag = 'privacy'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_children_order = {RPIDNote.qname: 0,
                           AudioPrivacy.qname: 1,
                           TextPrivacy.qname: 2,
                           VideoPrivacy.qname: 3}

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)

    audio = XMLElementChild('audio', type=AudioPrivacy, required=False, test_equal=True)
    text = XMLElementChild('text', type=TextPrivacy, required=False, test_equal=True)
    video = XMLElementChild('video', type=VideoPrivacy, required=False, test_equal=True)
    unknown = property(lambda self: all(getattr(self, name) is None for name in self._privacy_attributes))

    _note_map = NoteMap()

    def __init__(self, id=None, since=None, until=None, notes=[], audio=False, text=False, video=False):
        super(Privacy, self).__init__()
        self.id = id
        self.since = since
        self.until = until
        self.audio = audio
        self.text = text
        self.video = video
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, Privacy):
            return super(Privacy, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.since, self.until, list(self.notes), self.audio, self.text, self.video)

    def _parse_element(self, element):
        self.notes._parse_element(element)

    def _build_element(self):
        if self.unknown:
            if self.element.find('{%s}unknown' % self._xml_namespace) is None:
                etree.SubElement(self.element, '{%s}unknown' % self._xml_namespace, nsmap=self._xml_document.nsmap)
        else:
            unknown_element = self.element.find('{%s}unknown' % self._xml_namespace)
            if unknown_element is not None:
                self.element.remove(unknown_element)
        self.notes._build_element()

Person.register_extension('privacy', type=Privacy)


class RelationshipRegistry(object):
    __metaclass__ = XMLEmptyElementRegistryType

    _xml_namespace = namespace
    _xml_document = PIDFDocument

    names = ('assistant', 'associate', 'family', 'friend', 'self', 'supervisor', 'unknown')


class Relationship(XMLElement, ServiceExtension):
    _xml_tag = 'relationship'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_children_order = {RPIDNote: 0}

    value = XMLStringChoiceChild('value', registry=RelationshipRegistry, other_type=RPIDOther, extension_type=RelationshipElement)

    _note_map = NoteMap()

    def __init__(self, relationship='self', notes=[]):
        XMLElement.__init__(self)
        self.value = relationship
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, Relationship):
            return super(Relationship, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.value, list(self.notes))

    def _parse_element(self, element):
        self.notes._parse_element(element)

    def _build_element(self):
        self.notes._build_element()

Service.register_extension('relationship', type=Relationship)


class ServiceClassRegistry(object):
    __metaclass__ = XMLEmptyElementRegistryType

    _xml_namespace = namespace
    _xml_document = PIDFDocument

    names = ('courier', 'electronic', 'freight', 'in-person', 'postal', 'unknown')


class ServiceClass(XMLElement, ServiceExtension):
    _xml_tag = 'service-class'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    value = XMLStringChoiceChild('value', registry=ServiceClassRegistry, extension_type=ServiceClassElement)

    _note_map = NoteMap()

    def __init__(self, service_class=None, notes=[]):
        XMLElement.__init__(self)
        self.value = service_class
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, RPIDNote)

    def __eq__(self, other):
        if isinstance(other, ServiceClass):
            return super(ServiceClass, self).__eq__(other) and self.notes == other.notes
        else:
            return NotImplemented

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.value, list(self.notes))

    def _parse_element(self, element):
        self.notes._parse_element(element)

    def _build_element(self):
        self.notes._build_element()

Service.register_extension('service_class', type=ServiceClass)


class SphereRegistry(object):
    __metaclass__ = XMLEmptyElementRegistryType

    _xml_namespace = namespace
    _xml_document = PIDFDocument

    names = ('home', 'work', 'unknown')


class Sphere(XMLElement, PersonExtension):
    _xml_tag = 'sphere'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    id = XMLAttribute('id', type=ID, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)
    value = XMLStringChoiceChild('value', registry=SphereRegistry, extension_type=SphereElement)

    def __init__(self, value=None, id=None, since=None, until=None):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        self.value = value

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.value, self.id, self.since, self.until)

Person.register_extension('sphere', type=Sphere)


class StatusIcon(XMLStringElement, ServiceExtension, PersonExtension):
    _xml_tag = 'status-icon'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)

    def __init__(self, value=None, id=None, since=None, until=None):
        XMLStringElement.__init__(self, value)
        self.id = id
        self.since = since
        self.until = until

Person.register_extension('status_icon', type=StatusIcon)
Service.register_extension('status_icon', type=StatusIcon)


class TimeOffset(XMLStringElement, PersonExtension):
    _xml_tag = 'time-offset'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=DateTime, required=False, test_equal=True)
    until = XMLAttribute('until', type=DateTime, required=False, test_equal=True)
    description = XMLAttribute('description', type=str, required=False, test_equal=True)

    def __init__(self, value=None, id=None, since=None, until=None, description=None):
        if value is None:
            value = DateTime.now().utcoffset().seconds / 60
        XMLStringElement.__init__(self, str(value))
        self.id = id
        self.since = since
        self.until = until
        self.description = description

    def __int__(self):
        return int(self.value)

Person.register_extension('time_offset', type=TimeOffset)


class UserInput(XMLStringElement, ServiceExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'user-input'
    _xml_namespace = namespace
    _xml_document = PIDFDocument
    _xml_value_type = UserInputValue

    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    last_input = XMLAttribute('last_input', xmlname='last-input', type=DateTime, required=False, test_equal=True)
    idle_threshold = XMLAttribute('idle_threshold', xmlname='idle-threshold', type=UnsignedLong, required=False, test_equal=True)

    def __init__(self, value='active', id=None, last_input=None, idle_threshold=None):
        XMLStringElement.__init__(self, value)
        self.id = id
        self.last_input = last_input
        self.idle_threshold = idle_threshold

Service.register_extension('user_input', type=UserInput)
Person.register_extension('user_input', type=UserInput)
Device.register_extension('user_input', type=UserInput)


class Class(XMLStringElement, ServiceExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'class'
    _xml_namespace = namespace
    _xml_document = PIDFDocument

Service.register_extension('rpid_class', type=Class)
Person.register_extension('rpid_class', type=Class)
Device.register_extension('rpid_class', type=Class)



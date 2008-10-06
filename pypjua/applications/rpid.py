"""RPID handling according to RFC4480

This module provides an extension to PIDF (module pypjua.applications.pidf) to
support rich presence.
"""

from pypjua.applications import XMLExtension, XMLElement, XMLListElement, XMLEmptyElement, XMLStringElement, XMLChoiceElement
from pypjua.applications.pidf import PIDFTopElement, PIDF, PIDFMeta, TupleExtension, Timestamp, Note, NoteList, Tuple
from pypjua.applications.presdm import PersonExtension, DeviceExtension, Person, Device

__all__ = ['_namespace_',
           'PlaceTypeElement',
           'PrivacyElement',
           'RPIDNote',
           'Activities',
           'Mood',
           'PlaceIs',
           'Audio',
           'Video',
           'Text',
           'PlaceType',
           'Privacy',
           'Relationship',
           'ServiceClass',
           'Sphere',
           'StatusIcon',
           'TimeOffset',
           'UserInput',
           'Class',
           'Other']

_namespace_ = 'urn:ietf:params:xml:ns:pidf:rpid'


# Mixin types for extenisibility
class PlaceTypeElement(object): pass
class PrivacyElement(object): pass

class RPIDNote(Note):
    _xml_tag = 'note'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Activities(XMLChoiceElement, PersonExtension):
    _xml_tag = 'activities'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}
    _xml_values = set(('appointment', 'away', 'breakfast', 'busy', 'dinner',
                       'holiday', 'in transit', 'looking for work', 'meal', 'meeting',
                       'on the phone', 'performance', 'permanent absence', 'playing',
                       'presentation', 'shopping', 'sleeping', 'spectator', 'sterring',
                       'travel', 'tv', 'vacation', 'working', 'worship', 'unknown'))
    _xml_value_maps = {'in-transit': 'in transit', 'looking-for-work': 'looking for work',
                       'on-the-phone': 'on the phone', 'permanent-absence': 'permanent absence'}
    _xml_default_value = 'unknown'
    _xml_allow_many = True
    _xml_allow_other = True

    def __init__(self, id=None, since=None, until=None, notes=[], activities=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        XMLChoiceElement.__init__(self, activities)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLChoiceElement._build_element(self, element, nsmap)

class Mood(XMLChoiceElement, PersonExtension):
    _xml_tag = 'mood'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}
    _xml_values = set(('afraid', 'amazed', 'angry', 'annoyed', 'anxious', 'ashamed',
                       'bored', 'brave', 'calm', 'cold', 'confused', 'contended',
                       'cranky', 'curious', 'depressed', 'disappointed', 'disgusted',
                       'distracted', 'embarrassed', 'excited', 'flirtatious',
                       'frustrated', 'grumpy', 'guilty', 'happy', 'hot', 'humbled',
                       'humiliated', 'hungry', 'hurt', 'impressed', 'in awe',
                       'in_love', 'indignant', 'interested', 'invisible', 'jealous',
                       'lonely', 'mean', 'moody', 'nervous', 'neutral', 'offended',
                       'playful', 'proud', 'relieved', 'remorseful', 'restless',
                       'sad', 'sarcastic', 'serious', 'shocked', 'shy', 'sick',
                       'sleepy', 'stressed', 'surprised', 'thirsty', 'worried', 'unknown'))
    _xml_value_maps = {'in_awe': 'in awe', 'in_love': 'in love'}
    _xml_default_value = 'unknown'
    _xml_allow_many = True
    _xml_allow_other = True

    def __init__(self, id=None, since=None, until=None, notes=[], moods=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        XMLChoiceElement.__init__(self, moods)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLChoiceElement._build_element(self, element, nsmap)

class Audio(XMLChoiceElement):
    _xml_tag = 'audio'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('noisy', 'ok', 'quiet', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_allow_many = False
    _xml_allow_other = False

class Video(XMLChoiceElement):
    _xml_tag = 'video'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('toobright', 'ok', 'dark', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_allow_many = False
    _xml_allow_other = False

class Text(XMLChoiceElement):
    _xml_tag = 'text'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('uncomfortable', 'inappropriate', 'ok', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_allow_many = False
    _xml_allow_other = False

class PlaceIs(XMLElement, PersonExtension):
    _xml_tag = 'place-is'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, audio=None, video=None, text=None, notes=[]):
        self.id = id
        self.since = since
        self.until = until
        self.audio = audio
        self.video = video
        self.text = text
        self.notes = NoteList()
    
    def _parse_element(self, element):
        self.audio = None
        self.video = None
        self.text = None
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            elif child.tag == Audio.qname:
                self.audio = Audio.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Video.qname:
                self.video = Video.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Text.qname:
                self.text = Text.from_element(child, xml_meta=self._xml_meta)
    
    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)

class PlaceType(XMLListElement, PersonExtension):
    _xml_tag = 'place-type'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, notes=[], placetypes=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        self[0:0] = placetypes

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            else:
                child_cls = self._xml_meta.get(child.tag)
                if child_cls is not None:
                    self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, PlaceTypeElement):
            raise TypeError("PlaceType elements can only contain PlaceTypeElement children, got %s instead" % value.__class__.__name__)
        return value

class Other(XMLStringElement, PlaceTypeElement):
    _xml_tag = 'other'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = True

class Privacy(XMLListElement, PersonExtension):
    _xml_tag = 'privacy'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, notes=[], audio=False, text=False, video=False, privacy=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        self.audio = audio
        self.text = text
        self.video = video
        self[0:0] = privacy

    def _parse_element(self, element):
        self.notes = NoteList()
        self.audio = False
        self.text = False
        self.video = False
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            elif child.tag == '{%s}audio' % _namespace_:
                self.audio = True
            elif child.tag == '{%s}text' % _namespace_:
                self.text = True
            elif child.tag == '{%s}video' % _namespace_:
                self.video = True
            else:
                child_cls = self._xml_meta.get(child.tag)
                if child_cls is not None:
                    self.append(child_cls.from_element(child, xml_meta=self._xml_meta))

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        if len(self) == 0 and not self.audio and not self.text and not self.video:
            etree.SubElement(element, '{%s}unknown' % _namespace_, nsmap=nsmap)
        else:
            if self.audio:
                etree.SubElement(element, '{%s}audio' % _namespace_, nsmap=nsmap)
            if self.text:
                etree.SubElement(element, '{%s}text' % _namespace_, nsmap=nsmap)
            if self.video:
                etree.SubElement(element, '{%s}video' % _namespace_, nsmap=nsmap)
            for child in self:
                child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, PrivacyElement):
            raise TypeError("Privacy elements can only contain PrivacyElement children, got %s instead" % value.__class__.__name__)
        return value

class Relationship(XMLChoiceElement, TupleExtension):
    _xml_tag = 'relationship'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('assistant', 'associate', 'family', 'friend', 'self',
                       'supervisor', 'unknown'))
    _xml_default_value = 'self'
    _xml_allow_many = False
    _xml_allow_other = True

    def __init__(self, relationship=None, notes=[]):
        self.notes = NoteList()
        Relationship.__init__(self, (relationship is None) and [] or [relationship])

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLChoiceElement._build_element(self, element, nsmap)

class ServiceClass(XMLChoiceElement, TupleExtension):
    _xml_tag = 'service-class'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('courier', 'electronic', 'freight', 'in person', 'postal', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_allow_many = False
    _xml_allow_other = False

    def __init__(self, service_class=None, notes=[]):
        self.notes = NoteList()
        Relationship.__init__(self, (service_class is None) and [] or [service_class])

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLChoiceElement._build_element(self, element, nsmap)

class Sphere(XMLChoiceElement, PersonExtension):
    _xml_tag = 'sphere'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}
    _xml_values = set(('home', 'work', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_allow_many = False
    _xml_allow_other = False

    def __init__(self, sphere=None, id=None, since=None, until=None):
        self.id = id
        self.since = since
        self.until = until
        XMLChoiceElement.__init__(self, (sphere is None) and [] or [sphere])

class StatusIcon(XMLStringElement, TupleExtension, PersonExtension):
    _xml_tag = 'status-icon'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}
    
    def __init__(self, value=None, id=None, since=None, until=None):
        self.id = id
        self.since = since
        self.until = until
        XMLStringElement.__init__(self, value)

class TimeOffset(XMLStringElement, PersonExtension):
    _xml_tag = 'time-offset'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp},
                  'description': {}}
    
    def __init__(self, value=None, description=None, id=None, since=None, until=None):
        self.id = id
        self.since = since
        self.until = until
        self.description = description
        XMLStringElement.__init__(self, str(value))

class UserInput(XMLStringElement, TupleExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'user-input'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False
    _xml_values = ('active', 'idle')
    _xml_attrs = {'id': {'id_attribute': True},
                  'last_input': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'last-input'},
                  'idle_threshold': {'xml_attribute': 'idle-threshold'}}
    
    def __init__(self, value=None, id=None, last_input=None, idle_threshold=None):
        self.id = id
        self.last_input = since
        self.idle_threshold = idle_threshold
        XMLStringElement.__init__(self, value)

class Class(XMLStringElement, TupleExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'class'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

class RPIDExtension(XMLExtension):
    _xml_ext_def = [(Activities, [(Person, {'attribute': 'activities'})]),
                    (Mood, [(Person, {'attribute': 'mood'})]),
                    (PlaceIs, [(Person, {'attribute': 'place_is'})]),
                    (PlaceType, [(Person, {'attribute': 'place_type'})]),
                    (Privacy, [(Person, {'attribute': 'privacy'})]),
                    (Relationship, [(Tuple, {'attribute': 'relationship'})]),
                    (ServiceClass, [(Tuple, {'attribute': 'service_class'})]),
                    (Sphere, [(Person, {'attribute': 'sphere'})]),
                    (StatusIcon, [(Tuple, {'attribute': 'status_icon'}),
                                  (Person, {'attribute': 'status_icon'})]),
                    (TimeOffset, [(Person, {'attribute': 'time_offset'})]),
                    (UserInput, [(Tuple, {'attribute': 'user_input'}),
                                 (Person, {'attribute': 'user_input'}),
                                 (Device, {'attribute': 'user_input'})]),
                    (Class, [(Tuple, {'attribute': 'rpid_class'}),
                             (Person, {'attribute': 'rpid_class'}),
                             (Device, {'attribute': 'rpid_class'})]),
                    (RPIDNote, []),
                    (Audio, []),
                    (Video, []),
                    (Text, []),
                    (Other, [])]
    _xml_namespace = _namespace_
    _xml_prefix = 'rpid'
    _xml_schema_file = 'rpid.xsd'

PIDF.registerExtension(RPIDExtension)

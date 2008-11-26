"""RPID handling according to RFC4480

This module provides an extension to PIDF (module pypjua.applications.pidf) to
support rich presence.
"""

import datetime

from pypjua.applications import ParserError, BuilderError, XMLExtension, XMLElement, XMLListElement, XMLEmptyElement, XMLStringElement, XMLSingleChoiceElement, XMLMultipleChoiceElement
from pypjua.applications.pidf import PIDFTopElement, PIDF, PIDFMeta, TupleExtension, Timestamp, Note, NoteList, Tuple
from pypjua.applications.presdm import PersonExtension, DeviceExtension, Person, Device

__all__ = ['_namespace_',
           'ActivityElement',
           'MoodElement',
           'PlaceIsElement',
           'PlaceTypeElement',
           'PrivacyElement',
           'RelationshipElement',
           'ServiceClassElement',
           'SphereElement',
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
           'Home',
           'Work',
           'Other',
           'Unknown']

_namespace_ = 'urn:ietf:params:xml:ns:pidf:rpid'


# Mixin types for extensibility
class ActivityElement(object): pass
class MoodElement(object): pass
class PlaceIsElement(object): pass
class PlaceTypeElement(object): pass
class PrivacyElement(object): pass
class RelationshipElement(object): pass
class ServiceClassElement(object): pass
class SphereElement(object): pass

class RPIDNote(Note):
    _xml_tag = 'note'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

PIDFMeta.register(RPIDNote)

class Activities(XMLMultipleChoiceElement, PersonExtension):
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
    _xml_default_value = None
    _xml_ext_type = ActivityElement

    def __init__(self, id=None, since=None, until=None, notes=[], activities=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        XMLMultipleChoiceElement.__init__(self, activities)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLMultipleChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        values = self.values
        if 'unknown' in values and len(values) > 1:
            raise BuilderError("Cannot have any other activities if the `unknown' activity is specified")
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLMultipleChoiceElement._build_element(self, element, nsmap)

PIDFMeta.register(Activities)

class Mood(XMLMultipleChoiceElement, PersonExtension):
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
                       'in love', 'indignant', 'interested', 'invisible', 'jealous',
                       'lonely', 'mean', 'moody', 'nervous', 'neutral', 'offended',
                       'playful', 'proud', 'relieved', 'remorseful', 'restless',
                       'sad', 'sarcastic', 'serious', 'shocked', 'shy', 'sick',
                       'sleepy', 'stressed', 'surprised', 'thirsty', 'worried', 'unknown'))
    _xml_value_maps = {'in_awe': 'in awe', 'in_love': 'in love'}
    _xml_default_value = 'unknown'
    _xml_ext_type = MoodElement

    def __init__(self, id=None, since=None, until=None, notes=[], moods=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        XMLMultipleChoiceElement.__init__(self, moods)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLMultipleChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        values = self.values
        if 'unknown' in values and len(values) > 1:
            raise BuilderError("Cannot have any other moods if the `unknown' mood is specified")
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLMultipleChoiceElement._build_element(self, element, nsmap)

PIDFMeta.register(Mood)

class Audio(XMLSingleChoiceElement):
    _xml_tag = 'audio'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('noisy', 'ok', 'quiet', 'unknown'))
    _xml_default_value = 'unknown'

PIDFMeta.register(Audio)

class Video(XMLSingleChoiceElement):
    _xml_tag = 'video'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('toobright', 'ok', 'dark', 'unknown'))
    _xml_default_value = 'unknown'

PIDFMeta.register(Video)

class Text(XMLSingleChoiceElement):
    _xml_tag = 'text'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('uncomfortable', 'inappropriate', 'ok', 'unknown'))
    _xml_default_value = 'unknown'

PIDFMeta.register(Text)

class PlaceIs(XMLListElement, PersonExtension):
    _xml_tag = 'place-is'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, audio=None, video=None, text=None, notes=[], placeis=[]):
        self.id = id
        self.since = since
        self.until = until
        self.audio = audio
        self.video = video
        self.text = text
        self.notes = NoteList()
        self[0:0] = placeis
    
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
            else:
                child_cls = self._xml_meta.get(child.qname)
                if child_cls is not None:
                    self.append(child_cls.from_element(child, xml_meta=self._xml_meta))
    
    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        if self.audio is not None:
            self.audio.to_element(parent=element, nsmap=nsmap)
        if self.video is not None:
            self.video.to_element(parent=element, nsmap=nsmap)
        if self.text is not None:
            self.text.to_element(parent=element, nsmap=nsmap)
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, PlaceIsElement):
            raise TypeError("PlaceIs elements can only contain PlaceIsElement children, got %s instead" % value.__class__.__name__)
        return value

PIDFMeta.register(PlaceIs)

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

PIDFMeta.register(PlaceType)

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

PIDFMeta.register(Privacy)

class Relationship(XMLSingleChoiceElement, TupleExtension):
    _xml_tag = 'relationship'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('assistant', 'associate', 'family', 'friend', 'self',
                       'supervisor', 'unknown'))
    _xml_default_value = 'self'
    _xml_ext_type = RelationshipElement

    def __init__(self, relationship=None, notes=[]):
        self.notes = NoteList()
        XMLSingleChoiceElement.__init__(self, relationship)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLSingleChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLSingleChoiceElement._build_element(self, element, nsmap)

PIDFMeta.register(Relationship)

class ServiceClass(XMLSingleChoiceElement, TupleExtension):
    _xml_tag = 'service-class'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_values = set(('courier', 'electronic', 'freight', 'in person', 'postal', 'unknown'))
    _xml_default_value = 'unknown'
    _xml_ext_type = ServiceClassElement

    def __init__(self, service_class=None, notes=[]):
        self.notes = NoteList()
        XMLSingleChoiceElement.__init__(self, service_class)

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
                element.remove(child)
        XMLSingleChoiceElement._parse_element(self, element)

    def _build_element(self, element, nsmap):
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        XMLSingleChoiceElement._build_element(self, element, nsmap)

PIDFMeta.register(ServiceClass)

class Home(XMLEmptyElement, SphereElement):
    _xml_tag = 'home'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

PIDFMeta.register(Home)

class Work(XMLEmptyElement, SphereElement):
    _xml_tag = 'work'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

PIDFMeta.register(Work)

class Unknown(XMLEmptyElement, SphereElement):
    _xml_tag = 'unknown'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

PIDFMeta.register(Unknown)

class Sphere(XMLElement, PersonExtension):
    _xml_tag = 'sphere'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, value=None, id=None, since=None, until=None):
        self.__value = None
        self.id = id
        self.since = since
        self.until = until
        self.value = value

    def _parse_element(self, element):
        for child in element:
            child_cls = self._xml_meta.get(child.tag)
            if child_cls is not None:
                self.value = child_cls.from_element(child, xml_meta=self._xml_meta)
                break
        else:
            self.value = element.text

    def _set_value(self, value):
        if value is None:
            value = 'unknown'
        elif not isinstance(value, str) and not isinstance(value, SphereElement):
            raise ParserError("Sphere elements can only have SphereElement children, got %s instead" % value.__class__.__name__)
        self.__value = value
    
    value = property(lambda self: self.__value, _set_value)

PIDFMeta.register(Sphere)

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

PIDFMeta.register(StatusIcon)

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
        if value is None:
            diff = datetime.datetime.now()-datetime.datetime.utcnow()
            value = int(round(diff.days*1440+diff.seconds/60.0+diff.microseconds/60000000.0))
        XMLStringElement.__init__(self, str(value))

PIDFMeta.register(TimeOffset)

class UserInput(XMLStringElement, TupleExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'user-input'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False
    _xml_values = ('active', 'idle')
    _xml_attrs = {'id': {'id_attribute': True},
                  'last_input': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'last-input'},
                  'idle_threshold': {'xml_attribute': 'idle-threshold'}}
    
    def __init__(self, value='active', id=None, last_input=None, idle_threshold=None):
        self.id = id
        self.last_input = since
        self.idle_threshold = idle_threshold
        XMLStringElement.__init__(self, value)

PIDFMeta.register(UserInput)

class Class(XMLStringElement, TupleExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'class'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

PIDFMeta.register(Class)

class Other(XMLStringElement, ActivityElement, MoodElement, RelationshipElement):
    _xml_tag = 'other'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = True

PIDFMeta.register(Other)

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
                             (Device, {'attribute': 'rpid_class'})])]
    _xml_namespace = _namespace_
    _xml_prefix = 'rpid'
    _xml_schema_file = 'rpid.xsd'

PIDF.registerExtension(RPIDExtension)

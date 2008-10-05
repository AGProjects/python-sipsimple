"""RPID handling according to RFC4480

This module provides an extension to PIDF (module pypjua.applications.pidf) to
support rich presence.
"""

from pypjua.applications import XMLExtension, XMLListElement, XMLEmptyElement, XMLStringElement, XMLChoiceElement, XMLGenerator
from pypjua.applications.pidf import PIDFTopElement, PIDF, PIDFMeta, TupleExtension, Timestamp, Note, NoteList, Tuple
from pypjua.applications.presdm import PersonExtension, DeviceExtension, Person, Device

__all__ = ['_namespace_',
           'ActivityElement',
           'MoodElement',
           'PlaceTypeElement',
           'Activities',
           'Mood',
           'PlaceIs',
           'Audio',
           'Video',
           'Text',
           'Noisy',
           'Quiet',
           'TooBright',
           'Dark',
           'Uncomfortable',
           'Inappropriate',
           'PlaceType',
           'Class',
           'Ok',
           'Unknown',
           'Other']

_namespace_ = 'urn:ietf:params:xml:ns:pidf:rpid'


# Mixin types for extenisibility
class ActivityElement(object): pass
class MoodElement(object): pass
class PlaceTypeElement(object): pass
class PrivacyElement(object): pass

# Mixin types just for internal use
class AudioValueElement(object): pass
class VideoValueElement(object): pass
class TextValueElement(object): pass

class Activities(XMLListElement, PersonExtension):
    _xml_tag = 'activities'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, notes=[], activities=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        self[0:0] = activities

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == Note.qname:
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
        if not isinstance(value, ActivityElement):
            raise TypeError("Activities elements can only contain ActivityElement children, got %s instead" % value.__class__.__name__)
        return value

class ActivitiesGenerator(XMLGenerator):
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_bases = (XMLEmptyElement, ActivityElement)
    _xml_name_prefix = 'Activity'
    _xml_names = ['appointment', 'away', 'breakfast', 'busy', 'dinner',
                  'holiday', 'in-transit', 'looking-for-work', 'meal', 'meeting',
                  'on-the-phone', 'performance', 'permanent-absence', 'playing',
                  'presentation', 'shopping', 'sleeping', 'spectator', 'sterring',
                  'travel', 'tv', 'vacation', 'working', 'worship']

class Mood(XMLListElement, PersonExtension):
    _xml_tag = 'mood'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_attrs = {'id': {'id_attribute': True},
                  'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

    def __init__(self, id=None, since=None, until=None, notes=[], moods=[]):
        self.id = id
        self.since = since
        self.until = until
        self.notes = NoteList()
        self[0:0] = moods

    def _parse_element(self, element):
        self.notes = NoteList()
        for child in element:
            if child.tag == Note.qname:
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
        if not isinstance(value, MoodElement):
            raise TypeError("Mood elements can only contain MoodElement children, got %s instead" % value.__class__.__name__)
        return value

class MoodsGenerator(XMLGenerator):
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_bases = (XMLEmptyElement, MoodElement)
    _xml_name_prefix = 'Mood'
    _xml_names = ['afraid', 'amazed', 'angry', 'annoyed', 'anxious', 'ashamed',
                  'bored', 'brave', 'calm', 'cold', 'confused', 'contended',
                  'cranky', 'curious', 'depressed', 'disappointed', 'disgusted',
                  'distracted', 'embarrassed', 'excited', 'flirtatious',
                  'frustrated', 'grumpy', 'guilty', 'happy', 'hot', 'humbled',
                  'humiliated', 'hungry', 'hurt', 'impressed', 'in_awe',
                  'in_love', 'indignant', 'interested', 'invisible', 'jealous',
                  'lonely', 'mean', 'moody', 'nervous', 'neutral', 'offended',
                  'playful', 'proud', 'relieved', 'remorseful', 'restless',
                  'sad', 'sarcastic', 'serious', 'shocked', 'shy', 'sick',
                  'sleepy', 'stressed', 'surprised', 'thirsty', 'worried']

class Noisy(XMLEmptyElement, AudioValueElement):
    _xml_tag = 'noisy'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Quiet(XMLEmptyElement, AudioValueElement):
    _xml_tag = 'quiet'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class TooBright(XMLEmptyElement, VideoValueElement):
    _xml_tag = 'toobright'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Dark(XMLEmptyElement, VideoValueElement):
    _xml_tag = 'dark'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Uncomfortable(XMLEmptyElement, TextValueElement):
    _xml_tag = 'uncomfortable'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Inappropriate(XMLEmptyElement, TextValueElement):
    _xml_tag = 'inappropriate'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta

class Audio(XMLChoiceElement):
    _xml_tag = 'audio'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_type = AudioValueElement

class Video(XMLChoiceElement):
    _xml_tag = 'video'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_type = VideoValueElement

class Text(XMLChoiceElement):
    _xml_tag = 'text'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_type = TextValueElement

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
        self.notes = NoteList()
        for child in element:
            if child.tag == Note.qname:
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
        for child in self:
            child.to_element(parent=element, nsmap=nsmap)

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
            if child.tag == Note.qname:
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
            if child.tag == Note.qname:
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

class Class(XMLStringElement, TupleExtension, PersonExtension, DeviceExtension):
    _xml_tag = 'class'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

class Other(XMLStringElement, ActivityElement, MoodElement, PlaceTypeElement):
    _xml_tag = 'other'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = True

class Ok(XMLEmptyElement, AudioValueElement, VideoValueElement, TextValueElement):
    _xml_tag = 'ok'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

class Unknown(XMLEmptyElement, ActivityElement, MoodElement, AudioValueElement, VideoValueElement, TextValueElement):
    _xml_tag = 'unknown'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

class RPIDExtension(XMLExtension):
    _xml_ext_def = [(Activities, [(Person, {'attribute': 'activities'})]),
                    (Mood, [(Person, {'attribute': 'mood'})]),
                    (PlaceIs, [(Person, {'attribute': 'placeis'})]),
                    (PlaceType, [(Person, {'attribute': 'placetype'})]),
                    (Privacy, [(Person, {'attribute': 'privacy'})]),
                    (Class, [(Tuple, {'attribute': 'class'}),
                             (Person, {'attribute': 'class'}),
                             (Device, {'attribute': 'class'})]),
                    (Other, [])]
    _xml_namespace = _namespace_
    _xml_prefix = 'rpid'
    _xml_schema_file = 'rpid.xsd'

PIDF.registerExtension(RPIDExtension)

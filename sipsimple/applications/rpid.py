# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""RPID handling according to RFC4480

This module provides an extension to PIDF (module sipsimple.applications.presdm) to
support rich presence.
"""

from lxml import etree

from sipsimple.applications import util
from sipsimple.applications import parse_qname, ParserError, ValidationError, XMLElement, XMLListElement, XMLEmptyElement, XMLStringElement, XMLAttribute, XMLElementChild
from sipsimple.applications.presdm import PIDFApplication, ServiceExtension, PersonExtension, DeviceExtension, Note, NotesAttribute, Service, Person, Device

__all__ = ['rpid_namespace',
           'ActivityElement',
           'MoodElement',
           'PlaceTypeElement',
           'PrivacyElement',
           'SphereElement',
           'RPIDNote',
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
           'Class',
           'Other']

rpid_namespace = 'urn:ietf:params:xml:ns:pidf:rpid'
PIDFApplication.register_namespace(rpid_namespace, prefix='rpid')


## Marker mixins

class ActivityElement(object): pass
class MoodElement(object): pass
class PlaceTypeElement(object): pass
class PrivacyElement(object): pass
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

class RPIDNote(Note):
    _xml_tag = 'note'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication

class Other(Note):
    _xml_tag = 'note'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication

class Activities(XMLListElement, PersonExtension):
    _xml_tag = 'activities'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = ActivityElement
    _xml_children_order = {RPIDNote.qname: 0}
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    notes = NotesAttribute()

    values = set(('appointment', 'away', 'breakfast', 'busy', 'dinner',
                  'holiday', 'in-transit', 'looking-for-work', 'meal', 'meeting',
                  'on-the-phone', 'performance', 'permanent-absence', 'playing',
                  'presentation', 'shopping', 'sleeping', 'spectator', 'steering',
                  'travel', 'tv', 'vacation', 'working', 'worship', 'unknown'))

    def __init__(self, id=None, since=None, until=None, notes=[], activities=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        for note in notes:
            self.notes.add(note)
        self[:] = activities

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.add(RPIDNote.from_element(child, *args, **kwargs), with_element=False)
            elif child.tag == '{%s}other' % self._xml_namespace:
                value = child.text
                if value not in self:
                    list.append(self, value)
            else:
                value = parse_qname(child.tag)[1]
                if value in self.values and value not in self:
                    list.append(self, value)
        if 'unknown' in self and len(self) > 1:
            self.remove('unknown')

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def check_validity(self):
        if not self:
            raise ValidationError("Activity element must have at least one value")

    def _add_item(self, value):
        if value in self:
            raise ValueError("cannot add the same activity twice")
        if value == 'unknown' and len(self) > 0:
            raise ValueError("cannot add 'unknown' value in non-empty Activities element")
        if self[:] == ['unknown']:
            raise ValueError("cannot add activity if Activities element contains 'unknown'")
        if value in self.values:
            self._insert_element(etree.Element('{%s}%s' % (self._xml_namespace, value)))
        else:
            element = etree.Element('{%s}other' % (self._xml_namespace,))
            element.text = value
            self._insert_element(element)
        return value

    def _del_item(self, value):
        if value in self.values:
            self.element.remove(self.element.find('{%s}%s' % (self._xml_namespace, value)))
        else:
            tag = '{%s}other' % self._xml_namespace
            for child in self.element:
                if child.tag == tag and child.text == value:
                    self.element.remove(child)
                    break

    def __repr__(self):
        return '%s(%r, %r, %r, [%s], %s)' % (self.__class__.__name__, self.id, self.since, self.until, ', '.join('%r' % note for note in self.notes), list.__repr__(self))

    __str__ = __repr__

Person.register_extension('activities', type=Activities)


class Mood(XMLListElement, PersonExtension):
    _xml_tag = 'mood'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = MoodElement
    _xml_children_order = {RPIDNote.qname: 0}
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    notes = NotesAttribute()
    
    values = set(('afraid', 'amazed', 'angry', 'annoyed', 'anxious', 'ashamed',
                  'bored', 'brave', 'calm', 'cold', 'confused', 'contended',
                  'cranky', 'curious', 'depressed', 'disappointed', 'disgusted',
                  'distracted', 'embarrassed', 'excited', 'flirtatious',
                  'frustrated', 'grumpy', 'guilty', 'happy', 'hot', 'humbled',
                  'humiliated', 'hungry', 'hurt', 'impressed', 'in_awe',
                  'in_love', 'indignant', 'interested', 'invisible', 'jealous',
                  'lonely', 'mean', 'moody', 'nervous', 'neutral', 'offended',
                  'playful', 'proud', 'relieved', 'remorseful', 'restless',
                  'sad', 'sarcastic', 'serious', 'shocked', 'shy', 'sick',
                  'sleepy', 'stressed', 'surprised', 'thirsty', 'worried', 'unknown'))

    def __init__(self, id=None, since=None, until=None, notes=[], moods=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        for note in notes:
            self.notes.add(note)
        self[:] = moods

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.add(RPIDNote.from_element(child, *args, **kwargs), with_element=False)
            elif child.tag == '{%s}other' % self._xml_namespace:
                value = child.text
                if value not in self:
                    list.append(self, value)
            else:
                value = parse_qname(child.tag)[1]
                if value in self.values  and value not in self:
                    list.append(self, value)
        if 'unknown' in self and len(self) > 1:
            self.remove('unknown')

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def check_validity(self):
        if not self:
            raise ValidationError("Mood element must have at least one value")

    def _add_item(self, value):
        if value in self:
            raise ValueError("cannot add the same mood twice")
        if value == 'unknown' and len(self) > 0:
            raise ValueError("cannot add 'unknown' value in non-empty Mood element")
        if self[:] == ['unknown']:
            raise ValueError("cannot add mood if Mood element contains 'unknown'")
        if value in self.values:
            self._insert_element(etree.Element('{%s}%s' % (self._xml_namespace, value)))
        else:
            element = etree.Element('{%s}other' % (self._xml_namespace,))
            element.text = value
            self._insert_element(element)
        return value

    def _del_item(self, value):
        if value in self.values:
            self.element.remove(self.element.find('{%s}%s' % (self._xml_namespace, value)))
        else:
            tag = '{%s}other' % self._xml_namespace
            for child in self.element:
                if child.tag == tag and child.text == value:
                    self.element.remove(child)
                    break

    def __repr__(self):
        return '%s(%r, %r, %r, [%s], %s)' % (self.__class__.__name__, self.id, self.since, self.until, ', '.join('%r' % note for note in self.notes), list.__repr__(self))

    __str__ = __repr__

Person.register_extension('mood', type=Mood)


class AudioPlaceInformation(XMLStringElement):
    _xml_tag = 'audio'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_value_type = AudioPlaceValue


class VideoPlaceInformation(XMLStringElement):
    _xml_tag = 'video'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_value_type = VideoPlaceValue


class TextPlaceInformation(XMLStringElement):
    _xml_tag = 'text'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_value_type = TextPlaceValue


class PlaceIs(XMLElement, PersonExtension):
    _xml_tag = 'place-is'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_children_order = {RPIDNote.qname: 0,
                           AudioPlaceInformation.qname: 1,
                           VideoPlaceInformation.qname: 2,
                           TextPlaceInformation.qname: 3}
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    audio = XMLElementChild('audio', type=AudioPlaceInformation, required=False, test_equal=True)
    video = XMLElementChild('video', type=VideoPlaceInformation, required=False, test_equal=True)
    text = XMLElementChild('text', type=TextPlaceInformation, required=False, test_equal=True)
    notes = NotesAttribute()

    def __init__(self, id=None, since=None, until=None, audio=None, video=None, text=None, notes=[]):
        XMLElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        self.audio = audio
        self.video = video
        self.text = text
        for note in notes:
            self.notes.add(note)
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.add(RPIDNote.from_element(child, *args, **kwargs))
    
    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, [%s])' % (self.__class__.__name__, self.id, self.since, self.until, self.audio, self.video, self.text, ', '.join('%r' % note for note in self.notes))

    __str__ = __repr__

Person.register_extension('place_is', type=PlaceIs)


class PlaceType(XMLListElement, PersonExtension):
    _xml_tag = 'place-type'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_children_order = {RPIDNote.qname: 0}
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    notes = NotesAttribute()
    
    def _on_value_set(self, attribute):
        if getattr(self, attribute.name) is None:
            self.clear()
    value = XMLElementChild('value', type=Other, required=False, test_equal=True, onset=_on_value_set)
    del _on_value_set

    def __init__(self, id=None, since=None, until=None, notes=[], placetypes=[]):
        XMLListElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        for note in notes:
            self.notes.add(note)
        self[0:0] = placetypes

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(RPIDNote.from_element(child, *args, **kwargs))
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, PlaceTypeElement):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)
        for child in self:
            child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, PlaceTypeElement):
            raise TypeError("PlaceType elements can only contain PlaceTypeElement children, got %s instead" % value.__class__.__name__)
        self.value = None
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %r, %r, [%s], %s)' % (self.__class__.__name__, self.id, self.since, self.until, ', '.join('%r' % note for note in self.notes), list.__repr__(self))

    __str__ = __repr__

Person.register_extension('place_type', type=PlaceType)


class AudioPrivacy(XMLEmptyElement):
    _xml_tag = 'audio'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class TextPrivacy(XMLEmptyElement):
    _xml_tag = 'text'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class VideoPrivacy(XMLEmptyElement):
    _xml_tag = 'audio'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication

    def __init__(self, private=True):
        XMLEmptyElement.__init__(self)

    def __new__(cls, private=True):
        if not private:
            return None
        return XMLEmptyElement.__new__(cls)


class Privacy(XMLListElement, PersonExtension):
    _xml_tag = 'privacy'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_children_order = {RPIDNote.qname: 0,
                           AudioPrivacy.qname: 1,
                           TextPrivacy.qname: 2,
                           VideoPrivacy.qname: 3}
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    notes = NotesAttribute()

    audio = XMLElementChild('audio', type=AudioPrivacy, required=False, test_equal=True)
    text = XMLElementChild('text', type=TextPrivacy, required=False, test_equal=True)
    video = XMLElementChild('video', type=VideoPrivacy, required=False, test_equal=True)
    unknown = property(lambda self: len(self) == 0 and not self.audio and not self.text and not self.video)

    def __init__(self, id=None, since=None, until=None, notes=[], audio=False, text=False, video=False, privacy=[]):
        XMLListElement.__init__(self)
        self.id = id
        self.since = since
        self.until = until
        for note in notes:
            self.notes.add(note)
        self.audio = audio
        self.text = text
        self.video = video
        self[0:0] = privacy

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(RPIDNote.from_element(child, *args, **kwargs))
            elif child.tag == '{%s}unknown' % self._xml_namespace:
                pass
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, PrivacyElement):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)
        if self.unknown:
            if self.element.find('{%s}unknown' % self._xml_namespace) is None:
                etree.SubElement(self.element, '{%s}unknown' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
        else:
            unknown_element = self.element.find('{%s}unknown' % self._xml_namespace)
            if unknown_element is not None:
                self.element.remove(unknown_element)
            for child in self:
                child.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, PrivacyElement):
            raise TypeError("Privacy elements can only contain PrivacyElement children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %r, %r, [%s], %r, %r, %r, %s)' % (self.__class__.__name__, self.id, self.since, self.until, ', '.join('%r' % note for note in self.notes), self.audio, self.text, self.video, list.__repr__(self))

    __str__ = __repr__

Person.register_extension('privacy', type=Privacy)


class Relationship(XMLElement, ServiceExtension):
    _xml_tag = 'relationship'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_children_order = {RPIDNote: 0}
    
    values = set(('assistant', 'associate', 'family', 'friend', 'self',
                  'supervisor', 'unknown'))
    
    notes = NotesAttribute()

    def __init__(self, relationship='self', notes=[]):
        XMLElement.__init__(self)
        self._value = None
        self.value = relationship
        for note in notes:
            self.notes.add(note)

    def _parse_element(self, element, *args, **kwargs):
        self._value = None
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(RPIDNote.from_element(child, *args, **kwargs))
            elif child.tag == '{%s}other' % self._xml_namespace:
                value = child.text
                if value not in self:
                    self._value = value
            else:
                value = parse_qname(child.tag)[1]
                if value in self.values:
                    self._value = value

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        for child in self.element:
            if child.tag == '{%s}%s' % (self._xml_namespace, self._value) or (child.tag == '{%s}other' % self._xml_namespace and child.text == value):
                self.element.remove(child)
                break
        self._value = value
        if value is not None:
            if value in self.values:
                element = etree.Element('{%s}%s' % (self._xml_namespace, value), nsmap=self._xml_application.xml_nsmap)
            else:
                element = etree.Element('{%s}other' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
                element.text = value
            self._insert_element(element)

    value = property(_get_value, _set_value)
    del _get_value, _set_value

    def __repr__(self):
        return '%s(%r, [%s])' % (self.__class__.__name__, self.value, ', '.join('%r' % note for note in self.notes))

    __str__ = __repr__

Service.register_extension('relationship', type=Relationship)


class ServiceClass(XMLElement, ServiceExtension):
    _xml_tag = 'service-class'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    
    values = set(('courier', 'electronic', 'freight', 'in person', 'postal', 'unknown'))
    
    notes = NotesAttribute()

    def __init__(self, service_class=None, notes=[]):
        XMLElement.__init__(self)
        self.value = service_class
        for note in notes:
            self.notes.add(note)

    def _parse_element(self, element, *args, **kwargs):
        self.value = None
        for child in element:
            if child.tag == RPIDNote.qname:
                self.notes.append(RPIDNote.from_element(child, *args, **kwargs))
            elif child.tag == '{%s}other' % self._xml_namespace:
                value = child.text
                if value not in self:
                    self._value = value
            else:
                value = parse_qname(child.tag)[1]
                if value in self.values:
                    self._value = value

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        if not hasattr(self, '_value'):
            return
        for child in self.element:
            if child.tag == '{%s}%s' % (self._xml_namespace, self._value) or (child.tag == '{%s}other' % self._xml_namespace and child.text == value):
                self.element.remove(child)
                break
        self._value = value
        if value is not None:
            if value in self.values:
                element = etree.Element('{%s}%s' % (self._xml_namespace, value), nsmap=self._xml_application.xml_nsmap)
            else:
                element = etree.Element('{%s}other' % self._xml_namespace, nsmap=self._xml_application.xml_nsmap)
                element.text = value
            self._insert_element(element)

    value = property(_get_value, _set_value)
    del _get_value, _set_value

    def __repr__(self):
        return '%s(%r, [%s])' % (self.__class__.__name__, self.value, ', '.join('%r' % note for note in self.notes))

    __str__ = __repr__

Service.register_extension('service_class', type=ServiceClass)


class Sphere(XMLElement, PersonExtension):
    _xml_tag = 'sphere'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)

    def __init__(self, value=None, id=None, since=None, until=None):
        XMLElement.__init__(self)
        self.__value = None
        self.id = id
        self.since = since
        self.until = until
        self.value = value

    def _parse_element(self, element, *args, **kwargs):
        self.__value = None
        for child in element:
            value = parse_qname(child.tag)[1]
            if value in ('home', 'work', 'unknown'):
                self.__value = value
                break
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and issubclass(child_cls, SphereElement):
                    self.__value = child_cls.from_element(child, xml_meta=self._xml_meta)
                    break
        else:
            self.value = element.text

    def _set_value(self, value):
        if value is not None and not isinstance(value, str) and not isinstance(value, SphereElement):
            raise ParserError("Sphere elements can only have SphereElement children, got %s instead" % value.__class__.__name__)
        if self.__value is not None:
            for child in self.element:
                if (parse_qname(child.tag)[1] == self.__value and self.__value in ('home', 'work', 'unknown')) or \
                        (isinstance(self.__value, SphereElement) and self.__value.element == child):
                    self.element.remove(child)
                    break
            else:
                self.element.text = None
        if isinstance(value, SphereElement):
            self._insert_element(value.element)
        elif value in ('home', 'work', 'unknown') or value is None:
            if value is None:
                value = 'unknown'
            element = etree.Element('{%s}%s' % (self._xml_namespace, value))
            self._insert_element(element)
        else:
            self.element.text = value
        self.__value = value
    
    value = property(lambda self: self.__value, _set_value)

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.value, self.id, self.since, self.until)

    __str__ = __repr__

Person.register_extension('sphere', type=Sphere)


class StatusIcon(XMLStringElement, ServiceExtension, PersonExtension):
    _xml_tag = 'status-icon'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_lang = False
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    
    def __init__(self, value=None, id=None, since=None, until=None):
        XMLStringElement.__init__(self, value)
        self.id = id
        self.since = since
        self.until = until

Person.register_extension('status_icon', type=StatusIcon)
Service.register_extension('status_icon', type=StatusIcon)


class TimeOffset(XMLStringElement, PersonExtension):
    _xml_tag = 'time-offset'
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_lang = False
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)
    description = XMLAttribute('description', type=str, required=False, test_equal=True)
    
    def __init__(self, value=None, id=None, since=None, until=None, description=None):
        if value is None:
            value = util.Timestamp.utc_offset()
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
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_lang = False
    _xml_value_type = UserInputValue
    
    id = XMLAttribute('id', type=str, required=False, test_equal=True)
    last_input = XMLAttribute('last_input', xmlname='last-input', type=util.Timestamp, required=False, test_equal=True)
    idle_threshold = XMLAttribute('idle_threshold', xmlname='idle-threshold', type=util.UnsignedLong, required=False, test_equal=True)
    
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
    _xml_namespace = rpid_namespace
    _xml_application = PIDFApplication
    _xml_lang = False

Service.register_extension('rpid_class', type=Class)
Person.register_extension('rpid_class', type=Class)
Device.register_extension('rpid_class', type=Class)



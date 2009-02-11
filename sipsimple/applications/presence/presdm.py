"""PIDF handling according to RFC3863 and RFC3379

This module provides classes to parse and generate PIDF documents.

Example usage:

>>> from datetime import datetime
>>> pidf = PIDF('pres:someone@example.com')
>>> status = Status(basic=Basic('open'))
>>> contact = Contact('im:someone@mobilecarrier.net')
>>> contact.priority = "0.8"
>>> tuple1 = Service('bs35r9', notes=[ServiceNote("Don't Disturb Please!"), ServiceNote("Ne derangez pas, s'il vous plait", lang="fr")], status=status)
>>> tuple1.contact = contact
>>> tuple1.timestamp = Timestamp(datetime(2008, 9, 11, 20, 42, 03))
>>> tuple2 = Service('eg92n8', status=Status(basic=Basic('open')), contact=Contact('mailto:someone@example.com'))
>>> tuple2.contact.priority = "1.0"
>>> pidf.notes.add(Note("I'll be in Tokyo next week"))
>>> pidf.append(tuple1)
>>> pidf.append(tuple2)
>>> print pidf.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<presence xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:someone@example.com">
  <tuple id="bs35r9">
    <status>
      <basic>open</basic>
    </status>
    <contact priority="0.8">im:someone@mobilecarrier.net</contact>
    <note>Don't Disturb Please!</note>
    <note xml:lang="fr">Ne derangez pas, s'il vous plait</note>
    <timestamp>2008-09-11T20:42:03Z</timestamp>
  </tuple>
  <tuple id="eg92n8">
    <status>
      <basic>open</basic>
    </status>
    <contact priority="1.0">mailto:someone@example.com</contact>
  </tuple>
  <note>I'll be in Tokyo next week</note>
</presence>
<BLANKLINE>

"""

import datetime

from pypjua.applications import util
from pypjua.applications import ValidationError, XMLApplication, XMLListRootElement, XMLElement, XMLStringElement, XMLAttribute, XMLElementChild

__all__ = ['_pidf_namespace_',
           '_dm_namespace_',
           'PIDFApplication',
           'ServiceExtension',
           'DeviceExtension',
           'PersonExtension',
           'Note',
           'NoteList',
           'NotesAttribute',
           'DeviceID',
           'Status',
           'Basic',
           'Contact',
           'ServiceNote',
           'ServiceTimestamp',
           'Service',
           'DeviceNote',
           'DeviceTimestamp',
           'Device',
           'PersonNote',
           'PersonTimestamp',
           'Person',
           'PIDF']


_pidf_namespace_ = 'urn:ietf:params:xml:ns:pidf'
_dm_namespace_ = 'urn:ietf:params:xml:ns:pidf:data-model'


class PIDFApplication(XMLApplication): pass
PIDFApplication.register_namespace(_pidf_namespace_, prefix=None)
PIDFApplication.register_namespace(_dm_namespace_, prefix='dm')


## Marker mixin

class ServiceExtension(object): pass
class DeviceExtension(object): pass
class PersonExtension(object): pass


## Attribute value types

class BasicStatusValue(str):
    def __new__(cls, value):
        if value not in ('closed', 'open'):
            raise ValueError('illegal BasicStatusValue')
        return str.__new__(cls, value)


## General elements

class Timestamp(XMLElement):
    _xml_tag = 'timestamp'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication

    def __init__(self, value=None):
        XMLElement.__init__(self)
        self.value = value

    def _parse_element(self, element, *args, **kwargs):
        self.value = element.text

    def _build_element(self, *args, **kwargs):
        self.element.text = util.Timestamp.format_timestamp(self.value)
    
    def _set_value(self, value):
        if value is None:
            value = datetime.datetime.now()
        elif isinstance(value, basestring):
            value = util.Timestamp.parse_timestamp(value)
        elif isinstance(value, Timestamp):
            value = value.value
        self.__value = value

    value = property(lambda self: self.__value, _set_value)
    
    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)

    def __str__(self):
        return str(self.value)


class Note(XMLStringElement):
    _xml_tag = 'note'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_lang = True
    
    since = XMLAttribute('since', xmlname='from', type=util.Timestamp, required=False, test_equal=True)
    until = XMLAttribute('until', type=util.Timestamp, required=False, test_equal=True)


class NoteList(object):
    def __init__(self, xml_element):
        self._notes = {}
        self.xml_element = xml_element

    def __getitem__(self, key):
        return self._notes[key]

    def __delitem__(self, key):
        self.xml_element.element.remove(self._notes[key].element)
        del self._notes[key]

    def __iter__(self):
        return self._notes.itervalues()

    def __len__(self):
        return len(self._notes)

    def add(self, note, with_element=True):
        self._notes[note.lang] = note
        if with_element:
            self.xml_element._insert_element(note.element)


class NotesAttribute(object):
    def __init__(self):
        self.note_lists = {}

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        return self.note_lists.setdefault(id(obj), NoteList(obj))

    def __set__(self, obj, value):
        raise AttributeError("cannot overwrite NotesAttribute")

    def __delete__(self, obj):
        raise AttributeError("cannot delete NotesAttribute")


class DeviceID(XMLStringElement):
    _xml_tag = 'deviceID'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication
    _xml_lang = False


## Service elements

class Basic(XMLStringElement):
    _xml_tag = 'basic'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_lang = False
    _xml_value_type = BasicStatusValue


class Status(XMLElement):
    _xml_tag = 'status'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_children_order = {Basic.qname: 0}

    basic = XMLElementChild('basic', type=Basic, required=False, test_equal=True)

    def __init__(self, basic=None):
        XMLElement.__init__(self)
        self.basic = basic

    def check_validity(self):
        if len(self.element) == 0:
            raise ValidationError("Status objects must have at least one child")

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.basic)
    
    __str__ = __repr__

class Contact(XMLStringElement):
    _xml_tag = 'contact'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_lang = False

    priority = XMLAttribute('priority', type=float, required=False, test_equal=False)


class ServiceNote(Note): pass
class ServiceTimestamp(Timestamp): pass


class Service(XMLElement):
    _xml_tag = 'tuple'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_extension_type = ServiceExtension
    _xml_children_order = {Status.qname: 0,
                           None: 1,
                           Contact.qname: 2,
                           ServiceNote.qname: 3,
                           ServiceTimestamp.qname: 4}

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    status = XMLElementChild('status', type=Status, required=True, test_equal=True)
    contact = XMLElementChild('contact', type=Contact, required=False, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=ServiceTimestamp, required=False, test_equal=True)
    device_id = XMLElementChild('device_id', type=DeviceID, required=False, test_equal=True)
    notes = NotesAttribute()
    _xml_id = id
    
    def __init__(self, id, notes=[], status=None, contact=None, timestamp=None, device_id=None):
        XMLElement.__init__(self)
        self.id = id
        for note in notes:
            self.notes.add(note)
        self.status = status
        self.contact = contact
        self.timestamp = timestamp
        self.device_id = device_id
    
    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == Note.qname:
                self.notes.add(Note.from_element(child, *args, **kwargs), with_element=False)

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, [%s], %r, %r, %r, %r)' % (self.__class__.__name__, self.id, ', '.join('%r' % note for note in self.notes), self.status, self.contact, self.timestamp, self.device_id)

    __str__ = __repr__


class DeviceNote(Note):
    _xml_tag = 'note'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication


class DeviceTimestamp(Timestamp):
    _xml_tag = 'timestamp'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication


class Device(XMLElement):
    _xml_tag = 'device'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication
    _xml_extension_type = DeviceExtension
    _xml_children_order = {None: 0,
                           DeviceID.qname: 1,
                           DeviceNote.qname: 2,
                           DeviceTimestamp.qname: 3}
    
    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    device_id = XMLElementChild('device_id', type=DeviceID, required=False, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=DeviceTimestamp, required=False, test_equal=True)
    notes = NotesAttribute()
    _xml_id = id

    def __init__(self, id, device_id=None, notes=[], timestamp=None):
        XMLElement.__init__(self)
        self.id = id
        self.device_id = device_id
        for note in notes:
            self.notes.add(note)
        self.timestamp = timestamp

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == DeviceNote.qname:
                self.notes.add(DeviceNote.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, %r, [%s], %r)' % (self.__class__.__name__, self.id, self.device_id, ', '.join('%r' % note for note in self.notes), self.timestamp)

    __str__ = __repr__


class PersonNote(Note):
    _xml_tag = 'note'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication


class PersonTimestamp(Timestamp):
    _xml_tag = 'timestamp'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication


class Person(XMLElement):
    _xml_tag = 'person'
    _xml_namespace = _dm_namespace_
    _xml_application = PIDFApplication
    _xml_extension_type = PersonExtension
    _xml_children_order = {None: 0,
                           PersonNote.qname: 1,
                           PersonTimestamp.qname: 2}
    
    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=PersonTimestamp, required=False, test_equal=True)
    notes = NotesAttribute()
    _xml_id = id

    def __init__(self, id, notes=[], timestamp=None):
        XMLElement.__init__(self)
        self.id = id
        for note in notes:
            self.notes.add(note)
        self.timestamp = timestamp

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == PersonNote.qname:
                self.notes.add(PersonNote.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for note in self.notes:
            note.to_element(*args, **kwargs)
    
    def __repr__(self):
        return '%s(%r, [%s], %r)' % (self.__class__.__name__, self.id, ', '.join('%r' % note for note in self.notes), self.timestamp)

    __str__ = __repr__


class PIDF(XMLListRootElement):
    content_type = 'application/pidf+xml'
    
    _xml_tag = 'presence'
    _xml_namespace = _pidf_namespace_
    _xml_application = PIDFApplication
    _xml_schema_file = 'pidf.xsd'
    _xml_children_order = {Service.qname: 0,
                           Note.qname: 1,
                           Person.qname: 2,
                           Device.qname: 3}

    entity = XMLAttribute('entity', type=str, required=True, test_equal=True)
    notes = NotesAttribute()

    def __init__(self, entity, elems=[], notes=[]):
        XMLListRootElement.__init__(self)
        self.entity = entity
        self[0:0] = elems
        for note in notes:
            self.notes.add(note)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            if child.tag == Note.qname:
                self.notes.add(Note.from_element(child, *args, **kwargs))
            else:
                child_cls = self._xml_application.get_element(child.tag)
                if child_cls is not None and child_cls in (Service, Device, Person):
                    list.append(self, child_cls.from_element(child, *args, **kwargs))

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)
        for note in self.notes:
            note.to_element(*args, **kwargs)

    def _add_item(self, value):
        if not isinstance(value, (Service, Device, Person)):
            raise TypeError("PIDF elements can only contain Service, Device or Person children, got %s instead" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

    def _del_item(self, value):
        self.element.remove(value.element)

    def __repr__(self):
        return '%s(%r, %s, [%s])' % (self.__class__.__name__, self.entity, list.__repr__(self), ', '.join('%r' % note for note in self.notes))

    __str__ = __repr__



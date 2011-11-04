# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
PIDF handling according to RFC3863 and RFC4479
"""

import datetime

from sipsimple import util
from sipsimple.payloads import ValidationError, XMLApplication, XMLListRootElement, XMLElement, XMLStringElement, XMLAttribute, XMLElementChild

__all__ = ['pidf_namespace',
           'dm_namespace',
           'PIDFApplication',
           'ServiceExtension',
           'DeviceExtension',
           'PersonExtension',
           'Note',
           'PIDFNote',
           'DMNote',
           'NoteList',
           'DeviceID',
           'Status',
           'Basic',
           'Contact',
           'ServiceTimestamp',
           'Service',
           'DeviceTimestamp',
           'Device',
           'PersonTimestamp',
           'Person',
           'PIDF']


pidf_namespace = 'urn:ietf:params:xml:ns:pidf'
dm_namespace = 'urn:ietf:params:xml:ns:pidf:data-model'


class PIDFApplication(XMLApplication): pass
PIDFApplication.register_namespace(pidf_namespace, prefix=None)
PIDFApplication.register_namespace(dm_namespace, prefix='dm')


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
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication

    def __init__(self, value=None):
        XMLElement.__init__(self)
        self.value = value

    def _parse_element(self, element, *args, **kwargs):
        self.value = element.text

    def _build_element(self, *args, **kwargs):
        self.element.text = util.Timestamp.format(self.value)
    
    def _set_value(self, value):
        if value is None:
            value = datetime.datetime.now()
        elif isinstance(value, basestring):
            value = util.Timestamp.parse(value)
        elif isinstance(value, Timestamp):
            value = value.value
        self.__value = value

    value = property(lambda self: self.__value, _set_value)
    
    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)

    def __str__(self):
        return str(self.value)


class Note(unicode):
    def __new__(cls, value, lang=None):
        instance = unicode.__new__(cls, value)
        instance.lang = lang
        return instance

    def __repr__(self):
        return "%s(%s, lang=%r)" % (self.__class__.__name__, unicode.__repr__(self), self.lang)

    def __eq__(self, other):
        if isinstance(other, Note):
            return unicode.__eq__(self, other) and self.lang == other.lang
        elif isinstance(other, basestring):
            return self.lang is None and unicode.__eq__(self, other)
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class PIDFNote(XMLStringElement):
    _xml_tag = 'note'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_lang = True

    def __unicode__(self):
        return Note(self.value, self.lang)


class DMNote(XMLStringElement):
    _xml_tag = 'note'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication
    _xml_lang = True

    def __unicode__(self):
        return Note(self.value, self.lang)


class NoteList(object):
    def __init__(self, xml_element, note_type):
        self.xml_element = xml_element
        self.note_type = note_type

    def __contains__(self, item):
        if isinstance(item, Note):
            item = self.note_type(item, item.lang)
        elif isinstance(item, basestring):
            item = self.note_type(item)
        return item in self.xml_element._note_map.itervalues()

    def __iter__(self):
        return (unicode(self.xml_element._note_map[element]) for element in self.xml_element.element if element in self.xml_element._note_map)

    def __len__(self):
        return len(self.xml_element._note_map)

    def __nonzero__(self):
        return bool(self.xml_element._note_map)

    def _parse_element(self, element, *args, **kwargs):
        self.xml_element._note_map.clear()
        for child in element:
            if child.tag == self.note_type.qname:
                try:
                    note = self.note_type.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    self.xml_element._note_map[note.element] = note

    def _build_element(self, *args, **kwargs):
        for note in self.xml_element._note_map.itervalues():
            note.to_element(*args, **kwargs)

    def add(self, item):
        if isinstance(item, Note):
            item = self.note_type(item, item.lang)
        elif isinstance(item, basestring):
            item = self.note_type(item)
        if type(item) is not self.note_type:
            raise TypeError("%s cannot add notes of type %s" % (self.xml_element.__class__.__name__, item.__class__.__name__))
        self.xml_element._insert_element(item.element)
        self.xml_element._note_map[item.element] = item

    def remove(self, item):
        if isinstance(item, Note):
            try:
                item = (entry for entry in self.xml_element._note_map.itervalues() if unicode(entry) == item).next()
            except StopIteration:
                raise KeyError(item)
        elif isinstance(item, basestring):
            try:
                item = (entry for entry in self.xml_element._note_map.itervalues() if entry == item).next()
            except StopIteration:
                raise KeyError(item)
        if type(item) is not self.note_type:
            raise KeyError(item)
        self.xml_element.element.remove(item.element)
        del self.xml_element._note_map[item.element]

    def update(self, sequence):
        for item in sequence:
            self.add(item)

    def clear(self):
        for item in self.xml_element._note_map.values():
            self.remove(item)


class DeviceID(XMLStringElement):
    _xml_tag = 'deviceID'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication
    _xml_lang = False


## Service elements

class Basic(XMLStringElement):
    _xml_tag = 'basic'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_lang = False
    _xml_value_type = BasicStatusValue


class Status(XMLElement):
    _xml_tag = 'status'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_children_order = {Basic.qname: 0}

    basic = XMLElementChild('basic', type=Basic, required=False, test_equal=True)

    def __init__(self, basic=None):
        XMLElement.__init__(self)
        self.basic = basic

    def check_validity(self):
        if len(self.element) == 0:
            raise ValidationError("Status objects must have at least one child")
        super(Status, self).check_validity()

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.basic)
    
    __str__ = __repr__

class Contact(XMLStringElement):
    _xml_tag = 'contact'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_lang = False

    priority = XMLAttribute('priority', type=float, required=False, test_equal=False)


class ServiceTimestamp(Timestamp): pass


class Service(XMLElement):
    _xml_tag = 'tuple'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = ServiceExtension
    _xml_children_order = {Status.qname: 0,
                           None: 1,
                           Contact.qname: 2,
                           PIDFNote.qname: 3,
                           ServiceTimestamp.qname: 4}

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    status = XMLElementChild('status', type=Status, required=True, test_equal=True)
    contact = XMLElementChild('contact', type=Contact, required=False, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=ServiceTimestamp, required=False, test_equal=True)
    device_id = XMLElementChild('device_id', type=DeviceID, required=False, test_equal=True)
    _xml_id = id

    def __init__(self, id, notes=[], status=None, contact=None, timestamp=None, device_id=None):
        XMLElement.__init__(self)
        self._note_map = {}
        self.id = id
        self.status = status
        self.contact = contact
        self.timestamp = timestamp
        self.device_id = device_id
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, PIDFNote)

    def _parse_element(self, element, *args, **kwargs):
        super(Service, self)._parse_element(element, *args, **kwargs)
        self.notes._parse_element(element, *args, **kwargs)

    def _build_element(self, *args, **kwargs):
        super(Service, self)._build_element(*args, **kwargs)
        self.notes._build_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.id, list(self.notes), self.status, self.contact, self.timestamp, self.device_id)


class DeviceTimestamp(Timestamp):
    _xml_tag = 'timestamp'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication


class Device(XMLElement):
    _xml_tag = 'device'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = DeviceExtension
    _xml_children_order = {None: 0,
                           DeviceID.qname: 1,
                           DMNote.qname: 2,
                           DeviceTimestamp.qname: 3}

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    device_id = XMLElementChild('device_id', type=DeviceID, required=False, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=DeviceTimestamp, required=False, test_equal=True)
    _xml_id = id

    def __init__(self, id, device_id=None, notes=[], timestamp=None):
        XMLElement.__init__(self)
        self._note_map = {}
        self.id = id
        self.device_id = device_id
        self.timestamp = timestamp
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, DMNote)

    def _parse_element(self, element, *args, **kwargs):
        super(Device, self)._parse_element(element, *args, **kwargs)
        self.notes._parse_element(element, *args, **kwargs)

    def _build_element(self, *args, **kwargs):
        super(Device, self)._build_element(*args, **kwargs)
        self.notes._build_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (self.__class__.__name__, self.id, self.device_id, list(self.notes), self.timestamp)


class PersonTimestamp(Timestamp):
    _xml_tag = 'timestamp'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication


class Person(XMLElement):
    _xml_tag = 'person'
    _xml_namespace = dm_namespace
    _xml_application = PIDFApplication
    _xml_extension_type = PersonExtension
    _xml_children_order = {None: 0,
                           DMNote.qname: 1,
                           PersonTimestamp.qname: 2}

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    timestamp = XMLElementChild('timestamp', type=PersonTimestamp, required=False, test_equal=True)
    _xml_id = id

    def __init__(self, id, notes=[], timestamp=None):
        XMLElement.__init__(self)
        self._note_map = {}
        self.id = id
        self.timestamp = timestamp
        self.notes.update(notes)

    @property
    def notes(self):
        return NoteList(self, DMNote)

    def _parse_element(self, element, *args, **kwargs):
        super(Person, self)._parse_element(element, *args, **kwargs)
        self.notes._parse_element(element, *args, **kwargs)

    def _build_element(self, *args, **kwargs):
        super(Person, self)._build_element(*args, **kwargs)
        self.notes._build_element(*args, **kwargs)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.id, list(self.notes), self.timestamp)


class PIDF(XMLListRootElement):
    content_type = 'application/pidf+xml'
    
    _xml_tag = 'presence'
    _xml_namespace = pidf_namespace
    _xml_application = PIDFApplication
    _xml_schema_file = 'pidf.xsd'
    _xml_children_order = {Service.qname: 0,
                           PIDFNote.qname: 1,
                           Person.qname: 2,
                           Device.qname: 3}
    _xml_item_type = (Service, PIDFNote, Person, Device)

    entity = XMLAttribute('entity', type=str, required=True, test_equal=True)

    services = property(lambda self: (item for item in self if type(item) is Service))
    notes    = property(lambda self: (item for item in self if type(item) is Note))
    persons  = property(lambda self: (item for item in self if type(item) is Person))
    devices  = property(lambda self: (item for item in self if type(item) is Device))

    def __init__(self, entity, elements=[]):
        XMLListRootElement.__init__(self)
        self.entity = entity
        self.update(elements)

    def __contains__(self, item):
        if isinstance(item, Note):
            item = PIDFNote(item, item.lang)
        return super(PIDF, self).__contains__(item)

    def __iter__(self):
        return (unicode(item) if type(item) is PIDFNote else item for item in super(PIDF, self).__iter__())

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.entity, list(self))

    def add(self, item):
        if isinstance(item, Note):
            item = PIDFNote(item, item.lang)
        super(PIDF, self).add(item)

    def remove(self, item):
        if isinstance(item, Note):
            try:
                item = (entry for entry in super(PIDF, self).__iter__() if type(entry) is PIDFNote and unicode(entry) == item).next()
            except StopIteration:
                raise KeyError(item)
        super(PIDF, self).remove(item)



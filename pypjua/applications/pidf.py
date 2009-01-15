"""PIDF handling according to RFC3863

This module provides classes to parse and generate PIDF documents, and also
uses the XML Application extensibility API to allow extensions to PIDF.

Example usage:

>>> from datetime import datetime
>>> pidf = PIDF('pres:someone@example.com')
>>> status = Status(basic=Basic('open'))
>>> contact = Contact('im:someone@mobilecarrier.net')
>>> contact.priority = "0.8"
>>> tuple1 = Tuple('bs35r9', notes=[Note("Don't Disturb Please!"), Note("Ne derangez pas, s'il vous plait", lang="fr")], status=status)
>>> tuple1.contact = contact
>>> tuple1.timestamp = Timestamp(datetime(2008, 9, 11, 20, 42, 03))
>>> tuple2 = Tuple('eg92n8', status=Status(basic=Basic('open')), contact=Contact('mailto:someone@example.com'))
>>> tuple2.contact.priority = "1.0"
>>> pidf.notes.append(Note("I'll be in Tokyo next week"))
>>> pidf.append(tuple1)
>>> pidf.append(tuple2)
>>> print pidf.toxml(pretty_print=True)
<?xml version='1.0' encoding='UTF-8'?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:someone@example.com">
  <tuple id="bs35r9">
    <status>
      <basic>open</basic>
    </status>
    <contact priority="0.8">im:someone@mobilecarrier.net</contact>
    <note>Don't Disturb Please!</note>
    <note xml:lang="fr">Ne derangez pas, s'il vous plait</note>
    <timestamp>2008-09-11T20:42:03+01:00</timestamp>
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

import re
import datetime

from pypjua.applications import ParserError, BuilderError, XMLMeta, XMLApplication, XMLElement, XMLStringElement, ExtensibleXMLApplication, ExtensibleXMLListApplication, ExtensibleXMLElement

__all__ = ['_namespace_',
           'PIDFMeta',
           'PIDFTopElement',
           'TupleExtension',
           'StatusExtension',
           'Note',
           'NoteList',
           'Tuple',
           'Status',
           'Basic',
           'Contact',
           'Timestamp',
           'PIDF']

_namespace_ = 'urn:ietf:params:xml:ns:pidf'


class PIDFMeta(XMLMeta): pass

# Mixin types for extenisibility
class PIDFTopElement(object): pass
class TupleExtension(object): pass
class StatusExtension(object): pass

class Timestamp(XMLElement):
    _xml_tag = 'timestamp'
    _xml_namespace = _namespace_
    _xml_attrs = {}
    _xml_meta = PIDFMeta

    _timestamp_re = re.compile(r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(\.(?P<secfrac>\d{1,}))?((?P<UTC>Z)|((?P<tzsign>\+|-)(?P<tzhour>\d{2}):(?P<tzminute>\d{2})))')

    def __init__(self, value=None):
        self.value = value

    def _parse_element(self, element):
        self.value = self.parse_timestamp(element.text)

    def _build_element(self, element, nsmap):
        element.text = self.format_timestamp(self.value)
    
    @classmethod
    def utc_offset(cls):
        timediff = datetime.datetime.now() - datetime.datetime.utcnow()
        return int(round((timediff.days*86400 + timediff.seconds + timediff.microseconds/1000000.0)/60))

    @classmethod
    def parse_timestamp(cls, stamp):
        if stamp is None:
            return None
        match = cls._timestamp_re.match(stamp)
        if match is None:
            raise ParserError("Timestamp %s is not in RFC3339 format" % stamp)
        dct = match.groupdict()
        if dct['UTC'] is not None:
            secoffset = 0
        else:
            secoffset = int(dct['tzminute'])*60 + int(dct['tzhour'])*3600
            if dct['tzsign'] == '-':
                secoffset *= -1
        if dct['secfrac'] is not None:
            secfrac = dct['secfrac'][:6]
            secfrac += '0'*(6-len(secfrac))
            secfrac = int(secfrac)
        else:
            secfrac = 0
        dt = datetime.datetime(year=int(dct['year']), month=int(dct['month']), day=int(dct['day']),
                               hour=int(dct['hour']), minute=int(dct['minute']), second=int(dct['second']),
                               microsecond=secfrac)
        return dt - datetime.timedelta(seconds=secoffset) + datetime.timedelta(seconds=cls.utc_offset()*60)

    @classmethod
    def format_timestamp(cls, dt):
        if dt is None:
            return None
        minutes = cls.utc_offset()
        if minutes == 0:
            tzspec = 'Z'
        else:
            if minutes < 0:
                sign = '-'
                minutes *= -1
            else:
                sign = '+'
            hours = minutes / 60
            minutes = minutes % 60
            tzspec = '%s%02d:%02d' % (sign, hours, minutes)
        return dt.replace(microsecond=0).isoformat()+tzspec
    
    def _set_value(self, value):
        if value is None:
            value = datetime.datetime.now()
        self.__value = value

    value = property(lambda self: self.__value, _set_value)
    
    def __str__(self):
        return str(self.value)

PIDFMeta.register(Timestamp)


class Note(XMLStringElement):
    _xml_tag = 'note'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = True
    _xml_attrs = {'since': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp, 'xml_attribute': 'from'},
                  'until': {'parse': Timestamp.parse_timestamp, 'build': Timestamp.format_timestamp}}

PIDFMeta.register(Note)

class NoteList(object):
    def __init__(self):
        self.__notes = {}

    def __getitem__(self, key):
        return self.__notes[key]

    def __delitem__(self, key):
        del self.__notes[key]

    def __iter__(self):
        return self.__notes.itervalues()

    def __len__(self):
        return len(self.__notes)

    def append(self, note):
        self.__notes[note.lang] = note

class Basic(XMLStringElement):
    _xml_tag = 'basic'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False
    _xml_values = ('open', 'closed')

PIDFMeta.register(Basic)

class Status(ExtensibleXMLElement):
    _xml_tag = 'status'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = PIDFMeta
    _xml_ext_type = StatusExtension

    def __init__(self, basic=None, **kwargs):
        ExtensibleXMLElement.__init__(self, **kwargs)
        self.basic = basic

    def _parse_element(self, element):
        self.basic = None
        for child in element:
            if child.tag == Basic.qname:
                self.basic = Basic.from_element(child, xml_meta=self._xml_meta)

    def _build_element(self, element, nsmap):
        if self.basic is not None:
            self.basic.to_element(parent=element, nsmap=nsmap)
        self._build_extensions(element, nsmap)
        if len(element) == 0:
            raise BuilderError("Status objects must have at least one child")

PIDFMeta.register(Status)

class Contact(XMLStringElement):
    _xml_tag = 'contact'
    _xml_namespace = _namespace_
    _xml_attrs = {'priority': {}}
    _xml_meta = PIDFMeta
    _xml_lang = False

PIDFMeta.register(Contact)

class Tuple(ExtensibleXMLElement, PIDFTopElement):
    _xml_tag = 'tuple'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = PIDFMeta
    _xml_ext_type = TupleExtension
    
    def __init__(self, id, notes=[], status=None, contact=None, timestamp=None, **kwargs):
        ExtensibleXMLElement.__init__(self, **kwargs)
        self.id = id
        self.notes = NoteList()
        for note in notes:
            self.notes.append(note)
        self.status = status
        self.contact = contact
        self.timestamp = timestamp
    
    def _parse_element(self, element):
        self.notes = NoteList()
        self.status = None
        self.contact = None
        self.timestamp = None
        for child in element:
            if child.tag == Note.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            elif child.tag == Status.qname:
                self.status = Status.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Contact.qname:
                self.contact = Contact.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Timestamp.qname:
                self.timestamp = Timestamp.from_element(child, xml_meta=self._xml_meta)

    def _build_element(self, element, nsmap):
        if self.id is None:
            raise BuilderError("`id' attribute of Tuple object must be specified")
        if self.status is None:
            raise BuilderError("Tuple objects must contain a Status child")
        self.status.to_element(parent=element, nsmap=nsmap)
        self._build_extensions(element, nsmap)
        if self.contact is not None:
            self.contact.to_element(parent=element, nsmap=nsmap)
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        if self.timestamp is not None:
            self.timestamp.to_element(parent=element, nsmap=nsmap)

PIDFMeta.register(Tuple)

class PIDF(ExtensibleXMLListApplication):
    accept_types = ['application/pidf+xml']
    build_types = ['application/pidf+xml']
    
    _xml_tag = 'presence'
    _xml_namespace = _namespace_
    _xml_attrs = {'entity': {'id_attribute': True}}
    _xml_meta = PIDFMeta
    _xml_schema_file = 'pidf.xsd'
    _xml_nsmap = {None: _namespace_}

    _parser_opts = {'remove_blank_text': True}

    def __init__(self, entity, elems=[], notes=[]):
        self.entity = entity
        self[0:0] = elems
        self.notes = NoteList()
        for note in notes:
            self.notes.append(note)

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
        if self.entity is None:
            raise BuilderError("`entity' attribute of PIDF object must be specified")
        other_children = []
        for child in self:
            if isinstance(child, Tuple):
                child.to_element(parent=element, nsmap=nsmap)
            else:
                other_children.append(child)
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        for child in other_children:
            child.to_element(parent=element, nsmap=nsmap)

    def _before_add(self, value):
        if not isinstance(value, PIDFTopElement):
            raise TypeError("PIDF elements can only contain PIDFTopElement children, got %s instead" % value.__class__.__name__)
        return value

PIDFMeta.register(PIDF)


"""Presence data-model elements handling according to RFC4479

This module provides an extension to PIDF (module pypjua.applications.pidf) to
support the data module defined in RFC4479.
"""

from pypjua.applications import XMLExtension, XMLStringElement, ExtensibleXMLElement
from pypjua.applications.pidf import PIDFTopElement, PIDF, PIDFMeta

_namespace_ = 'urn:ietf:params:xml:ns:pidf:data-model'


class DeviceExtension(object): pass
class PersonExtension(object): pass

class DeviceID(XMLStringElement):
    _xml_tag = 'deviceID'
    _xml_namespace = _namespace_
    _xml_meta = PIDFMeta
    _xml_lang = False

class Device(ExtensibleXMLElement, PIDFTopElement):
    _xml_tag = 'device'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = PIDFMeta
    _xml_ext_type = DeviceExtension

    def __init__(self, id, deviceID=None, notes=[], timestamp=None, **kwargs):
        ExtensibleXMLElement.__init__(self, **kwargs)
        self.id = id
        self.deviceID = deviceID
        self.notes = NoteList()
        for note in notes:
            self.notes.append(note)
        self.timestamp = timestamp

    def _parse_element(self, element):
        self.deviceID = None
        self.notes = NoteList()
        self.timestamp = None
        for child in element:
            if child.tag == DeviceID.qname:
                self.deviceID = DeviceID.from_element(child, xml_meta=self._xml_meta)
            elif child.tag == Note.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            elif child.tag == Timestamp.qname:
                self.timestamp = Timestamp.from_element(child, xml_meta=self._xml_meta)

    def _build_element(self, element, nsmap):
        self._build_extensions(element, nsmap)
        if self.deviceID is not None:
            self.deviceID.to_element(parent=element, nsmap=nsmap)
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        if self.timestamp is not None:
            self.timestamp.to_element(parent=element, nsmap=nsmap)

class Person(ExtensibleXMLElement, PIDFTopElement):
    _xml_tag = 'person'
    _xml_namespace = _namespace_
    _xml_attrs = {'id': {'id_attribute': True}}
    _xml_meta = PIDFMeta
    _xml_ext_type = PersonExtension

    def __init__(self, id, notes=[], timestamp=None, **kwargs):
        ExtensibleXMLElement.__init__(self, **kwargs)
        self.id = id
        self.notes = NoteList()
        for note in notes:
            self.notes.append(note)
        self.timestamp = timestamp

    def _parse_element(self, element):
        self.notes = NoteList()
        self.timestamp = None
        for child in element:
            if child.tag == Note.qname:
                self.notes.append(Note.from_element(child, xml_meta=self._xml_meta))
            elif child.tag == Timestamp.qname:
                self.timestamp = Timestamp.from_element(child, xml_meta=self._xml_meta)

    def _build_element(self, element, nsmap):
        self._build_extensions(element, nsmap)
        for note in self.notes:
            note.to_element(parent=element, nsmap=nsmap)
        if self.timestamp is not None:
            self.timestamp.to_element(parent=element, nsmap=nsmap)

class PresDMExtension(XMLExtension):
    _xml_ext_def = [(Device, []),
                    (Person, [])]
    _xml_namespace = _namespace_
    _xml_prefix = 'dm'
    _xml_schema_file = 'data-model.xsd'

PIDF.registerExtension(PresDMExtension)

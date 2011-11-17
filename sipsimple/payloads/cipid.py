# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
CIPID handling according to RFC4482

This module provides an extension to PIDF to provide additional contact
information about a presentity.
"""

from sipsimple.payloads import XMLStringElement
from sipsimple.payloads.pidf import PIDFDocument, ServiceExtension, PersonExtension, Service, Person

__all__ = ['cipid_namespace', 'Card', 'DisplayName', 'Homepage', 'Icon', 'Map', 'Sound']

cipid_namespace = "urn:ietf:params:xml:ns:pidf:cipid"
PIDFDocument.register_namespace(cipid_namespace, prefix='c', schema='cipid.xsd')


class Card(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'card'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument

Person.register_extension('card', type=Card)
Service.register_extension('card', type=Card)

class DisplayName(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'display-name'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument
    _xml_lang = True

Person.register_extension('display_name', type=DisplayName)
Service.register_extension('display_name', type=DisplayName)

class Homepage(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'homepage'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument

Person.register_extension('homepage', type=Homepage)
Service.register_extension('homepage', type=Homepage)

class Icon(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'icon'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument

Person.register_extension('icon', type=Icon)
Service.register_extension('icon', type=Icon)

class Map(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'map'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument

Person.register_extension('map', type=Map)
Service.register_extension('map', type=Map)

class Sound(XMLStringElement, PersonExtension, ServiceExtension):
    _xml_tag = 'sound'
    _xml_namespace = cipid_namespace
    _xml_document = PIDFDocument

Person.register_extension('sound', type=Sound)
Service.register_extension('sound', type=Sound)


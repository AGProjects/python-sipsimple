# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""Generates presence content application documents according to OMA TS Presence SIMPLE Content"""


__all__ = ['namespace', 'PresenceContentApplication', 'MIMEType', 'Encoding', 'Description', 'Data', 'PresenceContent']


from sipsimple.payloads import XMLApplication, XMLRootElement, XMLStringElement, XMLElementChild


namespace = 'urn:oma:xml:prs:pres-content'


class PresenceContentApplication(XMLApplication): pass
PresenceContentApplication.register_namespace(namespace, prefix=None)

# Elements
class MIMEType(XMLStringElement):
    _xml_tag = 'mime-type'
    _xml_namespace = namespace
    _xml_application = PresenceContentApplication

class Encoding(XMLStringElement):
    _xml_tag = 'encoding'
    _xml_namespace = namespace
    _xml_application = PresenceContentApplication

class Description(XMLStringElement):
    _xml_tag = 'description'
    _xml_namespace = namespace
    _xml_application = PresenceContentApplication
    _xml_lang = True

class Data(XMLStringElement):
    _xml_tag = 'data'
    _xml_namespace = namespace
    _xml_application = PresenceContentApplication

class PresenceContent(XMLRootElement):
    content_type = "application/vnd.oma.pres-content+xml"

    _xml_tag = 'content'
    _xml_namespace = namespace
    _xml_application = PresenceContentApplication
    _xml_schema_file = 'oma-pres-content.xsd'
    _xml_children_order = {MIMEType.qname: 0,
                           Encoding.qname: 1,
                           Description.qname: 2,
                           Data.qname: 3,
                           None: 4}

    mime_type = XMLElementChild('mime_type', type=MIMEType, required=False, test_equal=True)
    encoding = XMLElementChild('encoding', type=Encoding, required=False, test_equal=True)
    description = XMLElementChild('description', type=Description, required=False, test_equal=True)
    data = XMLElementChild('data', type=Data, required=True, test_equal=True)

    def __init__(self, data, mime_type=None, encoding=None, description=None):
        XMLRootElement.__init__(self)
        self.data = data
        self.mime_type = mime_type
        self.encoding = encoding
        self.description = description



"""Generates presence content application documents according to OMA TS Presence SIMPLE Content"""


__all__ = ['namespace', 'PresenceContentDocument', 'MIMEType', 'Encoding', 'Description', 'Data', 'PresenceContent']


from sipsimple.payloads import XMLDocument, XMLRootElement, XMLStringElement, XMLLocalizedStringElement, XMLElementChild


namespace = 'urn:oma:xml:prs:pres-content'


class PresenceContentDocument(XMLDocument):
    content_type = "application/vnd.oma.pres-content+xml"

PresenceContentDocument.register_namespace(namespace, prefix=None, schema='oma-pres-content.xsd')

# Elements
class MIMEType(XMLStringElement):
    _xml_tag = 'mime-type'
    _xml_namespace = namespace
    _xml_document = PresenceContentDocument


class Encoding(XMLStringElement):
    _xml_tag = 'encoding'
    _xml_namespace = namespace
    _xml_document = PresenceContentDocument


class Description(XMLLocalizedStringElement):
    _xml_tag = 'description'
    _xml_namespace = namespace
    _xml_document = PresenceContentDocument


class Data(XMLStringElement):
    _xml_tag = 'data'
    _xml_namespace = namespace
    _xml_document = PresenceContentDocument


class PresenceContent(XMLRootElement):
    _xml_tag = 'content'
    _xml_namespace = namespace
    _xml_document = PresenceContentDocument
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


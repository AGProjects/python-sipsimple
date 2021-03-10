
"""Parses and produces IMDN messages according to RFC5438."""


__all__ = ['namespace',
           'IMDNDocument',
           'MessageId',
           'DateTime',
           'RecipientUri',
           'OriginalRecipientUri',
           'Subject',
           'Delivered',
           'Failed',
           'Displayed',
           'Processed',
           'Stored',
           'Error',
           'Forbidden',
           'DeliveryStatus',
           'DisplayStatus',
           'ProcessingStatus',
           'DeliveryNotification',
           'DisplayNotification',
           'ProcessingNotification',
           'IMDNMessage']


from sipsimple.payloads import XMLDocument, XMLRootElement, XMLAnyURIElement, XMLStringElement, XMLElementChild, XMLElementChoiceChild, XMLEmptyElement, XMLElement


namespace = 'urn:ietf:params:xml:ns:imdn'


class IMDNDocument(XMLDocument):
    content_type = "message/imdn+xml"


IMDNDocument.register_namespace(namespace, prefix=None, schema='imdn.xsd')


# Elements

class MessageId(XMLStringElement):
    _xml_tag = 'message-id'
    _xml_namespace = namespace
    _xml_document = IMDNDocument


class DateTime(XMLStringElement):
    _xml_tag = 'datetime'
    _xml_namespace = namespace
    _xml_document = IMDNDocument


class RecipientUri(XMLAnyURIElement):
    _xml_tag = 'recipient-uri'
    _xml_namespace = namespace
    _xml_document = IMDNDocument


class OriginalRecipientUri(XMLAnyURIElement):
    _xml_tag = 'original-recipient-uri'
    _xml_namespace = namespace
    _xml_document = IMDNDocument


class Subject(XMLStringElement):
    _xml_tag = 'subject'
    _xml_namespace = namespace
    _xml_document = IMDNDocument


class StatusElement(XMLEmptyElement):
    _xml_namespace = namespace
    _xml_document = IMDNDocument

    def __init__(self):
        XMLEmptyElement.__init__(self)

    def __str__(self):
        return "%s" % (self._xml_tag)


class Delivered(StatusElement):
    _xml_tag = 'delivered'


class Failed(StatusElement):
    _xml_tag = 'failed'


class Displayed(StatusElement):
    _xml_tag = 'displayed'


class Processed(StatusElement):
    _xml_tag = 'processed'


class Stored(StatusElement):
    _xml_tag = 'stored'


class Error(StatusElement):
    _xml_tag = 'error'


class Forbidden(StatusElement):
    _xml_tag = 'forbidden'


class Status(XMLElement):
    _xml_tag = 'status'
    _xml_namespace = namespace
    _xml_document = IMDNDocument

    def __init__(self, status):
        XMLElement.__init__(self)
        if isinstance(status, basestring) and status not in ('delivered', 'failed', 'displayed', 'processed', 'stored', 'forbidden', 'error'):
            raise ValueError("illegal value for status")
        self.status = status if not isinstance(status, basestring) else eval(status.title())()

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.status)

    def __str__(self):
        return "%s" % (self.status)


class DeliveryStatus(Status):
    status = XMLElementChoiceChild('status', types=(Delivered, Failed, Forbidden, Error), required=True, test_equal=True)


class DisplayStatus(Status):
    status = XMLElementChoiceChild('status', types=(Displayed, Forbidden, Error), required=True, test_equal=True)


class ProcessingStatus(Status):
    status = XMLElementChoiceChild('status', types=(Processed, Stored, Forbidden, Error), required=True, test_equal=True)


class NotificationType(XMLElement):
    _xml_namespace = namespace
    _xml_document = IMDNDocument

    def __init__(self, status):
        XMLElement.__init__(self)
        self.status = status


class DeliveryNotification(NotificationType):
    _xml_tag = 'delivery-notification'

    status = XMLElementChild('status', type=DeliveryStatus, required=True, test_equal=True)


class DisplayNotification(NotificationType):
    _xml_tag = 'display-notification'

    status = XMLElementChild('status', type=DisplayStatus, required=True, test_equal=True)


class ProcessingNotification(NotificationType):
    _xml_tag = 'processing-notification'

    status = XMLElementChild('status', type=ProcessingStatus, required=True, test_equal=True)


# document

class IMDNMessage(XMLRootElement):
    _xml_tag = 'imdn'
    _xml_namespace = namespace
    _xml_document = IMDNDocument
    _xml_children_order = {MessageId.qname: 0,
                           DateTime.qname: 1,
                           RecipientUri.qname: 2,
                           OriginalRecipientUri.qname: 3,
                           Subject.qname: 4,
                           DeliveryNotification.qname: 5,
                           DisplayNotification.qname: 6,
                           ProcessingNotification.qname: 7,
                           None: 8}

    message_id = XMLElementChild('message_id', type=MessageId, required=True, test_equal=True)
    datetime = XMLElementChild('datetime', type=DateTime, required=True, test_equal=True)
    recipient_uri = XMLElementChild('recipient_uri', type=RecipientUri, required=False, test_equal=True)
    original_recipient_uri = XMLElementChild('original_recipient_uri', type=OriginalRecipientUri, required=False, test_equal=True)
    subject = XMLElementChild('subject', type=Subject, required=False, test_equal=True)
    notification = XMLElementChoiceChild('notification', types=(DisplayNotification, DeliveryNotification, ProcessingNotification), required=True, test_equal=True)

    def __init__(self, message_id=None, datetime=None, recipient_uri=None, original_recipient_uri=None, subject=None, notification=None):
        XMLRootElement.__init__(self)
        self.message_id = message_id
        self.datetime = datetime
        self.recipient_uri = recipient_uri
        self.original_recipient_uri = original_recipient_uri if original_recipient_uri is not None else recipient_uri
        self.subject = subject
        self.notification = notification

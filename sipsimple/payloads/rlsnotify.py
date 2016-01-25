
"""Payload of the RLS notify messages."""

__all__ = ['RLSNotify']

import email

from sipsimple.payloads import IterateItems, ParserError
from sipsimple.payloads import rlmi, pidf
from sipsimple.payloads import rpid; rpid # needs to be imported to register its namespace


class ResourceURI(unicode):
    def __eq__(self, other):
        return super(ResourceURI, self).__eq__(other) or self.rpartition('sip:')[2] == other

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class Resource(object):
    __prioritymap__ = dict(active=10, pending=20, terminated=30)

    def __init__(self, uri, name=None, state=None, reason=None, pidf_list=None):
        self.uri = ResourceURI(uri)
        self.name = name
        self.state = state
        self.reason = reason
        self.pidf_list = pidf_list or []

    @classmethod
    def from_payload(cls, xml_element, payload_map):
        try:
            name = next(element for element in xml_element if isinstance(element, rlmi.Name))
        except StopIteration:
            name = None
        instances = list(xml_element[rlmi.Instance, IterateItems])
        if len(instances) == 0:
            state = None
            reason = None
        elif len(instances) == 1:
            instance = instances[0]
            state = instance.state
            reason = instance.reason
        else:
            instance = sorted(instances, key=lambda item: cls.__prioritymap__[item.state])[0]
            state = instance.state
            reason = instance.reason
        pidf_list = []
        for instance in (instance for instance in instances if instance.cid is not None):
            try:
                payload = payload_map['<%s>' % instance.cid].get_payload()
            except KeyError:
                continue
            try:
                pidf_list.append(pidf.PIDFDocument.parse(payload))
            except ParserError:
                pass
        return cls(xml_element.uri, name, state, reason, pidf_list)


class RLSNotify(object):
    """The payload from RLS notify messages"""

    content_type = 'multipart/related'

    def __init__(self, uri, version, full_state, resources):
        self.uri = ResourceURI(uri)
        self.version = version
        self.full_state = full_state
        self.resources = resources

    def __iter__(self):
        return iter(self.resources)

    def __len__(self):
        return len(self.resources)

    @classmethod
    def parse(cls, payload):
        message = email.message_from_string(payload)
        if message.get_content_type() != cls.content_type:
            raise ParserError("expected multipart/related content, got %s" % message.get_content_type())
        payloads = message.get_payload()
        if len(payloads) == 0:
            raise ParserError("multipart/related body contains no parts")
        payload_map = dict((payload['Content-ID'], payload) for payload in payloads if payload['Content-ID'] is not None)
        root_id = message.get_param('start')
        root_type = message.get_param('type', '').lower()
        if root_id is not None:
            try:
                root = payload_map[root_id]
            except KeyError:
                raise ParserError('cannot find root element')
        else:
            root = payloads[0]
        if root_type != rlmi.RLMIDocument.content_type != root.get_content_type():
            raise ParserError("the multipart/related root element must be of type %s" % rlmi.RLMIDocument.content_type)
        rlmi_document = rlmi.RLMIDocument.parse(root.get_payload())
        resources = [Resource.from_payload(xml_element, payload_map) for xml_element in rlmi_document[rlmi.Resource, IterateItems]]
        return cls(rlmi_document.uri, rlmi_document.version, rlmi_document.full_state, resources)



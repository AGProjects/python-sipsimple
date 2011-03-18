# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""Parses and produces dialog-info messages according to RFC4235."""


__all__ = ['namespace',
        'DialogInfoApplication',
        'DialogState',
        'Replaces',
        'ReferredBy',
        'Identity',
        'Param',
        'Target',
        'Local',
        'Remote',
        'Dialog',
        'DialogInfo']


from sipsimple.payloads import ValidationError, XMLApplication, XMLListRootElement, XMLListElement, XMLStringElement, XMLElementChild, XMLEmptyElement, XMLElement, XMLAttribute


namespace = 'urn:ietf:params:xml:ns:dialog-info'


class DialogInfoApplication(XMLApplication): pass
DialogInfoApplication.register_namespace(namespace, prefix=None)


# Attribute value types
class StateValue(str):
    def __new__(cls, value):
        if value not in ('full', 'partial'):
            raise ValueError("illegal value for state")
        return str.__new__(cls, value)

class VersionValue(int):
    def __new__(cls, value):
        value = int.__new__(cls, value)
        if value < 0:
            raise ValueError("illegal value for version")
        return value

class DirectionValue(str):
    def __new__(cls, value):
        if value not in ('initiator', 'recipient'):
            raise ValueError("illegal value for direction")
        return str.__new__(cls, value)

class DialogEventValue(str):
    def __new__(cls, value):
        if value not in ('rejected', 'cancelled', 'replaced', 'local-bye', 'remote-bye', 'error', 'timeout'):
            raise ValueError("illegal value for dialog state event")
        return str.__new__(cls, value)

class DialogStateValue(str):
    def __new__(cls, value):
        if value not in ('tying', 'proceeding', 'early', 'confirmed', 'terminated'):
            raise ValueError("illegal value for dialog state")
        return str.__new__(cls, value)

class CodeValue(int):
    def __new__(cls, value):
        value = int.__new__(cls, value)
        if value < 100 or value > 699:
            raise ValueError("illegal value for code")
        return value

# Elements
class CallId(XMLStringElement):
    _xml_tag = 'call-id'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

class LocalTag(XMLStringElement):
    _xml_tag = 'local-tag'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

class RemoteTag(XMLStringElement):
    _xml_tag = 'remote-tag'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

class DialogState(XMLStringElement):
    _xml_tag = 'state'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication
    _xml_value_type = DialogStateValue

    code = XMLAttribute('code', type=int, required=False, test_equal=True)
    event = XMLAttribute('event', type=DialogEventValue, required=False, test_equal=True)

class Duration(XMLStringElement):
    _xml_tag = 'duration'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication
    _xml_value_type = int

class Replaces(XMLEmptyElement):
    _xml_tag = 'replaces'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    call_id = XMLAttribute('call_id', xmlname='call-id', type=str, required=True, test_equal=True)
    local_tag = XMLAttribute('local_tag', xmlname='local-tag', type=str, required=True, test_equal=True)
    remote_tag = XMLAttribute('remote_tag', xmlname='remote-tag', type=str, required=True, test_equal=True)

    def __init__(self, call_id, local_tag, remote_tag):
        XMLEmptyElement.__init__(self)
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag

class ReferredBy(XMLStringElement):
    _xml_tag = 'referred-by'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    display_name = XMLAttribute('display_name', xmlname='display-name', type=str, required=False, test_equal=True)

class Identity(XMLStringElement):
    _xml_tag = 'identity'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    display_name = XMLAttribute('display_name', xmlname='display-name', type=str, required=False, test_equal=True)

class Param(XMLEmptyElement):
    _xml_tag = 'param'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    pname = XMLAttribute('pname', type=str, required=True, test_equal=True)
    pval = XMLAttribute('pval', type=str, required=True, test_equal=True)

    def __init__(self, pname, pval):
        XMLEmptyElement.__init__(self)
        self.pname = pname
        self.pval = pval

class Target(XMLListElement):
    _xml_tag = 'target'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    uri = XMLAttribute('uri', type=str, required=True, test_equal=True)

    def __init__(self, uri, params=[]):
        self.uri = uri
        self[0:0] = params

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Param]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Param)):
            raise TypeError("Target element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value

class Participant(XMLElement):
    _xml_tag = ''   # To be set by a subclass
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    identity = XMLElementChild('identity', type=Identity, required=False, test_equal=True)
    target = XMLElementChild('target', type=Target, required=False, test_equal=True)

    def __init__(self, identity=None, target=None):
        XMLElement.__init__(self)
        self.identity = identity
        self.target = target

class Local(Participant):
    _xml_tag = 'local'

class Remote(Participant):
    _xml_tag = 'remote'

class Dialog(XMLElement):
    _xml_tag = 'dialog'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication

    id = XMLAttribute('id', type=str, required=True, test_equal=True)
    call_id = XMLAttribute('call_id', xmlname='call-id', type=str, required=False, test_equal=True)
    local_tag = XMLAttribute('local_tag', xmlname='local-tag', type=str, required=False, test_equal=True)
    remote_tag = XMLAttribute('remote_tag', xmlname='remote-tag', type=str, required=False, test_equal=True)
    direction = XMLAttribute('direction', type=DirectionValue, required=False, test_equal=True)

    state = XMLElementChild('state', type=DialogState, required=True, test_equal=True)
    duration = XMLElementChild('duration', type=Duration, required=False, test_equal=True)
    replaces = XMLElementChild('replaces', type=Replaces, required=False, test_equal=True)
    referred_by = XMLElementChild('referred_by', type=ReferredBy, required=False, test_equal=True)
    local = XMLElementChild('local', type=Local, required=False, test_equal=True)
    remote = XMLElementChild('remote', type=Remote, required=False, test_equal=True)

    def __init__(self, id, state, call_id=None, local_tag=None, remote_tag=None, direction=None, duration=None, replaces=None, referred_by=None, local=None, remote=None):
        XMLElement.__init__(self)
        self.id = id
        self.state = state
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.direction = direction
        self.duration = duration
        self.replaces = replaces
        self.referred_by = referred_by
        self.local = local
        self.remote = remote

class DialogInfo(XMLListRootElement):
    content_type = "application/dialog-info+xml"

    _xml_tag = 'dialog-info'
    _xml_namespace = namespace
    _xml_application = DialogInfoApplication
    _xml_schema_file = 'dialog-info.xsd'
    _xml_children_order = {Dialog.qname: 0,
                           None: 1}

    version = XMLAttribute('version', type=VersionValue, required=True, test_equal=True)
    state = XMLAttribute('state', type=StateValue, required=True, test_equal=True)
    entity = XMLAttribute('entity', type=str, required=True, test_equal=True)

    def __init__(self, version, state, entity, dialogs=[]):
        XMLListRootElement.__init__(self)
        self.version = version
        self.state = state
        self.entity = entity
        self[0:0] = dialogs

    def _build_element(self, *args, **kwargs):
        for child in self:
            child.to_element(*args, **kwargs)

    def _del_item(self, value):
        self.element.remove(value.element)

    def _parse_element(self, element, *args, **kwargs):
        for child in element:
            child_cls = self._xml_application.get_element(child.tag)
            if child_cls is not None and (True if child_cls is [c for c in [Dialog]] else False):
                try:
                    list.append(self, child_cls.from_element(child, *args, **kwargs))
                except ValidationError:
                    pass

    def _add_item(self, value):
        if not isinstance(value, (Dialog)):
            raise TypeError("dialog-info element can't contain %s element" % value.__class__.__name__)
        self._insert_element(value.element)
        return value


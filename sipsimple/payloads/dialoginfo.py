
"""Parses and produces dialog-info messages according to RFC4235."""


__all__ = ['namespace',
           'DialogInfoDocument',
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


from sipsimple.payloads import XMLDocument, XMLListRootElement, XMLListElement, XMLStringElement, XMLNonNegativeIntegerElement, XMLElementChild, XMLEmptyElement, XMLElement, XMLElementID, XMLAttribute
from sipsimple.payloads import IterateIDs, IterateItems, All


namespace = 'urn:ietf:params:xml:ns:dialog-info'


class DialogInfoDocument(XMLDocument):
    content_type = "application/dialog-info+xml"

DialogInfoDocument.register_namespace(namespace, prefix=None, schema='dialog-info.xsd')


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
        if value not in ('trying', 'proceeding', 'early', 'confirmed', 'terminated'):
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
    _xml_document = DialogInfoDocument


class LocalTag(XMLStringElement):
    _xml_tag = 'local-tag'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument


class RemoteTag(XMLStringElement):
    _xml_tag = 'remote-tag'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument


class DialogState(XMLStringElement):
    _xml_tag = 'state'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument
    _xml_value_type = DialogStateValue

    code = XMLAttribute('code', type=int, required=False, test_equal=True)
    event = XMLAttribute('event', type=DialogEventValue, required=False, test_equal=True)


class Duration(XMLNonNegativeIntegerElement):
    _xml_tag = 'duration'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument


class Replaces(XMLEmptyElement):
    _xml_tag = 'replaces'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument

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
    _xml_document = DialogInfoDocument

    display = XMLAttribute('display', type=str, required=False, test_equal=True)


class Identity(XMLStringElement):
    _xml_tag = 'identity'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument

    display = XMLAttribute('display', type=str, required=False, test_equal=True)


class Param(XMLEmptyElement):
    _xml_tag = 'param'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument

    pname = XMLAttribute('pname', type=str, required=True, test_equal=True)
    pval = XMLAttribute('pval', type=str, required=True, test_equal=True)

    def __init__(self, pname, pval):
        XMLEmptyElement.__init__(self)
        self.pname = pname
        self.pval = pval


class Target(XMLListElement):
    _xml_tag = 'target'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument
    _xml_item_type = Param

    uri = XMLAttribute('uri', type=str, required=True, test_equal=True)

    def __init__(self, uri, params=[]):
        self.uri = uri
        self.update(params)


class Participant(XMLElement):
    identity = XMLElementChild('identity', type=Identity, required=False, test_equal=True)
    target = XMLElementChild('target', type=Target, required=False, test_equal=True)

    def __init__(self, identity=None, target=None):
        XMLElement.__init__(self)
        self.identity = identity
        self.target = target


class Local(Participant):
    _xml_tag = 'local'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument


class Remote(Participant):
    _xml_tag = 'remote'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument


class Dialog(XMLElement):
    _xml_tag = 'dialog'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument

    id = XMLElementID('id', type=str, required=True, test_equal=True)

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
    _xml_tag = 'dialog-info'
    _xml_namespace = namespace
    _xml_document = DialogInfoDocument
    _xml_children_order = {Dialog.qname: 0,
                           None: 1}
    _xml_item_type = Dialog

    version = XMLAttribute('version', type=VersionValue, required=True, test_equal=True)
    state = XMLAttribute('state', type=StateValue, required=True, test_equal=True)
    entity = XMLAttribute('entity', type=str, required=True, test_equal=True)

    def __init__(self, version, state, entity, dialogs=[]):
        XMLListRootElement.__init__(self)
        self.version = version
        self.state = state
        self.entity = entity
        self.update(dialogs)

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[Dialog].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[Dialog].itervalues()
        else:
            return self._xmlid_map[Dialog][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[Dialog].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[Dialog][key])

    def get(self, key, default=None):
        return self._xmlid_map[Dialog].get(key, default)



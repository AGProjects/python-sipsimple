
"""Parses application/watcherinfo+xml documents according to RFC3857 and RFC3858."""


__all__ = ['namespace',
           'NeedFullUpdateError',
           'WatcherInfoDocument',
           'Watcher',
           'WatcherList',
           'WatcherInfo']


from sipsimple.payloads import XMLDocument, XMLAnyURIElement, XMLListElement, XMLListRootElement, XMLElementID, XMLAttribute
from sipsimple.payloads import IterateIDs, IterateItems, All
from sipsimple.payloads.datatypes import NonNegativeInteger, UnsignedLong, SIPURI


namespace = 'urn:ietf:params:xml:ns:watcherinfo'


class NeedFullUpdateError(Exception): pass


class WatcherInfoDocument(XMLDocument):
    content_type = 'application/watcherinfo+xml'

WatcherInfoDocument.register_namespace(namespace, prefix=None, schema='watcherinfo.xsd')


## Attribute value types

class WatcherStatus(str):
    def __new__(cls, value):
        if value not in ('pending', 'active', 'waiting', 'terminated'):
            raise ValueError('illegal status value for watcher')
        return str.__new__(cls, value)


class WatcherEvent(str):
    def __new__(cls, value):
        if value not in ('subscribe', 'approved', 'deactivated', 'probation', 'rejected', 'timeout', 'giveup', 'noresource'):
            raise ValueError('illegal event value for watcher')
        return str.__new__(cls, value)


class WatcherInfoState(str):
    def __new__(cls, value):
        if value not in ('full', 'partial'):
            raise ValueError('illegal state value for watcherinfo')
        return str.__new__(cls, value)


## XMLElements

class Watcher(XMLAnyURIElement):
    """
    Definition for a watcher in a watcherinfo document

    Provides the attributes:
     * id
     * status
     * event
     * display_name
     * expiration
     * duration
     * sipuri

    Can be transformed to a string with the format DISPLAY_NAME <SIP_URI>.
    """

    _xml_tag = 'watcher'
    _xml_namespace = namespace
    _xml_document = WatcherInfoDocument
    _xml_value_type = SIPURI

    id           = XMLElementID('id', type=str, required=True, test_equal=True)
    status       = XMLAttribute('status', type=WatcherStatus, required=True, test_equal=True)
    event        = XMLAttribute('event', type=WatcherEvent, required=True, test_equal=True)
    display_name = XMLAttribute('display_name', xmlname='display-name', type=str, required=False, test_equal=True)
    expiration   = XMLAttribute('expiration', type=UnsignedLong, required=False, test_equal=False)
    duration     = XMLAttribute('duration', xmlname='duration-subscribed', type=UnsignedLong, required=False, test_equal=False)

    sipuri = XMLAnyURIElement.value

    def __init__(self, sipuri, id, status, event, display_name=None, expiration=None, duration=None):
        XMLAnyURIElement.__init__(self)
        self.sipuri = sipuri
        self.id = id
        self.status = status
        self.event = event
        self.display_name = display_name
        self.expiration = expiration
        self.duration = duration

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.sipuri, self.id, self.status, self.event, self.display_name, self.expiration, self.duration)

    def __str__(self):
        return '"%s" <%s>' % (self.display_name, self.sipuri) if self.display_name else self.sipuri


class WatcherList(XMLListElement):
    """
    Definition for a list of watchers in a watcherinfo document
    
    It behaves like a list in that it can be indexed by a number, can be
    iterated and counted.

    It also provides the properties pending, active and terminated which are
    generators returning Watcher objects with the corresponding status.
    """

    _xml_tag = 'watcher-list'
    _xml_namespace = namespace
    _xml_document = WatcherInfoDocument
    _xml_children_order = {Watcher.qname: 0}
    _xml_item_type = Watcher

    resource = XMLElementID('resource', type=SIPURI, required=True, test_equal=True)
    package  = XMLAttribute('package', type=str, required=True, test_equal=True)

    def __init__(self, resource, package, watchers=[]):
        XMLListElement.__init__(self)
        self.resource = resource
        self.package = package
        self.update(watchers)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.resource, self.package, list(self))

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[Watcher].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[Watcher].itervalues()
        else:
            return self._xmlid_map[Watcher][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[Watcher].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[Watcher][key])

    def get(self, key, default=None):
        return self._xmlid_map[Watcher].get(key, default)

    pending = property(lambda self: (watcher for watcher in self if watcher.status == 'pending'))
    waiting = property(lambda self: (watcher for watcher in self if watcher.status == 'waiting'))
    active = property(lambda self: (watcher for watcher in self if watcher.status == 'active'))
    terminated = property(lambda self: (watcher for watcher in self if watcher.status == 'terminated'))


class WatcherInfo(XMLListRootElement):
    """
    Definition for watcher info: a list of WatcherList elements
    
    The user agent instantiates this class once it subscribes to a *.winfo event
    and calls its update() method with the application/watcherinfo+xml documents
    it receives via NOTIFY.

    The watchers can be accessed in two ways:
     1. via the wlists property, which returns a list of WatcherList elements;
     2. via the pending, active and terminated properties, which return
     dictionaries, mapping WatcherList objects to lists of Watcher objects.
     Since WatcherList objects can be compared for equality to SIP URI strings,
     representing the presentity to which the watchers have subscribed, the
     dictionaries can also be indexed by such strings.
    """

    _xml_tag = 'watcherinfo'
    _xml_namespace = namespace
    _xml_document = WatcherInfoDocument
    _xml_children_order = {WatcherList.qname: 0}
    _xml_item_type = WatcherList

    version = XMLAttribute('version', type=NonNegativeInteger, required=True, test_equal=True)
    state   = XMLAttribute('state', type=WatcherInfoState, required=True, test_equal=True)

    def __init__(self, version=0, state='full', wlists=[]):
        XMLListRootElement.__init__(self)
        self.version = version
        self.state = state
        self.update(wlists)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.version, self.state, list(self))

    def __getitem__(self, key):
        if key is IterateIDs:
            return self._xmlid_map[WatcherList].iterkeys()
        elif key is IterateItems:
            return self._xmlid_map[WatcherList].itervalues()
        else:
            return self._xmlid_map[WatcherList][key]

    def __delitem__(self, key):
        if key is All:
            for item in self._xmlid_map[WatcherList].values():
                self.remove(item)
        else:
            self.remove(self._xmlid_map[WatcherList][key])

    def get(self, key, default=None):
        return self._xmlid_map[WatcherList].get(key, default)

    wlists = property(lambda self: self._element_map.values())
    pending = property(lambda self: dict((wlist, list(wlist.pending)) for wlist in self._element_map.itervalues()))
    waiting = property(lambda self: dict((wlist, list(wlist.waiting)) for wlist in self._element_map.itervalues()))
    active = property(lambda self: dict((wlist, list(wlist.active)) for wlist in self._element_map.itervalues()))
    terminated = property(lambda self: dict((wlist, list(wlist.terminated)) for wlist in self._element_map.itervalues()))



# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses application/watcherinfo+xml documents according to RFC3857 and RFC3858.

Example:

>>> winfo_doc='''<?xml version="1.0"?>
... <watcherinfo xmlns="urn:ietf:params:xml:ns:watcherinfo"
...              version="0" state="full">
...   <watcher-list resource="sip:professor@example.net" package="presence">
...     <watcher status="active"
...              id="8ajksjda7s"
...              duration-subscribed="509"
...              event="approved" >sip:userA@example.net</watcher>
...     <watcher status="pending"
...              id="hh8juja87s997-ass7"
...              display-name="Mr. Subscriber"
...              event="subscribe">sip:userB@example.org</watcher>
...   </watcher-list>
... </watcherinfo>'''
>>> winfo = WatcherInfo()

The return value of winfo.update() is a dictionary containing WatcherList objects
as keys and lists of the updated watchers as values.

>>> updated = winfo.update(winfo_doc)
>>> len(updated['sip:professor@example.net'])
2

winfo.pending, winfo.terminated and winfo.active are dictionaries indexed by
WatcherList objects as keys and lists of Wacher objects as values.

>>> print winfo.pending['sip:professor@example.net'][0]
"Mr. Subscriber" <sip:userB@example.org>
>>> print winfo.pending['sip:professor@example.net'][1]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
IndexError: list index out of range
>>> print winfo.active['sip:professor@example.net'][0]
sip:userA@example.net
>>> len(winfo.terminated['sip:professor@example.net'])
0

winfo.wlists is the list of WatcherList objects

>>> list(winfo.wlists[0].active) == list(winfo.active['sip:professor@example.net'])
True


See the classes for more information.
"""

from sipsimple.applications import ValidationError, XMLApplication, XMLElement, XMLListElement, XMLListRootElement, XMLAttribute
from sipsimple.applications.util import UnsignedLong, SIPURI

__all__ = ['namespace',
           'NeedFullUpdateError',
           'WatcherInfoApplication',
           'Watcher',
           'WatcherList',
           'WatcherInfo']


namespace = 'urn:ietf:params:xml:ns:watcherinfo'

class NeedFullUpdateError(Exception): pass


class WatcherInfoApplication(XMLApplication): pass
WatcherInfoApplication.register_namespace(namespace, prefix=None)


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

class Watcher(XMLElement):
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
    _xml_application = WatcherInfoApplication
    
    id           = XMLAttribute('id', type=str, required=True, test_equal=True)
    status       = XMLAttribute('status', type=WatcherStatus, required=True, test_equal=True)
    event        = XMLAttribute('event', type=WatcherEvent, required=True, test_equal=True)
    display_name = XMLAttribute('display_name', xmlname='display-name', type=str, required=False, test_equal=True)
    expiration   = XMLAttribute('expiration', type=UnsignedLong, required=False, test_equal=False)
    duration     = XMLAttribute('duration', xmlname='duration-subscribed', type=UnsignedLong, required=False, test_equal=False)
    _xml_id      = id

    def __init__(self, sipuri, id, status, event, display_name=None, expiration=None, duration=None):
        XMLElement.__init__(self)
        self.sipuri = sipuri
        self.id = id
        self.status = status
        self.event = event
        self.display_name = display_name
        self.expiration = expiration
        self.duration = duration

    def _parse_element(self, element, *args, **kwargs):
        try:
            self.sipuri = element.text
        except ValueError, e:
            raise ValidationError("invalid SIPURI in Watcher: %s" % e.message)

    def _build_element(self, *args, **kwargs):
        pass

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r)' % (self.__class__.__name__, self.sipuri, self.id, self.status, self.event, self.display_name, self.expiration, self.duration)

    def __str__(self):
        return self.display_name and '"%s" <%s>' % (self.display_name, self.sipuri) or self.sipuri

    def _get_sipuri(self):
        return self._sipuri

    def _set_sipuri(self, value):
        if not isinstance(value, SIPURI):
            value = SIPURI(value)
        self._sipuri = value
        self.element.text = value
    
    sipuri = property(_get_sipuri, _set_sipuri)
    del _get_sipuri, _set_sipuri


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
    _xml_application = WatcherInfoApplication
    _xml_children_order = {Watcher.qname: 0}

    resource = XMLAttribute('resource', type=SIPURI, required=True, test_equal=True)
    package  = XMLAttribute('package', type=str, required=True, test_equal=True)
    _xml_id  = resource

    def __init__(self, resource, package, watchers=[]):
        XMLListElement.__init__(self)
        self.resource = resource
        self.package = package
        self._watchers = {}
        self[:] = watchers

    def _parse_element(self, element, *args, **kwargs):
        self._watchers = {}
        for child in element:
            if child.tag == Watcher.qname:
                try:
                    watcher = Watcher.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    if watcher.id in self._watchers:
                        element.remove(child)
                        continue
                    self._watchers[watcher.id] = watcher
                    list.append(self, watcher)

    def _build_element(self, *args, **kwargs):
        for watcher in self:
            watcher.to_element(*args, **kwargs)

    def update(self, watcherlist):
        updated = []
        for watcher in watcherlist:
            old = self._watchers.get(watcher.id, None)
            if old is not None:
                self.remove(old)
            self.append(watcher)
            if old is None or old != watcher:
                updated.append(watcher)
        return updated

    def _add_item(self, watcher):
        if not isinstance(watcher, Watcher):
            raise TypeError("WatcherList can only contain Watcher elements")
        old_watcher = self._watchers.get(watcher.id)
        if old_watcher is not None:
            self.remove(old_watcher)
        self._watchers[watcher.id] = watcher
        self._insert_element(watcher.element)
        return watcher

    def _del_item(self, watcher):
        del self._watchers[watcher.id]
        self.element.remove(watcher.element)
    
    def get(self, id, default=None):
        return self._watchers.get(id, default)
    
    # it also makes sense to be able to get a watcher by its id
    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._watchers[key]
        else:
            return super(WatcherList, self).__getitem__(key)

    def __repr__(self):
        return '%s(%r, %r, [%s])' % (self.__class__.__name__, self.resource, self.package, ', '.join('%r' % watcher for watcher in self._watchers.itervalues()))

    __str__ = __repr__

    pending = property(lambda self: (watcher for watcher in self if watcher.status == 'pending'))
    waiting = property(lambda self: (watcher for watcher in self if watcher.status == 'waiting'))
    active = property(lambda self: (watcher for watcher in self if watcher.status == 'active'))
    terminated = property(lambda self: (watcher for watcher in self if watcher.status == 'terminated'))


class WatcherInfo(XMLListRootElement):
    """
    Definition for watcher info: a list of WatcherList elements
    
    The user agent instantiates this class once it subscribes to a *.winfo event
    and calls its update() method with the applicatin/watcherinfo+xml documents
    it receives via NOTIFY.

    The watchers can be accessed in two ways:
     1. via the wlists property, which returns a list of WatcherList elements;
     2. via the pending, active and terminated properties, which return
     dictionaries, mapping WatcherList objects to lists of Watcher objects.
     Since WatcherList objects can be compared for equality to SIP URI strings,
     representing the presentity to which the watchers have subscribed, the
     dictionaries can also be indexed by such strings.
    """
    
    content_type = 'application/watcherinfo+xml'

    _xml_tag = 'watcherinfo'
    _xml_namespace = namespace
    _xml_application = WatcherInfoApplication
    _xml_children_order = {WatcherList.qname: 0}
    _xml_schema_file = 'watcherinfo.xsd'

    version = XMLAttribute('version', type=int, required=True, test_equal=True)
    state   = XMLAttribute('state', type=WatcherInfoState, required=True, test_equal=True)
    
    def __init__(self, version=-1, state='full', wlists=[]):
        XMLListRootElement.__init__(self)
        self.version = version
        self.state = state
        self._wlists = {}
        self[:] = wlists

    def _parse_element(self, element, *args, **kwargs):
        self._wlists = {}
        for child in element:
            if child.tag == WatcherList.qname:
                try:
                    wlist = WatcherList.from_element(child, *args, **kwargs)
                except ValidationError:
                    pass
                else:
                    if wlist.resource in self._wlists:
                        element.remove(child)
                        continue
                    self._wlists[wlist.resource] = wlist
                    list.append(self, wlist)

    def _build_element(self, *args, **kwargs):
        for wlist in self:
            wlist.to_element(*args, **kwargs)
    
    def update(self, document):
        """
        Updates the state of this WatcherInfo object with data from an
        application/watcherinfo+xml document, passed as a string. 
        
        Will throw a NeedFullUpdateError if the current document is a partial
        update and the previous version wasn't received.
        """
        winfo = WatcherInfo.parse(document)
        
        if winfo.version <= self.version:
            return {}
        if winfo.state == 'partial' and winfo.version != self.version + 1:
            raise NeedFullUpdateError("cannot update with version %d since last version received is %d" % (winfo.version, self.version))
        self.version = winfo.version

        updated_lists = {}
        if winfo.state == 'full':
            self.clear()
            for new_wlist in winfo:
                self.append(new_wlist)
                updated_lists[new_wlist] = list(new_wlist)
        elif winfo.state == 'partial':
            for new_wlist in winfo:
                if new_wlist.resource in self._wlists:
                    wlist = self._wlists.get(new_wlist.resource, None)
                    updated = wlist.update(new_wlist)
                    if updated:
                        updated_lists[wlist] = updated
                else:
                    self.append(new_wlist)
                    updated_lists[new_wlist] = list(new_wlist)
        
        return updated_lists

    def _add_item(self, wlist):
        if not isinstance(wlist, WatcherList):
            raise TypeError("WatcherInfo can only contain WatcherList elements")
        old_wlist = self._wlists.get(wlist.resource, None)
        if old_wlist is not None:
            self.remove(old_wlist)
        self._wlists[wlist.resource] = wlist
        self._insert_element(wlist.element)
        return wlist

    def _del_item(self, wlist):
        del self._wlists[wlist.resource]
        self.element.remove(wlist.element)

    def get(self, id, default=None):
        return self._wlists.get(id, default)

    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self._wlists[key]
        else:
            return super(WatcherInfo, self).__getitem__(key)

    def __repr__(self):
        return '%s(%r, %r, %s)' % (self.__class__.__name__, self.version, self.state, list.__repr__(self))

    __str__ = __repr__

    wlists = property(lambda self: self._wlists.values())
    pending = property(lambda self: dict((wlist, list(wlist.pending)) for wlist in self))
    waiting = property(lambda self: dict((wlist, list(wlist.waiting)) for wlist in self))
    active = property(lambda self: dict((wlist, list(wlist.active)) for wlist in self))
    terminated = property(lambda self: dict((wlist, list(wlist.terminated)) for wlist in self))



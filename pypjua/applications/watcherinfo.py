"""
Parses application/watcherinfo+xml documents according to RFC3857 and RFC3858.

See WatcherInfo class for more information.
"""

from lxml import etree

from pypjua.applications import XMLParser, XMLElementMapping, ParserError

__all__ = ["NeedFullUpdateError", "WatcherInfo"]

class NeedFullUpdateError(Exception): pass

class Watcher(XMLElementMapping):
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
    _xml_attrs = {
            'id': {'id_attribute': True},
            'status': {},
            'event': {},
            'display_name': {'xml_attribute': 'display-name'},
            'expiration': {'testequal': False},
            'duration': {'testequal': False}}

    def __init__(self, element):
        XMLElementMapping.__init__(self, element)
        self.sipuri = element.text

    def __str__(self):
        return self.display_name and '%s <%s>' % (self.display_name, self.sipuri) or self.sipuri

class WatcherList(XMLElementMapping):
    """
    Definition for a list of watchers in a watcherinfo document
    
    It behaves like a list in that it can be indexed by a number, can be
    iterated and counted.

    It also provides the properties pending, active and terminated which are
    generators returning Watcher objects with the corresponding status.
    """
    _xml_attrs = {
            'resource': {'id_attribute': True},
            'package': {}}

    def __init__(self, element, full_parse=True):
        self._watchers = {}
        XMLElementMapping.__init__(self, element, full_parse)

    def _parse_element(self, element, full_parse):
        if full_parse:
            self.update(element)

    def update(self, element):
        updated = []
        for child in element:
            watcher = Watcher(child)
            old = self._watchers.get(watcher.id)
            self._watchers[watcher.id] = watcher
            if old is None or old != watcher:
                updated.append(watcher)
        return updated
    
    def __iter__(self):
        return self._watchers.itervalues()

    def __getitem__(self, index):
        return self._watchers.values()[index]

    def __len__(self):
        return len(self._watchers)

    pending = property(lambda self: (watcher for watcher in self if watcher.status in ('pending', 'waiting')))
    active = property(lambda self: (watcher for watcher in self if watcher.status == 'active'))
    terminated = property(lambda self: (watcher for watcher in self if watcher.status == 'terminated'))

class WatcherInfo(XMLParser):
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

    Example:
     Given the following watcherinfo document:
<?xml version="1.0"?>
<watcherinfo xmlns="urn:ietf:params:xml:ns:watcherinfo"
             version="0" state="full">
  <watcher-list resource="sip:professor@example.net" package="presence">
    <watcher status="active"
             id="8ajksjda7s"
             duration-subscribed="509"
             event="approved" >sip:userA@example.net</watcher>
    <watcher status="pending"
             id="hh8juja87s997-ass7"
             display-name="Mr. Subscriber"
             event="subscribe">sip:userB@example.org</watcher>
  </watcher-list>
</watcherinfo>
      
      winfo = WatcherInfo()
      winfo.update(documentstring)
      winfo.pending['sip:professor@example.net'] # contains Watcher describing sip:userB@example.org
      winfo.active['sip:professor@example.net'] # contains Watcher describing sip:userA@example.org
      winfo.terminated['sip:professor@example.net'] # is an empty list
      winfo.wlists is a list of WatcherList objects
    """
    
    accept_types = ['application/watcherinfo+xml']
    _namespace = 'urn:ietf:params:xml:ns:watcherinfo'
    _schema_file = 'watcherinfo.xsd'
    _parser = etree.XMLParser(remove_blank_text=True)
    
    def __init__(self, document=None):
        self.version = -1
        self._wlists = {}
        if document is not None:
            self.update(document)
    
    def update(self, document):
        """
        Updates the state of this WatcherInfo object with data from an
        application/watcherinfo+xml document, passed as a string. 
        
        Will throw a NeedFullUpdateError if the current document is a partial
        update and the previous version wasn't received.
        """
        root = self._parse(document)
        version = int(root.get('version'))
        state = root.get('state')

        if version <= self.version:
            return {}
        if state == 'partial' and version != self.version + 1:
            raise NeedFullUpdateError()

        self.version = version

        updated_lists = {}
        if state == 'full':
            self._wlists = {}
            for xml_wlist in root:
                wlist = WatcherList(xml_wlist)
                self._wlists[wlist.resource] = wlist
                updated_lists[wlist] = list(wlist)
        elif state == 'partial':
            for xml_wlist in root:
                wlist = WatcherList(xml_wlist, full_parse=False)
                wlist = self._wlists.get(wlist.resource, wlist)
                self._wlists[wlist.resource] = wlist
                updated = wlist.update(xml_wlist)
                if updated:
                    updated_lists[wlist] = updated
        return updated_lists
    
    def __iter__(self):
        return self._wlists.itervalues()

    def __getitem__(self, index):
        return self._wlists[index]

    wlists = property(lambda self: self._wlists.values())
    pending = property(lambda self: dict((wlist, list(wlist.pending)) for wlist in self))
    active = property(lambda self: dict((wlist, list(wlist.active)) for wlist in self))
    terminated = property(lambda self: dict((wlist, list(wlist.terminated)) for wlist in self))

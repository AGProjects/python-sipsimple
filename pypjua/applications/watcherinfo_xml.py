from lxml import etree

from pypjua.applications import XMLParser, XMLElementMapping, ParserError

__all__ = ["NeedFullUpdateError", "WatcherInfo"]

class NeedFullUpdateError(Exception): pass

class Watcher(XMLElementMapping):
    """Definition for a watcher in a watcherinfo document"""
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
    """Definition for a list of watchers in a watcherinfo documennt"""
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

    pending = property(lambda self: (watcher for watcher in self if watcher.status in ('pending', 'waiting')))
    active = property(lambda self: (watcher for watcher in self if watcher.status == 'active'))
    terminated = property(lambda self: (watcher for watcher in self if watcher.status == 'terminated'))

class WatcherInfo(XMLParser):
    """Definition for watcher info: a list of WatcherList elements"""
    
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

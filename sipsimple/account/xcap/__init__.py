
"""High-level management of XCAP documents based on OMA specifications"""

__all__ = ['Group', 'Contact', 'ContactURI', 'EventHandling', 'Policy', 'Icon', 'OfflineStatus', 'XCAPManager', 'XCAPTransaction']


import base64
import cPickle
import os
import random
import socket
import weakref

from cStringIO import StringIO
from collections import OrderedDict
from datetime import datetime
from itertools import chain
from operator import attrgetter
from urllib2 import URLError

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from application.python.decorator import execute_once
from eventlib import api, coros, proc
from eventlib.green.httplib import BadStatusLine
from twisted.internet.error import ConnectionLost
from xcaplib.green import XCAPClient
from xcaplib.error import HTTPError
from zope.interface import implements

from sipsimple.account.subscription import Subscriber, Content
from sipsimple.account.xcap.storage import IXCAPStorage, XCAPStorageError
from sipsimple.configuration.datatypes import SIPAddress
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.payloads import ParserError, IterateTypes, IterateIDs, IterateItems, All
from sipsimple.payloads import addressbook, commonpolicy, dialogrules, omapolicy, pidf, prescontent, presrules, resourcelists, rlsservices, xcapcaps, xcapdiff
from sipsimple.payloads import rpid; rpid # needs to be imported to register its namespace
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, Worker, run_in_green_thread



class XCAPError(Exception): pass
class FetchRequiredError(XCAPError): pass


class Document(object):
    name               = None
    application        = None
    payload_type       = None
    default_namespace  = None
    global_tree        = None
    filename           = None
    cached             = True

    def __init__(self, manager):
        self.manager = weakref.proxy(manager)
        self.content = None
        self.etag = None
        self.fetch_time = datetime.fromtimestamp(0)
        self.update_time = datetime.fromtimestamp(0)
        self.dirty = False
        self.supported = False

    def __nonzero__(self):
        return self.content is not None

    def _get_dirty(self):
        return self.__dict__['dirty'] or (self.content is not None and self.content.__dirty__)

    def _set_dirty(self, dirty):
        if self.content is not None and not dirty:
            self.content.__dirty__ = dirty
        self.__dict__['dirty'] = dirty

    dirty = property(_get_dirty, _set_dirty)
    del _get_dirty, _set_dirty

    @property
    def relative_url(self):
        return self.url[len(self.manager.xcap_root):].lstrip('/')

    @property
    def url(self):
        return self.manager.client.get_url(self.application, None, globaltree=self.global_tree, filename=self.filename)

    def load_from_cache(self):
        if not self.cached:
            return
        try:
            document = StringIO(self.manager.storage.load(self.name))
            self.etag = document.readline().strip() or None
            self.content = self.payload_type.parse(document)
            self.__dict__['dirty'] = False
        except (XCAPStorageError, ParserError):
            self.etag = None
            self.content = None
            self.dirty = False
        self.fetch_time = datetime.utcnow()

    def initialize(self, server_caps):
        self.supported = self.application in server_caps.auids
        if not self.supported:
            self.reset()

    def reset(self):
        if self.cached and self.content is not None:
            try:
                self.manager.storage.delete(self.name)
            except XCAPStorageError:
                pass
        self.content = None
        self.etag = None
        self.dirty = False

    def fetch(self):
        try:
            document = self.manager.client.get(self.application, etagnot=self.etag, globaltree=self.global_tree, headers={'Accept': self.payload_type.content_type}, filename=self.filename)
            self.content = self.payload_type.parse(document)
            self.etag = document.etag
            self.__dict__['dirty'] = False
        except (BadStatusLine, ConnectionLost, URLError, socket.error), e:
            raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except HTTPError, e:
            if e.status == 404: # Not Found
                if self.content is not None:
                    self.reset()
                    self.fetch_time = datetime.utcnow()
            elif e.status != 304: # Other than Not Modified:
                raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except ParserError, e:
            raise XCAPError("failed to parse %s document: %s" % (self.name, e))
        else:
            self.fetch_time = datetime.utcnow()
            if self.cached:
                try:
                    self.manager.storage.save(self.name, self.etag + os.linesep + document)
                except XCAPStorageError:
                    pass

    def update(self):
        if not self.dirty:
            return
        data = self.content.toxml() if self.content is not None else None
        try:
            kw = dict(etag=self.etag) if self.etag is not None else dict(etagnot='*')
            if data is not None:
                response = self.manager.client.put(self.application, data, globaltree=self.global_tree, filename=self.filename, headers={'Content-Type': self.payload_type.content_type}, **kw)
            else:
                response = self.manager.client.delete(self.application, data, globaltree=self.global_tree, filename=self.filename, **kw)
        except (BadStatusLine, ConnectionLost, URLError), e:
            raise XCAPError("failed to update %s document: %s" % (self.name, e))
        except HTTPError, e:
            if e.status == 412: # Precondition Failed
                raise FetchRequiredError("document %s was modified externally" % self.name)
            elif e.status == 404 and data is None: # attempted to delete a document that did't exist in the first place
                pass
            else:
                raise XCAPError("failed to update %s document: %s" % (self.name, e))
        self.etag = response.etag if data is not None else None
        self.dirty = False
        self.update_time = datetime.utcnow()
        if self.cached:
            try:
                if data is not None:
                    self.manager.storage.save(self.name, self.etag + os.linesep + data)
                else:
                    self.manager.storage.delete(self.name)
            except XCAPStorageError:
                pass


class DialogRulesDocument(Document):
    name               = 'dialog-rules'
    application        = 'org.openxcap.dialog-rules'
    payload_type       = dialogrules.DialogRulesDocument
    default_namespace  = dialogrules.namespace
    global_tree        = False
    filename           = 'index'


class PresRulesDocument(Document):
    name               = 'pres-rules'
    application        = 'org.openmobilealliance.pres-rules'
    payload_type       = presrules.PresRulesDocument
    default_namespace  = presrules.namespace
    global_tree        = False
    filename           = 'index'


class ResourceListsDocument(Document):
    name               = 'resource-lists'
    application        = 'resource-lists'
    payload_type       = resourcelists.ResourceListsDocument
    default_namespace  = resourcelists.namespace
    global_tree        = False
    filename           = 'index'

    def update(self):
        if self.content is not None:
            sipsimple_addressbook = self.content['sipsimple_addressbook']

            groups = ItemCollection(sipsimple_addressbook[addressbook.Group, IterateItems])
            contacts = ItemCollection(sipsimple_addressbook[addressbook.Contact, IterateItems])
            policies = ItemCollection(sipsimple_addressbook[addressbook.Policy, IterateItems])

            for group, missing_id in ((group, missing_id) for group in groups for missing_id in [id for id in group.contacts if id not in contacts]):
                group.contacts.remove(missing_id)

            if any(item.__dirty__ for item in chain(contacts, policies)):
                oma_grantedcontacts = self.content['oma_grantedcontacts']
                oma_blockedcontacts = self.content['oma_blockedcontacts']
                dialog_grantedcontacts = self.content['dialog_grantedcontacts']
                dialog_blockedcontacts = self.content['dialog_blockedcontacts']
                sipsimple_presence_rls = self.content['sipsimple_presence_rls']
                sipsimple_dialog_rls = self.content['sipsimple_dialog_rls']

                all_contact_uris = set(uri.uri for contact in contacts for uri in contact.uris)

                contact_allow_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.policy=='allow')
                contact_block_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.policy=='block')
                contact_allow_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.policy=='allow')
                contact_block_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.policy=='block')
                contact_subscribe_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.subscribe==True)
                contact_subscribe_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.subscribe==True)

                policy_allow_presence_uris = set(policy.uri for policy in policies if policy.presence.policy=='allow')
                policy_block_presence_uris = set(policy.uri for policy in policies if policy.presence.policy=='block')
                policy_allow_dialog_uris = set(policy.uri for policy in policies if policy.dialog.policy=='allow')
                policy_block_dialog_uris = set(policy.uri for policy in policies if policy.dialog.policy=='block')
                policy_subscribe_presence_uris = set(policy.uri for policy in policies if policy.presence.subscribe==True)
                policy_subscribe_dialog_uris = set(policy.uri for policy in policies if policy.dialog.subscribe==True)

                allowed_presence_uris = contact_allow_presence_uris - contact_block_presence_uris | policy_allow_presence_uris - policy_block_presence_uris - all_contact_uris
                blocked_presence_uris = contact_block_presence_uris | policy_block_presence_uris - all_contact_uris
                allowed_dialog_uris = contact_allow_dialog_uris - contact_block_dialog_uris | policy_allow_dialog_uris - policy_block_dialog_uris - all_contact_uris
                blocked_dialog_uris = contact_block_dialog_uris | policy_block_dialog_uris - all_contact_uris
                subscribe_presence_uris = contact_subscribe_presence_uris | policy_subscribe_presence_uris - all_contact_uris
                subscribe_dialog_uris = contact_subscribe_dialog_uris | policy_subscribe_dialog_uris - all_contact_uris

                if allowed_presence_uris != set(entry.uri for entry in oma_grantedcontacts):
                    oma_grantedcontacts.clear()
                    oma_grantedcontacts.update(resourcelists.Entry(uri) for uri in allowed_presence_uris)
                if blocked_presence_uris != set(entry.uri for entry in oma_blockedcontacts):
                    oma_blockedcontacts.clear()
                    oma_blockedcontacts.update(resourcelists.Entry(uri) for uri in blocked_presence_uris)
                if allowed_dialog_uris != set(entry.uri for entry in dialog_grantedcontacts):
                    dialog_grantedcontacts.clear()
                    dialog_grantedcontacts.update(resourcelists.Entry(uri) for uri in allowed_dialog_uris)
                if blocked_dialog_uris != set(entry.uri for entry in dialog_blockedcontacts):
                    dialog_blockedcontacts.clear()
                    dialog_blockedcontacts.update(resourcelists.Entry(uri) for uri in blocked_dialog_uris)
                if subscribe_presence_uris != set(entry.uri for entry in sipsimple_presence_rls):
                    sipsimple_presence_rls.clear()
                    sipsimple_presence_rls.update(resourcelists.Entry(uri) for uri in subscribe_presence_uris)
                if subscribe_dialog_uris != set(entry.uri for entry in sipsimple_dialog_rls):
                    sipsimple_dialog_rls.clear()
                    sipsimple_dialog_rls.update(resourcelists.Entry(uri) for uri in subscribe_dialog_uris)
        super(ResourceListsDocument, self).update()


class RLSServicesDocument(Document):
    name               = 'rls-services'
    application        = 'rls-services'
    payload_type       = rlsservices.RLSServicesDocument
    default_namespace  = rlsservices.namespace
    global_tree        = False
    filename           = 'index'


class XCAPCapsDocument(Document):
    name               = 'xcap-caps'
    application        = 'xcap-caps'
    payload_type       = xcapcaps.XCAPCapabilitiesDocument
    default_namespace  = xcapcaps.namespace
    global_tree        = True
    filename           = 'index'
    cached             = False

    def initialize(self):
        self.supported = True


class StatusIconDocument(Document):
    name               = 'status-icon'
    application        = 'org.openmobilealliance.pres-content'
    payload_type       = prescontent.PresenceContentDocument
    default_namespace  = prescontent.namespace
    global_tree        = False
    filename           = 'oma_status-icon/index'


class PIDFManipulationDocument(Document):
    name               = 'pidf-manipulation'
    application        = 'pidf-manipulation'
    payload_type       = pidf.PIDFDocument
    default_namespace  = pidf.pidf_namespace
    global_tree        = False
    filename           = 'index'


class ItemCollection(object):
    def __init__(self, items):
        self.items = OrderedDict((item.id, item) for item in items)
    def __getitem__(self, key):
        return self.items[key]
    def __contains__(self, key):
        return key in self.items
    def __iter__(self):
        return self.items.itervalues()
    def __reversed__(self):
        return (self[id] for id in reversed(self.items))
    def __len__(self):
        return len(self.items)
    def __eq__(self, other):
        if isinstance(other, ItemCollection):
            return self.items == other.items
        return NotImplemented
    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal
    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.items.values())
    def ids(self):
        return self.items.keys()
    def iterids(self):
        return self.items.iterkeys()
    def get(self, key, default=None):
        return self.items.get(key, default)
    def add(self, item):
        self.items[item.id] = item
    def remove(self, item):
        del self.items[item.id]


class ContactList(ItemCollection):
    pass


class ContactURIList(ItemCollection):
    def __init__(self, items, default=None):
        super(ContactURIList, self).__init__(items)
        self.default = default

    def __eq__(self, other):
        if isinstance(other, ContactURIList):
            return self.items == other.items and self.default == other.default
        return NotImplemented

    def __repr__(self):
        return "%s(%r, default=%r)" % (self.__class__.__name__, self.items.values(), self.default)


class Group(object):
    def __init__(self, id, name, contacts, **attributes):
        self.id = id
        self.name = name
        self.contacts = contacts
        self.attributes = attributes

    def __eq__(self, other):
        if isinstance(other, Group):
            return self is other or (self.id == other.id and self.name == other.name and self.contacts.ids() == other.contacts.ids() and self.attributes == other.attributes)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __setattr__(self, name, value):
        if name == 'contacts' and not isinstance(value, ContactList):
            value = ContactList(value)
        object.__setattr__(self, name, value)


class ContactURI(object):
    def __init__(self, id, uri, type, **attributes):
        self.id = id
        self.uri = uri
        self.type = type
        self.attributes = attributes

    def __eq__(self, other):
        if isinstance(other, ContactURI):
            return self is other or (self.id == other.id and self.uri == other.uri and self.type == other.type and self.attributes == other.attributes)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class EventHandling(object):
    def __init__(self, policy, subscribe):
        self.policy = policy
        self.subscribe = subscribe

    def __eq__(self, other):
        if isinstance(other, EventHandling):
            return self is other or (self.policy == other.policy and self.subscribe == other.subscribe)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.policy, self.subscribe)


class Contact(object):
    def __init__(self, id, name, uris, presence_handling=None, dialog_handling=None, **attributes):
        self.id = id
        self.name = name
        self.uris = uris
        self.dialog = dialog_handling or EventHandling(policy='default', subscribe=False)
        self.presence = presence_handling or EventHandling(policy='default', subscribe=False)
        self.attributes = attributes

    def __eq__(self, other):
        if isinstance(other, Contact):
            return self is other or (self.id == other.id and self.name == other.name and self.uris == other.uris and self.dialog == other.dialog and self.presence == other.presence and
                                     self.attributes == other.attributes)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __setattr__(self, name, value):
        if name == 'uris' and not isinstance(value, ContactURIList):
            value = ContactURIList(value)
        object.__setattr__(self, name, value)


class Policy(object):
    def __init__(self, id, uri, name, presence_handling=None, dialog_handling=None, **attributes):
        self.id = id
        self.uri = uri
        self.name = name
        self.dialog = dialog_handling or EventHandling(policy='default', subscribe=False)
        self.presence = presence_handling or EventHandling(policy='default', subscribe=False)
        self.attributes = attributes

    def __eq__(self, other):
        if isinstance(other, Policy):
            return self is other or (self.id == other.id and self.uri == other.uri and self.name == other.name and self.dialog == other.dialog and self.presence == other.presence and
                                     self.attributes == other.attributes)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class Addressbook(object):
    def __init__(self, contacts, groups, policies):
        self.contacts = contacts
        self.groups = groups
        self.policies = policies

    def __eq__(self, other):
        if isinstance(other, Addressbook):
            return self is other or (self.contacts == other.contacts and self.groups == other.groups and self.policies == other.policies)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    @classmethod
    def from_payload(cls, payload):
        def payload_to_contact(payload):
            uris = ContactURIList((ContactURI(uri.id, uri.uri, uri.type, **(uri.attributes or {})) for uri in payload.uris), default=payload.uris.default)
            presence_handling = EventHandling(payload.presence.policy.value, payload.presence.subscribe.value)
            dialog_handling = EventHandling(payload.dialog.policy.value, payload.dialog.subscribe.value)
            return Contact(payload.id, payload.name.value, uris, presence_handling, dialog_handling, **(payload.attributes or {}))
        def payload_to_group(payload):
            return Group(payload.id, payload.name.value, [contacts[contact_id] for contact_id in payload.contacts], **(payload.attributes or {}))
        def payload_to_policy(payload):
            presence_handling = EventHandling(payload.presence.policy.value, payload.presence.subscribe.value)
            dialog_handling = EventHandling(payload.dialog.policy.value, payload.dialog.subscribe.value)
            return Policy(payload.id, payload.uri, payload.name.value, presence_handling, dialog_handling, **(payload.attributes or {}))
        contacts = ItemCollection(payload_to_contact(item) for item in payload[addressbook.Contact, IterateItems])
        groups = ItemCollection(payload_to_group(item) for item in payload[addressbook.Group, IterateItems])
        policies = ItemCollection(payload_to_policy(item) for item in payload[addressbook.Policy, IterateItems])
        return cls(contacts, groups, policies)


class PresenceRules(object):
    def __init__(self, default_policy):
        self.default_policy = default_policy

    def __eq__(self, other):
        if isinstance(other, PresenceRules):
            return self is other or (self.default_policy == other.default_policy)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    @classmethod
    def from_payload(cls, default_rule):
        default_policy = next(item for item in default_rule.actions if isinstance(item, presrules.SubHandling)).value
        return cls(default_policy)


class DialogRules(object):
    def __init__(self, default_policy):
        self.default_policy = default_policy

    def __eq__(self, other):
        if isinstance(other, DialogRules):
            return self is other or (self.default_policy == other.default_policy)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    @classmethod
    def from_payload(cls, default_rule):
        if default_rule is not None:
            default_policy = next(item for item in default_rule.actions if isinstance(item, dialogrules.SubHandling)).value
        else:
            default_policy = None
        return cls(default_policy)


class Icon(object):
    __mimetypes__ = ('image/jpeg', 'image/png', 'image/gif')

    def __init__(self, data, mime_type, description=None):
        self.data = data
        self.mime_type = mime_type
        self.description = description
        self.url = None
        self.etag = None

    def __eq__(self, other):
        if isinstance(other, Icon):
            return self is other or (self.data == other.data and self.mime_type == other.mime_type and self.description == other.description)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __setattr__(self, name, value):
        if name == 'mime_type' and value not in self.__mimetypes__:
            raise ValueError("invalid mime type: '%s'. Should be one of: %s" % (value, ', '.join(self.__mimetypes__)))
        object.__setattr__(self, name, value)

    @classmethod
    def from_payload(cls, payload):
        try:
            data = base64.decodestring(payload.data.value)
        except Exception:
            return None
        else:
            description = payload.description.value if payload.description else None
            return cls(data, payload.mime_type.value, description)


class OfflineStatus(object):
    __slots__ = ('pidf',)

    def __init__(self, pidf):
        self.pidf = pidf

    def __setattr__(self, name, value):
        if name == 'pidf' and not isinstance(value, pidf.PIDF):
            raise ValueError("pidf must be a PIDF payload")
        object.__setattr__(self, name, value)

    def __eq__(self, other):
        if isinstance(other, OfflineStatus):
            return self is other or (self.pidf == other.pidf)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __getstate__(self):
        return {'pidf': self.pidf.toxml()}

    def __setstate__(self, state):
        self.pidf = pidf.PIDFDocument.parse(state['pidf'])


class Operation(object):
    __params__ = ()
    def __init__(self, **params):
        for name, value in params.iteritems():
            setattr(self, name, value)
        for param in set(self.__params__).difference(params):
            raise ValueError("missing operation parameter: '%s'" % param)
        self.applied = False
        self.timestamp = datetime.utcnow()


class NormalizeOperation(Operation):
    __params__ = ()

class AddContactOperation(Operation):
    __params__ = ('contact',)

class UpdateContactOperation(Operation):
    __params__ = ('contact', 'attributes')

class RemoveContactOperation(Operation):
    __params__ = ('contact',)

class AddContactURIOperation(Operation):
    __params__ = ('contact', 'uri')

class UpdateContactURIOperation(Operation):
    __params__ = ('contact', 'uri', 'attributes')

class RemoveContactURIOperation(Operation):
    __params__ = ('contact', 'uri')

class AddGroupOperation(Operation):
    __params__ = ('group',)

class UpdateGroupOperation(Operation):
    __params__ = ('group', 'attributes')

class RemoveGroupOperation(Operation):
    __params__ = ('group',)

class AddGroupMemberOperation(Operation):
    __params__ = ('group', 'contact')

class RemoveGroupMemberOperation(Operation):
    __params__ = ('group', 'contact')

class AddPolicyOperation(Operation):
    __params__ = ('policy',)

class UpdatePolicyOperation(Operation):
    __params__ = ('policy', 'attributes')

class RemovePolicyOperation(Operation):
    __params__ = ('policy',)

class SetDefaultPresencePolicyOperation(Operation):
    __params__ = ('policy',)

class SetDefaultDialogPolicyOperation(Operation):
    __params__ = ('policy',)

class SetStatusIconOperation(Operation):
    __params__ = ('icon',)

class SetOfflineStatusOperation(Operation):
    __params__ = ('status',)


class XCAPSubscriber(Subscriber):
    __transports__ = frozenset(['tls', 'tcp'])

    @property
    def event(self):
        return 'xcap-diff'

    @property
    def content(self):
        rlist = resourcelists.List()
        for document in (doc for doc in self.account.xcap_manager.documents if doc.supported):
            rlist.add(resourcelists.Entry(document.relative_url))
        return Content(resourcelists.ResourceLists([rlist]).toxml(), resourcelists.ResourceListsDocument.content_type)


class XCAPManager(object):
    implements(IObserver)

    def __init__(self, account):
        from sipsimple.application import SIPApplication
        if SIPApplication.storage is None:
            raise RuntimeError("SIPApplication.storage must be defined before instantiating XCAPManager")
        storage = SIPApplication.storage.xcap_storage_factory(account.id)
        if not IXCAPStorage.providedBy(storage):
            raise TypeError("storage must implement the IXCAPStorage interface")
        self.account = account
        self.storage = storage
        self.storage_factory = SIPApplication.storage.xcap_storage_factory
        self.client = None
        self.command_proc = None
        self.command_channel = coros.queue()
        self.last_fetch_time = datetime.fromtimestamp(0)
        self.last_update_time = datetime.fromtimestamp(0)
        self.not_executed_fetch = None
        self.state = 'stopped'
        self.timer = None
        self.transaction_level = 0
        self.xcap_subscriber = None

        self.server_caps = XCAPCapsDocument(self)
        self.dialog_rules = DialogRulesDocument(self)
        self.pidf_manipulation = PIDFManipulationDocument(self)
        self.pres_rules = PresRulesDocument(self)
        self.resource_lists = ResourceListsDocument(self)
        self.rls_services = RLSServicesDocument(self)
        self.status_icon = StatusIconDocument(self)

        for document in self.documents:
            document.load_from_cache()

        try:
            journal = self.storage.load('journal')
        except XCAPStorageError:
            self.journal = []
        else:
            try:
                self.journal = cPickle.loads(journal)
            except Exception:
                self.journal = []

        for operation in self.journal:
            operation.applied = False

        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=account, name='CFGSettingsObjectDidChange')
        notification_center.add_observer(self, sender=account, name='CFGSettingsObjectWasDeleted')

    def _get_state(self):
        return self.__dict__['state']

    def _set_state(self, value):
        old_value = self.__dict__.get('state', Null)
        self.__dict__['state'] = value
        if old_value != value and old_value is not Null:
            notification_center = NotificationCenter()
            notification_center.post_notification('XCAPManagerDidChangeState', sender=self, data=NotificationData(prev_state=old_value, state=value))

    state = property(_get_state, _set_state)
    del _get_state, _set_state

    @property
    def documents(self):
        return [self.resource_lists, self.rls_services, self.pres_rules, self.dialog_rules, self.pidf_manipulation, self.status_icon]

    @property
    def document_names(self):
        return [document.name for document in self.documents]

    @property
    def xcap_root(self):
        return getattr(self.client, 'root', None)

    @property
    def rls_presence_uri(self):
        return SIPAddress('%s+presence@%s' % (self.account.id.username, self.account.id.domain))

    @property
    def rls_dialog_uri(self):
        return SIPAddress('%s+dialog@%s' % (self.account.id.username, self.account.id.domain))

    @execute_once
    def init(self):
        """
        Initializes the XCAP manager before it can be started. Needs to be
        called before any other method and in a green thread.
        """
        self.command_proc = proc.spawn(self._run)

    def start(self):
        """
        Starts the XCAP manager. This method needs to be called in a green
        thread.
        """
        command = Command('start')
        self.command_channel.send(command)
        command.wait()

    def stop(self):
        """
        Stops the XCAP manager. This method blocks until all the operations are
        stopped and needs to be called in a green thread.
        """
        command = Command('stop')
        self.command_channel.send(command)
        command.wait()

    def transaction(self):
        return XCAPTransaction(self)

    @run_in_twisted_thread
    def start_transaction(self):
        self.transaction_level += 1

    @run_in_twisted_thread
    def commit_transaction(self):
        if self.transaction_level == 0:
            return
        self.transaction_level -= 1
        if self.transaction_level == 0 and self.journal:
            self._save_journal()
            self.command_channel.send(Command('update'))

    def add_contact(self, contact):
        self._schedule_operation(AddContactOperation(contact=contact))

    def update_contact(self, contact, attributes):
        self._schedule_operation(UpdateContactOperation(contact=contact, attributes=attributes))

    def remove_contact(self, contact):
        self._schedule_operation(RemoveContactOperation(contact=contact))

    def add_contact_uri(self, contact, uri):
        self._schedule_operation(AddContactURIOperation(contact=contact, uri=uri))

    def update_contact_uri(self, contact, uri, attributes):
        self._schedule_operation(UpdateContactURIOperation(contact=contact, uri=uri, attributes=attributes))

    def remove_contact_uri(self, contact, uri):
        self._schedule_operation(RemoveContactURIOperation(contact=contact, uri=uri))

    def add_group(self, group):
        self._schedule_operation(AddGroupOperation(group=group))

    def update_group(self, group, attributes):
        self._schedule_operation(UpdateGroupOperation(group=group, attributes=attributes))

    def remove_group(self, group):
        self._schedule_operation(RemoveGroupOperation(group=group))

    def add_group_member(self, group, contact):
        self._schedule_operation(AddGroupMemberOperation(group=group, contact=contact))

    def remove_group_member(self, group, contact):
        self._schedule_operation(RemoveGroupMemberOperation(group=group, contact=contact))

    def add_policy(self, policy):
        self._schedule_operation(AddPolicyOperation(policy=policy))

    def update_policy(self, policy, attributes):
        self._schedule_operation(UpdatePolicyOperation(policy=policy, attributes=attributes))

    def remove_policy(self, policy):
        self._schedule_operation(RemovePolicyOperation(policy=policy))

    def set_default_presence_policy(self, policy):
        self._schedule_operation(SetDefaultPresencePolicyOperation(policy=presrules.SubHandlingValue(policy)))

    def set_default_dialog_policy(self, policy):
        self._schedule_operation(SetDefaultDialogPolicyOperation(policy=dialogrules.SubHandlingValue(policy)))

    def set_status_icon(self, icon):
        self._schedule_operation(SetStatusIconOperation(icon=icon))

    def set_offline_status(self, status):
        self._schedule_operation(SetOfflineStatusOperation(status=status))

    @run_in_twisted_thread
    def _schedule_operation(self, operation):
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    def _run(self):
        while True:
            command = self.command_channel.wait()
            try:
                handler = getattr(self, '_CH_%s' % command.name)
                handler(command)
            except:
                self.command_proc = None
                raise

    # Command handlers
    #

    def _CH_start(self, command):
        if self.state != 'stopped':
            command.signal()
            return
        self.state = 'initializing'
        self.xcap_subscriber = XCAPSubscriber(self.account)
        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerWillStart', sender=self)
        notification_center.add_observer(self, sender=self.xcap_subscriber)
        notification_center.add_observer(self, sender=SIPSimpleSettings(), name='CFGSettingsObjectDidChange')
        self.xcap_subscriber.start()
        self.command_channel.send(Command('initialize'))
        notification_center.post_notification('XCAPManagerDidStart', sender=self)
        command.signal()

    def _CH_stop(self, command):
        if self.state in ('stopped', 'terminated'):
            command.signal()
            return
        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerWillEnd', sender=self)
        notification_center.remove_observer(self, sender=self.xcap_subscriber)
        notification_center.remove_observer(self, sender=SIPSimpleSettings(), name='CFGSettingsObjectDidChange')
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.xcap_subscriber.stop()
        self.xcap_subscriber = None
        self.client = None
        self.state = 'stopped'
        self._save_journal()
        notification_center.post_notification('XCAPManagerDidEnd', sender=self)
        command.signal()

    def _CH_cleanup(self, command):
        if self.state != 'stopped':
            command.signal()
            return
        try:
            self.storage.purge()
        except XCAPStorageError:
            pass
        self.journal = []
        self.state = 'terminated'
        command.signal()
        raise proc.ProcExit

    def _CH_initialize(self, command):
        self.state = 'initializing'
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None
        if self.account.xcap.xcap_root:
            self.client = XCAPClient(self.account.xcap.xcap_root, self.account.id, password=self.account.auth.password)
        else:
            try:
                lookup = DNSLookup()
                xcap_root = random.choice(lookup.lookup_xcap_server(self.account.uri).wait())
            except DNSLookupError:
                self.timer = self._schedule_command(60,  Command('initialize', command.event))
                return
            else:
                self.client = XCAPClient(xcap_root, self.account.id, password=self.account.auth.password)

        try:
            self.server_caps.fetch()
        except XCAPError:
            self.timer = self._schedule_command(60,  Command('initialize', command.event))
            return
        else:
            if self.server_caps.content is None:
                # XCAP server must always return some content for xcap-caps
                self.timer = self._schedule_command(60,  Command('initialize', command.event))
                return
            if not set(self.server_caps.content.auids).issuperset(('resource-lists', 'rls-services', 'org.openmobilealliance.pres-rules')):
                # Server must support at least resource-lists, rls-services and org.openmobilealliance.pres-rules
                self.timer = self._schedule_command(3600,  Command('initialize', command.event))
                return
        self.server_caps.initialize()
        for document in self.documents:
            document.initialize(self.server_caps.content)

        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerDidDiscoverServerCapabilities', sender=self, data=NotificationData(auids=self.server_caps.content.auids))

        self.state = 'fetching'
        self.command_channel.send(Command('fetch', documents=set(self.document_names)))
        self.xcap_subscriber.activate()

    def _CH_reload(self, command):
        if self.state == 'terminated':
            command.signal()
            return
        if '__id__' in command.modified:
            try:
                self.storage.purge()
            except XCAPStorageError:
                pass
            self.storage = self.storage_factory(self.account.id)
            self.journal = []
            self._save_journal()
        if set(['__id__', 'xcap.xcap_root']).intersection(command.modified):
            for document in self.documents:
                document.reset()
        if self.state == 'stopped':
            command.signal()
            return
        if set(['__id__', 'auth.username', 'auth.password', 'xcap.xcap_root']).intersection(command.modified):
            self.state = 'initializing'
            self.command_channel.send(Command('initialize'))
        else:
            self.xcap_subscriber.resubscribe()
        command.signal()

    def _CH_fetch(self, command):
        if self.state not in ('insync', 'fetching'):
            if self.not_executed_fetch is not None:
                command.documents.update(self.not_executed_fetch.documents)
            self.not_executed_fetch = command
            return
        if self.not_executed_fetch is not None:
            command.documents.update(self.not_executed_fetch.documents)
            self.not_executed_fetch = None
        self.state = 'fetching'
        if self.timer is not None and self.timer.active():
            command.documents.update(self.timer.command.documents)
            self.timer.cancel()
        self.timer = None

        try:
            self._fetch_documents(command.documents)
        except XCAPError:
            self.timer = self._schedule_command(60, Command('fetch', command.event, documents=command.documents))
            return

        if not self.journal and self.last_fetch_time > datetime.fromtimestamp(0) and all(doc.fetch_time < command.timestamp for doc in self.documents):
            self.last_fetch_time = datetime.utcnow()
            self.state = 'insync'
            return
        else:
            self.last_fetch_time = datetime.utcnow()

        self.state = 'updating'
        if not self.journal or type(self.journal[0]) is not NormalizeOperation:
            self.journal.insert(0, NormalizeOperation())
        self.command_channel.send(Command('update', command.event))

    def _CH_update(self, command):
        if self.state not in ('insync', 'updating'):
            return
        if self.transaction_level != 0:
            return
        self.state = 'updating'
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None
        journal = self.journal[:]
        for operation in (operation for operation in journal if not operation.applied):
            handler = getattr(self, '_OH_%s' % operation.__class__.__name__)
            try:
                handler(operation)
            except Exception:
                # Error while applying operation, needs to be logged -Luci
                log.err()
            operation.applied = True
            api.sleep(0) # Operations are quite CPU intensive
        try:
            for document in (doc for doc in self.documents if doc.dirty and doc.supported):
                document.update()
        except FetchRequiredError:
            for document in (doc for doc in self.documents if doc.dirty and doc.supported):
                document.reset()
            for operation in journal:
                operation.applied = False
            self.state = 'fetching'
            self.command_channel.send(Command('fetch', documents=set(self.document_names))) # Try to fetch them all just in case
        except XCAPError:
            self.timer = self._schedule_command(60, Command('update'))
        else:
            del self.journal[:len(journal)]
            if not self.journal:
                self.state = 'insync'
                if any(max(doc.update_time, doc.fetch_time) > self.last_update_time for doc in self.documents):
                    self._load_data()
                self.last_update_time = datetime.utcnow()
            command.signal()
            if self.not_executed_fetch is not None:
                self.command_channel.send(self.not_executed_fetch)
                self.not_executed_fetch = None
            self._save_journal()

    # Operation handlers
    #

    def _OH_NormalizeOperation(self, operation):
        # Normalize resource-lists
        #
        if self.resource_lists.content is None:
            self.resource_lists.content = resourcelists.ResourceLists()

        resource_lists = self.resource_lists.content

        try:
            oma_buddylist = resource_lists['oma_buddylist']
        except KeyError:
            oma_buddylist = resourcelists.List(name='oma_buddylist')
            resource_lists.add(oma_buddylist)
        try:
            oma_grantedcontacts = resource_lists['oma_grantedcontacts']
        except KeyError:
            oma_grantedcontacts = resourcelists.List(name='oma_grantedcontacts')
            resource_lists.add(oma_grantedcontacts)
        try:
            oma_blockedcontacts = resource_lists['oma_blockedcontacts']
        except KeyError:
            oma_blockedcontacts = resourcelists.List(name='oma_blockedcontacts')
            resource_lists.add(oma_blockedcontacts)
        try:
            oma_allcontacts = resource_lists['oma_allcontacts']
        except KeyError:
            oma_allcontacts = resourcelists.List(name='oma_allcontacts')
            oma_allcontacts.add(resourcelists.External(self.resource_lists.url + '/~~' + resource_lists.get_xpath(oma_buddylist)))
            oma_allcontacts.add(resourcelists.External(self.resource_lists.url + '/~~' + resource_lists.get_xpath(oma_grantedcontacts)))
            oma_allcontacts.add(resourcelists.External(self.resource_lists.url + '/~~' + resource_lists.get_xpath(oma_blockedcontacts)))
            resource_lists.add(oma_allcontacts)

        try:
            dialog_grantedcontacts = resource_lists['dialog_grantedcontacts']
        except KeyError:
            dialog_grantedcontacts = resourcelists.List(name='dialog_grantedcontacts')
            resource_lists.add(dialog_grantedcontacts)
        try:
            dialog_blockedcontacts = resource_lists['dialog_blockedcontacts']
        except KeyError:
            dialog_blockedcontacts = resourcelists.List(name='dialog_blockedcontacts')
            resource_lists.add(dialog_blockedcontacts)

        try:
            sipsimple_presence_rls = resource_lists['sipsimple_presence_rls']
        except KeyError:
            sipsimple_presence_rls = resourcelists.List(name='sipsimple_presence_rls')
            resource_lists.add(sipsimple_presence_rls)
        try:
            sipsimple_dialog_rls = resource_lists['sipsimple_dialog_rls']
        except KeyError:
            sipsimple_dialog_rls = resourcelists.List(name='sipsimple_dialog_rls')
            resource_lists.add(sipsimple_dialog_rls)

        try:
            sipsimple_addressbook = resource_lists['sipsimple_addressbook']
        except KeyError:
            sipsimple_addressbook = resourcelists.List(name='sipsimple_addressbook')
            resource_lists.add(sipsimple_addressbook)

        for cls in (cls for cls in sipsimple_addressbook[IterateTypes] if cls not in (addressbook.Contact, addressbook.Group, addressbook.Policy)):
            del sipsimple_addressbook[cls, All]
        for cls in (cls for cls in oma_grantedcontacts[IterateTypes] if cls is not resourcelists.Entry):
            del oma_grantedcontacts[cls, All]
        for cls in (cls for cls in oma_blockedcontacts[IterateTypes] if cls is not resourcelists.Entry):
            del oma_blockedcontacts[cls, All]
        for cls in (cls for cls in dialog_grantedcontacts[IterateTypes] if cls is not resourcelists.Entry):
            del dialog_grantedcontacts[cls, All]
        for cls in (cls for cls in dialog_blockedcontacts[IterateTypes] if cls is not resourcelists.Entry):
            del dialog_blockedcontacts[cls, All]
        for cls in (cls for cls in sipsimple_presence_rls[IterateTypes] if cls is not resourcelists.Entry):
            del sipsimple_presence_rls[cls, All]
        for cls in (cls for cls in sipsimple_dialog_rls[IterateTypes] if cls is not resourcelists.Entry):
            del sipsimple_dialog_rls[cls, All]

        groups = ItemCollection(sipsimple_addressbook[addressbook.Group, IterateItems])
        contacts = ItemCollection(sipsimple_addressbook[addressbook.Contact, IterateItems])
        policies = ItemCollection(sipsimple_addressbook[addressbook.Policy, IterateItems])

        for group, missing_id in [(group, missing_id) for group in groups for missing_id in (id for id in group.contacts if id not in contacts)]:
            group.contacts.remove(missing_id)

        all_contact_uris = set(uri.uri for contact in contacts for uri in contact.uris)

        contact_allow_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.policy=='allow')
        contact_block_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.policy=='block')
        contact_allow_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.policy=='allow')
        contact_block_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.policy=='block')
        contact_subscribe_presence_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.presence.subscribe==True)
        contact_subscribe_dialog_uris = set(uri.uri for contact in contacts for uri in contact.uris if contact.dialog.subscribe==True)

        policy_allow_presence_uris = set(policy.uri for policy in policies if policy.presence.policy=='allow')
        policy_block_presence_uris = set(policy.uri for policy in policies if policy.presence.policy=='block')
        policy_allow_dialog_uris = set(policy.uri for policy in policies if policy.dialog.policy=='allow')
        policy_block_dialog_uris = set(policy.uri for policy in policies if policy.dialog.policy=='block')
        policy_subscribe_presence_uris = set(policy.uri for policy in policies if policy.presence.subscribe==True)
        policy_subscribe_dialog_uris = set(policy.uri for policy in policies if policy.dialog.subscribe==True)

        allowed_presence_uris = contact_allow_presence_uris - contact_block_presence_uris | policy_allow_presence_uris - policy_block_presence_uris - all_contact_uris
        blocked_presence_uris = contact_block_presence_uris | policy_block_presence_uris - all_contact_uris
        allowed_dialog_uris = contact_allow_dialog_uris - contact_block_dialog_uris | policy_allow_dialog_uris - policy_block_dialog_uris - all_contact_uris
        blocked_dialog_uris = contact_block_dialog_uris | policy_block_dialog_uris - all_contact_uris
        subscribe_presence_uris = contact_subscribe_presence_uris | policy_subscribe_presence_uris - all_contact_uris
        subscribe_dialog_uris = contact_subscribe_dialog_uris | policy_subscribe_dialog_uris - all_contact_uris

        if allowed_presence_uris != set(entry.uri for entry in oma_grantedcontacts):
            oma_grantedcontacts.clear()
            oma_grantedcontacts.update(resourcelists.Entry(uri) for uri in allowed_presence_uris)
        if blocked_presence_uris != set(entry.uri for entry in oma_blockedcontacts):
            oma_blockedcontacts.clear()
            oma_blockedcontacts.update(resourcelists.Entry(uri) for uri in blocked_presence_uris)
        if allowed_dialog_uris != set(entry.uri for entry in dialog_grantedcontacts):
            dialog_grantedcontacts.clear()
            dialog_grantedcontacts.update(resourcelists.Entry(uri) for uri in allowed_dialog_uris)
        if blocked_dialog_uris != set(entry.uri for entry in dialog_blockedcontacts):
            dialog_blockedcontacts.clear()
            dialog_blockedcontacts.update(resourcelists.Entry(uri) for uri in blocked_dialog_uris)
        if subscribe_presence_uris != set(entry.uri for entry in sipsimple_presence_rls):
            sipsimple_presence_rls.clear()
            sipsimple_presence_rls.update(resourcelists.Entry(uri) for uri in subscribe_presence_uris)
        if subscribe_dialog_uris != set(entry.uri for entry in sipsimple_dialog_rls):
            sipsimple_dialog_rls.clear()
            sipsimple_dialog_rls.update(resourcelists.Entry(uri) for uri in subscribe_dialog_uris)

        # Normalize rls-services
        #
        if self.rls_services.content is None:
            self.rls_services.content = rlsservices.RLSServices()

        rls_services = self.rls_services.content

        rls_presence_uri = 'sip:' + self.rls_presence_uri
        rls_dialog_uri   = 'sip:' + self.rls_dialog_uri
        rls_presence_list = rlsservices.ResourceList(self.resource_lists.url + '/~~' + resource_lists.get_xpath(sipsimple_presence_rls))
        rls_dialog_list = rlsservices.ResourceList(self.resource_lists.url + '/~~' + resource_lists.get_xpath(sipsimple_dialog_rls))

        try:
            rls_presence_service = rls_services[rls_presence_uri]
        except KeyError:
            rls_presence_service = rlsservices.Service(rls_presence_uri, list=rls_presence_list, packages=['presence'])
            rls_services.add(rls_presence_service)
        else:
            if rls_presence_service.list != rls_presence_list:
                rls_presence_service.list = rls_presence_list
            if list(rls_presence_service.packages) != ['presence']:
                rls_presence_service.packages = ['presence']
        try:
            rls_dialog_service = rls_services[rls_dialog_uri]
        except KeyError:
            rls_dialog_service = rlsservices.Service(rls_dialog_uri, list=rls_dialog_list, packages=['dialog'])
            rls_services.add(rls_dialog_service)
        else:
            if rls_dialog_service.list != rls_dialog_list:
                rls_dialog_service.list = rls_dialog_list
            if list(rls_dialog_service.packages) != ['dialog']:
                rls_dialog_service.packages = ['dialog']

        # Normalize pres-rules
        #
        if self.pres_rules.content is None:
            self.pres_rules.content = presrules.PresRules()

        def fix_subhandling(rule, valid_values=[]):
            subhandling_elements = sorted((item for item in rule.actions if isinstance(item, presrules.SubHandling)), key=attrgetter('value.priority'))
            if not subhandling_elements:
                subhandling_elements = [presrules.SubHandling('block')] # spec specifies that missing SubHandling means block
                rule.actions.update(subhandling_elements)
            subhandling = subhandling_elements.pop()
            for item in subhandling_elements: # remove any extraneous SubHandling elements
                rule.actions.remove(item)
            if subhandling.value not in valid_values:
                subhandling.value = valid_values[0]

        pres_rules = self.pres_rules.content

        oma_grantedcontacts_ref = omapolicy.ExternalList([self.resource_lists.url + '/~~' + resource_lists.get_xpath(oma_grantedcontacts)])
        oma_blockedcontacts_ref = omapolicy.ExternalList([self.resource_lists.url + '/~~' + resource_lists.get_xpath(oma_blockedcontacts)])

        try:
            wp_prs_grantedcontacts = pres_rules['wp_prs_grantedcontacts']
        except KeyError:
            wp_prs_grantedcontacts = commonpolicy.Rule('wp_prs_grantedcontacts', conditions=[oma_grantedcontacts_ref], actions=[presrules.SubHandling('allow')])
            pres_rules.add(wp_prs_grantedcontacts)
        else:
            fix_subhandling(wp_prs_grantedcontacts, valid_values=['allow'])
            if list(wp_prs_grantedcontacts.conditions) != [oma_grantedcontacts_ref]:
                wp_prs_grantedcontacts.conditions = [oma_grantedcontacts_ref]
            if wp_prs_grantedcontacts.transformations:
                wp_prs_grantedcontacts.transformations = None
        try:
            wp_prs_blockedcontacts = pres_rules['wp_prs_blockedcontacts']
        except KeyError:
            wp_prs_blockedcontacts = commonpolicy.Rule('wp_prs_blockedcontacts', conditions=[oma_blockedcontacts_ref], actions=[presrules.SubHandling('polite-block')])
            pres_rules.add(wp_prs_blockedcontacts)
        else:
            fix_subhandling(wp_prs_blockedcontacts, valid_values=['polite-block'])
            if list(wp_prs_blockedcontacts.conditions) != [oma_blockedcontacts_ref]:
                wp_prs_blockedcontacts.conditions = [oma_blockedcontacts_ref]
            if wp_prs_blockedcontacts.transformations:
                wp_prs_blockedcontacts.transformations = None

        wp_prs_unlisted = pres_rules.get('wp_prs_unlisted', None)
        wp_prs_allow_unlisted = pres_rules.get('wp_prs_allow_unlisted', None)

        if wp_prs_unlisted is not None and wp_prs_allow_unlisted is not None:
            pres_rules.remove(wp_prs_allow_unlisted)
            wp_prs_allow_unlisted = None

        wp_prs_unlisted_rule = wp_prs_unlisted or wp_prs_allow_unlisted

        if wp_prs_unlisted_rule is None:
            wp_prs_unlisted = commonpolicy.Rule('wp_prs_unlisted', conditions=[omapolicy.OtherIdentity()], actions=[presrules.SubHandling('confirm')])
            pres_rules.add(wp_prs_unlisted)
            wp_prs_unlisted_rule = wp_prs_unlisted
        else:
            if wp_prs_unlisted_rule is wp_prs_unlisted:
                fix_subhandling(wp_prs_unlisted_rule, valid_values=['confirm', 'block', 'polite-block'])
            else:
                fix_subhandling(wp_prs_unlisted_rule, valid_values=['allow'])
            if list(wp_prs_unlisted_rule.conditions) != [omapolicy.OtherIdentity()]:
                wp_prs_unlisted_rule.conditions = [omapolicy.OtherIdentity()]
            if wp_prs_unlisted_rule.transformations:
                wp_prs_unlisted_rule.transformations = None

        match_anonymous = omapolicy.AnonymousRequest()
        try:
            wp_prs_block_anonymous = pres_rules['wp_prs_block_anonymous']
        except KeyError:
            wp_prs_block_anonymous = commonpolicy.Rule('wp_prs_block_anonymous', conditions=[match_anonymous], actions=[presrules.SubHandling('block')])
            pres_rules.add(wp_prs_block_anonymous)
        else:
            fix_subhandling(wp_prs_block_anonymous, valid_values=['block', 'polite-block'])
            if list(wp_prs_block_anonymous.conditions) != [match_anonymous]:
                wp_prs_block_anonymous.conditions = [match_anonymous]
            if wp_prs_block_anonymous.transformations:
                wp_prs_block_anonymous.transformations = None

        match_self = commonpolicy.Identity([commonpolicy.IdentityOne('sip:' + self.account.id)])
        try:
            wp_prs_allow_own = pres_rules['wp_prs_allow_own']
        except KeyError:
            wp_prs_allow_own = commonpolicy.Rule('wp_prs_allow_own', conditions=[match_self], actions=[presrules.SubHandling('allow')])
            pres_rules.add(wp_prs_allow_own)
        else:
            fix_subhandling(wp_prs_allow_own, valid_values=['allow'])
            if list(wp_prs_allow_own.conditions) != [match_self]:
                wp_prs_allow_own.conditions = [match_self]
            if wp_prs_allow_own.transformations:
                wp_prs_allow_own.transformations = None

        # Remove any other rules
        all_rule_names = set(pres_rules[IterateIDs])
        known_rule_names = set(('wp_prs_grantedcontacts', 'wp_prs_blockedcontacts', 'wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_block_anonymous', 'wp_prs_allow_own'))
        for name in all_rule_names - known_rule_names:
            del pres_rules[name]

        del fix_subhandling

        # Normalize dialog-rules
        #
        if self.dialog_rules.supported:
            if self.dialog_rules.content is None:
                self.dialog_rules.content = dialogrules.DialogRules()
            elif self.dialog_rules.content.element.nsmap.get('dr') != dialogrules.namespace: # TODO: this elif branch should be removed in a later version as it is
                self.dialog_rules.content = dialogrules.DialogRules()                        #       only used to discard documents created with the old namespace. -Dan

            def fix_subhandling(rule, valid_values=[]):
                subhandling_elements = sorted((item for item in rule.actions if isinstance(item, dialogrules.SubHandling)), key=attrgetter('value.priority'))
                if not subhandling_elements:
                    subhandling_elements = [dialogrules.SubHandling('block')] # spec specifies that missing SubHandling means block
                    rule.actions.update(subhandling_elements)
                subhandling = subhandling_elements.pop()
                for item in subhandling_elements: # remove any extraneous SubHandling elements
                    rule.actions.remove(item)
                if subhandling.value not in valid_values:
                    subhandling.value = valid_values[0]

            dialog_rules = self.dialog_rules.content

            dialog_grantedcontacts_ref = omapolicy.ExternalList([self.resource_lists.url + '/~~' + resource_lists.get_xpath(dialog_grantedcontacts)])
            dialog_blockedcontacts_ref = omapolicy.ExternalList([self.resource_lists.url + '/~~' + resource_lists.get_xpath(dialog_blockedcontacts)])

            try:
                wp_dlg_grantedcontacts = dialog_rules['wp_dlg_grantedcontacts']
            except KeyError:
                wp_dlg_grantedcontacts = commonpolicy.Rule('wp_dlg_grantedcontacts', conditions=[dialog_grantedcontacts_ref], actions=[dialogrules.SubHandling('allow')])
                dialog_rules.add(wp_dlg_grantedcontacts)
            else:
                fix_subhandling(wp_dlg_grantedcontacts, valid_values=['allow'])
                if list(wp_dlg_grantedcontacts.conditions) != [dialog_grantedcontacts_ref]:
                    wp_dlg_grantedcontacts.conditions = [dialog_grantedcontacts_ref]
                if wp_dlg_grantedcontacts.transformations:
                    wp_dlg_grantedcontacts.transformations = None
            try:
                wp_dlg_blockedcontacts = dialog_rules['wp_dlg_blockedcontacts']
            except KeyError:
                wp_dlg_blockedcontacts = commonpolicy.Rule('wp_dlg_blockedcontacts', conditions=[dialog_blockedcontacts_ref], actions=[dialogrules.SubHandling('polite-block')])
                dialog_rules.add(wp_dlg_blockedcontacts)
            else:
                fix_subhandling(wp_dlg_blockedcontacts, valid_values=['polite-block'])
                if list(wp_dlg_blockedcontacts.conditions) != [dialog_blockedcontacts_ref]:
                    wp_dlg_blockedcontacts.conditions = [dialog_blockedcontacts_ref]
                if wp_dlg_blockedcontacts.transformations:
                    wp_dlg_blockedcontacts.transformations = None

            wp_dlg_unlisted = dialog_rules.get('wp_dlg_unlisted', None)
            wp_dlg_allow_unlisted = dialog_rules.get('wp_dlg_allow_unlisted', None)

            if wp_dlg_unlisted is not None and wp_dlg_allow_unlisted is not None:
                dialog_rules.remove(wp_dlg_allow_unlisted)
                wp_dlg_allow_unlisted = None

            wp_dlg_unlisted_rule = wp_dlg_unlisted or wp_dlg_allow_unlisted

            if wp_dlg_unlisted_rule is None:
                wp_dlg_unlisted = commonpolicy.Rule('wp_dlg_unlisted', conditions=[omapolicy.OtherIdentity()], actions=[dialogrules.SubHandling('confirm')])
                dialog_rules.add(wp_dlg_unlisted)
                wp_dlg_unlisted_rule = wp_dlg_unlisted
            else:
                if wp_dlg_unlisted_rule is wp_dlg_unlisted:
                    fix_subhandling(wp_dlg_unlisted_rule, valid_values=['confirm', 'block', 'polite-block'])
                else:
                    fix_subhandling(wp_dlg_unlisted_rule, valid_values=['allow'])
                if list(wp_dlg_unlisted_rule.conditions) != [omapolicy.OtherIdentity()]:
                    wp_dlg_unlisted_rule.conditions = [omapolicy.OtherIdentity()]
                if wp_dlg_unlisted_rule.transformations:
                    wp_dlg_unlisted_rule.transformations = None

            match_anonymous = omapolicy.AnonymousRequest()
            try:
                wp_dlg_block_anonymous = dialog_rules['wp_dlg_block_anonymous']
            except KeyError:
                wp_dlg_block_anonymous = commonpolicy.Rule('wp_dlg_block_anonymous', conditions=[match_anonymous], actions=[dialogrules.SubHandling('block')])
                dialog_rules.add(wp_dlg_block_anonymous)
            else:
                fix_subhandling(wp_dlg_block_anonymous, valid_values=['block', 'polite-block'])
                if list(wp_dlg_block_anonymous.conditions) != [match_anonymous]:
                    wp_dlg_block_anonymous.conditions = [match_anonymous]
                if wp_dlg_block_anonymous.transformations:
                    wp_dlg_block_anonymous.transformations = None

            match_self = commonpolicy.Identity([commonpolicy.IdentityOne('sip:' + self.account.id)])
            try:
                wp_dlg_allow_own = dialog_rules['wp_dlg_allow_own']
            except KeyError:
                wp_dlg_allow_own = commonpolicy.Rule('wp_dlg_allow_own', conditions=[match_self], actions=[dialogrules.SubHandling('allow')])
                dialog_rules.add(wp_dlg_allow_own)
            else:
                fix_subhandling(wp_dlg_allow_own, valid_values=['allow'])
                if list(wp_dlg_allow_own.conditions) != [match_self]:
                    wp_dlg_allow_own.conditions = [match_self]
                if wp_dlg_allow_own.transformations:
                    wp_dlg_allow_own.transformations = None

            # Remove any other rules
            all_rule_names = set(dialog_rules[IterateIDs])
            known_rule_names = set(('wp_dlg_grantedcontacts', 'wp_dlg_blockedcontacts', 'wp_dlg_unlisted', 'wp_dlg_allow_unlisted', 'wp_dlg_block_anonymous', 'wp_dlg_allow_own'))
            for name in all_rule_names - known_rule_names:
                del dialog_rules[name]

        # Normalize status icon
        #
        if self.status_icon.supported and self.status_icon.content is not None:
            content = self.status_icon.content
            if None in (content.encoding, content.mime_type) or content.encoding.value.lower() != 'base64' or content.mime_type.value.lower() not in Icon.__mimetypes__:
                self.status_icon.content = None
                self.status_icon.dirty = True

    def _OH_AddContactOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        contact = operation.contact
        presence_handling = addressbook.PresenceHandling(contact.presence.policy, contact.presence.subscribe)
        dialog_handling = addressbook.DialogHandling(contact.dialog.policy, contact.dialog.subscribe)
        xml_contact = addressbook.Contact(contact.id, contact.name, presence_handling=presence_handling, dialog_handling=dialog_handling)
        for uri in contact.uris:
            contact_uri = addressbook.ContactURI(uri.id, uri.uri, uri.type)
            contact_uri.attributes = addressbook.ContactURI.attributes.type(uri.attributes)
            xml_contact.uris.add(contact_uri)
        xml_contact.uris.default = contact.uris.default
        xml_contact.attributes = addressbook.Contact.attributes.type(contact.attributes)
        sipsimple_addressbook.add(xml_contact)

    def _OH_UpdateContactOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            contact = sipsimple_addressbook[addressbook.Contact, operation.contact.id]
        except KeyError:
            return
        attributes = dict(operation.attributes)
        attributes.pop('id', None) # id is never modified
        attributes.pop('uris', None) # uris are modified using dedicated methods
        if 'name' in attributes:
            contact.name = attributes.pop('name')
        if 'uris.default' in attributes:
            contact.uris.default = attributes.pop('uris.default')
        if 'presence.policy' in attributes:
            contact.presence.policy = attributes.pop('presence.policy')
        if 'presence.subscribe' in attributes:
            contact.presence.subscribe = attributes.pop('presence.subscribe')
        if 'dialog.policy' in attributes:
            contact.dialog.policy = attributes.pop('dialog.policy')
        if 'dialog.subscribe' in attributes:
            contact.dialog.subscribe = attributes.pop('dialog.subscribe')
        if contact.attributes is None:
            contact.attributes = addressbook.Contact.attributes.type()
        contact.attributes.update(attributes)

    def _OH_RemoveContactOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        for group in (group for group in sipsimple_addressbook[addressbook.Group, IterateItems] if operation.contact.id in group.contacts):
            group.contacts.remove(operation.contact.id)
        try:
            del sipsimple_addressbook[addressbook.Contact, operation.contact.id]
        except KeyError:
            pass

    def _OH_AddContactURIOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            contact = sipsimple_addressbook[addressbook.Contact, operation.contact.id]
        except KeyError:
            return
        uri = addressbook.ContactURI(operation.uri.id, operation.uri.uri, operation.uri.type)
        uri.attributes = addressbook.ContactURI.attributes.type(operation.uri.attributes)
        contact.uris.add(uri)

    def _OH_UpdateContactURIOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            contact = sipsimple_addressbook[addressbook.Contact, operation.contact.id]
            uri = contact.uris[operation.uri.id]
        except KeyError:
            return
        attributes = dict(operation.attributes)
        attributes.pop('id', None) # id is never modified
        if 'uri' in attributes:
            uri.uri = attributes.pop('uri')
        if 'type' in attributes:
            uri.type = attributes.pop('type')
        if uri.attributes is None:
            uri.attributes = addressbook.ContactURI.attributes.type()
        uri.attributes.update(attributes)

    def _OH_RemoveContactURIOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            contact = sipsimple_addressbook[addressbook.Contact, operation.contact.id]
            del contact.uris[operation.uri.id]
        except KeyError:
            pass

    def _OH_AddGroupOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        group = addressbook.Group(operation.group.id, operation.group.name, [contact.id for contact in operation.group.contacts])
        group.attributes = addressbook.Group.attributes.type(operation.group.attributes)
        sipsimple_addressbook.add(group)

    def _OH_UpdateGroupOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            group = sipsimple_addressbook[addressbook.Group, operation.group.id]
        except KeyError:
            return
        attributes = dict(operation.attributes)
        attributes.pop('id', None) # id is never modified
        attributes.pop('contacts', None) # contacts are added/removed using dedicated methods
        if 'name' in attributes:
            group.name = attributes.pop('name')
        if group.attributes is None:
            group.attributes = addressbook.Group.attributes.type()
        group.attributes.update(attributes)

    def _OH_RemoveGroupOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            del sipsimple_addressbook[addressbook.Group, operation.group.id]
        except KeyError:
            pass

    def _OH_AddGroupMemberOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            group = sipsimple_addressbook[addressbook.Group, operation.group.id]
        except KeyError:
            return
        if operation.contact.id in group.contacts:
            return
        group.contacts.add(operation.contact.id)

    def _OH_RemoveGroupMemberOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            group = sipsimple_addressbook[addressbook.Group, operation.group.id]
            group.contacts.remove(operation.contact.id)
        except KeyError:
            return

    def _OH_AddPolicyOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        presence_handling = addressbook.PresenceHandling(operation.policy.presence.policy, operation.policy.presence.subscribe)
        dialog_handling = addressbook.DialogHandling(operation.policy.dialog.policy, operation.policy.dialog.subscribe)
        policy = addressbook.Policy(operation.policy.id, operation.policy.uri, operation.policy.name, presence_handling=presence_handling, dialog_handling=dialog_handling)
        policy.attributes = addressbook.Policy.attributes.type(operation.policy.attributes)
        sipsimple_addressbook.add(policy)

    def _OH_UpdatePolicyOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            policy = sipsimple_addressbook[addressbook.Policy, operation.policy.id]
        except KeyError:
            return
        attributes = dict(operation.attributes)
        attributes.pop('id', None) # id is never modified
        if 'uri' in attributes:
            policy.uri = attributes.pop('uri')
        if 'name' in attributes:
            policy.name = attributes.pop('name')
        if 'presence.policy' in attributes:
            policy.presence.policy = attributes.pop('presence.policy')
        if 'presence.subscribe' in attributes:
            policy.presence.subscribe = attributes.pop('presence.subscribe')
        if 'dialog.policy' in attributes:
            policy.dialog.policy = attributes.pop('dialog.policy')
        if 'dialog.subscribe' in attributes:
            policy.dialog.subscribe = attributes.pop('dialog.subscribe')
        if policy.attributes is None:
            policy.attributes = addressbook.Policy.attributes.type()
        policy.attributes.update(attributes)

    def _OH_RemovePolicyOperation(self, operation):
        sipsimple_addressbook = self.resource_lists.content['sipsimple_addressbook']
        try:
            del sipsimple_addressbook[addressbook.Policy, operation.policy.id]
        except KeyError:
            pass

    def _OH_SetStatusIconOperation(self, operation):
        if not self.status_icon.supported:
            return
        icon = operation.icon
        if icon is None or not icon.data:
            self.status_icon.dirty = self.status_icon.content is not None
            self.status_icon.content = None
        else:
            content = prescontent.PresenceContent(data=base64.encodestring(icon.data), mime_type=icon.mime_type, encoding='base64', description=icon.description)
            if self.status_icon.content == content:
                return
            self.status_icon.content = content

    def _OH_SetOfflineStatusOperation(self, operation):
        pidf = operation.status.pidf if operation.status is not None else None
        if not self.pidf_manipulation.supported or pidf == self.pidf_manipulation.content:
            return
        self.pidf_manipulation.content = pidf
        self.pidf_manipulation.dirty = True

    def _OH_SetDefaultPresencePolicyOperation(self, operation):
        pres_rules = self.pres_rules.content
        if operation.policy == 'allow':
            rule_id, other_rule_id = 'wp_prs_allow_unlisted', 'wp_prs_unlisted'
        else:
            rule_id, other_rule_id = 'wp_prs_unlisted', 'wp_prs_allow_unlisted'
        try:
            del pres_rules[other_rule_id]
        except KeyError:
            rule = pres_rules[rule_id]
            subhandling = next(item for item in rule.actions if isinstance(item, presrules.SubHandling))
            subhandling.value = operation.policy
        else:
            rule = commonpolicy.Rule(rule_id, conditions=[omapolicy.OtherIdentity()], actions=[presrules.SubHandling(operation.policy)])
            pres_rules.add(rule)

    def _OH_SetDefaultDialogPolicyOperation(self, operation):
        if not self.dialog_rules.supported:
            return
        dialog_rules = self.dialog_rules.content
        if operation.policy == 'allow':
            rule_id, other_rule_id = 'wp_dlg_allow_unlisted', 'wp_dlg_unlisted'
        else:
            rule_id, other_rule_id = 'wp_dlg_unlisted', 'wp_dlg_allow_unlisted'
        try:
            del dialog_rules[other_rule_id]
        except KeyError:
            rule = dialog_rules[rule_id]
            subhandling = next(item for item in rule.actions if isinstance(item, dialogrules.SubHandling))
            subhandling.value = operation.policy
        else:
            rule = commonpolicy.Rule(rule_id, conditions=[omapolicy.OtherIdentity()], actions=[dialogrules.SubHandling(operation.policy)])
            dialog_rules.add(rule)

    # Notification handlers
    #

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if set(['__id__', 'xcap.xcap_root', 'auth.username', 'auth.password', 'sip.subscribe_interval', 'sip.transport_list']).intersection(notification.data.modified):
            self.command_channel.send(Command('reload', modified=notification.data.modified))
        if 'enabled' in notification.data.modified:
            return # global account activation is handled separately by the account itself
        if self.account.enabled and 'xcap.enabled' in notification.data.modified:
            if self.account.xcap.enabled:
                self.start()
            else:
                self.stop()

    def _NH_CFGSettingsObjectWasDeleted(self, notification):
        notification.center.remove_observer(self, sender=self.account, name='CFGSettingsObjectDidChange')
        notification.center.remove_observer(self, sender=self.account, name='CFGSettingsObjectWasDeleted')
        self.command_channel.send(Command('stop'))
        self.command_channel.send(Command('cleanup'))

    def _NH_XCAPSubscriptionDidStart(self, notification):
        self.command_channel.send(Command('fetch', documents=set(self.document_names)))

    def _NH_XCAPSubscriptionDidFail(self, notification):
        self.command_channel.send(Command('fetch', documents=set(self.document_names)))

    def _NH_XCAPSubscriptionGotNotify(self, notification):
        if notification.data.content_type == xcapdiff.XCAPDiffDocument.content_type:
            try:
                xcap_diff = xcapdiff.XCAPDiffDocument.parse(notification.data.body)
            except ParserError:
                self.command_channel.send(Command('fetch', documents=set(self.document_names)))
            else:
                applications = set(child.selector.auid for child in xcap_diff if isinstance(child, xcapdiff.Document))
                documents = set(document.name for document in self.documents if document.application in applications)
                self.command_channel.send(Command('fetch', documents=documents))

    def _load_data(self):
        addressbook = Addressbook.from_payload(self.resource_lists.content['sipsimple_addressbook'])

        default_presence_rule = self.pres_rules.content.get('wp_prs_unlisted', None) or self.pres_rules.content.get('wp_prs_allow_unlisted', None)
        if self.dialog_rules.supported:
            default_dialog_rule = self.dialog_rules.content.get('wp_dlg_unlisted', None) or self.dialog_rules.content.get('wp_dlg_allow_unlisted', None)
        else:
            default_dialog_rule = None
        presence_rules = PresenceRules.from_payload(default_presence_rule)
        dialog_rules = DialogRules.from_payload(default_dialog_rule)

        if self.status_icon.supported and self.status_icon.content:
            status_icon = Icon.from_payload(self.status_icon.content)
            status_icon.url = self.status_icon.url
            status_icon.etag = self.status_icon.etag
        else:
            status_icon = None

        if self.pidf_manipulation.supported and self.pidf_manipulation.content:
            offline_status = OfflineStatus(self.pidf_manipulation.content)
        else:
            offline_status = None

        data=NotificationData(addressbook=addressbook, presence_rules=presence_rules, dialog_rules=dialog_rules, status_icon=status_icon, offline_status=offline_status)
        NotificationCenter().post_notification('XCAPManagerDidReloadData', sender=self, data=data)

    def _fetch_documents(self, documents):
        workers = [Worker.spawn(document.fetch) for document in (doc for doc in self.documents if doc.name in documents and doc.supported)]
        try:
            while workers:
                worker = workers.pop()
                worker.wait()
        finally:
            for worker in workers:
                worker.wait_ex()

    def _save_journal(self):
        try:
            self.storage.save('journal', cPickle.dumps(self.journal))
        except XCAPStorageError:
            pass

    def _schedule_command(self, timeout, command):
        from twisted.internet import reactor
        timer = reactor.callLater(timeout, self.command_channel.send, command)
        timer.command = command
        return timer


class XCAPTransaction(object):
    def __init__(self, xcap_manager):
        self.xcap_manager = xcap_manager

    def __enter__(self):
        self.xcap_manager.start_transaction()
        return self

    def __exit__(self, type, value, traceback):
        self.xcap_manager.commit_transaction()



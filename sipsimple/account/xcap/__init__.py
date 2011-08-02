# Copyright (C) 2010-2011 AG Projects. See LICENSE for details.
#

"""High-level management of XCAP documents based on OMA specifications"""

__all__ = ['Contact', 'Service', 'CatchAllCondition', 'DomainCondition', 'DomainExcepton', 'UserException', 'Policy', 'Class', 'OccurenceID', 'DeviceID',
           'ServiceURI', 'ServiceURIScheme', 'PresencePolicy', 'DialoginfoPolicy', 'FallbackPolicies', 'Icon', 'OfflineStatus', 'XCAPManager', 'XCAPTransaction']


import base64
import cPickle
import os
import random
import re
import string
import weakref
from cStringIO import StringIO
from collections import deque
from copy import deepcopy
from datetime import datetime
from itertools import chain, count
from time import time
from urllib2 import URLError

from application import log
from application.notification import IObserver, NotificationCenter
from application.python import Null, limit
from application.python.types import NullType
from eventlet import api, coros, proc
from eventlet.green.httplib import BadStatusLine
from twisted.internet.error import ConnectionLost
from xcaplib.green import XCAPClient
from xcaplib.error import HTTPError
from zope.interface import implements

from sipsimple.account.xcap.storage import IXCAPStorage, XCAPStorageError
from sipsimple.account.xcap.uri import XCAPURI
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import ContactHeader, FromHeader, PJSIPError, RouteHeader, ToHeader, SIPCoreError, SIPURI, Subscription
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.payloads import ParserError
from sipsimple.payloads import dialogrules, omapolicy, policy as common_policy, prescontent, presdm, presrules, resourcelists, rlsservices, rpid, xcapcaps, xcapdiff
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command
from sipsimple.util import All, Any, TimestampedNotificationData


class XCAPError(Exception): pass
class FetchRequiredError(XCAPError): pass

class SubscriptionError(Exception):
    def __init__(self, error, timeout, refresh_interval=None):
        self.error = error
        self.refresh_interval = refresh_interval
        self.timeout = timeout

class SIPSubscriptionDidFail(Exception):
    def __init__(self, data):
        self.data = data

class InterruptSubscription(Exception): pass
class TerminateSubscription(Exception): pass


class Document(object):
    name            = None
    payload_type    = None
    application     = None
    global_tree     = None
    filename        = None
    cached          = True

    def __init__(self, manager):
        self.manager = weakref.proxy(manager)
        self.client = None
        self.content = None
        self.etag = None
        self.fetch_time = datetime.fromtimestamp(0)
        self.dirty = False
        self.supported = True

    @property
    def relative_uri(self):
        uri = self.uri[len(self.client.root):]
        if uri.startswith('/'):
            uri = uri[1:]
        return uri

    @property
    def uri(self):
        return self.client.get_url(self.application, None, globaltree=self.global_tree, filename=self.filename)

    def load_from_cache(self):
        if not self.cached:
            return
        try:
            document = StringIO(self.manager.storage.load(self.name))
            self.etag = document.readline().strip() or None
            self.content = self.payload_type.parse(document)
        except (XCAPStorageError, ParserError):
            self.etag = None
            self.content = None

    def initialize(self, client, server_caps):
        self.client = client
        self.supported = self.application in server_caps.auids

    def reset(self):
        self.content = None
        self.etag = None

    def fetch(self):
        try:
            document = self.client.get(self.application, etagnot=self.etag, globaltree=self.global_tree, headers={'Accept': self.payload_type.content_type}, filename=self.filename)
            self.content = self.payload_type.parse(document)
            self.etag = document.etag
        except (BadStatusLine, ConnectionLost, URLError), e:
            raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except HTTPError, e:
            if e.status == 404: # Not Found
                self.reset()
                self.fetch_time = datetime.utcnow()
                if self.cached:
                    try:
                        self.manager.storage.delete(self.name)
                    except XCAPStorageError:
                        pass
            elif e.status != 304: # Other than Not Modified:
                raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except ParserError, e:
            raise XCAPError("failed to parse %s document: %s" % (self.name, e))
        else:
            self.fetch_time = datetime.utcnow()
            if self.cached:
                try:
                    self.manager.storage.save(self.name, (self.etag or '') + os.linesep + document)
                except XCAPStorageError:
                    pass

    def update(self):
        if not self.dirty:
            return
        data = self.content.toxml() if self.content is not None else None
        try:
            kw = dict(etag=self.etag) if self.etag is not None else dict(etagnot='*')
            if data is not None:
                response = self.client.put(self.application, data, globaltree=self.global_tree, filename=self.filename, headers={'Content-Type': self.payload_type.content_type}, **kw)
            else:
                response = self.client.delete(self.application, data, globaltree=self.global_tree, filename=self.filename, **kw)
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
        if self.cached:
            try:
                if data is not None:
                    self.manager.storage.save(self.name, self.etag + os.linesep + data)
                else:
                    self.manager.storage.delete(self.name)
            except XCAPStorageError:
                pass


class DialogRulesDocument(Document):
    name            = 'dialog-rules'
    payload_type    = dialogrules.DialogRules
    application     = 'org.openxcap.dialog-rules'
    global_tree     = False
    filename        = 'index'


class PresRulesDocument(Document):
    name            = 'pres-rules'
    payload_type    = presrules.PresRules
    application     = 'pres-rules'
    global_tree     = False
    filename        = 'index'

    def initialize(self, client, server_caps):
        self.application = 'org.openmobilealliance.pres-rules' if 'org.openmobilealliance.pres-rules' in server_caps.auids else 'pres-rules'
        super(PresRulesDocument, self).initialize(client, server_caps)


class ResourceListsDocument(Document):
    name            = 'resource-lists'
    payload_type    = resourcelists.ResourceLists
    application     = 'resource-lists'
    global_tree     = False
    filename        = 'index'


class RLSServicesDocument(Document):
    name            = 'rls-services'
    payload_type    = rlsservices.RLSServices
    application     = 'rls-services'
    global_tree     = False
    filename        = 'index'


class XCAPCapsDocument(Document):
    name            = 'xcap-caps'
    payload_type    = xcapcaps.XCAPCapabilities
    application     = 'xcap-caps'
    global_tree     = True
    filename        = 'index'
    cached          = False

    def initialize(self, client):
        self.client = client


class StatusIconDocument(Document):
    name            = 'status-icon'
    payload_type    = prescontent.PresenceContent
    application     = 'org.openmobilealliance.pres-content'
    global_tree     = False
    filename        = 'oma_status-icon/index'

    def __init__(self, manager):
        super(StatusIconDocument, self).__init__(manager)
        self.alternative_location = None

    def fetch(self):
        try:
            document = self.client.get(self.application, etagnot=self.etag, globaltree=self.global_tree, headers={'Accept': self.payload_type.content_type}, filename=self.filename)
            self.content = self.payload_type.parse(document)
            self.etag = document.etag
        except (BadStatusLine, ConnectionLost, URLError), e:
            raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except HTTPError, e:
            if e.status == 404: # Not Found
                self.reset()
                self.fetch_time = datetime.utcnow()
                if self.cached:
                    try:
                        self.manager.storage.delete(self.name)
                    except XCAPStorageError:
                        pass
            elif e.status == 304: # Not Modified:
                self.alternative_location = e.headers.get('X-AGP-Alternative-Location', None)
            else:
                raise XCAPError("failed to fetch %s document: %s" % (self.name, e))
        except ParserError, e:
            raise XCAPError("failed to parse %s document: %s" % (self.name, e))
        else:
            self.fetch_time = datetime.utcnow()
            self.alternative_location = e.headers.get('X-AGP-Alternative-Location', None)
            if self.cached:
                try:
                    self.manager.storage.save(self.name, (self.etag or '') + os.linesep + document)
                except XCAPStorageError:
                    pass

    def update(self):
        if not self.dirty:
            return
        data = self.content.toxml() if self.content is not None else None
        try:
            kw = dict(etag=self.etag) if self.etag is not None else dict(etagnot='*')
            if data is not None:
                response = self.client.put(self.application, data, globaltree=self.global_tree, filename=self.filename, headers={'Content-Type': self.payload_type.content_type}, **kw)
            else:
                response = self.client.delete(self.application, data, globaltree=self.global_tree, filename=self.filename, **kw)
        except (BadStatusLine, ConnectionLost, URLError), e:
            raise XCAPError("failed to update %s document: %s" % (self.name, e))
        except HTTPError, e:
            if e.status == 412: # Precondition Failed
                raise FetchRequiredError("document %s was modified externally" % self.name)
            elif e.status == 404 and data is None: # attempted to delete a document that did't exist in the first place
                pass
            else:
                raise XCAPError("failed to update %s document: %s" % (self.name, e))
        self.alternative_location = response.headers.get('X-AGP-Alternative-Location', None)
        self.etag = response.etag if data is not None else None
        self.dirty = False
        if self.cached:
            try:
                if data is not None:
                    self.manager.storage.save(self.name, self.etag + os.linesep + data)
                else:
                    self.manager.storage.delete(self.name)
            except XCAPStorageError:
                pass

    def reset(self):
        super(StatusIconDocument, self).reset()
        self.alternative_location = None


class PIDFManipulationDocument(Document):
    name            = 'pidf-manipulation'
    payload_type    = presdm.PIDF
    application     = 'pidf-manipulation'
    global_tree     = False
    filename        = 'index'


class Contact(object):
    def __init__(self, name, uri, group, **attributes):
        self.name = name
        self.uri = uri
        self.group = group
        self.attributes = attributes
        self.presence_policies = []
        self.dialoginfo_policies = []
        self.subscribe_to_presence = True
        self.subscribe_to_dialoginfo = True

    def __eq__(self, other):
        if isinstance(other, Contact):
            return (self.name == other.name and self.uri == other.uri and self.group == other.group and self.attributes == other.attributes and
                    self.presence_policies == other.presence_policies and self.dialoginfo_policies == other.dialoginfo_policies and
                    self.subscribe_to_presence == other.subscribe_to_presence and self.subscribe_to_dialoginfo == other.subscribe_to_dialoginfo)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __hash__(self):
        return hash(self.uri)


class Service(object):
    def __init__(self, uri, packages, entries=None):
        self.uri = uri
        self.packages = packages
        self.entries = entries or []


class CatchAllCondition(object):
    def __init__(self, exceptions=None):
        self.exceptions = exceptions or []

    def __eq__(self, other):
        if isinstance(other, CatchAllCondition):
            return self.exceptions == other.exceptions
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class DomainCondition(object):
    def __init__(self, domain, exceptions=None):
        self.domain = domain
        self.exceptions = exceptions or []

    def __eq__(self, other):
        if isinstance(other, DomainCondition):
            return self.domain == other.domain and self.exceptions == other.exceptions
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class DomainException(object):
    def __init__(self, domain):
        self.domain = domain

    def __eq__(self, other):
        if isinstance(other, DomainException):
            return self.domain == other.domain
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class UserException(object):
    def __init__(self, uri):
        self.uri = uri

    def __eq__(self, other):
        if isinstance(other, UserException):
            return self.uri == other.uri
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class Policy(object):
    def __init__(self, id, action, name=None, validity=None, sphere=None, multi_identity_conditions=None):
        self.id = id
        self.action = action
        self.name = name
        self.validity = validity
        self.sphere = sphere
        self.multi_identity_conditions = multi_identity_conditions

    def check_validity(self, timestamp, sphere=Any):
        if sphere is not Any and sphere != self.sphere:
            return False
        if self.validity is None:
            return True
        for from_timestamp, until_timestamp in self.validity:
            if from_timestamp <= timestamp <= until_timestamp:
                return True
        else:
            return False

    def __eq__(self, other):
        if isinstance(other, Policy):
            return (self.id == other.id and self.action == other.action and self.name == other.name and self.validity == other.validity and
                    self.sphere == other.sphere and self.multi_identity_conditions == other.multi_identity_conditions)
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __hash__(self):
        return hash(self.id)


# elements to represent provide_(devices|persons|services) components for pres-rules
class Class(unicode): pass
class OccurenceID(unicode): pass
class DeviceID(unicode): pass
class ServiceURI(unicode): pass
class ServiceURIScheme(unicode): pass


class PresencePolicy(Policy):
    def __init__(self, id, action, name=None, validity=None, sphere=None, multi_identity_conditions=None):
        super(PresencePolicy, self).__init__(id, action, name, validity, sphere, multi_identity_conditions)
        self.provide_devices = All
        self.provide_persons = All
        self.provide_services = All
        self.provide_activities = None
        self.provide_class = None
        self.provide_device_id = None
        self.provide_mood = None
        self.provide_place_is = None
        self.provide_place_type = None
        self.provide_privacy = None
        self.provide_relationship = None
        self.provide_status_icon = None
        self.provide_sphere = None
        self.provide_time_offset = None
        self.provide_user_input = None
        self.provide_unknown_attributes = None
        self.provide_all_attributes = True

    def __eq__(self, other):
        if isinstance(other, PresencePolicy):
            return (super(PresencePolicy, self).__eq__(other) and self.provide_devices == other.provide_devices and
                   self.provide_persons == other.provide_persons and self.provide_services == other.provide_services and
                   self.provide_activities == other.provide_activities and self.provide_class == other.provide_class and
                   self.provide_device_id == other.provide_device_id and self.provide_mood == other.provide_mood and
                   self.provide_place_is == other.provide_place_is and self.provide_place_type == other.provide_place_type and
                   self.provide_privacy == other.provide_privacy and self.provide_relationship == other.provide_relationship and
                   self.provide_status_icon == other.provide_status_icon and self.provide_sphere == other.provide_sphere and
                   self.provide_time_offset == other.provide_time_offset and self.provide_user_input == other.provide_user_input and
                   self.provide_unknown_attributes == other.provide_unknown_attributes and self.provide_all_attributes == other.provide_all_attributes)
        elif isinstance(other, Policy):
            return super(PresencePolicy, self).__eq__(other)
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class DialoginfoPolicy(Policy):
    pass


class FallbackPoliciesType(NullType):
    __name__ = 'FallbackPolicies'

FallbackPolicies = FallbackPoliciesType()


class Icon(object):
    def __init__(self, data, mime_type, description=None, location=None):
        self.data = data
        self.mime_type = mime_type
        self.description = description
        self.location = location


class OfflineStatus(object):
    def __init__(self, activity=None, note=None):
        self.activity = activity
        self.note = note


class Operation(object):
    name = None
    documents = []
    params = []

    def __init__(self, **params):
        self.__dict__.update(dict.fromkeys(self.params))
        self.__dict__.update(params)
        self.applied = False
        self.timestamp = datetime.utcnow()


class NormalizeOperation(Operation):
    name = 'normalize'
    documents = ['dialog-rules', 'pres-rules', 'resource-lists', 'rls-services']
    params = []

class AddGroupOperation(Operation):
    name = 'add_group'
    documents = ['resource-lists']
    params = ['group']

class RenameGroupOperation(Operation):
    name = 'rename_group'
    documents = ['resource-lists']
    params = ['old_name', 'new_name']

class RemoveGroupOperation(Operation):
    name = 'remove_group'
    documents = ['resource-lists']
    params = ['group']

class AddContactOperation(Operation):
    name = 'add_contact'
    documents = ['dialog-rules', 'pres-rules', 'resource-lists', 'rls-services']
    params = ['contact']

class UpdateContactOperation(Operation):
    name = 'update_contact'
    documents = ['dialog-rules', 'pres-rules', 'resource-lists', 'rls-services']
    params = ['contact', 'attributes']

class RemoveContactOperation(Operation):
    name = 'remove_contact'
    documents = ['dialog-rules', 'pres-rules', 'resource-lists', 'rls-services']
    params = ['contact']

class AddPresencePolicyOperation(Operation):
    name = 'add_presence_policy'
    documents = ['pres-rules']
    params = ['policy']

class UpdatePresencePolicyOperation(Operation):
    name = 'update_presence_policy'
    documents = ['pres-rules']
    params = ['policy', 'attributes']

class RemovePresencePolicyOperation(Operation):
    name = 'remove_presence_policy'
    documents = ['pres-rules']
    params = ['policy']

class AddDialoginfoPolicyOperation(Operation):
    name = 'add_dialoginfo_policy'
    documents = ['pres-rules']
    params = ['policy']

class UpdateDialoginfoPolicyOperation(Operation):
    name = 'update_dialoginfo_policy'
    documents = ['pres-rules']
    params = ['policy', 'attributes']

class RemoveDialoginfoPolicyOperation(Operation):
    name = 'remove_dialoginfo_policy'
    documents = ['pres-rules']
    params = ['policy']

class SetStatusIconOperation(Operation):
    name = 'set_status_icon'
    documents = ['status-icon']
    params = ['icon']

class SetOfflineStatusOperation(Operation):
    name = 'set_offline_status'
    documents = ['pidf-manipulation']
    params = ['status']


class XCAPSubscriber(object):
    implements(IObserver)

    def __init__(self, account, documents):
        self.account = account
        self.documents = documents
        self.active = False
        self.subscribed = False
        self._command_proc = None
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._subscription = None
        self._subscription_proc = None
        self._subscription_timer = None
        self._wakeup_timer = None

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='DNSNameserversDidChange')
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        self._command_proc = proc.spawn(self._run)

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='DNSNameserversDidChange')
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
        self._command_proc.kill()
        self._command_proc = None

    def activate(self):
        self.active = True
        command = Command('subscribe')
        self._command_channel.send(command)

    def deactivate(self):
        self.active = False
        command = Command('unsubscribe')
        self._command_channel.send(command)
        command.wait()

    def resubscribe(self):
        command = Command('subscribe')
        self._command_channel.send(command)

    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _CH_subscribe(self, command):
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(InterruptSubscription)
            subscription_proc.wait()
        self._subscription_proc = proc.spawn(self._subscription_handler, command)

    def _CH_unsubscribe(self, command):
        # Cancel any timer which would restart the subscription process
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._wakeup_timer is not None and self._wakeup_timer.active():
            self._wakeup_timer.cancel()
        self._wakeup_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(TerminateSubscription)
            subscription_proc.wait()
            self._subscription_proc = None
        command.signal()

    def _subscription_handler(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        refresh_interval =  getattr(command, 'refresh_interval', None) or self.account.sip.subscribe_interval

        try:
            if self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host,
                             port=self.account.sip.outbound_proxy.port,
                             parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                timeout = random.uniform(15, 30)
                raise SubscriptionError(error='DNS lookup failed: %s' % e, timeout=timeout)

            rlist = resourcelists.List()
            for document in (doc for doc in self.documents if doc.supported):
                rlist.append(resourcelists.Entry(document.relative_uri))
            body = resourcelists.ResourceLists([rlist]).toxml()
            content_type = resourcelists.ResourceLists.content_type
            timeout = time() + 30
            for route in routes:
                remaining_time = timeout - time()
                if remaining_time > 0:
                    try:
                        contact_uri = self.account.contact[route]
                    except KeyError:
                        continue
                    subscription = Subscription(self.account.uri, FromHeader(self.account.uri, self.account.display_name),
                                                ToHeader(self.account.uri, self.account.display_name),
                                                ContactHeader(contact_uri),
                                                'xcap-diff',
                                                RouteHeader(route.get_uri()),
                                                credentials=self.account.credentials,
                                                refresh=refresh_interval)
                    notification_center.add_observer(self, sender=subscription)
                    try:
                        subscription.subscribe(body=body, content_type=content_type, timeout=limit(remaining_time, min=1, max=5))
                    except (PJSIPError, SIPCoreError):
                        notification_center.remove_observer(self, sender=subscription)
                        timeout = 5
                        raise SubscriptionError(error='Internal error', timeout=timeout)
                    self._subscription = subscription
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.sender is subscription and notification.name == 'SIPSubscriptionDidStart':
                                break
                    except SIPSubscriptionDidFail, e:
                        notification_center.remove_observer(self, sender=subscription)
                        self._subscription = None
                        if e.data.code == 407:
                            # Authentication failed, so retry the subscription in some time
                            timeout = random.uniform(60, 120)
                            raise SubscriptionError(error='authentication failed', timeout=timeout)
                        elif e.data.code == 423:
                            # Get the value of the Min-Expires header
                            timeout = random.uniform(60, 120)
                            if e.data.min_expires is not None and e.data.min_expires > refresh_interval:
                                raise SubscriptionError(error='Interval too short', timeout=timeout, refresh_interval=e.data.min_expires)
                            else:
                                raise SubscriptionError(error='Interval too short', timeout=timeout)
                        elif e.data.code in (405, 406, 489):
                            timeout = random.uniform(60, 120)
                            raise SubscriptionError(error='Subscription error', timeout=timeout)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        self.subscribed = True
                        command.signal()
                        break
            else:
                # No more routes to try, reschedule the subscription
                timeout = random.uniform(60, 180)
                raise SubscriptionError(error='no more routes to try', timeout=timeout)
            # At this point it is subscribed. Handle notifications and ending/failures.
            notification_center.post_notification('XCAPSubscriptionDidStart', sender=self, data=TimestampedNotificationData())
            try:
                while True:
                    notification = self._data_channel.wait()
                    if notification.sender is not self._subscription:
                        continue
                    if notification.name == 'SIPSubscriptionGotNotify':
                        notification_center.post_notification('XCAPSubscriptionGotNotify', sender=self, data=notification.data)
                    elif notification.name == 'SIPSubscriptionDidEnd':
                        break
            except SIPSubscriptionDidFail:
                notification_center.post_notification('XCAPSubscriptionDidFail', sender=self, data=TimestampedNotificationData())
                self._command_channel.send(Command('subscribe'))
            notification_center.remove_observer(self, sender=self._subscription)
        except InterruptSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                notification_center.remove_observer(self, sender=self._subscription)
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
        except TerminateSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
                else:
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.sender is self._subscription and notification.name == 'SIPSubscriptionDidEnd':
                                break
                    except SIPSubscriptionDidFail:
                        pass
                finally:
                    notification_center.remove_observer(self, sender=self._subscription)
        except SubscriptionError, e:
            from twisted.internet import reactor
            notification_center.post_notification('XCAPSubscriptionDidFail', sender=self, data=TimestampedNotificationData())
            self._subscription_timer = reactor.callLater(e.timeout, self._command_channel.send, Command('subscribe', command.event, refresh_interval=e.refresh_interval))
        finally:
            self.subscribed = False
            self._subscription = None
            self._subscription_proc = None

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPSubscriptionDidStart(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidEnd(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidFail(self, notification):
        self._data_channel.send_exception(SIPSubscriptionDidFail(notification.data))

    def _NH_SIPSubscriptionGotNotify(self, notification):
        self._data_channel.send(notification)

    def _NH_DNSNameserversDidChange(self, notification):
        if self.active:
            self.resubscribe()

    def _NH_SystemIPAddressDidChange(self, notification):
        if self.active:
            self.resubscribe()

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._wakeup_timer is None:
            from twisted.internet import reactor
            def wakeup_action():
                if self.active:
                    self.resubscribe()
                self._wakeup_timer = None
            self._wakeup_timer = reactor.callLater(5, wakeup_action) # wait for system to stabilize


class XCAPManager(object):
    implements(IObserver)

    def __init__(self, account):
        from sipsimple.application import SIPApplication
        if SIPApplication.storage is None:
            raise RuntimeError("SIPApplication.storage must be defined before instantiating XCAPManager")
        self.account = account
        self.storage = None
        self.storage_factory = SIPApplication.storage.xcap_storage_factory
        self.client = None
        self.command_proc = None
        self.command_channel = coros.queue()
        self.journal = []
        self.last_fetch_time = datetime.fromtimestamp(0)
        self.not_executed_fetch = None
        self.oma_compliant = False
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
            notification_center.post_notification('XCAPManagerDidChangeState', sender=self, data=TimestampedNotificationData(prev_state=old_value, state=value))

    state = property(_get_state, _set_state)
    del _get_state, _set_state

    @property
    def cached_documents(self):
        return [document for document in self.dialog_rules, self.pidf_manipulation, self.pres_rules, self.resource_lists, self.rls_services, self.status_icon, self.server_caps if document.cached]

    @property
    def documents(self):
        return [self.dialog_rules, self.pidf_manipulation, self.pres_rules, self.resource_lists, self.rls_services, self.status_icon]

    @property
    def document_names(self):
        return [document.name for document in self.documents]

    @property
    def contactlist_supported(self):
        return self.resource_lists.supported and self.rls_services.supported

    @property
    def presence_policies_supported(self):
        return self.pres_rules.supported

    @property
    def dialoginfo_policies_supported(self):
        return self.dialog_rules.supported

    @property
    def status_icon_supported(self):
        return self.status_icon.supported

    @property
    def offline_status_supported(self):
        return self.pidf_manipulation.supported

    @property
    def namespaces(self):
        return dict((document.application, document.payload_type._xml_namespace) for document in self.documents)

    @property
    def xcap_root(self):
        return self.client.root if self.client else None

    def load(self):
        """
        Initializes the XCAP manager, by loading any saved data from disk. Needs
        to be called before any other method and in a green thread.
        """
        if self.storage is not None:
            raise RuntimeError("XCAPManager cache already loaded")
        storage = self.storage_factory(self.account.id)
        if not IXCAPStorage.providedBy(storage):
            raise TypeError("storage must implement the IXCAPStorage interface")
        self.storage = storage
        for document in self.cached_documents:
            document.load_from_cache()
        try:
            self.journal = cPickle.loads(storage.load('journal'))
        except (XCAPStorageError, cPickle.UnpicklingError):
            self.journal = []
        else:
            for operation in self.journal:
                operation.applied = False
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

    @run_in_twisted_thread
    def add_group(self, group):
        operation = AddGroupOperation(group=group)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def rename_group(self, old_name, new_name):
        operation = RenameGroupOperation(old_name=old_name, new_name=new_name)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def remove_group(self, group):
        operation = RemoveGroupOperation(group=group)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def add_contact(self, contact):
        operation = AddContactOperation(contact=contact)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def update_contact(self, contact, **attributes):
        operation = UpdateContactOperation(contact=contact, attributes=attributes)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def remove_contact(self, contact):
        operation = RemoveContactOperation(contact=contact)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def add_presence_policy(self, policy):
        operation = AddPresencePolicyOperation(policy=policy)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def update_presence_policy(self, policy, **attributes):
        operation = UpdatePresencePolicyOperation(policy=policy, attributes=attributes)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def remove_presence_policy(self, policy):
        operation = RemovePresencePolicyOperation(policy=policy)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def add_dialoginfo_policy(self, policy):
        operation = AddDialoginfoPolicyOperation(policy=policy)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def update_dialoginfo_policy(self, policy, **attributes):
        operation = UpdateDialoginfoPolicyOperation(policy=policy, attributes=attributes)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def remove_dialoginfo_policy(self, policy):
        operation = RemoveDialoginfoPolicyOperation(policy=policy)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def set_status_icon(self, icon):
        operation = SetStatusIconOperation(icon=icon)
        self.journal.append(operation)
        if self.transaction_level == 0:
            self._save_journal()
            self.command_channel.send(Command('update'))

    @run_in_twisted_thread
    def set_offline_status(self, status):
        operation = SetOfflineStatusOperation(status=status)
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

    # command handlers
    #

    def _CH_start(self, command):
        if self.state != 'stopped':
            command.signal()
            return
        self.state = 'initializing'
        self.xcap_subscriber = XCAPSubscriber(self.account, self.documents)
        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerWillStart', sender=self, data=TimestampedNotificationData())
        notification_center.add_observer(self, sender=self.xcap_subscriber)
        notification_center.add_observer(self, sender=SIPSimpleSettings(), name='CFGSettingsObjectDidChange')
        self.xcap_subscriber.start()
        self.command_channel.send(Command('initialize'))
        notification_center.post_notification('XCAPManagerDidStart', sender=self, data=TimestampedNotificationData())
        command.signal()

    def _CH_stop(self, command):
        if self.state in ('stopped', 'terminated'):
            command.signal()
            return
        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerWillEnd', sender=self, data=TimestampedNotificationData())
        notification_center.remove_observer(self, sender=self.xcap_subscriber)
        notification_center.remove_observer(self, sender=SIPSimpleSettings(), name='CFGSettingsObjectDidChange')
        if self.timer is not None and self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.xcap_subscriber.deactivate()
        self.xcap_subscriber.stop()
        self.xcap_subscriber = None
        self.client = None
        self.state = 'stopped'
        self._save_journal()
        notification_center.post_notification('XCAPManagerDidEnd', sender=self, data=TimestampedNotificationData())
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
            self.client = XCAPClient(self.account.xcap.xcap_root, self.account.id, password=self.account.auth.password, auth=None)
        else:
            try:
                lookup = DNSLookup()
                uri = random.choice(lookup.lookup_xcap_server(self.account.uri).wait())
            except DNSLookupError:
                self.timer = self._schedule_command(60,  Command('initialize', command.event))
                return
            else:
                self.client = XCAPClient(uri, self.account.id, password=self.account.auth.password, auth=None)

        self.server_caps.initialize(self.client)
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
            if not set(self.server_caps.content.auids).issuperset(('pres-rules', 'resource-lists', 'rls-services')):
                # Server must support at least pres-rules, resource-lists and rls-services
                self.timer = self._schedule_command(60,  Command('initialize', command.event))
                return
        self.oma_compliant = 'org.openmobilealliance.pres-rules' in self.server_caps.content.auids
        for document in self.documents:
            document.initialize(self.client, self.server_caps.content)

        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerDidDiscoverServerCapabilities', sender=self,
                                              data=TimestampedNotificationData(contactlist_supported         = self.contactlist_supported,
                                                                               presence_policies_supported   = self.presence_policies_supported,
                                                                               dialoginfo_policies_supported = self.dialoginfo_policies_supported,
                                                                               status_icon_supported         = self.status_icon_supported,
                                                                               offline_status_supported      = self.offline_status_supported))

        self.state = 'fetching'
        self.command_channel.send(Command('fetch', documents=self.document_names))
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
        elif self.xcap_subscriber.active:
            self.xcap_subscriber.resubscribe()
        command.signal()

    def _CH_fetch(self, command):
        if self.state not in ('insync', 'fetching'):
            self.not_executed_fetch = command
            return
        if self.not_executed_fetch is not None:
            self.not_executed_fetch = None
        if self.last_fetch_time > command.timestamp:
            self.state = 'insync'
            return
        self.state = 'fetching'
        if self.timer is not None and self.timer.active():
            command.documents = list(set(command.documents) | set(self.timer.command.documents))
            self.timer.cancel()
        self.timer = None

        try:
            for document in (doc for doc in self.documents if doc.name in command.documents and doc.supported):
                document.fetch()
        except XCAPError:
            self.timer = self._schedule_command(60, Command('fetch', command.event, documents=command.documents))
            return
        if self.last_fetch_time > datetime.fromtimestamp(0) and all(doc.fetch_time < command.timestamp for doc in self.documents):
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
            handler = getattr(self, '_OH_%s' % operation.name)
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
            self.command_channel.send(Command('fetch', documents=self.document_names)) # Try to fetch them all just in case
        except XCAPError:
            self.timer = self._schedule_command(60, Command('update'))
        else:
            del self.journal[:len(journal)]
            if not self.journal:
                self.state = 'insync'
                self._load_data()
            command.signal()
            if self.not_executed_fetch is not None:
                self.command_channel.send(self.not_executed_fetch)
                self.not_executed_fetch = None
            self._save_journal()

    # operation handlers
    #

    def _OH_normalize(self, operation):
        # Normalize resource-lists document :
        #  * create one if it doesn't exist
        #  * use OMA suggested names for lists (create them if inexistent)
        #  * if no OMA suggested lists existed, then assume all lists contain buddies and add them to the oma_buddylist
        if self.resource_lists.supported:
            if self.resource_lists.content is None:
                self.resource_lists.content = resourcelists.ResourceLists()
                self.resource_lists.dirty = True
            resource_lists = self.resource_lists.content
            try:
                oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
            except StopIteration:
                oma_buddylist = None
            try:
                oma_grantedcontacts = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_grantedcontacts').next()
            except StopIteration:
                oma_grantedcontacts = None
            try:
                oma_blockedcontacts = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_blockedcontacts').next()
            except StopIteration:
                oma_blockedcontacts = None
            try:
                oma_allcontacts = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_allcontacts').next()
            except StopIteration:
                oma_allcontacts = None
            buddy_lists = []
            if oma_buddylist is None:
                oma_buddylist = resourcelists.List(name='oma_buddylist')
                # If no other oma defined list exists, assume all the current lists in the resource list document contain buddies
                if (oma_grantedcontacts, oma_blockedcontacts, oma_allcontacts) == (None, None, None):
                    for rlist in (child for child in resource_lists if isinstance(child, resourcelists.List)):
                        path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                        oma_buddylist.append(resourcelists.External(path))
                resource_lists.append(oma_buddylist)
                self.resource_lists.dirty = True
            else:
                for child in oma_buddylist:
                    if isinstance(child, resourcelists.List):
                        buddy_lists.append(child)
                    elif isinstance(child, resourcelists.External):
                        try:
                            buddy_lists.extend(self._follow_rl_external(resource_lists, child))
                        except ValueError:
                            continue
            if oma_grantedcontacts is None:
                oma_grantedcontacts = resourcelists.List(name='oma_grantedcontacts')
                resource_lists.append(oma_grantedcontacts)
                self.resource_lists.dirty = True
            else:
                # Make sure there are no references to oma_buddylist (like OMA suggests)
                for child in oma_grantedcontacts:
                    if isinstance(child, resourcelists.External):
                        try:
                            if oma_buddylist in self._follow_rl_external(resource_lists, child):
                                oma_grantedcontacts.remove(child)
                                oma_grantedcontacts.extend(resourcelists.External(self.resource_lists.uri+'/~~'+resource_lists.get_xpath(blist)) for blist in buddy_lists)
                                self.resource_lists.dirty = True
                                break
                        except ValueError:
                            continue
            if oma_blockedcontacts is None:
                oma_blockedcontacts = resourcelists.List(name='oma_blockedcontacts')
                resource_lists.append(oma_blockedcontacts)
                self.resource_lists.dirty = True
            if oma_allcontacts is None:
                oma_allcontacts = resourcelists.List(name='oma_allcontacts')
                for rlist in (oma_buddylist, oma_grantedcontacts, oma_blockedcontacts):
                    path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                    oma_allcontacts.append(resourcelists.External(path))
                resource_lists.append(oma_allcontacts)
                self.resource_lists.dirty = True
            # Remove any external references which don't point to anything
            notexpanded = deque([resource_lists])
            visited = set(notexpanded)
            remove_elements = []
            while notexpanded:
                rlist = notexpanded.popleft()
                for child in rlist:
                    if isinstance(child, resourcelists.List) and child not in visited:
                        visited.add(child)
                        notexpanded.append(child)
                    elif isinstance(child, resourcelists.External):
                        try:
                            ref_lists = self._follow_rl_external(resource_lists, child)
                        except ValueError:
                            continue
                        if not ref_lists:
                            remove_elements.append((child, rlist))
            for element, parent in remove_elements:
                parent.remove(element)

        # Normalize rls-services document:
        #  * create one if it doesn't exist
        #  * if it is empty, start by assuming we want to subscribe to all the buddies
        if self.rls_services.supported:
            if self.rls_services.content is None:
                self.rls_services.content = rlsservices.RLSServices()
                self.rls_services.dirty = True
            rls_services = self.rls_services.content
            if len(rls_services) == 0 and self.resource_lists.supported and buddy_lists:
                rlist = resourcelists.List()
                service = rlsservices.Service('sip:buddies@%s' % self.account.id.domain, list=rlist, packages=rlsservices.Packages(['presence', 'dialog']))
                for blist in buddy_lists:
                    path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(blist)
                    rlist.append(resourcelists.External(path))
                rls_services.append(service)
                self.rls_services.dirty = True

        # Normalize pres-rules document:
        #  * create one if it doesn't exist
        #  * if OMA support is enabled on the presence server, create some OMA suggested rules
        #  * also normalize the document so that it is OMA compliant
        #  * get rid of any wp_prs_(allow_)one_* rules because they can't be supported
        if self.pres_rules.supported:
            if self.pres_rules.content is None:
                self.pres_rules.content = presrules.PresRules()
                self.pres_rules.dirty = True
            if self.oma_compliant and self.resource_lists.supported:
                pres_rules = self.pres_rules.content
                resource_lists = self.resource_lists.content
                try:
                    path = self.resource_lists.uri + '/~~/resource-lists/list[@name="oma_grantedcontacts"]'
                    wp_prs_grantedcontacts = (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id=='wp_prs_grantedcontacts').next()
                except StopIteration:
                    wp_prs_grantedcontacts = common_policy.Rule('wp_prs_grantedcontacts', conditions=[omapolicy.ExternalList([path])], actions=[presrules.SubHandling('allow')])
                    #wp_prs_grantedcontacts.display_name = 'Allow' # Rule display-name extension
                    pres_rules.append(wp_prs_grantedcontacts)
                    self.pres_rules.dirty = True
                else:
                    if wp_prs_grantedcontacts.conditions != common_policy.Conditions([omapolicy.ExternalList([path])]):
                        wp_prs_grantedcontacts.conditions = [omapolicy.ExternalList([path])]
                        self.pres_rules.dirty = True
                    if wp_prs_grantedcontacts.actions != common_policy.Actions([presrules.SubHandling('allow')]):
                        wp_prs_grantedcontacts.actions = [presrules.SubHandling('allow')]
                        self.pres_rules.dirty = True
                try:
                    path = self.resource_lists.uri + '/~~/resource-lists/list[@name="oma_blockedcontacts"]'
                    wp_prs_blockedcontacts = (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id=='wp_prs_blockedcontacts').next()
                except StopIteration:
                    wp_prs_blockedcontacts = common_policy.Rule('wp_prs_blockedcontacts', conditions=[omapolicy.ExternalList([path])], actions=[presrules.SubHandling('polite-block')])
                    #wp_prs_blockedcontacts.display_name = 'Block' # Rule display-name extension
                    pres_rules.append(wp_prs_blockedcontacts)
                    self.pres_rules.dirty = True
                else:
                    if wp_prs_blockedcontacts.conditions != common_policy.Conditions([omapolicy.ExternalList([path])]):
                        wp_prs_blockedcontacts.conditions = [omapolicy.ExternalList([path])]
                        self.pres_rules.dirty = True
                    if wp_prs_blockedcontacts.actions not in [common_policy.Actions([presrules.SubHandling('block')]), common_policy.Actions([presrules.SubHandling('polite-block')])]:
                        wp_prs_blockedcontacts.actions = [presrules.SubHandling('polite-block')]
                        self.pres_rules.dirty = True
                    if wp_prs_blockedcontacts.transformations:
                        wp_prs_blockedcontacts.transformations = None
                        self.pres_rules.dirty = True
                wp_prs_unlisted = [child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id in ('wp_prs_unlisted', 'wp_prs_allow_unlisted')]
                if len(wp_prs_unlisted) == 0:
                    wp_prs_unlisted = common_policy.Rule('wp_prs_unlisted', conditions=[omapolicy.OtherIdentity()], actions=[presrules.SubHandling('confirm')])
                    pres_rules.append(wp_prs_unlisted)
                    self.pres_rules.dirty = True
                else:
                    for rule in wp_prs_unlisted[1:]:
                        pres_rules.remove(rule)
                    wp_prs_unlisted = wp_prs_unlisted[0]
                    if wp_prs_unlisted.conditions != common_policy.Conditions([omapolicy.OtherIdentity()]):
                        wp_prs_unlisted.conditions = [omapolicy.OtherIdentity()]
                        self.pres_rules.dirty = True
                    if wp_prs_unlisted.id == 'wp_prs_unlisted' and wp_prs_unlisted.actions not in [common_policy.Actions([presrules.SubHandling('confirm')]), common_policy.Actions([presrules.SubHandling('block')]), common_policy.Actions([presrules.SubHandling('polite-block')])]:
                        wp_prs_unlisted.actions = [presrules.SubHandling('confirm')]
                        self.pres_rules.dirty = True
                    elif wp_prs_unlisted.id == 'wp_prs_allow_unlisted' and wp_prs_unlisted.actions != common_policy.Actions([presrules.SubHandling('allow')]):
                        wp_prs_unlisted.actions = [presrules.SubHandling('allow')]
                        self.pres_rules.dirty = True
                    if wp_prs_unlisted.id == 'wp_prs_unlisted' and wp_prs_unlisted.transformations:
                        wp_prs_unlisted.transformations = None
                        self.pres_rules.dirty = True
                try:
                    wp_prs_block_anonymous = (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id=='wp_prs_block_anonymous').next()
                except StopIteration:
                    wp_prs_block_anonymous = common_policy.Rule('wp_prs_block_anonymous', conditions=[omapolicy.AnonymousRequest()], actions=[presrules.SubHandling('block')])
                    pres_rules.append(wp_prs_block_anonymous)
                    self.pres_rules.dirty = True
                else:
                    if wp_prs_block_anonymous.conditions != common_policy.Conditions([omapolicy.AnonymousRequest()]):
                        wp_prs_block_anonymous.conditions = [omapolicy.AnonymousRequest()]
                        self.pres_rules.dirty = True
                    if wp_prs_block_anonymous.actions not in [common_policy.Actions([presrules.SubHandling('block')]), common_policy.Actions([presrules.SubHandling('polite-block')])]:
                        wp_prs_block_anonymous.actions = [presrules.SubHandling('block')]
                        self.pres_rules.dirty = True
                    if wp_prs_block_anonymous.transformations:
                        wp_prs_block_anonymous.transformations = None
                        self.pres_rules.dirty = True
                try:
                    identity = 'sip:'+self.account.id
                    wp_prs_allow_own = (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id=='wp_prs_allow_own').next()
                except StopIteration:
                    wp_prs_allow_own = common_policy.Rule('wp_prs_allow_own', conditions=[common_policy.Identity([common_policy.IdentityOne(identity)])], actions=[presrules.SubHandling('allow')])
                    pres_rules.append(wp_prs_allow_own)
                    self.pres_rules.dirty = True
                else:
                    if wp_prs_allow_own.conditions != common_policy.Conditions([common_policy.Identity([common_policy.IdentityOne(identity)])]):
                        wp_prs_allow_own.conditions = [common_policy.Identity([common_policy.IdentityOne(identity)])]
                        self.pres_rules.dirty = True
                    if wp_prs_allow_own.actions != common_policy.Actions([presrules.SubHandling('allow')]):
                        wp_prs_allow_own.actions = [presrules.SubHandling('allow')]
                        self.pres_rules.dirty = True
                # We cannot work with wp_prs_allow_one_* rules because they don't allow adding new identities to the rule
                for rule in (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id.startswith('wp_prs_allow_one_')):
                    # Create a new list just for this identity
                    rlist = resourcelists.List(name=self.unique_name('presrules_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                    resource_lists.append(rlist)
                    # Change the name to wp_prs_allow_onelist_<group name>
                    rule.id = self.unique_name('wp_prs_allow_onelist_'+rlist.name, (rule.id for rule in pres_rules)).next()
                    # Change the condition
                    for condition in (rule.conditions or []):
                        if isinstance(condition, common_policy.Identity):
                            for identity in (identity_condition for identity_condition in condition if isinstance(identity_condition, common_policy.IdentityOne)):
                                rlist.append(resourcelists.Entry(uri=identity.id))
                        elif isinstance(condition, omapolicy.ExternalList):
                            # This shouldn't happen but accept it anyway
                            for uri in condition:
                                rlist.append(resourcelists.External(uri))
                    path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                    rule.conditions = [omapolicy.ExternalList([path])]
                    # Make sure the action is allow
                    if rule.actions != common_policy.Actions([presrules.SubHandling('allow')]):
                        rule.actions = [presrules.SubHandling('allow')]
                    self.resource_lists.dirty = True
                    self.pres_rules.dirty = True
                for rule in (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id.startswith('wp_prs_allow_onelist_')):
                    if rule.actions != common_policy.Actions([presrules.SubHandling('allow')]):
                        rule.actions = [presrules.SubHandling('allow')]
                        self.pres_rules.dirty = True
                # We cannot work with wp_prs_one_* rules because they don't allow adding new identities to the rule
                for rule in (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id.startswith('wp_prs_one_')):
                    # Create a new list just for this identity
                    rlist = resourcelists.List(name=self.unique_name('presrules_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                    resource_lists.append(rlist)
                    # Change the name to wp_prs_onelist_<group name>
                    rule.id = self.unique_name('wp_prs_onelist_'+rlist.name, (rule.id for rule in pres_rules)).next()
                    # Change the condition
                    for condition in (rule.conditions or []):
                        if isinstance(condition, common_policy.Identity):
                            for identity in (identity_condition for identity_condition in condition if isinstance(identity_condition, common_policy.IdentityOne)):
                                rlist.append(resourcelists.Entry(uri=identity.id))
                        elif isinstance(condition, omapolicy.ExternalList):
                            # This shouldn't happen but accept it anyway
                            for uri in condition:
                                rlist.append(resourcelists.External(uri))
                    path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                    rule.conditions = [omapolicy.ExternalList([path])]
                    # Make sure the action is one of confirm, block or polite-block
                    if rule.actions not in [common_policy.Actions([presrules.SubHandling('confirm')]), common_policy.Actions([presrules.SubHandling('block')]), common_policy.Actions([presrules.SubHandling('polite-block')])]:
                        rule.actions = [presrules.SubHandling('confirm')]
                    # Make sure there are no transformations
                    if rule.transformations:
                        rule.transformations = None
                    self.resource_lists.dirty = True
                    self.pres_rules.dirty = True
                for rule in (child for child in pres_rules if isinstance(child, common_policy.Rule) and child.id.startswith('wp_prs_onelist_')):
                    if rule.actions not in [common_policy.Actions([presrules.SubHandling('confirm')]), common_policy.Actions([presrules.SubHandling('block')]), common_policy.Actions([presrules.SubHandling('polite-block')])]:
                        rule.actions = [presrules.SubHandling('confirm')]
                        self.pres_rules.dirty = True
                    if rule.transformations:
                        rule.transformations = None
                        self.pres_rules.dirty = True

        # Normalize dialog-rules document:
        #  * create one if it doesn't exist
        #  * create a rule of each of the four possible actions except 'confirm'
        if self.dialog_rules.supported:
            if self.dialog_rules.content is None:
                self.dialog_rules.content = dialogrules.DialogRules()
                self.dialog_rules.dirty = True
            dialog_rules = self.dialog_rules.content
            for action in ('allow', 'block', 'polite-block'):
                try:
                    (child for child in dialog_rules if isinstance(child, common_policy.Rule) and any(isinstance(a, dialogrules.SubHandling) and a.value==action for a in (child.actions or []))).next()
                except StopIteration:
                    name = self.unique_name('dialog_%s' % action, (rule.id for rule in dialog_rules)).next()
                    rule = common_policy.Rule(name, conditions=[], actions=[dialogrules.SubHandling(action)])
                    dialog_rules.append(rule)
                    self.dialog_rules.dirty = True

    def _OH_add_group(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        # See if there already is a group with the specified name: a group reachable from within oma_buddylist
        notexpanded = deque([oma_buddylist])
        visited = set(notexpanded)
        while notexpanded:
            rlist = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    if child.display_name is not None and child.display_name.value == operation.group:
                        return
                    visited.add(child)
                    notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = set(l for l in self._follow_rl_external(resource_lists, child) if l not in visited)
                    except ValueError:
                        ref_lists = set()
                    if child.display_name is not None and child.display_name.value == operation.group and ref_lists:
                        # Only assume the group exists if there is at least one list obtained by dereferencing this external element
                        return
                    if child.display_name is None and any(l.display_name is not None and l.display_name.value == operation.group for l in ref_lists):
                        # The lists obtained by dereferencing this external element inherit its display name if it exists, otherwise they use their own display name
                        return
                    visited.update(ref_lists)
                    notexpanded.extend(ref_lists)
        # A list with the specified name was not found, create it
        name = self.unique_name('group', (list.name for list in resource_lists), skip_preferred_name=True).next()
        rlist = resourcelists.List(name=name, display_name=operation.group)
        resource_lists.append(rlist)
        path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
        oma_buddylist.append(resourcelists.External(path))
        self.resource_lists.dirty = True

    def _OH_rename_group(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        notexpanded = deque([oma_buddylist])
        visited = set(notexpanded)
        while notexpanded:
            rlist = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    if child.display_name is not None and child.display_name.value == operation.old_name:
                        child.display_name = operation.new_name
                        self.resource_lists.dirty = True
                    visited.add(child)
                    notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = self._follow_rl_external(resource_lists, child)
                    except ValueError:
                        ref_lists = []
                    if child.display_name is not None and child.display_name.value == operation.old_name and ref_lists:
                        child.display_name = operation.new_name
                    ref_lists = set(l for l in ref_lists if l not in visited)
                    if child.display_name is None:
                        for ref_list in ref_lists:
                            if ref_list.display_name is not None and ref_list.display_name.value == operation.old_name:
                                ref_list.display_name = operation.new_name
                                self.resource_lists.dirty = True
                    visited.update(ref_lists)
                    notexpanded.extend(ref_lists)

    def _OH_remove_group(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        remove_elements = [] # (element, parent)
        move_elements = [] # (element, new_parent)
        notexpanded = deque([(oma_buddylist, False, None)])
        visited = set([oma_buddylist])
        while notexpanded:
            rlist, list_removed, new_parent = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    if child.display_name is not None and child.display_name.value == operation.group:
                        # Needs to be removed
                        if not list_removed:
                            # Only remove the child if the parent (rlist) will not be removed
                            remove_elements.append((child, rlist))
                        notexpanded.append((child, True, new_parent if list_removed else rlist))
                    else:
                        if list_removed and child.display_name is not None:
                            # If the parent is removed, the child needs to be moved
                            move_elements.append((child, new_parent))
                        # Will not be removed
                        notexpanded.append((child, list_removed and child.display_name is None, new_parent))
                    visited.add(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        all_references = self._follow_rl_external(resource_lists, child)
                    except ValueError:
                        all_references = []
                    ref_lists = set(l for l in all_references if l not in visited)
                    if child.display_name is not None and child.display_name.value == operation.group and all_references:
                        # The whole reference needs to be removed
                        if not list_removed:
                            # Only remove the child if the parent (rlist) will not be removed
                            remove_elements.append((child, rlist))
                        # The referenced lists may also need to be removed from their parents as they can also have a display name
                        for l in ref_lists:
                            if l.display_name is not None and l.display_name.value == operation.group:
                                parent = resource_lists.find_parent(l)
                                if parent is not None:
                                    remove_elements.append((l, parent))
                                    notexpanded.append((l, True, parent))
                                else:
                                    notexpanded.append((l, False, None))
                            else:
                                notexpanded.append((l, False, None))
                        visited.update(ref_lists)
                    elif child.display_name is None and all_references:
                        # If the display name is None, the list's display name applies
                        for l in ref_lists:
                            if l.display_name is not None and l.display_name.value == operation.group:
                                # Also remove from all_references so that we can check whether to remove the external reference or not
                                all_references.remove(l)
                                parent = resource_lists.find_parent(l)
                                if parent is not None:
                                    remove_elements.append((l, parent))
                                    notexpanded.append((l, True, parent))
                                else:
                                    notexpanded.append((l, False, None))
                            else:
                                notexpanded.append((l, False, None))
                        if not all_references and not list_removed:
                            # If the external reference would not point to any other *thing*, remove it
                            remove_elements.append((child, rlist))
                        elif list_removed and isinstance(new_parent, resourcelists.List):
                            # If the parent is removed, the child needs to be moved
                            move_elements.append((child, new_parent))
                        visited.update(ref_lists)
                    else:
                        if list_removed and all_references and isinstance(new_parent, resourcelists.List):
                            # If the parent is removed, the child needs to be moved
                            move_elements.append((child, new_parent))
                        notexpanded.extend((l, False, None) for l in ref_lists)
                        # Do not update visited with ref_lists since these lists might also have a display name and be referenced some other way
        for element, parent in move_elements:
            parent.append(element)
        for element, parent in remove_elements:
            parent.remove(element)
        if move_elements or remove_elements:
            self.resource_lists.dirty = True
        # Remove any external references which no longer point to anything
        notexpanded = deque([resource_lists])
        visited = set(notexpanded)
        del remove_elements[:]
        while notexpanded:
            rlist = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    visited.add(child)
                    notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = self._follow_rl_external(resource_lists, child)
                    except ValueError:
                        continue
                    if not ref_lists:
                        remove_elements.append((child, rlist))
        for element, parent in remove_elements:
            parent.remove(element)

    def _OH_add_contact(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        if operation.contact.presence_policies is None:
            operation.contact.presence_policies = []
        elif self.oma_compliant:
            # Filter out policies we mustn't add contacts to
            operation.contact.presence_policies = [policy for policy in operation.contact.presence_policies if policy.id not in ('wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_block_anonymous', 'wp_prs_allow_own')]
        if operation.contact.dialoginfo_policies is None:
            operation.contact.dialoginfo_policies = []
        # First see if this contact (uniquely identified by uri) is already a buddy; if it is, don't do anything
        notexpanded = deque([oma_buddylist])
        visited = set(notexpanded)
        while notexpanded:
            rlist = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    visited.add(child)
                    notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = set(l for l in self._follow_rl_external(resource_lists, child) if l not in visited)
                    except ValueError:
                        ref_lists = set()
                    visited.update(ref_lists)
                    notexpanded.extend(ref_lists)
                elif isinstance(child, resourcelists.EntryRef):
                    try:
                        entries = self._follow_rl_entry_ref(resource_lists, child)
                    except ValueError:
                        continue
                    if any(entry.uri == operation.contact.uri for entry in entries):
                        return
                elif isinstance(child, resourcelists.Entry):
                    if child.uri == operation.contact.uri:
                        return
        # Then find all the lists where we can add this new contact
        if operation.contact.group is not None:
            # Only add contacts to lists directly referenced from oma_buddylist by an external element.
            candidate_lists = []
            for child in oma_buddylist:
                if isinstance(child, resourcelists.External):
                    try:
                        ref_lists = set(l for l in self._follow_rl_external(resource_lists, child))
                    except ValueError:
                        ref_lists = set()
                    if child.display_name is not None:
                        if child.display_name.value == operation.contact.group:
                            candidate_lists.extend(ref_lists)
                        else:
                            continue
                    else:
                        candidate_lists.extend(l for l in ref_lists if l.display_name is not None and l.display_name.value == operation.contact.group)
        else:
            # Add contacts which are not buddies to top-level lists which are not referenced by oma_buddylist
            candidate_lists = [l for l in resource_lists if l not in visited]
        # Add a fallback candidate which should never, ever be referenced from anywhere
        fallback_candidate = resourcelists.List(name=self.unique_name('group', (l.name for l in resource_lists), skip_preferred_name=True).next(), display_name=operation.contact.group)
        candidate_lists.append(fallback_candidate)
        # We may need the XPath to this list
        resource_lists.append(fallback_candidate)
        presence_lists = set() # Lists to which, if added, the rls services document need not be modified for presence subscription
        dialoginfo_lists = set() # Lists to which, if added, the rls services document need not be modified for dialoginfo subscription
        presrules_lists = set() # Lists to which, if added, the presrules document need not be modified
        not_wanted_lists = set() # Lists we don't want to add the contact to because they are referenced from other places
        remove_from_lists = set() # Lists we need to remove the contact from
        to_remove = [] # (child, parent)
        # Filter candidates based on subscribe_to_* flags
        if self.rls_services.supported:
            # While filtering candidates, also remove any reference to the uri from unwanted services
            rls_services = self.rls_services.content
            for service in rls_services:
                packages = set(package.value for package in (service.packages or []))
                if isinstance(service.list, rlsservices.RLSList):
                    expanded_list = [service.list]
                elif isinstance(service.list, rlsservices.ResourceList):
                    try:
                        expanded_list = self._follow_rls_resource_list(resource_lists, service.list)
                    except ValueError:
                        expanded_list = []
                else:
                    expanded_list = []
                if any(package not in ('presence', 'dialog') for package in packages):
                    # We do not want lists referenced by this service because we do not know what we'd add the contact to.
                    # However, if the contact is already in this list, allow it to stay here
                    not_wanted_lists.update(expanded_list)
                if not operation.contact.subscribe_to_presence and 'presence' in packages:
                    not_wanted_lists.update(expanded_list)
                    remove_from_lists.update(expanded_list)
                elif not operation.contact.subscribe_to_dialoginfo and 'dialog' in packages:
                    not_wanted_lists.update(expanded_list)
                    remove_from_lists.update(expanded_list)
                elif set(['presence', 'dialog']).issuperset(packages):
                    if 'presence' in packages:
                        presence_lists.update(expanded_list)
                    if 'dialog' in packages:
                        dialoginfo_lists.update(expanded_list)
        else:
            # Any list will do
            presence_lists.update(l for l in candidate_lists if l is not fallback_candidate)
            dialoginfo_lists.update(l for l in candidate_lists if l is not fallback_candidate)
        # Filter out condidates based on presence policy
        if self.pres_rules.supported:
            pres_rules = self.pres_rules.content
            # While filtering candidates based on presence policy also remove any reference to the uri
            remaining_policies = [policy.id for policy in operation.contact.presence_policies]
            policy_lists = {}
            for rule in pres_rules:
                # Action is used to ignore rules whose actions we don't understand
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                except StopIteration:
                    action = None
                if not operation.contact.presence_policies or rule.id not in (policy.id for policy in operation.contact.presence_policies) or action is None:
                    # We do not want to add the contact to lists referenced by this rule (we also want to remove the contact from them if we understand the rule)
                    for condition in (rule.conditions or []):
                        if isinstance(condition, omapolicy.ExternalList):
                            try:
                                ref_lists = self._follow_policy_external_list(resource_lists, condition)
                                not_wanted_lists.update(ref_lists)
                                if action is not None:
                                    remove_from_lists.update(ref_lists)
                            except ValueError:
                                continue
                        elif isinstance(condition, common_policy.Identity) and action is not None and operation.contact.presence_policies is not FallbackPolicies:
                            for identity in condition:
                                if isinstance(identity, common_policy.IdentityOne) and identity.id == operation.contact.uri:
                                    to_remove.append((identity, condition))
                                    self.pres_rules.dirty = True
                                elif isinstance(identity, common_policy.IdentityMany) and identity.matches(operation.contact.uri):
                                    identity.append(common_policy.IdentityExcept(operation.contact.uri))
                                    self.pres_rules.dirty = True
                elif operation.contact.presence_policies and action is not None:
                    # This is one of the rules we want to add the contact to
                    remaining_policies.remove(rule.id)
                    policy_lists[rule.id] = set()
                    for condition in (rule.conditions or []):
                        if isinstance(condition, omapolicy.ExternalList):
                            try:
                                ref_lists = self._follow_policy_external_list(resource_lists, condition)
                                policy_lists[rule.id].update(ref_lists)
                            except ValueError:
                                continue
                        elif isinstance(condition, common_policy.Identity):
                            if condition.matches(operation.contact.uri):
                                policy_lists[rule.id].update(l for l in candidate_lists if l is not fallback_candidate) # Any list will do
            if remaining_policies:
                # Some policies do not exist, they need to be added; therefore, no list will do
                pass
            elif operation.contact.presence_policies:
                lists = policy_lists.popitem()[1]
                while policy_lists:
                    lists = lists.intersection(policy_lists.popitem()[1])
                presrules_lists.update(lists)
            else:
                presrules_lists.update(l for l in candidate_lists if l is not fallback_candidate) # Any list will do
        else:
            presrules_lists.update(l for l in candidate_lists if l is not fallback_candidate) # Any list will do
        notexpanded = deque(presence_lists|dialoginfo_lists|presrules_lists|not_wanted_lists|remove_from_lists)
        visited = set(notexpanded)
        add_to_presence_list = operation.contact.subscribe_to_presence
        add_to_dialoginfo_list = operation.contact.subscribe_to_dialoginfo
        while notexpanded:
            rlist = notexpanded.popleft()
            if rlist in not_wanted_lists and rlist in candidate_lists:
                candidate_lists.remove(rlist)
            # Some children will need to be revisited so that their descendents are added to appropriate sets
            for child in rlist:
                if isinstance(child, resourcelists.List):
                    revisit = False
                    if rlist in presence_lists:
                        revisit = (child not in presence_lists) or revisit
                        presence_lists.add(child)
                    if rlist in dialoginfo_lists:
                        revisit = (child not in dialoginfo_lists) or revisit
                        dialoginfo_lists.add(child)
                    if rlist in presrules_lists:
                        revisit = (child not in presrules_lists) or revisit
                        presrules_lists.add(child)
                    if rlist in not_wanted_lists:
                        revisit = (child not in not_wanted_lists) or revisit
                        not_wanted_lists.add(child)
                    if rlist in remove_from_lists:
                        revisit = (child not in remove_from_lists) or revisit
                        remove_from_lists.add(child)
                    if child not in visited or revisit:
                        visited.add(child)
                        notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = self._follow_rl_external(resource_lists, child)
                    except ValueError:
                        ref_lists = []
                    revisit = set()
                    if rlist in presence_lists:
                        revisit.update(l for l in ref_lists if l not in presence_lists)
                        presence_lists.update(ref_lists)
                    if rlist in dialoginfo_lists:
                        revisit.update(l for l in ref_lists if l not in dialoginfo_lists)
                        dialoginfo_lists.update(ref_lists)
                    if rlist in presrules_lists:
                        revisit.update(l for l in ref_lists if l not in presrules_lists)
                        presrules_lists.update(ref_lists)
                    if rlist in not_wanted_lists:
                        revisit.update(l for l in ref_lists if l not in not_wanted_lists)
                        not_wanted_lists.update(ref_lists)
                    if rlist in remove_from_lists:
                        revisit.update(l for l in ref_lists if l not in remove_from_lists)
                        remove_from_lists.update(ref_lists)
                    visited.update(l for l in ref_lists if l not in visited)
                    notexpanded.extend(l for l in ref_lists if l not in visited or l in revisit)
                elif isinstance(child, resourcelists.EntryRef):
                    try:
                        entries = self._follow_rl_entry_ref(resource_lists, child)
                    except ValueError:
                        continue
                    if any(entry.uri == operation.contact.uri for entry in entries):
                        if rlist in remove_from_lists:
                            to_remove.append((child, rlist))
                            self.resource_lists.dirty = True
                            self.rls_services.dirty = True
                        if operation.contact.subscribe_to_presence and rlist in presence_lists:
                            add_to_presence_list = False
                        if operation.contact.subscribe_to_dialoginfo and rlist in dialoginfo_lists:
                            add_to_dialoginfo_list = False
                elif isinstance(child, resourcelists.Entry):
                    if child.uri == operation.contact.uri:
                        if rlist in remove_from_lists:
                            to_remove.append((child, rlist))
                            self.resource_lists.dirty = True
                            self.rls_services.dirty = True
                        if operation.contact.subscribe_to_presence and rlist in presence_lists:
                            add_to_presence_list = False
                        if operation.contact.subscribe_to_dialoginfo and rlist in dialoginfo_lists:
                            add_to_dialoginfo_list = False
        # Update the dialoginfo rules
        if self.dialog_rules.supported and operation.contact.dialoginfo_policies is not FallbackPolicies:
            dialog_rules = self.dialog_rules.content
            # Create any non-existing rules
            if operation.contact.dialoginfo_policies:
                for policy in (p for p in operation.contact.dialoginfo_policies if p.id not in dialog_rules):
                    op = AddDialoginfoPolicyOperation(policy=policy)
                    handler = getattr(self, '_OH_%s' % op.name)
                    handler(op)
            # Remove any reference to the uri and add it to the correct rule
            for rule in dialog_rules:
                if not operation.contact.dialoginfo_policies or rule.id not in (policy.id for policy in operation.contact.dialoginfo_policies):
                    for condition in (rule.conditions or []):
                        if isinstance(condition, common_policy.Identity):
                            for identity in condition:
                                if isinstance(identity, common_policy.IdentityOne) and identity.id == operation.contact.uri:
                                    to_remove.append((identity, condition))
                                    self.dialog_rules.dirty = True
                                elif isinstance(identity, common_policy.IdentityMany) and identity.matches(operation.contact.uri):
                                    identity.append(common_policy.IdentityExcept(operation.contact.uri))
                                    self.dialog_rules.dirty = True
                elif operation.contact.dialoginfo_policies:
                    # This is one of the rules we want to add the contact to
                    if rule.conditions is None:
                        rule.conditions = common_policy.Conditions()
                    for condition in rule.conditions:
                        if isinstance(condition, common_policy.Identity):
                            if not condition.matches(operation.contact.uri):
                                # First see if there is an exception added for this uri
                                for identity_condition in condition:
                                    if isinstance(identity_condition, common_policy.IdentityMany):
                                        try:
                                            except_condition = (child for child in identity_condition if isinstance(child, common_policy.IdentityExcept) and child.id==operation.contact.uri).next()
                                        except StopIteration:
                                            continue
                                        else:
                                            identity_condition.remove(except_condition)
                                            self.dialog_rules.dirty = True
                                            break
                                else:
                                    # Otherwise just add a identity one
                                    condition.append(common_policy.IdentityOne(operation.contact.uri))
                                    self.dialog_rules.dirty = True
                            break
                    else:
                        # No identity condition found, add it
                        rule.conditions.append(common_policy.Identity([common_policy.IdentityOne(operation.contact.uri)]))
                        self.dialog_rules.dirty = True
        # Remove the elements we wanted to remove
        for child, parent in to_remove:
            parent.remove(child)
        # Identity elements can't be empty
        if self.pres_rules.supported:
            pres_rules = self.pres_rules.content
            for rule in pres_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (condition for condition in (rule.conditions[:] or []) if isinstance(condition, common_policy.Identity)):
                    if len(condition) == 0:
                        rule.conditions.remove(condition)
                        rule.conditions.append(common_policy.FalseCondition())
        if self.dialog_rules.supported:
            dialog_rules = self.dialog_rules.content
            for rule in dialog_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, dialogrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (condition for condition in (rule.conditions[:] or []) if isinstance(condition, common_policy.Identity)):
                    if len(condition) == 0:
                        rule.conditions.remove(condition)
                        rule.conditions.append(common_policy.FalseCondition())
        # Preferred candidates are candidates where if added, the pres-rules and rls-services document need not be modified.
        preferred_candidate_lists = presrules_lists.intersection(candidate_lists)
        if operation.contact.subscribe_to_presence:
            preferred_candidate_lists.intersection_update(presence_lists)
        if operation.contact.subscribe_to_dialoginfo:
            preferred_candidate_lists.intersection_update(dialoginfo_lists)
        if preferred_candidate_lists:
            rlist = preferred_candidate_lists.pop()
        else:
            rlist = candidate_lists[0]
            if self.pres_rules.supported and operation.contact.presence_policies and rlist not in presrules_lists:
                pres_rules = self.pres_rules.content
                for policy in operation.contact.presence_policies:
                    try:
                        rule = pres_rules[policy.id]
                    except KeyError:
                        op = AddPresencePolicyOperation(policy=policy)
                        handler = getattr(self, '_OH_%s' % op.name)
                        handler(op)
                        if policy.id not in pres_rules:
                            continue
                        rule = pres_rules[policy.id]
                    if rule.conditions is None:
                        rule.conditions = []
                    else:
                        try:
                            action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                        except StopIteration:
                            continue # We don't understand this rule, ignore the request to add to this policy
                    # If we have an identity condition, use that one
                    identity_conditions = [condition for condition in rule.conditions if isinstance(condition, common_policy.Identity)]
                    if identity_conditions:
                        # First see if there is an exception added for this uri
                        for subcondition in chain(*identity_conditions):
                            if isinstance(subcondition, common_policy.IdentityMany):
                                try:
                                    except_condition = (child for child in subcondition if isinstance(child, common_policy.IdentityExcept) and child.id==operation.contact.uri).next()
                                except StopIteration:
                                    continue
                                else:
                                    subcondition.remove(except_condition)
                                    break
                        else:
                            # Otherwise just add a identity one
                            identity_conditions[0].append(common_policy.IdentityOne(operation.contact.uri))
                    elif self.oma_compliant:
                        external_lists = [condition for condition in rule.conditions if isinstance(condition, omapolicy.ExternalList)]
                        if external_lists or len(rlist) > 0 or rule.id in ('wp_prs_grantedcontacts', 'wp_prs_blockedcontacts'):
                            # We cannot modify the references of wp_prs_grantedcontacts and wp_prs_blockedcontacts
                            for external_list in external_lists:
                                try:
                                    container_list = (l for l in self._follow_policy_external_list(resource_lists, external_list) if l not in not_wanted_lists).next()
                                except (ValueError, StopIteration):
                                    continue
                                else:
                                    break
                            else:
                                if rule.id in ('wp_prs_grantedcontacts', 'wp_prs_blockedcontacts'):
                                    # The user wants to add this contact to one of these rules, but the lists referenced by them are not 
                                    # good because they are referenced from other places; create a new rule, similar to this one
                                    container_list = resourcelists.List(name=self.unique_name('presrules_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                                    resource_lists.append(container_list)
                                    new_policy = deepcopy(policy)
                                    new_policy.id = self.unique_name(('wp_prs_allow_onelist_' if new_policy.action=='allow' else 'wp_prs_onelist_')+container_list.name, (rule.id for rule in pres_rules)).next()
                                    op = AddPresencePolicyOperation(policy=new_policy)
                                    handler = getattr(self, '_OH_%s' % op.name)
                                    handler(op)
                                    rule = pres_rules[new_policy.id]
                                    path = self.resource_lists.uri + '/~~/resource-lists/list[@name="%s"]' % container_list.name
                                    rule.conditions.append(omapolicy.ExternalList([path]))
                                else:
                                    for external_list in external_lists:
                                        rule.conditions.remove(external_list)
                                    container_list = resourcelists.List(name=self.unique_name('presrules_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                                    container_list.extend(resourcelists.External(uri) for uri in chain(*external_lists))
                                    resource_lists.append(container_list)
                                    path = self.resource_lists.uri + '/~~/resource-lists/list[@name="%s"]' % container_list.name
                                    rule.conditions.append(omapolicy.ExternalList([path]))
                            if len(rlist) == 0:
                                path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                                container_list.append(resourcelists.External(path))
                            else:
                                container_list.append(resourcelists.Entry(operation.contact.uri))
                        else:
                            path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                            rule.conditions.append(omapolicy.ExternalList([path]))
                    else:
                        rule.conditions.append(common_policy.Identity([common_policy.IdentityOne(operation.contact.uri)]))
                self.pres_rules.dirty = True
            if self.rls_services.supported and (add_to_presence_list or add_to_dialoginfo_list):
                if operation.contact.subscribe_to_presence and not operation.contact.subscribe_to_dialoginfo:
                    good_lists = presence_lists - dialoginfo_lists
                elif not operation.contact.subscribe_to_presence and operation.contact.subscribe_to_dialoginfo:
                    good_lists = dialoginfo_lists - presence_lists
                else:
                    good_lists = presence_lists & dialoginfo_lists
                if rlist not in good_lists:
                    rls_services = self.rls_services.content
                    try:
                        # First, find those lists which are according to what we want (good_lists) and are not unwanted
                        container_lists = [(l for l in good_lists if l not in not_wanted_lists).next()]
                    except StopIteration:
                        # Then find separate lists which are not unwanted
                        container_lists = []
                        if add_to_presence_list:
                            try:
                                container_lists.append((l for l in presence_lists if l not in not_wanted_lists).next())
                            except StopIteration:
                                # Too bad, we have to create a new service
                                service_list = resourcelists.List(name=self.unique_name('subscribe_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                                resource_lists.append(service_list)
                                path = self.resource_lists.uri + '/~~/resource-lists/list[@name="%s"]' % service_list.name
                                # Find a new uri
                                uri_re = re.compile(r'sip:(buddies_.*)@%s' % self.account.id.domain)
                                taken_names = [m.group(1) for m in (uri_re.match(service.uri) for service in rls_services) if m]
                                uri = 'sip:%s@%s' % (self.unique_name('buddies', taken_names, skip_preferred_name=True).next(), self.account.id.domain)
                                # We'll also make it a dialog service just so that it can also be used as a container for dialog
                                service = rlsservices.Service(uri=uri, list=rlsservices.ResourceList(path), packages=['presence', 'dialog'] if add_to_dialoginfo_list and rlist not in dialoginfo_lists else ['presence'])
                                rls_services.append(service)
                                container_lists.append(service_list)
                                add_to_dialoginfo_list = False
                        if add_to_dialoginfo_list:
                            try:
                                container_lists.append((l for l in dialoginfo_lists if l not in not_wanted_lists).next())
                            except StopIteration:
                                # Too bad, we have to create a new service
                                service_list = resourcelists.List(name=self.unique_name('subscribe_group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                                resource_lists.append(service_list)
                                path = self.resource_lists.uri + '/~~/resource-lists/list[@name="%s"]' % service_list.name
                                # Find a new uri
                                uri_re = re.compile(r'sip:(buddies_.*)@%s' % self.account.id.domain)
                                taken_names = [m.group(1) for m in (uri_re.match(service.uri) for service in rls_services) if m]
                                uri = 'sip:%s@%s' % (self.unique_name('buddies', taken_names, skip_preferred_name=True).next(), self.account.id.domain)
                                # We'll also make it a presence service just so that it can also be used as a container for presence
                                service = rlsservices.Service(uri=uri, list=rlsservices.ResourceList(path), packages=['presence', 'dialog'] if operation.contact.subscribe_to_presence and rlist not in presence_lists else ['dialog'])
                                rls_services.append(service)
                                container_lists = [service_list] # Don't use the previously determined presence service
                    for container_list in container_lists:
                        if container_list is rlist:
                            continue
                        container_list.append(resourcelists.Entry(operation.contact.uri))
                    self.rls_services.dirty = True
        if rlist is not fallback_candidate:
            resource_lists.remove(fallback_candidate)
        elif operation.contact.group is not None:
            path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
            oma_buddylist.append(resourcelists.External(path))
        # After all this trouble, we've found a list that can take our new contact: add it to the list!
        entry = resourcelists.Entry(uri=operation.contact.uri, display_name=operation.contact.name)
        if operation.contact.attributes:
            entry.attributes = resourcelists.Entry.attributes.type(operation.contact.attributes)
        rlist.append(entry)
        self.resource_lists.dirty = True

    def _OH_update_contact(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return

        if not set(['uri', 'group', 'presence_policies', 'dialoginfo_policies', 'subscribe_to_presence', 'subscribe_to_dialoginfo']).intersection(operation.attributes):
            # If none of these attributes are specified, then we only need to look at the resource-lists document
            # and since we prefer keeping the name and additional attributes in the buddies entry, start with oma_buddylist
            # and do a DFS.
            notexpanded = deque([oma_buddylist]+[l for l in resource_lists if l is not oma_buddylist])
            visited = set(notexpanded)
            entries = []
            while notexpanded:
                rlist = notexpanded.popleft()
                for child in rlist:
                    if isinstance(child, resourcelists.List) and child not in visited:
                        visited.add(child)
                        notexpanded.appendleft(child)
                    elif isinstance(child, resourcelists.External):
                        try:
                            ref_lists = set(l for l in self._follow_rl_external(resource_lists, child) if l not in visited)
                        except ValueError:
                            ref_lists = set()
                        visited.update(ref_lists)
                        notexpanded.extendleft(ref_lists)
                    elif isinstance(child, resourcelists.EntryRef):
                        try:
                            ref_entries = self._follow_rl_entry_ref(resource_lists, child)
                        except ValueError:
                            continue
                        entries.extend(entry for entry in ref_entries if entry.uri==operation.contact.uri)
                    elif isinstance(child, resourcelists.Entry) and child.uri == operation.contact.uri:
                        entries.append(child)
            if entries:
                entry = entries[0]
            else:
                # This contact might be referenced only from a rls-services, pres-rules or dialog-rules document; create a list
                # for any additional information we want to store about the contact
                rlist = resourcelists.List(name=self.unique_name('group', (list.name for list in resource_lists), skip_preferred_name=True).next())
                resource_lists.append(rlist)
                entry = resourcelists.Entry(uri=operation.contact.uri, display_name=operation.contact.name)
                rlist.append(entry)
            if 'name' in operation.attributes:
                entry.display_name = operation.attributes.pop('name')
            if operation.attributes and entry.attributes is None:
                entry.attributes = resourcelists.Entry.attributes.type()
            entry.attributes.update(operation.attributes)
            self.resource_lists.dirty = True
        else:
            # We may need to move the contact to a different place; the logic would be too complicated, so first remove the contact and then add it.
            # We retrieve any missing information from what currently exists
            contact = Contact(operation.attributes.pop('name', Null), operation.attributes.pop('uri', operation.contact.uri), operation.attributes.pop('group', Null))
            contact.presence_policies = operation.attributes.pop('presence_policies', Null)
            contact.dialoginfo_policies = operation.attributes.pop('dialoginfo_policies', Null)
            contact.subscribe_to_presence = operation.attributes.pop('subscribe_to_presence', Null)
            contact.subscribe_to_dialoginfo = operation.attributes.pop('subscribe_to_dialoginfo', Null)
            contact.attributes = dict(operation.attributes)

            if contact.presence_policies is None:
                contact.presence_policies = set()
            elif contact.presence_policies is not Null and self.oma_compliant:
                # Filter out policies we mustn't add contacts to
                contact.presence_policies = set(policy for policy in contact.presence_policies if policy.id not in ('wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_block_anonymous', 'wp_prs_allow_own'))
            if contact.dialoginfo_policies is None:
                contact.dialoginfo_policies = set()
            elif contact.dialoginfo_policies is not Null:
                contact.dialoginfo_policies = set(contact.dialoginfo_policies)

            presence_lists = set()
            dialoginfo_lists = set()
            list_policies = {} # Maps a resourcelists.List to a list of PresencePolicy objects
            buddy_lists = set([oma_buddylist])
            if self.rls_services.supported and Null in (contact.subscribe_to_presence, contact.subscribe_to_dialoginfo):
                # Only bother reading the rls services document if we don't change at least one of the subsccribe_to_* flags
                rls_services = self.rls_services.content
                for service in rls_services:
                    packages = set(package.value for package in (service.packages or []))
                    if isinstance(service.list, rlsservices.RLSList):
                        expanded_list = [service.list]
                    elif isinstance(service.list, rlsservices.ResourceList):
                        try:
                            expanded_list = self._follow_rls_resource_list(resource_lists, service.list)
                        except ValueError:
                            expanded_list = []
                    else:
                        expanded_list = []
                    if 'presence' in packages:
                        presence_lists.update(expanded_list)
                    if 'dialog' in packages:
                        dialoginfo_lists.update(expanded_list)
            if self.pres_rules.supported and contact.presence_policies is Null:
                pres_rules = self.pres_rules.content
                contact.presence_policies = set()
                for rule in pres_rules:
                    try:
                        action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                    except StopIteration:
                        continue # Ignore rules whose actions we don't understand
                    policy = PresencePolicy(rule.id, action)
                    for condition in (rule.conditions or []):
                        if isinstance(condition, omapolicy.ExternalList):
                            try:
                                ref_lists = self._follow_policy_external_list(resource_lists, condition)
                            except ValueError:
                                continue
                            else:
                                for ref_list in ref_lists:
                                    list_policies.setdefault(ref_list, set()).add(policy)
                        elif isinstance(condition, common_policy.Identity):
                            if condition.matches(operation.contact.uri):
                                contact.presence_policies.add(policy)
                                break
            if self.dialog_rules.supported and contact.dialoginfo_policies is Null:
                dialog_rules = self.dialog_rules.content
                contact.dialoginfo_policies = set()
                for rule in dialog_rules:
                    try:
                        action = (action.value for action in (rule.actions or []) if isinstance(action, dialogrules.SubHandling)).next()
                    except StopIteration:
                        continue # Ignore rules whose actions we don't understand
                    policy = DialoginfoPolicy(rule.id, action)
                    for condition in (rule.conditions or []):
                        if isinstance(condition, common_policy.Identity) and condition.matches(operation.contact.uri):
                            contact.dialoginfo_policies.add(policy)
                            break
            notexpanded = deque((l, l.display_name.value if l.display_name else None) for l in resource_lists if isinstance(l, resourcelists.List))
            visited = set(notexpanded)
            while notexpanded:
                rlist, list_name = notexpanded.popleft()
                # Some children will need to be revisited so that their descendents are added to appropriate sets
                for child in rlist:
                    if isinstance(child, resourcelists.List):
                        revisit = False
                        if rlist in presence_lists:
                            revisit = (child not in presence_lists) or revisit
                            presence_lists.add(child)
                        if rlist in dialoginfo_lists:
                            revisit = (child not in dialoginfo_lists) or revisit
                            dialoginfo_lists.add(child)
                        if rlist in list_policies:
                            revisit = (child not in list_policies or not list_policies[child].issuperset(list_policies[rlist])) or revisit
                            list_policies.setdefault(child, set()).update(list_policies[rlist])
                        if rlist in buddy_lists:
                            revisit = (child not in buddy_lists) or revisit
                            buddy_lists.add(child)
                        if child not in visited or revisit:
                            visited.add(child)
                            notexpanded.append((child, child.display_name.value if child.display_name else list_name))
                    elif isinstance(child, resourcelists.External):
                        try:
                            ref_lists = self._follow_rl_external(resource_lists, child)
                        except ValueError:
                            ref_lists = []
                        revisit = set()
                        if rlist in presence_lists:
                            revisit.update(l for l in ref_lists if l not in presence_lists)
                            presence_lists.update(ref_lists)
                        if rlist in dialoginfo_lists:
                            revisit.update(l for l in ref_lists if l not in dialoginfo_lists)
                            dialoginfo_lists.update(ref_lists)
                        if rlist in list_policies:
                            revisit.update(l for l in ref_lists if l not in list_policies or not list_policies[l].issuperset(list_policies[rlist]))
                            for l in ref_lists:
                                list_policies.setdefault(l, set()).update(list_policies[rlist])
                        if rlist in buddy_lists:
                            revisit.update(l for l in ref_lists if l not in buddy_lists)
                            buddy_lists.update(ref_lists)
                        visited.update(l for l in ref_lists if l not in visited)
                        if child.display_name:
                            notexpanded.extend((l, child.display_name.value) for l in ref_lists if l not in visited or l in revisit)
                        else:
                            notexpanded.extend((l, l.display_name.value if l.display_name else list_name) for l in ref_lists if l not in visited or l in revisit)
                    elif isinstance(child, resourcelists.EntryRef):
                        try:
                            entries = self._follow_rl_entry_ref(resource_lists, child)
                        except ValueError:
                            continue
                        if any(entry.uri==operation.contact.uri for entry in entries):
                            if rlist in list_policies:
                                contact.presence_policies.update(list_policies[rlist])
                            if contact.name is Null and rlist in buddy_lists and child.display_name:
                                contact.name = child.display_name.value
                        for entry in (e for e in entries if e.uri==operation.contact.uri):
                            if contact.group is Null and rlist in buddy_lists and list_name is not None:
                                contact.group = list_name
                            if contact.name is Null and rlist in buddy_lists and entry.display_name:
                                contact.name = entry.display_name.value
                            if contact.subscribe_to_presence is Null and rlist in presence_lists:
                                contact.subscribe_to_presence = True
                            if contact.subscribe_to_dialoginfo is Null and rlist in dialoginfo_lists:
                                contact.subscribe_to_dialoginfo = True
                            if entry.attributes and rlist in buddy_lists:
                                for key in (key for key in entry.attributes if key not in contact.attributes):
                                    contact.attributes[key] = entry.attributes[key]
                    elif isinstance(child, resourcelists.Entry):
                        if child.uri == operation.contact.uri:
                            if rlist in list_policies:
                                contact.presence_policies.update(list_policies[rlist])
                            if contact.group is Null and rlist in buddy_lists and list_name is not None:
                                contact.group = list_name
                            if contact.name is Null and rlist in buddy_lists and child.display_name:
                                contact.name = child.display_name.value
                            if contact.subscribe_to_presence is Null and rlist in presence_lists:
                                contact.subscribe_to_presence = True
                            if contact.subscribe_to_dialoginfo is Null and rlist in dialoginfo_lists:
                                contact.subscribe_to_dialoginfo = True
                            if child.attributes and rlist in buddy_lists:
                                for key in (key for key in child.attributes if key not in contact.attributes):
                                    contact.attributes[key] = child.attributes[key]
            if contact.name is Null:
                contact.name = operation.contact.uri
            if contact.group is Null:
                # We still don't know where to add this contact, just assume we don't want it as a buddy
                contact.group = operation.contact.group
            contact.presence_policies = list(contact.presence_policies) if contact.presence_policies is not Null else operation.contact.presence_policies
            contact.dialoginfo_policies = list(contact.dialoginfo_policies) if contact.dialoginfo_policies is not Null else operation.contact.dialoginfo_policies
            if contact.subscribe_to_presence is Null:
                contact.subscribe_to_presence = operation.contact.subscribe_to_presence
            if contact.subscribe_to_dialoginfo is Null:
                contact.subscribe_to_dialoginfo = operation.contact.subscribe_to_dialoginfo
            # Now we can delete the contact and add it again
            ops = [RemoveContactOperation(contact=operation.contact), AddContactOperation(contact=contact)]
            for op in ops:
                handler = getattr(self, '_OH_%s' % op.name)
                handler(op)

    def _OH_remove_contact(self, operation):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        lists = set([oma_buddylist])
        to_remove = []
        # Get all rls lists
        if self.rls_services.supported:
            rls_services = self.rls_services.content
            for service in rls_services:
                packages = set(package.value for package in (service.packages or []))
                if isinstance(service.list, rlsservices.RLSList):
                    expanded_list = [service.list]
                elif isinstance(service.list, rlsservices.ResourceList):
                    try:
                        expanded_list = self._follow_rls_resource_list(resource_lists, service.list)
                    except ValueError:
                        expanded_list = []
                else:
                    expanded_list = []
                if 'presence' in packages or 'dialog' in packages:
                    lists.update(expanded_list)
        # Get all pres-rules lists and update the pres-rules document so that it doesn't contain references to this contact
        if self.pres_rules.supported:
            pres_rules = self.pres_rules.content
            for rule in pres_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (rule.conditions or []):
                    if isinstance(condition, omapolicy.ExternalList):
                        try:
                            ref_lists = self._follow_policy_external_list(resource_lists, condition)
                        except ValueError:
                            continue
                        else:
                            lists.update(ref_lists)
                    elif isinstance(condition, common_policy.Identity):
                        for identity in condition:
                            if isinstance(identity, common_policy.IdentityOne) and identity.id == operation.contact.uri:
                                to_remove.append((identity, condition))
                                self.pres_rules.dirty = True
                            elif isinstance(identity, common_policy.IdentityMany) and identity.matches(operation.contact.uri):
                                identity.append(common_policy.IdentityExcept(operation.contact.uri))
                                self.pres_rules.dirty = True
        # Update the dialoginfo rules
        if self.dialog_rules.supported:
            dialog_rules = self.dialog_rules.content
            # Remove any reference to the uri and add it to the correct rule
            for rule in dialog_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, dialogrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (rule.conditions or []):
                    if isinstance(condition, common_policy.Identity):
                        for identity in condition:
                            if isinstance(identity, common_policy.IdentityOne) and identity.id == operation.contact.uri:
                                to_remove.append((identity, condition))
                                self.dialog_rules.dirty = True
                            elif isinstance(identity, common_policy.IdentityMany) and identity.matches(operation.contact.uri):
                                identity.append(common_policy.IdentityExcept(operation.contact.uri))
                                self.dialog_rules.dirty = True
        notexpanded = deque(lists)
        visited = set(notexpanded)
        while notexpanded:
            rlist = notexpanded.popleft()
            for child in rlist:
                if isinstance(child, resourcelists.List) and child not in visited:
                    visited.add(child)
                    notexpanded.append(child)
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = set(l for l in self._follow_rl_external(resource_lists, child) if l not in visited)
                    except ValueError:
                        ref_lists = set()
                    visited.update(ref_lists)
                    notexpanded.extend(ref_lists)
                elif isinstance(child, resourcelists.EntryRef):
                    try:
                        entries = self._follow_rl_entry_ref(resource_lists, child)
                    except ValueError:
                        continue
                    if any(entry.uri == operation.contact.uri for entry in entries):
                        to_remove.append((child, rlist))
                        self.resource_lists.dirty = True
                        self.rls_services.dirty = True
                elif isinstance(child, resourcelists.Entry):
                    if child.uri == operation.contact.uri:
                        to_remove.append((child, rlist))
                        self.resource_lists.dirty = True
                        self.rls_services.dirty = True
        for child, parent in to_remove:
            parent.remove(child)
        # Identity elements can't be empty
        if self.pres_rules.supported:
            pres_rules = self.pres_rules.content
            for rule in pres_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (condition for condition in (rule.conditions[:] or []) if isinstance(condition, common_policy.Identity)):
                    if len(condition) == 0:
                        rule.conditions.remove(condition)
                        rule.conditions.append(common_policy.FalseCondition())
        if self.dialog_rules.supported:
            dialog_rules = self.dialog_rules.content
            for rule in dialog_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, dialogrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                for condition in (condition for condition in (rule.conditions[:] or []) if isinstance(condition, common_policy.Identity)):
                    if len(condition) == 0:
                        rule.conditions.remove(condition)
                        rule.conditions.append(common_policy.FalseCondition())

    def _OH_add_presence_policy(self, operation):
        if not self.pres_rules.supported or operation.policy.id in ('wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_grantedcontacts', 'wp_prs_blockedcontacts', 'wp_prs_block_anonymous', 'wp_prs_allow_own'):
            return
        if operation.policy.id is not None and (operation.policy.id.startswith('wp_prs_allow_one_') or operation.policy.id.startswith('wp_prs_one_')):
            return
        if operation.policy.action is None:
            return
        pres_rules = self.pres_rules.content
        if operation.policy.id is None and self.oma_compliant and not operation.policy.multi_identity_conditions:
            operation.policy.id = self.unique_name('wp_prs_allow_onelist_presrules_group' if operation.policy.action=='allow' else 'wp_prs_onelist_presrules_group', (rule.id for rule in pres_rules), skip_preferred_name=True).next()
        elif operation.policy.id is None:
            operation.policy.id = self.unique_name('rule', (rule.id for rule in pres_rules), skip_preferred_name=True).next()
        elif operation.policy.id in pres_rules:
            return
        elif (operation.policy.id.startswith('wp_prs_allow_onelist_') or operation.policy.id.startswith('wp_prs_onelist_')) and operation.policy.multi_identity_conditions:
            operation.policy.id = self.unique_name('rule', (rule.id for rule in pres_rules), skip_preferred_name=True).next()
        rule = common_policy.Rule(operation.policy.id, conditions=[], actions=[], transformations=[])
        #rule.display_name = operation.policy.name # Rule display-name extension
        rule.actions.append(presrules.SubHandling(operation.policy.action))
        if operation.policy.sphere:
            rule.conditions.append(common_policy.Sphere(operation.policy.sphere))
        if operation.policy.validity:
            rule.conditions.append(common_policy.Validity(operation.policy.validity))
        if operation.policy.action == 'allow':
            if operation.policy.provide_devices is All:
                rule.transformations.append(presrules.ProvideDevices(all=True))
            elif operation.policy.provide_devices:
                provide_devices = presrules.ProvideDevices()
                for component in provide_devices:
                    if isinstance(component, Class):
                        provide_devices.append(presrules.Class(component))
                    elif isinstance(component, OccurenceID):
                        provide_devices.append(presrules.OccurenceID(component))
                    elif isinstance(component, DeviceID):
                        provide_devices.append(presrules.DeviceID(component))
                rule.transformations.append(provide_devices)
            if operation.policy.provide_persons is All:
                rule.transformations.append(presrules.ProvidePersons(all=True))
            elif operation.policy.provide_persons:
                provide_persons = presrules.ProvidePersons()
                for component in provide_persons:
                    if isinstance(component, Class):
                        provide_persons.append(presrules.Class(component))
                    elif isinstance(component, OccurenceID):
                        provide_persons.append(presrules.OccurenceID(component))
                rule.transformations.append(provide_persons)
            if operation.policy.provide_services is All:
                rule.transformations.append(presrules.ProvideServices(all=True))
            else:
                provide_services = presrules.ProvideServices()
                for component in provide_services:
                    if isinstance(component, Class):
                        provide_services.append(presrules.Class(component))
                    elif isinstance(component, OccurenceID):
                        provide_services.append(presrules.OccurenceID(component))
                    elif isinstance(component, ServiceURI):
                        provide_services.append(presrules.ServiceURI(component))
                    elif isinstance(component, ServiceURIScheme):
                        provide_services.append(presrules.ServiceURIScheme(component))
                rule.transformations.append(provide_services)
            if operation.policy.provide_all_attributes:
                rule.transformations.append(presrules.ProvideAllAttributes())
            else:
                attribute_class = {'provide_activities':            presrules.ProvideActivities,
                                   'provide_class':                 presrules.ProvideClass,
                                   'provide_device_id':             presrules.ProvideDeviceID,
                                   'provide_mood':                  presrules.ProvideMood,
                                   'provide_place_is':              presrules.ProvidePlaceIs,
                                   'provide_place_type':            presrules.ProvidePlaceType,
                                   'provide_privacy':               presrules.ProvidePrivacy,
                                   'provide_relationship':          presrules.ProvideRelationship,
                                   'provide_status_icon':           presrules.ProvideStatusIcon,
                                   'provide_sphere':                presrules.ProvideSphere,
                                   'provide_time_offset':           presrules.ProvideTimeOffset,
                                   'provide_user_input':            presrules.ProvideUserInput,
                                   'provide_unknown_attributes':    presrules.ProvideUnknownAttribute}
                for attribute, cls in attribute_class.iteritems():
                    value = getattr(operation.policy, attribute)
                    if value is not None:
                        rule.transformations.append(cls(value))
        if self.oma_compliant and self.resource_lists.supported and (rule.id.startswith('wp_prs_allow_onelist_') or rule.id.startswith('wp_prs_onelist_')):
            resource_lists = self.resource_lists.content
            preferred_name = rule.id[len('wp_prs_allow_onelist_'):] if rule.id.startswith('wp_prs_allow_onelist') else rule.id[len('wp_prs_onelist_'):]
            rlist = resourcelists.List(name=self.unique_name(preferred_name, (list.name for list in resource_lists)).next())
            resource_lists.append(rlist)
            path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
            rule.conditions.append(omapolicy.ExternalList([path]))
            self.resource_lists.dirty = True
        else:
            identity_condition = common_policy.Identity()
            for multi_identity_condition in (operation.policy.multi_identity_conditions or []):
                if isinstance(multi_identity_condition, CatchAllCondition):
                    condition = common_policy.IdentityMany()
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, DomainException):
                            condition.append(common_policy.IdentityExcept(domain=exception.domain))
                        elif isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
                elif isinstance(multi_identity_condition, DomainCondition):
                    condition = common_policy.IdentityMany(domain=multi_identity_condition.domain)
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
            if len(identity_condition) == 0:
                rule.conditions.append(common_policy.FalseCondition())
            else:
                rule.conditions.append(identity_condition)
        pres_rules.append(rule)
        self.pres_rules.dirty = True

    def _OH_update_presence_policy(self, operation):
        if not self.pres_rules.supported or operation.policy.id in ('wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_grantedcontacts', 'wp_prs_blockedcontacts', 'wp_prs_block_anonymous', 'wp_prs_allow_own'):
            return
        pres_rules = self.pres_rules.content
        if operation.policy.id is None or operation.policy.id not in pres_rules:
            if 'action' not in operation.attributes:
                # We cannot assume what this policy's action was
                return
            policy = PresencePolicy(operation.policy.id, operation.attributes.pop('action'))
            if 'name' in operation.attributes:
                policy.name = operation.attributes.pop('name')
            if 'sphere' in operation.attributes:
                policy.sphere = operation.attributes.pop('sphere')
            if 'validity' in operation.attributes:
                policy.validity = operation.attributes.pop('validity')
            if 'multi_identity_conditions' in operation.attributes:
                policy.multi_identity_conditions = operation.attributes.pop('multi_identity_conditions')
            if 'provide_devices' in operation.attributes:
                policy.provide_devices = operation.attributes.pop('provide_devices')
            if 'provide_persons' in operation.attributes:
                policy.provide_persons = operation.attributes.pop('provide_persons')
            if 'provide_services' in operation.attributes:
                policy.provide_services = operation.attributes.pop('provide_services')
            if operation.attributes.get('provide_all_attributes', False):
                policy.provide_all_attributes = operation.attributes.pop('provide_all_attributes')
            else:
                policy.provide_all_attributes = operation.attributes.pop('provide_all_attributes', False)
                for key, value in operation.attributes.iteritems():
                    setattr(policy, key, value)
            op = AddPresencePolicyOperation(policy=policy)
            handler = getattr(self, '_OH_%s' % op.name)
            handler(op)
            return
        rule = pres_rules[operation.policy.id]
        if operation.attributes.get('multi_identity_conditions', None) and (rule.id.startswith('wp_prs_allow_onelist_') or \
                rule.id.startswith('wp_prs_onelist') or any(isinstance(condition, omapolicy.ExternalList) for condition in (rule.conditions or []))):
            # We canot add multi identity conditions to this rule, so create a new one using whatever data from the old one
            try:
                action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
            except StopIteration:
                action = None
            policy = PresencePolicy(None, operation.attributes.pop('action', action))
            policy.name = operation.attributes.pop('name', None) # rule.display_name.value if rule.display_name else None # Rule display-name extension
            try:
                sphere = (condition.value for condition in (rule.conditions or []) if isinstance(condition, common_policy.Sphere)).next()
            except StopIteration:
                sphere = None
            policy.sphere = operation.attributes.pop('sphere', sphere)
            try:
                validity = list((condition for condition in (rule.conditions or []) if isinstance(condition, common_policy.Validity)).next())
            except StopIteration:
                validity = None
            policy.validity = operation.attributes.pop('validity', validity)
            transformation_attribute = {presrules.ProvideDeviceID:          'provide_device_id',
                                        presrules.ProvidePlaceType:         'provide_place_type',
                                        presrules.ProvidePrivacy:           'provide_privacy',
                                        presrules.ProvideRelationship:      'provide_relationship',
                                        presrules.ProvideUnknownAttribute:  'provide_unknown_attributes',
                                        presrules.ProvidePlaceIs:           'provide_place_is',
                                        presrules.ProvideClass:             'provide_class',
                                        presrules.ProvideUserInput:         'provide_user_input',
                                        presrules.ProvideTimeOffset:        'provide_time_offset',
                                        presrules.ProvideStatusIcon:        'provide_status_icon',
                                        presrules.ProvideMood:              'provide_mood',
                                        presrules.ProvideActivities:        'provide_activities',
                                        presrules.ProvideSphere:            'provide_sphere'}
            policy.provide_all_attributes = rule.transformations is None
            for transformation in (rule.transformations or []):
                if transformation.__class__ in transformation_attribute:
                    setattr(policy, transformation_attribute[transformation.__class__], transformation.value)
                elif isinstance(transformation, presrules.ProvideAllAttributes):
                    policy.provide_all_attributes = True
                elif isinstance(transformation, presrules.ProvideDevices):
                    if transformation.all:
                        policy.provide_devices = All
                    else:
                        policy.provide_devices = []
                        for component in transformation:
                            if isinstance(component, presrules.Class):
                                policy.provide_devices.append(Class(component.value))
                            elif isinstance(component, presrules.OccurenceID):
                                policy.provide_devices.append(OccurenceID(component.value))
                            elif isinstance(component, presrules.DeviceID):
                                policy.provide_devices.append(DeviceID(component.value))
                elif isinstance(transformation, presrules.ProvidePersons):
                    if transformation.all:
                        policy.provide_persons = All
                    else:
                        policy.provide_persons = []
                        for component in transformation:
                            if isinstance(component, presrules.Class):
                                policy.provide_persons.append(Class(component.value))
                            elif isinstance(component, presrules.OccurenceID):
                                policy.provide_persons.append(OccurenceID(component.value))
                elif isinstance(transformation, presrules.ProvideServices):
                    if transformation.all:
                        policy.provide_services = All
                    else:
                        policy.provide_services = []
                        for component in transformation:
                            if isinstance(component, presrules.Class):
                                policy.provide_services.append(Class(component.value))
                            elif isinstance(component, presrules.OccurenceID):
                                policy.provide_services.append(OccurenceID(component.value))
                            elif isinstance(component, presrules.ServiceURI):
                                policy.provide_services.append(ServiceURI(component.value))
                            elif isinstance(component, presrules.ServiceURIScheme):
                                policy.provide_services.append(ServiceURIScheme(component.value))
            policy.provide_devices = operation.attributes.pop('provide_devices', policy.provide_devices)
            policy.provide_persons = operation.attributes.pop('provide_persons', policy.provide_persons)
            policy.provide_services = operation.attributes.pop('provide_persons', policy.provide_persons)
            if operation.attributes.get('provide_all_attributes', policy.provide_all_attributes):
                policy.provide_all_attributes = operation.attributes.pop('provide_all_attributes', True)
            else:
                policy.provide_all_attributes = operation.attributes.pop('provide_all_attributes', False)
                for key, value in operation.attributes.iteritems():
                    setattr(policy, key, value)
            op = AddPresencePolicyOperation(policy=policy)
            handler = getattr(self, '_OH_%s' % op.name)
            handler(op)
            return
        if rule.conditions is None:
            rule.conditions = []
        if rule.transformations is None:
            rule.transformations = []
        if 'name' in operation.attributes:
            # rule.display_name = operation.attributes.pop('name') # Rule display-name extension
            operation.attributes.pop('name')
        if 'action' in operation.attributes:
            rule.actions = [presrules.SubHandling(operation.attributes.pop('action'))]
        if 'sphere' in operation.attributes:
            sphere = operation.attributes.pop('sphere')
            try:
                condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Sphere)).next()
            except StopIteration:
                if sphere is not None:
                    rule.conditions.append(common_policy.Sphere(sphere))
            else:
                if sphere is not None:
                    condition.value = sphere
                else:
                    rule.conditions.remove(condition)
        if 'validity' in operation.attributes:
            validity = operation.attributes.pop('validity')
            try:
                condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Validity)).next()
            except StopIteration:
                if validity is not None:
                    rule.conditions.append(common_policy.Validity(validity))
            else:
                if validity is not None:
                    condition[:] = validity
                else:
                    rule.conditions.remove(condition)
        try:
            action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
        except StopIteration:
            action = None
        if action == 'allow':
            attribute_class = {'provide_devices':   presrules.ProvideDevices,
                               'provide_persons':   presrules.ProvidePersons,
                               'provide_services':  presrules.ProvideServices}
            for attribute, cls in attribute_class.iteritems():
                value = operation.attributes.pop('provide_devices', Null)
                if value is Null:
                    continue
                try:
                    transformation = (transformation for transformation in rule.transformations if isinstance(transformation, cls)).next()
                except StopIteration:
                    if value is All:
                        rule.transformations.append(cls(all=True))
                    elif value is not None:
                        rule.transformations.append(cls(value))
                else:
                    if value is All:
                        transformation.all = True
                    elif value is not None:
                        del transformation[:]
                        for component in value:
                            if isinstance(component, Class):
                                transformation.append(presrules.Class(component))
                            elif isinstance(component, OccurenceID):
                                transformation.append(presrules.OccurenceID(component))
                            elif isinstance(component, DeviceID) and attribute == 'provide_devices':
                                transformation.append(presrules.DeviceID(component))
                            elif isinstance(component, ServiceURI) and attribute == 'provide_services':
                                transformation.append(presrules.ServiceURI(component))
                            elif isinstance(component, ServiceURIScheme) and attribute == 'provide_services':
                                transformation.append(presrules.ServiceURIScheme(component))
                    else:
                        rule.transformations.remove(transformation)
            provide_all_attributes = operation.attributes.pop('provide_all_attributes', Null)
            if provide_all_attributes is True:
                rule.transformations.clear()
                rule.transformations.append(presrules.ProvideAllAttributes())
            elif not (provide_all_attributes is Null and any(isinstance(transformation, presrules.ProvideAllAttributes) for transformation in rule.transformations)):
                if provide_all_attributes is False:
                    for transformation in [t for t in rule.transformations if isinstance(t, presrules.ProvideAllAttributes)]:
                        rule.transformations.remove(transformation)
                attribute_class = {'provide_activities':            presrules.ProvideActivities,
                                   'provide_class':                 presrules.ProvideClass,
                                   'provide_device_id':             presrules.ProvideDeviceID,
                                   'provide_mood':                  presrules.ProvideMood,
                                   'provide_place_is':              presrules.ProvidePlaceIs,
                                   'provide_place_type':            presrules.ProvidePlaceType,
                                   'provide_privacy':               presrules.ProvidePrivacy,
                                   'provide_relationship':          presrules.ProvideRelationship,
                                   'provide_status_icon':           presrules.ProvideStatusIcon,
                                   'provide_sphere':                presrules.ProvideSphere,
                                   'provide_time_offset':           presrules.ProvideTimeOffset,
                                   'provide_user_input':            presrules.ProvideUserInput,
                                   'provide_unknown_attributes':    presrules.ProvideUnknownAttribute}
                for attribute, cls in attribute_class.iteritems():
                    value = operation.attributes.pop(attribute, Null)
                    if value is Null:
                        continue
                    try:
                        transformation = (transformation for transformation in rule.transformations if isinstance(transformation, cls)).next()
                    except StopIteration:
                        if value is not None:
                            rule.transformations.append(cls(value))
                    else:
                        if value is not None:
                            transformation.value = value
                        else:
                            rule.transformations.remove(transformation)
        elif self.oma_compliant:
            # No transformations are allowed if action is not 'allow'
            rule.transformations = []
        if not any(isinstance(condition, (common_policy.Identity, omapolicy.ExternalList)) for condition in rule.conditions):
            if self.oma_compliant and self.resource_lists.supported and (rule.id.startswith('wp_prs_allow_onelist_') or rule.id.startswith('wp_prs_onelist_')):
                resource_lists = self.resource_lists.content
                preferred_name = rule.id[len('wp_prs_allow_onelist_'):] if rule.id.startswith('wp_prs_allow_onelist') else rule.id[len('wp_prs_onelist_'):]
                rlist = resourcelists.List(name=self.unique_name(preferred_name, (list.name for list in resource_lists)).next())
                resource_lists.append(rlist)
                path = self.resource_lists.uri + '/~~' + resource_lists.get_xpath(rlist)
                rule.conditions.append(omapolicy.ExternalList([path]))
                self.resource_lists.dirty = True
        try:
            identity_condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Identity)).next()
        except StopIteration:
            identity_condition = common_policy.Identity()
        if 'multi_identity_conditions' in operation.attributes:
            for multi_identity_condition in [id_condition for id_condition in identity_condition if isinstance(id_condition, common_policy.IdentityMany)]:
                identity_condition.remove(multi_identity_condition)
            for multi_identity_condition in (operation.attributes.pop('multi_identity_conditions') or []):
                if isinstance(multi_identity_condition, CatchAllCondition):
                    condition = common_policy.IdentityMany()
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, DomainException):
                            condition.append(common_policy.IdentityExcept(domain=exception.domain))
                        elif isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
                elif isinstance(multi_identity_condition, DomainCondition):
                    condition = common_policy.IdentityMany(domain=multi_identity_condition.domain)
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
        # Identity condition can't be empty
        if not identity_condition:
            rule.conditions.append(common_policy.FalseCondition())
        else:
            rule.conditions.append(identity_condition)
        self.pres_rules.dirty = True

    def _OH_remove_presence_policy(self, operation):
        if not self.pres_rules.supported or operation.policy.id in (None, 'wp_prs_unlisted', 'wp_prs_allow_unlisted', 'wp_prs_grantedcontacts', 'wp_prs_blockedcontacts', 'wp_prs_block_anonymous', 'wp_prs_allow_own'):
            return
        pres_rules = self.pres_rules.content
        try:
            del pres_rules[operation.policy.id]
        except KeyError:
            return
        self.pres_rules.dirty = True

    def _OH_add_dialoginfo_policy(self, operation):
        if not self.dialog_rules.supported:
            return
        dialog_rules = self.dialog_rules.content
        if operation.policy.id is None:
            operation.policy.id = self.unique_name('rule', (rule.id for rule in dialog_rules), skip_preferred_name=True).next()
        elif operation.policy.id in dialog_rules:
            return
        rule = common_policy.Rule(operation.policy.id, conditions=[], actions=[])
        #rule.display_name = operation.policy.name # Rule display-name extension
        rule.actions.append(dialogrules.SubHandling(operation.policy.action))
        if operation.policy.sphere:
            rule.conditions.append(common_policy.Sphere(operation.policy.sphere))
        if operation.policy.validity:
            rule.conditions.append(common_policy.Validity(operation.policy.validity))
        identity_condition = common_policy.Identity()
        for multi_identity_condition in (operation.policy.multi_identity_conditions or []):
            if isinstance(multi_identity_condition, CatchAllCondition):
                condition = common_policy.IdentityMany()
                identity_condition.append(condition)
                for exception in multi_identity_condition.exceptions:
                    if isinstance(exception, DomainException):
                        condition.append(common_policy.IdentityExcept(domain=exception.domain))
                    elif isinstance(exception, UserException):
                        condition.append(common_policy.IdentityExcept(id=exception.uri))
            elif isinstance(multi_identity_condition, DomainCondition):
                condition = common_policy.IdentityMany(domain=multi_identity_condition.domain)
                identity_condition.append(condition)
                for exception in multi_identity_condition.exceptions:
                    if isinstance(exception, UserException):
                        condition.append(common_policy.IdentityExcept(id=exception.uri))
        if len(identity_condition) == 0:
            rule.conditions.append(common_policy.FalseCondition())
        else:
            rule.conditions.append(identity_condition)
        dialog_rules.append(rule)
        self.dialog_rules.dirty = True

    def _OH_update_dialoginfo_policy(self, operation):
        if not self.dialog_rules.supported:
            return
        dialog_rules = self.dialog_rules.content
        if operation.policy.id is None or operation.policy.id not in dialog_rules:
            if 'action' not in operation.attributes:
                # We cannot assume what this policy's action was
                return
            policy = DialoginfoPolicy(operation.policy.id, operation.attributes.pop('action'))
            if 'name' in operation.attributes:
                policy.name = operation.attributes.pop('name')
            if 'sphere' in operation.attributes:
                policy.sphere = operation.attributes.pop('sphere')
            if 'validity' in operation.attributes:
                policy.validity = operation.attributes.pop('validity')
            op = AddDialoginfoPolicyOperation(policy=policy)
            handler = getattr(self, '_OH_%s' % op.name)
            handler(op)
            return
        rule = dialog_rules[operation.policy.id]
        if rule.conditions is None:
            rule.conditions = []
        if 'name' in operation.attributes:
            #rule.display_name = operation.attributes.pop('name') # Rule display-name extension
            operation.attributes.pop('name')
        if 'action' in operation.attributes:
            rule.actions = [dialogrules.SubHandling(operation.attributes.pop('action'))]
        if 'sphere' in operation.attributes:
            sphere = operation.attributes.pop('sphere')
            try:
                condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Sphere)).next()
            except StopIteration:
                if sphere is not None:
                    rule.conditions.append(common_policy.Sphere(sphere))
            else:
                if sphere is not None:
                    condition.value = sphere
                else:
                    rule.conditions.remove(condition)
        if 'validity' in operation.attributes:
            validity = operation.attributes.pop('validity')
            try:
                condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Validity)).next()
            except StopIteration:
                if validity is not None:
                    rule.conditions.append(common_policy.Validity(validity))
            else:
                if validity is not None:
                    condition[:] = validity
                else:
                    rule.conditions.remove(condition)
        try:
            identity_condition = (condition for condition in rule.conditions if isinstance(condition, common_policy.Identity)).next()
        except StopIteration:
            identity_condition = common_policy.Identity()
        if 'multi_identity_conditions' in operation.attributes:
            for multi_identity_condition in [id_condition for id_condition in identity_condition if isinstance(id_condition, common_policy.IdentityMany)]:
                identity_condition.remove(multi_identity_condition)
            for multi_identity_condition in (operation.attributes.pop('multi_identity_conditions') or []):
                if isinstance(multi_identity_condition, CatchAllCondition):
                    condition = common_policy.IdentityMany()
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, DomainException):
                            condition.append(common_policy.IdentityExcept(domain=exception.domain))
                        elif isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
                elif isinstance(multi_identity_condition, DomainCondition):
                    condition = common_policy.IdentityMany(domain=multi_identity_condition.domain)
                    identity_condition.append(condition)
                    for exception in multi_identity_condition.exceptions:
                        if isinstance(exception, UserException):
                            condition.append(common_policy.IdentityExcept(id=exception.uri))
        # Identity condition can't be empty
        if len(identity_condition) == 0:
            rule.conditions.append(common_policy.FalseCondition())
        else:
            rule.conditions.append(identity_condition)
        self.dialog_rules.dirty = True

    def _OH_remove_dialoginfo_policy(self, operation):
        if not self.dialog_rules.supported or operation.policy.id is None:
            return
        dialog_rules = self.dialog_rules.content
        try:
            del dialog_rules[operation.policy.id]
        except KeyError:
            return
        self.dialog_rules.dirty = True

    def _OH_set_status_icon(self, operation):
        if not self.status_icon.supported:
            return
        if operation.icon is None or not operation.icon.data:
            self.status_icon.content = None
        else:
            data = base64.encodestring(operation.icon.data)
            mime_type = operation.icon.mime_type if operation.icon.mime_type in ('image/gif', 'image/jpeg', 'image/png') else 'image/jpeg'
            self.status_icon.content = prescontent.PresenceContent(data=data, mime_type=mime_type, encoding='base64', description=operation.icon.description)
        self.status_icon.dirty = True

    def _OH_set_offline_status(self, operation):
        if not self.pidf_manipulation.supported:
            return
        if operation.status is None:
            self.pidf_manipulation.content = None
        else:
            self.pidf_manipulation.content = presdm.PIDF('sip:'+self.account.id)
            person = presdm.Person('offline_status')
            person.timestamp = presdm.PersonTimestamp()
            if operation.status.note:
                person.notes.add(presdm.PersonNote(operation.status.note))
            if operation.status.activity:
                person.activities = rpid.Activities()
                person.activities.append(operation.status.activity)
            self.pidf_manipulation.content.append(person)
        self.pidf_manipulation.dirty = True


    # notification handling
    #

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        if set(['__id__', 'xcap.xcap_root', 'auth.username', 'auth.password', 'sip.subscribe_interval', 'sip.transport_list']).intersection(notification.data.modified):
            self.command_channel.send(Command('reload', modified=notification.data.modified))

    def _NH_CFGSettingsObjectWasDeleted(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.account, name='CFGSettingsObjectDidChange')
        notification_center.remove_observer(self, sender=self.account, name='CFGSettingsObjectWasDeleted')
        self.command_channel.send(Command('stop'))
        self.command_channel.send(Command('cleanup'))

    def _NH_XCAPSubscriptionDidStart(self, notification):
        self.command_channel.send(Command('fetch', documents=self.document_names))

    def _NH_XCAPSubscriptionDidFail(self, notification):
        self.command_channel.send(Command('fetch', documents=self.document_names))

    def _NH_XCAPSubscriptionGotNotify(self, notification):
        if notification.data.content_type == xcapdiff.XCAPDiff.content_type:
            try:
                xcap_diff = xcapdiff.XCAPDiff.parse(notification.data.body)
            except ParserError:
                self.command_channel.send(Command('fetch', documents=self.document_names))
            else:
                applications = set(child.selector.auid for child in xcap_diff if isinstance(child, xcapdiff.Document))
                documents = [document.name for document in self.documents if document.application in applications]
                self.command_channel.send(Command('fetch', documents=documents))

    def _load_data(self):
        if not self.resource_lists.supported:
            return
        resource_lists = self.resource_lists.content
        try:
            oma_buddylist = (child for child in resource_lists if isinstance(child, resourcelists.List) and child.name=='oma_buddylist').next()
        except StopIteration:
            # This should never happen as the document is normalized
            return
        list_presence_policies = {} # Maps a resourcelists.List to a list of PresencePolicy objects
        presence_policies = {} # Maps a PresencePolicy to a common_policy.Identity condition if the policy contains one, otherwise to None
        dialoginfo_policies = {} # Maps a DialoginfoPolicy to a common_policy.Identity condition if the policy contains one, otherwise to None
        presence_lists = set() # resourcelists.List objects which are referenced from an rls service with package presence
        dialoginfo_lists = set() # resourcelists.List objects which are referenced from an rls service with package dialog
        list_services = {} # Maps a resourcelists.List to the set of services which reference the list
        buddy_lists = set([oma_buddylist]) # resourcelists.List objects which are referenced from oma_buddylist
        contacts = {} # Maps a URI to a Contact object
        services = []
        groups = set() # Group names
        if self.rls_services.supported:
            rls_services = self.rls_services.content
            for service_element in rls_services:
                packages = set(package.value for package in (service_element.packages or []))
                service = Service(service_element.uri, list(packages))
                service.entries = set()
                services.append(service)
                if isinstance(service_element.list, rlsservices.RLSList):
                    expanded_list = [service_element.list]
                elif isinstance(service_element.list, rlsservices.ResourceList):
                    try:
                        expanded_list = self._follow_rls_resource_list(resource_lists, service_element.list)
                    except ValueError:
                        expanded_list = []
                else:
                    expanded_list = []
                if 'presence' in packages:
                    presence_lists.update(expanded_list)
                if 'dialog' in packages:
                    dialoginfo_lists.update(expanded_list)
                for rlist in expanded_list:
                    list_services.setdefault(rlist, set()).add(service)
        if self.pres_rules.supported:
            pres_rules = self.pres_rules.content
            for rule in pres_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, presrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                policy = PresencePolicy(rule.id, action)
                #policy.name = rule.display_name.value if rule.display_name else None # Rule display-name extension
                presence_policies[policy] = None
                policy.multi_identity_conditions = []
                for condition in (rule.conditions or []):
                    if isinstance(condition, omapolicy.ExternalList):
                        try:
                            ref_lists = self._follow_policy_external_list(resource_lists, condition)
                        except ValueError:
                            continue
                        else:
                            for ref_list in ref_lists:
                                list_presence_policies.setdefault(ref_list, set()).add(policy)
                    elif isinstance(condition, common_policy.Identity):
                        presence_policies[policy] = condition
                        for identity_many_condition in (identity_condition for identity_condition in condition if isinstance(identity_condition, common_policy.IdentityMany)):
                            if identity_many_condition.domain:
                                multi_condition = DomainCondition(identity_many_condition.domain)
                            else:
                                multi_condition = CatchAllCondition()
                            policy.multi_identity_conditions.append(multi_condition)
                            for exception_condition in (sub_condition for sub_condition in identity_many_condition if isinstance(sub_condition, common_policy.IdentityExcept)):
                                if exception_condition.domain:
                                    multi_condition.exceptions.append(DomainException(exception_condition.domain))
                                elif exception_condition.id:
                                    multi_condition.exceptions.append(UserException(exception_condition.id))
                    elif isinstance(condition, common_policy.Sphere):
                        policy.sphere = condition.value
                    elif isinstance(condition, common_policy.Validity):
                        policy.validity = list(condition)
                transformation_attribute = {presrules.ProvideDeviceID:          'provide_device_id',
                                            presrules.ProvidePlaceType:         'provide_place_type',
                                            presrules.ProvidePrivacy:           'provide_privacy',
                                            presrules.ProvideRelationship:      'provide_relationship',
                                            presrules.ProvideUnknownAttribute:  'provide_unknown_attributes',
                                            presrules.ProvidePlaceIs:           'provide_place_is',
                                            presrules.ProvideClass:             'provide_class',
                                            presrules.ProvideUserInput:         'provide_user_input',
                                            presrules.ProvideTimeOffset:        'provide_time_offset',
                                            presrules.ProvideStatusIcon:        'provide_status_icon',
                                            presrules.ProvideMood:              'provide_mood',
                                            presrules.ProvideActivities:        'provide_activities',
                                            presrules.ProvideSphere:            'provide_sphere'}
                policy.provide_all_attributes = rule.transformations is None
                for transformation in (rule.transformations or []):
                    if transformation.__class__ in transformation_attribute:
                        setattr(policy, transformation_attribute[transformation.__class__], transformation.value)
                    elif isinstance(transformation, presrules.ProvideAllAttributes):
                        policy.provide_all_attributes = True
                    elif isinstance(transformation, presrules.ProvideDevices):
                        if transformation.all:
                            policy.provide_devices = All
                        else:
                            policy.provide_devices = []
                            for component in transformation:
                                if isinstance(component, presrules.Class):
                                    policy.provide_devices.append(Class(component.value))
                                elif isinstance(component, presrules.OccurenceID):
                                    policy.provide_devices.append(OccurenceID(component.value))
                                elif isinstance(component, presrules.DeviceID):
                                    policy.provide_devices.append(DeviceID(component.value))
                    elif isinstance(transformation, presrules.ProvidePersons):
                        if transformation.all:
                            policy.provide_persons = All
                        else:
                            policy.provide_persons = []
                            for component in transformation:
                                if isinstance(component, presrules.Class):
                                    policy.provide_persons.append(Class(component.value))
                                elif isinstance(component, presrules.OccurenceID):
                                    policy.provide_persons.append(OccurenceID(component.value))
                    elif isinstance(transformation, presrules.ProvideServices):
                        if transformation.all:
                            policy.provide_services = All
                        else:
                            policy.provide_services = []
                            for component in transformation:
                                if isinstance(component, presrules.Class):
                                    policy.provide_services.append(Class(component.value))
                                elif isinstance(component, presrules.OccurenceID):
                                    policy.provide_services.append(OccurenceID(component.value))
                                elif isinstance(component, presrules.ServiceURI):
                                    policy.provide_services.append(ServiceURI(component.value))
                                elif isinstance(component, presrules.ServiceURIScheme):
                                    policy.provide_services.append(ServiceURIScheme(component.value))
        if self.dialog_rules.supported:
            dialog_rules = self.dialog_rules.content
            for rule in dialog_rules:
                try:
                    action = (action.value for action in (rule.actions or []) if isinstance(action, dialogrules.SubHandling)).next()
                except StopIteration:
                    continue # Ignore rules whose actions we don't understand
                policy = DialoginfoPolicy(rule.id, action)
                #policy.name = rule.display_name.value if rule.display_name else None # Rule display-name extension
                dialoginfo_policies[policy] = None
                policy.multi_identity_conditions = []
                for condition in (rule.conditions or []):
                    if isinstance(condition, common_policy.Identity):
                        dialoginfo_policies[policy] = condition
                        for identity_many_condition in (identity_condition for identity_condition in condition if isinstance(identity_condition, common_policy.IdentityMany)):
                            if identity_many_condition.domain:
                                multi_condition = DomainCondition(identity_many_condition.domain)
                            else:
                                multi_condition = CatchAllCondition()
                            policy.multi_identity_conditions.append(multi_condition)
                            for exception_condition in (sub_condition for sub_condition in identity_many_condition if isinstance(sub_condition, common_policy.IdentityExcept)):
                                if exception_condition.domain:
                                    multi_condition.exceptions.append(DomainException(exception_condition.domain))
                                elif exception_condition.id:
                                    multi_condition.exceptions.append(UserException(exception_condition.id))
                    elif isinstance(condition, common_policy.Sphere):
                        policy.sphere = condition.value
                    elif isinstance(condition, common_policy.Validity):
                        policy.validity = list(condition)
        notexpanded = deque((l, l.display_name.value if l.display_name else None) for l in presence_lists|dialoginfo_lists|set(list_presence_policies)|buddy_lists)
        visited = set(notexpanded)
        while notexpanded:
            rlist, list_name = notexpanded.popleft()
            if rlist in buddy_lists and list_name is not None:
                groups.add(list_name)
            # Some children will need to be revisited so that their descendents are added to appropriate sets
            for child in rlist:
                if isinstance(child, resourcelists.List):
                    revisit = False
                    if rlist in presence_lists:
                        revisit = (child not in presence_lists) or revisit
                        presence_lists.add(child)
                    if rlist in dialoginfo_lists:
                        revisit = (child not in dialoginfo_lists) or revisit
                        dialoginfo_lists.add(child)
                    if rlist in list_presence_policies:
                        revisit = (child not in list_presence_policies) or not list_presence_policies[child].issuperset(list_presence_policies[rlist]) or revisit
                        list_presence_policies.setdefault(child, set()).update(list_presence_policies[rlist])
                    if rlist in list_services:
                        revisit = (child not in list_services) or not list_services[child].issuperset(list_services[rlist]) or revisit
                        list_services.setdefault(child, set()).update(list_services[rlist])
                    if rlist in buddy_lists:
                        revisit = (child not in buddy_lists) or revisit
                        buddy_lists.add(child)
                    if child not in visited or revisit:
                        visited.add(child)
                        notexpanded.append((child, child.display_name.value if child.display_name else list_name))
                elif isinstance(child, resourcelists.External):
                    try:
                        ref_lists = self._follow_rl_external(resource_lists, child)
                    except ValueError:
                        ref_lists = []
                    revisit = set()
                    if rlist in presence_lists:
                        revisit.update(l for l in ref_lists if l not in presence_lists)
                        presence_lists.update(ref_lists)
                    if rlist in dialoginfo_lists:
                        revisit.update(l for l in ref_lists if l not in dialoginfo_lists)
                        dialoginfo_lists.update(ref_lists)
                    if rlist in list_presence_policies:
                        revisit.update(l for l in ref_lists if l not in list_presence_policies or not list_presence_policies[l].issuperset(list_presence_policies[rlist]))
                        for l in ref_lists:
                            list_presence_policies.setdefault(l, set()).update(list_presence_policies[rlist])
                    if rlist in list_services:
                        revisit.update(l for l in ref_lists if l not in list_services or not list_services[l].issuperset(list_services[rlist]))
                        for l in ref_lists:
                            list_services.setdefault(l, set()).update(list_services[rlist])
                    if rlist in buddy_lists:
                        revisit.update(l for l in ref_lists if l not in buddy_lists)
                        buddy_lists.update(ref_lists)
                    visited.update(l for l in ref_lists if l not in visited)
                    if child.display_name:
                        notexpanded.extend((l, child.display_name.value) for l in ref_lists if l not in visited or l in revisit)
                    else:
                        notexpanded.extend((l, l.display_name.value if l.display_name else list_name) for l in ref_lists if l not in visited or l in revisit)
                elif isinstance(child, resourcelists.EntryRef):
                    try:
                        entries = self._follow_rl_entry_ref(resource_lists, child)
                    except ValueError:
                        continue
                    for service in list_services.get(rlist, ()):
                        service.entries.update(entry.uri for entry in entries)
                    for entry in entries:
                        try:
                            contact = contacts[entry.uri]
                        except KeyError:
                            contact = contacts[entry.uri] = Contact(None, entry.uri, None)
                            contact.presence_policies = set(policy for policy, identity in presence_policies.iteritems() if identity is not None and identity.matches(contact.uri))
                            contact.dialoginfo_policies = set(policy for policy, identity in dialoginfo_policies.iteritems() if identity is not None and identity.matches(contact.uri))
                            contact.subscribe_to_presence = False
                            contact.subscribe_to_dialoginfo = False
                        if contact.group is None and rlist in buddy_lists and list_name is not None:
                            contact.group = list_name
                        if contact.name is None and rlist in buddy_lists and child.display_name:
                            contact.name = child.display_name.value
                        elif contact.name is None and rlist in buddy_lists and entry.display_name:
                            contact.name = entry.display_name.value
                        if rlist in list_presence_policies:
                            contact.presence_policies.update(list_presence_policies[rlist])
                        if not contact.subscribe_to_presence  and rlist in presence_lists:
                            contact.subscribe_to_presence = True
                        if not contact.subscribe_to_dialoginfo and rlist in dialoginfo_lists:
                            contact.subscribe_to_dialoginfo = True
                        if entry.attributes and rlist in buddy_lists:
                            for key in (key for key in entry.attributes if key not in contact.attributes):
                                contact.attributes[key] = entry.attributes[key]
                elif isinstance(child, resourcelists.Entry):
                    for service in list_services.get(rlist, ()):
                        service.entries.add(child.uri)
                    try:
                        contact = contacts[child.uri]
                    except KeyError:
                        contact = contacts[child.uri] = Contact(None, child.uri, None)
                        contact.presence_policies = set(policy for policy, identity in presence_policies.iteritems() if identity is not None and identity.matches(contact.uri))
                        contact.dialoginfo_policies = set(policy for policy, identity in dialoginfo_policies.iteritems() if identity is not None and identity.matches(contact.uri))
                        contact.subscribe_to_presence = False
                        contact.subscribe_to_dialoginfo = False
                    if contact.group is None and rlist in buddy_lists and list_name is not None:
                        contact.group = list_name
                    if contact.name is None and rlist in buddy_lists and child.display_name:
                        contact.name = child.display_name.value
                    if rlist in list_presence_policies:
                        contact.presence_policies.update(list_presence_policies[rlist])
                    if not contact.subscribe_to_presence and rlist in presence_lists:
                        contact.subscribe_to_presence = True
                    if not contact.subscribe_to_dialoginfo and rlist in dialoginfo_lists:
                        contact.subscribe_to_dialoginfo = True
                    if child.attributes and rlist in buddy_lists:
                        for key in (key for key in child.attributes if key not in contact.attributes):
                            contact.attributes[key] = child.attributes[key]
        if self.status_icon.supported and self.status_icon.content:
            status_icon = self.status_icon.content
            try:
                data = base64.decodestring(status_icon.data)
            except Exception:
                icon = None
            else:
                mime_type = status_icon.mime_type.value if status_icon.mime_type else None
                description = status_icon.description.value if status_icon.description else None
                location = self.status_icon.alternative_location or self.status_icon.uri
                icon = Icon(data, mime_type, description, location)
        else:
            icon = None
        if self.pidf_manipulation.supported and self.pidf_manipulation.content:
            pidf_manipulation = self.pidf_manipulation.content
            persons = [child for child in pidf_manipulation if isinstance(child, presdm.Person)]
            try:
                note = unicode(chain(*(person.notes for person in persons if person.notes)).next())
            except StopIteration:
                note = None
            try:
                activity = chain(*(person.activities for person in persons if person.activities)).next()
            except StopIteration:
                activity = None
            offline_status = OfflineStatus(activity, note)
        else:
            offline_status = None
        contacts = contacts.values()
        groups = list(groups)
        presence_policies = list(presence_policies)
        dialoginfo_policies = list(dialoginfo_policies)
        for contact in contacts:
            contact.presence_policies = list(contact.presence_policies)
            contact.dialoginfo_policies = list(contact.dialoginfo_policies)
        for service in services:
            service.entries = list(service.entries)
        notification_center = NotificationCenter()
        notification_center.post_notification('XCAPManagerDidReloadData', sender=self,
                                              data=TimestampedNotificationData(contacts=contacts, groups=groups, services=services, presence_policies=presence_policies,
                                                                               dialoginfo_policies=dialoginfo_policies, status_icon=icon, offline_status=offline_status))

    def _follow_policy_external_list(self, resource_lists, external_list):
        result = []
        for relative_uri in (uri[len(self.xcap_root):] for uri in external_list if uri.startswith(self.xcap_root)):
            try:
                uri = XCAPURI(self.xcap_root, relative_uri, self.namespaces)
                # Only follow references to default resource-lists document which belongs to ourselves
                if uri.application_id == self.resource_lists.application and uri.document_selector.document_path == self.resource_lists.filename and \
                   uri.user is not None and (uri.user.username, uri.user.domain) == (self.account.id.username, self.account.id.domain):
                    result.extend(l for l in resource_lists.xpath(uri.node_selector.normalized, uri.node_selector.nsmap) if isinstance(l, resourcelists.List))
            except ValueError:
                pass
        return result

    def _follow_rl_external(self, resource_lists, external):
        if external.anchor.startswith(self.xcap_root):
            uri = XCAPURI(self.xcap_root, external.anchor[len(self.xcap_root):], self.namespaces)
            # Only follow references to default resource-lists document which belongs to ourselves
            if uri.application_id == self.resource_lists.application and uri.document_selector.document_path == self.resource_lists.filename and \
               uri.user is not None and (uri.user.username, uri.user.domain) == (self.account.id.username, self.account.id.domain):
                return [l for l in resource_lists.xpath(uri.node_selector.normalized, uri.node_selector.nsmap) if isinstance(l, resourcelists.List)]
        raise ValueError("XCAP URI does not point to default resource-lists document")

    def _follow_rl_entry_ref(self, resource_lists, entry_ref):
        uri = XCAPURI(self.xcap_root, entry_ref.ref, self.namespaces)
        # Only follow references to default resource-lists document which belongs to ourselves
        if uri.application_id == self.resource_lists.application and uri.document_selector.document_path == self.resource_lists.filename and \
           uri.user is not None and (uri.user.username, uri.user.domain) == (self.account.id.username, self.account.id.domain):
            return [e for e in resource_lists.xpath(uri.node_selector.normalized, uri.node_selector.nsmap) if isinstance(e, resourcelists.Entry)]

    def _follow_rls_resource_list(self, resource_lists, resource_list):
        if resource_list.value.startswith(self.xcap_root):
            uri = XCAPURI(self.xcap_root, resource_list.value[len(self.xcap_root):], self.namespaces)
            # Only follow references to default resource-lists document which belongs to ourselves
            if uri.application_id == self.resource_lists.application and uri.document_selector.document_path == self.resource_lists.filename and \
               uri.user is not None and (uri.user.username, uri.user.domain) == (self.account.id.username, self.account.id.domain):
                return [l for l in resource_lists.xpath(uri.node_selector.normalized, uri.node_selector.nsmap) if isinstance(l, resourcelists.List)]
        raise ValueError("XCAP URI does not point to default resource-lists document")

    def _schedule_command(self, timeout, command):
        from twisted.internet import reactor
        timer = reactor.callLater(timeout, self.command_channel.send, command)
        timer.command = command
        return timer

    def _save_journal(self):
        try:
            self.storage.save('journal', cPickle.dumps(self.journal))
        except XCAPStorageError:
            pass

    @staticmethod
    def unique_name(preferred_name, disallowed_names, skip_preferred_name=False):
        disallowed_names = set(disallowed_names)
        if not skip_preferred_name and preferred_name not in disallowed_names:
            disallowed_names.add(preferred_name)
            yield preferred_name
        for i in xrange(100):
            name = '%s_%03d' % (preferred_name, i)
            if name not in disallowed_names:
                disallowed_names.add(name)
                yield name
        while True:
            characters = len(string.ascii_letters+string.digits)
            for limit in count(4):
                for i in xrange(characters**(limit-2)):
                    name = preferred_name + '_' + ''.join(random.choice(string.ascii_letters+string.digits) for x in xrange(limit))
                    if name not in disallowed_names:
                        disallowed_names.add(name)
                        yield name


class XCAPTransaction(object):
    def __init__(self, xcap_manager):
        self.xcap_manager = xcap_manager

    def __enter__(self):
        self.xcap_manager.start_transaction()
        return self

    def __exit__(self, type, value, traceback):
        self.xcap_manager.commit_transaction()



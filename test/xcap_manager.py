#!/usr/bin/python

"""
Script for testing XCAPManager. Initializes middleware using a configuration
file named "test-config" in the current directory. Uses the default account to
initialize an XCAPManager. Type "help" for a list of implemented commands. The
commands have the same arguments as the ones in XCAPManager. Arguments are
specified using JSON (don't use spaces or quote each argument):
add_contact 'contact={"name": "My buddy", "uri": "sip:buddy@example.org", "group": "Buddies"}'
or
add_contact contact={"name":"My buddy","uri":"sip:buddy@example.org","group":"Buddies"}

To exit, type "exit".
"""

import cjson
import os
import shlex
import string
from cmd import Cmd
from itertools import count, takewhile
from StringIO import StringIO

from application.notification import NotificationCenter, IObserver
from application.python import Null
from application.python.decorator import decorator, preserve_signature
from application.python.types import Singleton
from threading import Event
from zope.interface import implements

from sipsimple.account import Account, AccountManager, XCAPSettings
from sipsimple.account.xcap import All, CatchAllCondition, Class, Contact, DeviceID, DialoginfoPolicy, DomainCondition, DomainException, OccurenceID, OfflineStatus, PresencePolicy, ServiceURI, ServiceURIScheme, UserException, XCAPManager
from sipsimple.application import SIPApplication
from sipsimple.configuration import Setting, SettingsObjectExtension
from sipsimple.storage import FileStorage
from sipsimple.threading.green import run_in_green_thread
from sipsimple.util import Timestamp


class XCAPSettingsExtension(XCAPSettings):
    enabled = Setting(type=bool, default=True)

class AccountExtension(SettingsObjectExtension):
    xcap = XCAPSettingsExtension


class XCAPApplication(object):
    __metaclass__ = Singleton

    implements(IObserver)

    def __init__(self):
        self.application = SIPApplication()
        self.xcap_manager = None
        self.quit_event = Event()
        Account.register_extension(AccountExtension)
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.application)

    def start(self):
        self.application.start(FileStorage(os.path.realpath('.')))

    @run_in_green_thread
    def stop(self):
        self.xcap_manager.stop()
        self.application.stop()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    @run_in_green_thread
    def _NH_SIPApplicationDidStart(self, notification):
        account_manager = AccountManager()
        self.xcap_manager = XCAPManager(account_manager.default_account)
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.xcap_manager)
        self.xcap_manager.load()
        self.xcap_manager.start()
        if not account_manager.default_account.xcap.enabled:
            print 'XCAP support is not enabled'

    def _NH_SIPApplicationDidEnd(self, notification):
        self.quit_event.set()

    def _NH_XCAPManagerDidChangeState(self, notification):
        print 'XCAP Manager state %s -> %s' % (notification.data.prev_state, notification.data.state)

    def _NH_XCAPManagerWillStart(self, notification):
        print 'XCAP Manager will start'

    def _NH_XCAPManagerDidStart(self, notification):
        print 'XCAP Manager did start'

    def _NH_XCAPManagerDidDiscoverServerCapabilities(self, notification):
        print '  contact list supported: %s' % notification.data.contactlist_supported
        print '  presence policies supported: %s' % notification.data.presence_policies_supported
        print '  dialoginfo policies supported: %s' % notification.data.dialoginfo_policies_supported
        print '  status icon supported: %s' % notification.data.status_icon_supported
        print '  offline status supported: %s' % notification.data.offline_status_supported

    def _NH_XCAPManagerWillEnd(self, notification):
        print 'XCAP Manager will end'

    def _NH_XCAPManagerDidEnd(self, notification):
        print 'XCAP Manager did end'

    def _NH_XCAPManagerDidReloadData(self, notification):
        print 'XCAP Manager reloaded data:'
        groups = dict.fromkeys(notification.data.groups)
        for group in groups:
            groups[group] = []
        for contact in notification.data.contacts:
            if contact.group is not None:
                groups[contact.group].append(contact)
        print 'Buddies:'
        for group, contacts in groups.iteritems():
            print '  %s:' % group
            for contact in contacts:
                if contact.name:
                    print '    %s <%s>' % (contact.name, contact.uri)
                else:
                    print '    %s' % contact.uri
                print '      subscribe-to-presence    = %s' % contact.subscribe_to_presence
                print '      subscribe-to-dialoginfo  = %s' % contact.subscribe_to_dialoginfo
                print '      presence-policies        = %s' % (', '.join(p.id for p in contact.presence_policies) if contact.presence_policies else None)
                print '      dialoginfo-policies      = %s' % (', '.join(p.id for p in contact.dialoginfo_policies) if contact.dialoginfo_policies else None)
                for attr, value in contact.attributes.iteritems():
                    print '      x: %s = %s' % (attr, value)
            print

        print 'Presence policies:'
        for policy in notification.data.presence_policies:
            print '  %s -> %s' % (policy.id, policy.action)
            if policy.sphere:
                print '    sphere                     = %s' % policy.sphere
            if policy.validity:
                print '    valid between:'
                for from_timestamp, until_timestamp in policy.validity:
                    print '      %s - %s' % (from_timestamp, until_timestamp)
            if policy.multi_identity_conditions:
                print '    multi identity conditions:'
                for multi_condition in policy.multi_identity_conditions:
                    if isinstance(multi_condition, CatchAllCondition) and multi_condition.exceptions:
                        print '      anyone except'
                        for exception in multi_condition.exceptions:
                            if isinstance(exception, DomainException):
                                print '        users from domain %s' % exception.domain
                            elif isinstance(exception, UserException):
                                print '        user %s' % exception.uri
                    elif isinstance(multi_condition, CatchAllCondition):
                        print '      anyone'
                    elif isinstance(multi_condition, DomainCondition) and multi_condition.exceptions:
                        print '      anyone from domain %s except' % multi_condition.domain
                        for exception in multi_condition.exceptions:
                            if isinstance(exception, UserException):
                                print '        user %s' % exception.uri
                    elif isinstance(multi_condition, DomainCondition):
                        print '      anyone from domain %s' % multi_condition.domain
            if policy.provide_devices is All:
                print '    provide-devices            = All'
            elif policy.provide_devices:
                print '    provide-devices:'
                for prv in policy.provide_devices:
                    if isinstance(prv, Class):
                        print '      class                    = %s' % prv
                    elif isinstance(prv, OccurenceID):
                        print '      occurence-id             = %s' % prv
                    elif isinstance(prv, DeviceID):
                        print '      device-id                = %s' % prv
                    else:
                        print '      unknown                  = %s(%r)' % (prv, type(prv).__name__)
            if policy.provide_persons is All:
                print '    provide-persons            = All'
            elif policy.provide_persons:
                print '    provide-persons:'
                for prv in policy.provide_persons:
                    if isinstance(prv, Class):
                        print '      class                    = %s' % prv
                    elif isinstance(prv, OccurenceID):
                        print '      occurence-id             = %s' % prv
                    else:
                        print '      unknown                  = %s(%r)' % (prv, type(prv).__name__)
            if policy.provide_services is All:
                print '    provide-services           = All'
            elif policy.provide_services:
                print '    provide-services:'
                for prv in policy.provide_services:
                    if isinstance(prv, Class):
                        print '      class                    = %s' % prv
                    elif isinstance(prv, OccurenceID):
                        print '      occurence-id             = %s' % prv
                    elif isinstance(prv, ServiceURI):
                        print '      service-uri              = %s' % prv
                    elif isinstance(prv, ServiceURIScheme):
                        print '      service-uri-scheme       = %s' % prv
                    else:
                        print '      unknown                  = %s(%r)' % (prv, type(prv).__name__)
            print '    provide-activities         = %s' % policy.provide_activities
            print '    provide-class              = %s' % policy.provide_class
            print '    provide-device-id          = %s' % policy.provide_device_id
            print '    provide-mood               = %s' % policy.provide_mood
            print '    provide-place-is           = %s' % policy.provide_place_is
            print '    provide-place-type         = %s' % policy.provide_place_type
            print '    provide-privacy            = %s' % policy.provide_privacy
            print '    provide-relationship       = %s' % policy.provide_relationship
            print '    provide-status-icon        = %s' % policy.provide_status_icon
            print '    provide-sphere             = %s' % policy.provide_sphere
            print '    provide-time-offset        = %s' % policy.provide_time_offset
            print '    provide-user-input         = %s' % policy.provide_user_input
            print '    provide-unknown-attributes = %s' % policy.provide_unknown_attributes
            print '    provide-all-attributes     = %s' % policy.provide_all_attributes
            print

        print 'Dialog-info policies:'
        for policy in notification.data.dialoginfo_policies:
            print '  %s -> %s' % (policy.id, policy.action)
            if policy.sphere:
                print '    sphere                     = %s' % policy.sphere
            if policy.validity:
                print '    valid between:'
                for from_timestamp, until_timestamp in policy.validity:
                    print '      %s - %s' % (from_timestamp, until_timestamp)
            print

        print 'RLS services:'
        for service in notification.data.services:
            print '  %s -> %s' % (service.uri, ', '.join(service.packages))
            for entry in service.entries:
                print '    %s' % entry
            print

        print 'Offline status:'
        if notification.data.offline_status:
            print '  Note: %s' % notification.data.offline_status.note
            print '  Activity: %s' % notification.data.offline_status.activity
        else:
            print '  Missing'


application = XCAPApplication()
application.start()

class Stop(object):
    pass


@decorator
def command_handler(func):
    @preserve_signature(func)
    def wrapper(*args, **kw):
        try:
            return func(*args, **kw)
        except Exception, e:
            print 'Error: %s' % e
    return wrapper


class Interface(Cmd):
    prompt = 'xcap> '
    def emptyline(self):
        return

    def parse_arguments(self, line):
        s = shlex.shlex(StringIO(line))
        s.wordchars = ''.join(c for c in string.printable if c!="'" and c not in string.whitespace)
        s.quotes = "'"
        args = list(takewhile(lambda x: x, (s.get_token() for _ in count())))
        arguments = {}
        for arg in args:
            if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in ('"', "'"):
                arg = arg[1:-1]
            try:
                name, value = arg.split('=', 1)
                arguments[name] = cjson.decode(value)
            except (ValueError, cjson.DecodeError):
                continue
        return arguments

    @command_handler
    def do_start_transaction(self, line):
        application.xcap_manager.start_transaction()

    @command_handler
    def do_commit_transaction(self, line):
        application.xcap_manager.commit_transaction()

    @command_handler
    def do_add_group(self, line):
        arguments = self.parse_arguments(line)
        group = arguments.get('group')
        if not isinstance(group, basestring):
            raise ValueError('expected string group')
        application.xcap_manager.add_group(group)

    @command_handler
    def do_rename_group(self, line):
        arguments = self.parse_arguments(line)
        old_name = arguments.get('old_name')
        new_name = arguments.get('new_name')
        if not isinstance(old_name, basestring):
            raise ValueError('expected string old_name')
        if not isinstance(new_name, basestring):
            raise ValueError('expected string new_name')
        application.xcap_manager.rename_group(old_name, new_name)

    @command_handler
    def do_remove_group(self, line):
        arguments = self.parse_arguments(line)
        group = arguments.get('group')
        if not isinstance(group, basestring):
            raise ValueError('expected string group')
        application.xcap_manager.remove_group(group)

    @command_handler
    def do_add_contact(self, line):
        arguments = self.parse_arguments(line)
        contact_attrs = arguments.get('contact')
        if not isinstance(contact_attrs, dict):
            raise ValueError('expected object contact')
        contact = self.get_contact(contact_attrs)
        application.xcap_manager.add_contact(contact)

    @command_handler
    def do_update_contact(self, line):
        arguments = self.parse_arguments(line)
        contact_attrs = arguments.pop('contact', None)
        if not isinstance(contact_attrs, dict):
            raise ValueError('expected object contact')
        contact = self.get_contact(contact_attrs)
        if 'presence_policies' in arguments:
            presence_policies = arguments.pop('presence_policies')
            if presence_policies is not None and not isinstance(presence_policies, list):
                raise ValueError('expected list attribute presence_policies')
            if any(not isinstance(policy, dict) for policy in presence_policies):
                raise ValueError('expected object items in presence_policies')
            arguments['presence_policies'] = [self.get_presence_policy(policy) for policy in presence_policies]
        if 'dialoginfo_policies' in arguments:
            dialoginfo_policies = arguments.pop('dialoginfo_policies')
            if dialoginfo_policies is not None and not isinstance(dialoginfo_policies, list):
                raise ValueError('expected list attribute dialoginfo_policies')
            if any(not isinstance(policy, dict) for policy in dialoginfo_policies):
                raise ValueError('expected object items in dialoginfo_policies')
            arguments['dialoginfo_policies'] = [self.get_dialoginfo_policy(policy) for policy in dialoginfo_policies]
        application.xcap_manager.update_contact(contact, **arguments)

    @command_handler
    def do_remove_contact(self, line):
        arguments = self.parse_arguments(line)
        contact_attrs = arguments.pop('contact', None)
        if not isinstance(contact_attrs, dict):
            raise ValueError('expected object contact')
        contact = self.get_contact(contact_attrs)
        application.xcap_manager.remove_contact(contact)

    @command_handler
    def do_add_presence_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        application.xcap_manager.add_presence_policy(self.get_presence_policy(policy))

    @command_handler
    def do_update_presence_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        policy = self.get_presence_policy(policy)
        if 'validity' in arguments:
            validity = arguments.pop('validity')
            if validity is not None:
                if not isinstance(validity, list):
                    raise ValueError('expected list validity or nill')
                validity = [(Timestamp(from_timestamp), Timestamp(until_timestamp)) for from_timestamp, until_timestamp in validity]
            arguments['validity'] = validity
        multi_identity_conditions = arguments.pop('multi_identity_conditions', None)
        if multi_identity_conditions is not None and not isinstance(multi_identity_conditions, list):
            raise ValueError('expected list multi_identity_conditions or nill')
        if multi_identity_conditions is not None:
            arguments['multi_identity_conditions'] = []
            for multi_condition_attributes in multi_identity_conditions:
                if 'domain' in multi_condition_attributes:
                    multi_condition = DomainCondition(multi_condition_attributes.pop('domain'))
                else:
                    multi_condition = CatchAllCondition()
                arguments['multi_identity_conditions'].append(multi_condition)
                if multi_condition_attributes.get('exceptions', None):
                    for exception_attributes in multi_condition_attributes['exceptions']:
                        if 'domain' in exception_attributes:
                            multi_condition.exceptions.append(DomainException(exception_attributes.pop('domain')))
                        elif 'uri' in exception_attributes:
                            multi_condition.exceptions.append(UserException(exception_attributes.pop('uri')))
        application.xcap_manager.update_presence_policy(policy, **arguments)

    @command_handler
    def do_remove_presence_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        policy = self.get_presence_policy(policy)
        application.xcap_manager.remove_presence_policy(policy)

    @command_handler
    def do_add_dialoginfo_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        application.xcap_manager.add_dialoginfo_policy(self.get_dialoginfo_policy(policy))

    @command_handler
    def do_update_dialoginfo_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        policy = self.get_dialoginfo_policy(policy)
        if 'validity' in arguments:
            validity = arguments.pop('validity')
            if validity is not None:
                if not isinstance(validity, list):
                    raise ValueError('expected list validity or nill')
                validity = [(Timestamp(from_timestamp), Timestamp(until_timestamp)) for from_timestamp, until_timestamp in validity]
            arguments['validity'] = validity
        multi_identity_conditions = arguments.pop('multi_identity_conditions', None)
        if multi_identity_conditions is not None and not isinstance(multi_identity_conditions, list):
            raise ValueError('expected list multi_identity_conditions or nill')
        if multi_identity_conditions is not None:
            arguments['multi_identity_conditions'] = []
            for multi_condition_attributes in multi_identity_conditions:
                if 'domain' in multi_condition_attributes:
                    multi_condition = DomainCondition(multi_condition_attributes.pop('domain'))
                else:
                    multi_condition = CatchAllCondition()
                arguments['multi_identity_conditions'].append(multi_condition)
                if multi_condition_attributes.get('exceptions', None):
                    for exception_attributes in multi_condition_attributes['exceptions']:
                        if 'domain' in exception_attributes:
                            multi_condition.exceptions.append(DomainException(exception_attributes.pop('domain')))
                        elif 'uri' in exception_attributes:
                            multi_condition.exceptions.append(UserException(exception_attributes.pop('uri')))
        application.xcap_manager.update_dialoginfo_policy(policy, **arguments)

    @command_handler
    def do_remove_dialoginfo_policy(self, line):
        arguments = self.parse_arguments(line)
        policy = arguments.pop('policy', None)
        if not isinstance(policy, dict):
            raise ValueError('expected object policy')
        policy = self.get_dialoginfo_policy(policy)
        application.xcap_manager.remove_dialoginfo_policy(policy)

    @command_handler
    def do_set_offline_status(self, line):
        arguments = self.parse_arguments(line)
        if not arguments:
            application.xcap_manager.set_offline_status(None)
        else:
            note = arguments.pop('note', None)
            activity = arguments.pop('activity', None)
            application.xcap_manager.set_offline_status(OfflineStatus(activity, note))

    @command_handler
    def do_exit(self, line):
        application.stop()
        application.quit_event.wait()
        return Stop

    def get_contact(self, obj):
        if 'uri' not in obj:
            raise ValueError('expected string attribute uri of contact object')
        contact = Contact(obj.pop('name', None), obj.pop('uri'), obj.pop('group', None))
        presence_policies = obj.pop('presence_policies', None)
        if presence_policies is not None:
            if not isinstance(presence_policies, list):
                raise ValueError('expected list attribute presence_policies of contact object or nill')
            if any(not isinstance(policy, dict) for policy in presence_policies):
                raise ValueError('expected object items in attribute presence_policies of contact object')
            contact.presence_policies = [self.get_presence_policy(policy) for policy in presence_policies]
        dialoginfo_policies = obj.pop('dialoginfo_policies', None)
        if dialoginfo_policies is not None:
            if not isinstance(dialoginfo_policies, list):
                raise ValueError('expected list attribute dialoginfo_policies of contact object or nill')
            if any(not isinstance(policy, dict) for policy in dialoginfo_policies):
                raise ValueError('expected object items in attribute dialoginfo_policies of contact object')
            contact.dialoginfo_policies = [self.get_dialoginfo_policy(policy) for policy in dialoginfo_policies]
        for attr, value in obj.iteritems():
            if attr in ('subscribe_to_presence', 'subscribe_to_dialoginfo'):
                value = True if value == 'True' else False
            setattr(contact, attr, value)
        return contact

    def get_policy(self, cls, obj):
        policy = cls(obj.pop('id', None), obj.pop('action', None))
        policy.name = obj.pop('name', None)
        validity = obj.pop('validity', None)
        if validity is not None:
            if not isinstance(validity, list):
                raise ValueError('expected list attribute validity of policy object or nill')
            policy.validity = [(Timestamp(from_timestamp), Timestamp(until_timestamp)) for from_timestamp, until_timestamp in validity]
        sphere = obj.pop('sphere', None)
        if sphere is not None and not isinstance(sphere, basestring):
            raise ValueError('expected string attribute sphere of policy object or nill')
        policy.sphere = sphere
        multi_identity_conditions = obj.pop('multi_identity_conditions', None)
        if multi_identity_conditions is not None and not isinstance(multi_identity_conditions, list):
            raise ValueError('expected list attribute multi_identity_conditions of policy object or nill')
        if multi_identity_conditions is not None:
            policy.multi_identity_conditions = []
            for multi_condition_attributes in multi_identity_conditions:
                if 'domain' in multi_condition_attributes:
                    multi_condition = DomainCondition(multi_condition_attributes.pop('domain'))
                else:
                    multi_condition = CatchAllCondition()
                policy.multi_identity_conditions.append(multi_condition)
                if multi_condition_attributes.get('exceptions', None):
                    for exception_attributes in multi_condition_attributes['exceptions']:
                        if 'domain' in exception_attributes:
                            print 'adding exception for domain'
                            multi_condition.exceptions.append(DomainException(exception_attributes.pop('domain')))
                        elif 'uri' in exception_attributes:
                            print 'adding exception for uri'
                            multi_condition.exceptions.append(UserException(exception_attributes.pop('uri')))
        return policy

    def get_presence_policy(self, obj):
        policy = self.get_policy(PresencePolicy, obj)
        return policy

    def get_dialoginfo_policy(self, obj):
        policy = self.get_policy(DialoginfoPolicy, obj)
        return policy

    def postcmd(self, stop, line):
        if stop is Stop:
            return True

interface = Interface()
interface.cmdloop()


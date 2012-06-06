# Copyright (C) 2011 AG Projects. See LICENSE for details.
#

"""Implementation of a contact management system"""

from __future__ import absolute_import, with_statement

__all__ = ['ContactGroup', 'ContactGroupExtension', 'ContactGroupManager', 'Contact', 'ContactExtension', 'ContactManager', 'AccountContactManager', 'SharedSetting']

import sys
from itertools import chain, count
from threading import Lock
from zope.interface import implements

from application import log
from application.notification import IObserver, NotificationCenter
from application.python import Null
from application.python.decorator import execute_once
from application.python.types import Singleton
from eventlet import coros

from sipsimple.account import xcap
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroupMeta, SettingsObjectID, SettingsState, ObjectNotFoundError, DuplicateIDError, ModifiedValue, PersistentKey
from sipsimple.payloads.resourcelists import Entry, EntryAttributes, ResourceListsDocument
from sipsimple.threading import call_in_thread, call_in_twisted_thread, run_in_thread
from sipsimple.util import TimestampedNotificationData, weakobjectmap



class ContactGroup(SettingsState):
    __group__ = 'ContactGroups'
    __id__    = SettingsObjectID(type=unicode)
    __lock__  = Lock()

    id = __id__
    name = Setting(type=unicode, default=None, nillable=True)

    def __new__(cls, name, id=None):
        with ContactGroupManager.load_groups.lock:
            if not ContactGroupManager.load_groups.called:
                raise RuntimeError("cannot instantiate %s before calling ContactGroupManager.load_groups" % cls.__name__)
        with cls.__lock__:
            if id is None:
                existing_ids = set(chain(cls.__id__.values.itervalues(), cls.__id__.oldvalues.itervalues()))
                for i in count():
                    id = 'Group_%d' % i
                    if id not in existing_ids:
                        break
                else:
                    raise ValueError("Cannot generate %s id" % cls.__name__)
            elif not isinstance(id, basestring):
                raise TypeError("id needs to be a string or unicode object")
            elif id == 'None':
                raise ValueError("id cannot have the value 'None'")
            instance = SettingsState.__new__(cls)
            instance.__id__ = id
            instance.__state__ = 'new'
        configuration = ConfigurationManager()
        try:
            data = configuration.get(instance.__key__)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
            instance.__state__ = 'loaded'
        if name is not None:
            instance.name = name
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded':
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('ContactGroupWasActivated', sender=self, data=TimestampedNotificationData())

    def __repr__(self):
        return "%s(name=%r, id=%r)" % (self.__class__.__name__, self.name, self.__id__)

    @property
    def __key__(self):
        return [self.__group__, PersistentKey(self.__id__)]

    @property
    def __oldkey__(self):
        return [self.__group__, PersistentKey(self.__class__.__id__.get_old(self))]

    @run_in_thread('file-io')
    def save(self):
        """
        Use the ConfigurationManager to store the contact group in the
        ContactGroups group.

        This method will also post a ContactGroupDidChange notification,
        regardless of whether the contact group has been saved to persistent
        storage or not. If the save does fail, a CFGManagerSaveFailed
        notification is posted as well.
        """

        if self.__state__ == 'deleted':
            return

        configuration = ConfigurationManager()
        notification_center = NotificationCenter()

        oldkey = self.__oldkey__ # save this here as get_modified will reset it

        modified_id = self.__class__.__id__.get_modified(self)
        modified_settings = self.get_modified()

        if not modified_id and not modified_settings and self.__state__ != 'new':
            return

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            notification_center.post_notification('ContactGroupWasActivated', sender=self, data=TimestampedNotificationData())
            notification_center.post_notification('ContactGroupWasCreated', sender=self, data=TimestampedNotificationData())
            modified_data = None
        else:
            if modified_id:
                configuration.rename(oldkey, self.__key__)
                for account_name in configuration.get_names([Contact.__group__]):
                    group_names = configuration.get_names([Contact.__group__, account_name])
                    if modified_id.old in group_names:
                        configuration.rename([Contact.__group__, account_name, modified_id.old], [Contact.__group__, account_name, modified_id.new])
            if modified_settings:
                configuration.update(self.__key__, self.__getstate__())
            modified_data = modified_settings or {}
            if modified_id:
                modified_data['__id__'] = modified_id
            notification_center.post_notification('ContactGroupDidChange', sender=self, data=TimestampedNotificationData(modified=modified_data))

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def delete(self):
        """Remove the contact group from the persistent configuration."""

        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        from sipsimple.account import AccountManager, Account
        account_manager = AccountManager()
        contact_manager = ContactManager()
        for contact in (contact for contact in contact_manager.get_contacts() if contact.__class__.group.get_old(contact) is self):
            contact.delete()
        for contact_manager in (account.contact_manager for account in account_manager.iter_accounts() if isinstance(account, Account)):
            with contact_manager.xcap_transaction:
                for contact in (contact for contact in contact_manager.get_contacts() if contact.__class__.group.get_old(contact) is self):
                    contact.delete()
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        configuration.delete(self.__oldkey__) # we need the key that wasn't yet saved
        notification_center.post_notification('ContactGroupWasDeleted', sender=self, data=TimestampedNotificationData())
        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='delete', exception=e))

    def clone(self, new_uri):
        """Create a copy of this contact group and all its sub-settings."""
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension of this ContactGroup. All Settings and
        SettingsGroups defined in the extension will be added to this
        ContactGroup, overwriting any attributes with the same name.
        Other attributes in the extension are ignored.
        """
        if not issubclass(extension, ContactGroupExtension):
            raise TypeError("expected subclass of ContactGroupExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, (Setting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class ContactGroupExtension(object):
    """Base class for extensions of ContactGroups"""
    def __new__(self, *args, **kw):
        raise TypeError("ContactGroupExtension subclasses cannot be instantiated")


class ContactGroupManager(object):
    __metaclass__ = Singleton

    implements(IObserver)

    def __init__(self):
        self.groups = {}
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='ContactGroupWasActivated')

    @execute_once
    def load_groups(self):
        """Load all contact groups from the configuration."""
        configuration = ConfigurationManager()
        names = configuration.get_names([ContactGroup.__group__])
        [ContactGroup(name=None, id=id) for id in names]

    def start(self):
        pass

    def stop(self):
        pass

    def has_group(self, id):
        return id in self.groups

    def get_group(self, id):
        return self.groups[id]

    def get_group_byname(self, name):
        try:
            return (group for group in self.groups.values() if group.name==name).next()
        except StopIteration:
            raise KeyError(name)

    def get_groups(self):
        return self.groups.values()

    def iter_groups(self):
        return self.groups.itervalues()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_ContactGroupWasActivated(self, notification):
        group = notification.sender
        self.groups[group.id] = group
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=group, name='ContactGroupDidChange')
        notification_center.add_observer(self, sender=group, name='ContactGroupWasDeleted')
        notification_center.post_notification('ContactGroupManagerDidAddGroup', sender=self, data=TimestampedNotificationData(group=group))

    def _NH_ContactGroupWasDeleted(self, notification):
        group = notification.sender
        del self.groups[group.__class__.__id__.get_old(group)]
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=group, name='ContactGroupDidChange')
        notification_center.remove_observer(self, sender=group, name='ContactGroupWasDeleted')
        notification_center.post_notification('ContactGroupManagerDidRemoveGroup', sender=self, data=TimestampedNotificationData(group=group))

    def _NH_ContactGroupDidChange(self, notification):
        if '__id__' in notification.data.modified:
            modified_id = notification.data.modified['__id__']
            self.groups[modified_id.new] = self.groups.pop(modified_id.old)


class UndefinedValue(object):
    pass


class IdentityDescriptor(object):
    """Base class for contact's identity descriptors (uri, account and group)"""

    lock = Lock() # need a class lock because Contact IDs are correlated

    def __new__(cls):
        if cls is IdentityDescriptor:
            raise TypeError("IdentityDescriptor cannot be instantiated")
        return object.__new__(cls)

    def __init__(self):
        self.values = weakobjectmap()
        self.oldvalues = weakobjectmap()
        self.dirty = weakobjectmap()

    def __get__(self, obj, objtype):
        return self if obj is None else self.values[obj]

    def __set__(self, obj, value):
        with self.lock:
            value = self._validate_value(obj, value)
            current_value = self.values.get(obj, UndefinedValue)
            old_value = self.oldvalues.get(obj, UndefinedValue)
            if value == current_value:
                return
            elif value == old_value:
                self.values[obj] = old_value
                self.dirty[obj] = False
            else:
                self._validate_unique_id(obj, value)
                if obj in self.values:
                    self.values[obj] = value
                    self.dirty[obj] = True
                else:
                    self.values[obj] = self.oldvalues[obj] = value
                    self.dirty[obj] = False

    def _validate_value(self, obj, value):
        raise NotImplementedError

    def _validate_unique_id(self, obj, value):
        raise NotImplementedError

    def get_modified(self, obj):
        """
        Returns a ModifiedValue instance with references to the old and new
        values or None if not modified.
        """
        with self.lock:
            try:
                if self.dirty.get(obj, False):
                    return ModifiedValue(old=self.oldvalues[obj], new=self.values[obj])
                else:
                    return None
            finally:
                self.oldvalues[obj] = self.values[obj]
                self.dirty[obj] = False

    def get_values(self, obj):
        """Return a tuple with (current_value, old_value) if the value was set, else an empty tuple ()"""
        return (self.values[obj], self.oldvalues[obj]) if obj in self.values else ()

    def get_old(self, obj):
        return self.oldvalues[obj]

    def undo(self, obj):
        with self.lock:
            self.values[obj] = self.oldvalues[obj]
            self.dirty[obj] = False


class AccountDescriptor(IdentityDescriptor):
    """Descriptor represeting the account reference on a contact"""

    def _validate_value(self, obj, value):
        from sipsimple.account import Account
        if value is not None and not isinstance(value, Account):
            raise TypeError("Expected an Account instance or None")
        return value

    def _validate_unique_id(self, obj, new_account):
        cls = obj.__class__
        id_pairs = set((u, new_account) for u in cls.uri.get_values(obj))
        if not id_pairs:
            return
        for other_obj in (other_obj for other_obj in self.values.iterkeys() if other_obj is not obj):
            other_id_pairs = ((u, a) for u in cls.uri.get_values(other_obj) for a in self.get_values(other_obj))
            if id_pairs.intersection(other_id_pairs):
                raise DuplicateIDError('Contact uri/account pair already used by another Contact')


class URIDescriptor(IdentityDescriptor):
    """Descriptor represeting the URI reference on a contact"""

    def _validate_value(self, obj, value):
        if not isinstance(value, basestring):
            raise TypeError("Expected an unicode object")
        return unicode(value)

    def _validate_unique_id(self, obj, new_uri):
        cls = obj.__class__
        id_pairs = set((new_uri, a) for a in cls.account.get_values(obj))
        if not id_pairs:
            return
        for other_obj in (other_obj for other_obj in self.values.iterkeys() if other_obj is not obj):
            other_id_pairs = ((u, a) for u in self.get_values(other_obj) for a in cls.account.get_values(other_obj))
            if id_pairs.intersection(other_id_pairs):
                raise DuplicateIDError('Contact uri/account pair already used by another Contact')


class GroupDescriptor(IdentityDescriptor):
    """Descriptor represeting the group reference on a contact"""

    def _validate_value(self, obj, value):
        if value is not None and not isinstance(value, ContactGroup):
            raise TypeError("Expected a ContactGroup instance or None")
        return value

    def _validate_unique_id(self, obj, new_group):
        pass


class XCAPContact(xcap.Contact):
    """An XCAP Contact with attributes normalized to unicode"""

    __attributes__ = set()

    def __init__(self, name, uri, group, **attributes):
        normalized_attributes = dict((name, unicode(value) if value is not None else None) for name, value in attributes.iteritems() if name in self.__attributes__)
        super(XCAPContact, self).__init__(name, uri, group, **normalized_attributes)

    @classmethod
    def normalize_xcap_contact(cls, contact):
        instance = cls(contact.name, contact.uri, contact.group, **contact.attributes)
        instance.presence_policies = contact.presence_policies
        instance.dialoginfo_policies = contact.dialoginfo_policies
        instance.subscribe_to_presence = contact.subscribe_to_presence
        instance.subscribe_to_dialoginfo = contact.subscribe_to_dialoginfo
        return instance


class SharedSetting(Setting):
    """A setting that is shared by being also stored remotely in XCAP"""

    __namespace__ = None

    @classmethod
    def set_namespace(cls, namespace):
        """
        Set the XML namespace to be used for the extra shared attributes of
        a contact, when storing it in XCAP
        """
        if cls.__namespace__ is not None:
            raise RuntimeError("namespace already set to %s" % cls.__namespace__)
        cls.__namespace__ = namespace
        class ApplicationEntryAttributes(EntryAttributes):
            _xml_namespace = 'urn:%s:xml:ns:resource-lists' % namespace
        ResourceListsDocument.unregister_namespace(EntryAttributes._xml_namespace)
        ResourceListsDocument.register_namespace(ApplicationEntryAttributes._xml_namespace, prefix='%s-rl' % namespace.rsplit(':', 1)[-1])
        Entry.unregister_extension('attributes')
        Entry.register_extension('attributes', ApplicationEntryAttributes)


class Contact(SettingsState):
    __group__ = 'Contacts'

    uri = URIDescriptor()
    account = AccountDescriptor()
    group = GroupDescriptor()

    name = Setting(type=unicode, default=None, nillable=True)

    def __new__(cls, uri, group=None, account=None):
        with ContactManager.load_contacts.lock:
            if not ContactManager.load_contacts.called:
                raise RuntimeError("cannot instantiate %s before calling ContactManager.load_contacts" % cls.__name__)
        instance = SettingsState.__new__(cls)
        instance.uri = uri
        instance.account = account
        instance.group = group
        instance.__state__ = 'new'
        instance.__xcapcontact__ = None
        configuration = ConfigurationManager()
        try:
            data = configuration.get(instance.__key__)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
            instance.__state__ = 'loaded'
            attributes = dict((name, getattr(instance, name)) for name, attr in vars(cls).iteritems() if isinstance(attr, SharedSetting))
            instance.__xcapcontact__ = XCAPContact(instance.name, uri, group.name if group is not None else None, **attributes)
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded':
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('ContactWasActivated', sender=self, data=TimestampedNotificationData())

    def __repr__(self):
        return "%s(uri=%r, group=%r, account=%r)" % (self.__class__.__name__, self.uri, self.group, self.account)

    @property
    def __key__(self):
        return [self.__group__, unicode(self.account.id if self.account is not None else 'None'), unicode(self.group.id if self.group is not None else 'None'), PersistentKey(self.uri)]

    @property
    def __oldkey__(self):
        uri = self.__class__.uri.get_old(self)
        account = self.__class__.account.get_old(self)
        group = self.__class__.group.get_old(self)
        return [self.__group__, unicode(account.id if account is not None else 'None'), unicode(group.id if group is not None else 'None'), PersistentKey(uri)]

    @run_in_thread('file-io')
    def _internal_save(self, remote_xcap_contact=None):
        if self.__state__ == 'deleted':
            return

        notification_center = NotificationCenter()

        # check if the depended upon attributes are still valid
        attributes = {'group': self.group, 'account': self.account}
        invalid = [name for name, entity in attributes.iteritems() if entity is not None and entity.__state__ == 'deleted']
        if remote_xcap_contact is not None:
            if invalid == ['group']:
                self.group = ContactGroup(self.group.name)
                self.group.save()
            elif invalid:
                return
        elif invalid:
            notification_center.post_notification('ContactSaveFailed', sender=self, data=TimestampedNotificationData(invalid=invalid))
            return

        oldkey = self.__oldkey__ # save this here as get_modified will reset it

        modified_uri = self.__class__.uri.get_modified(self)
        modified_account = self.__class__.account.get_modified(self)
        modified_group = self.__class__.group.get_modified(self)
        modified_settings = self.get_modified()

        if not modified_uri and not modified_account and not modified_group and not modified_settings and self.__state__ != 'new':
            return

        old_xcapcontact = self.__xcapcontact__
        attributes = dict((name, getattr(self, name)) for name, attr in vars(self.__class__).iteritems() if isinstance(attr, SharedSetting))
        self.__xcapcontact__ = XCAPContact(self.name, self.uri, self.group.name if self.group is not None else None, **attributes)
        if remote_xcap_contact is not None: # temporarily copy them over until we support policies -Dan
            self.__xcapcontact__.presence_policies = remote_xcap_contact.presence_policies
            self.__xcapcontact__.dialoginfo_policies = remote_xcap_contact.dialoginfo_policies

        configuration = ConfigurationManager()

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            notification_center.post_notification('ContactWasActivated', sender=self, data=TimestampedNotificationData())
            notification_center.post_notification('ContactWasCreated', sender=self, data=TimestampedNotificationData())
            modified_data = None
            if remote_xcap_contact is None and self.account and self.account.xcap.discovered:
                self.account.xcap_manager.add_contact(self.__xcapcontact__)
        else:
            if modified_account or modified_uri or modified_group:
                configuration.rename(oldkey, self.__key__)
            if modified_settings:
                configuration.update(self.__key__, self.__getstate__())
            modified_data = modified_settings or {}
            if modified_uri:
                modified_data['uri'] = modified_uri
            if modified_account:
                modified_data['account'] = modified_account
            if modified_group:
                modified_data['group'] = modified_account
            notification_center.post_notification('ContactDidChange', sender=self, data=TimestampedNotificationData(modified=modified_data))
            if modified_account and modified_account.old is not None and modified_account.old.xcap.discovered:
                modified_account.old.xcap_manager.remove_contact(old_xcapcontact)
            if self.account is not None and self.account.xcap.discovered:
                if modified_account or (remote_xcap_contact or old_xcapcontact) != self.__xcapcontact__:
                    attributes = dict((name, value) for name, value in self.__xcapcontact__.__dict__.iteritems() if name!='attributes')
                    attributes.update(self.__xcapcontact__.attributes)
                    self.account.xcap_manager.update_contact(old_xcapcontact, **attributes)

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def _internal_delete(self, update_remote=True):
        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        configuration.delete(self.__oldkey__) # we need the key that wasn't yet saved
        notification_center.post_notification('ContactWasDeleted', sender=self, data=TimestampedNotificationData())
        if update_remote and self.account and self.account.xcap.discovered:
            self.account.xcap_manager.remove_contact(self.__xcapcontact__)
        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='delete', exception=e))

    def save(self):
        """
        Use the ConfigurationManager to store the contact using the uri under
        the account id and group id in the Contacts group.

        This method will also post ContactWasCreated and ContactWasActivated
        notifications on the first save or a ContactDidChange notification on
        subsequent saves, regardless of whether the contact has been saved to
        persistent storage or not. A CFGManagerSaveFailed notification is
        posted if saving to the persistent configuration storage fails.
        If the account or group were already deleted when save is called, it
        will post a ContactSaveFailed notification and will do nothing.
        """
        self._internal_save(remote_xcap_contact=None)

    def delete(self):
        """Remove the contact from the persistent configuration."""
        self._internal_delete(update_remote=True)

    def clone(self, new_uri):
        """Create a copy of this contact and all its sub-settings."""
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension of this Contact. All Settings and SettingsGroups
        defined in the extension will be added to this Contact, overwriting
        any attributes with the same name. Other attributes in the extension
        are ignored.
        """
        if not issubclass(extension, ContactExtension):
            raise TypeError("expected subclass of ContactExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, SharedSetting):
                if SharedSetting.__namespace__ is None:
                    raise RuntimeError("cannot use SharedSetting attributes without first calling SharedSetting.set_namespace")
                XCAPContact.__attributes__.add(name)
            if isinstance(attribute, (Setting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class ContactExtension(object):
    """Base class for extensions of Contacts"""
    def __new__(self, *args, **kw):
        raise TypeError("ContactExtension subclasses cannot be instantiated")


class ContactManagerBase(object):
    implements(IObserver)

    def __new__(cls, account):
        if cls is ContactManagerBase:
            raise TypeError("ContactManagerBase cannot be instantiated")
        instance = object.__new__(cls)
        instance.account = account
        instance.contacts = {}
        notification_center = NotificationCenter()
        notification_center.add_observer(instance, name='ContactWasActivated')
        notification_center.add_observer(instance, name='ContactWasDeleted')
        notification_center.add_observer(instance, name='ContactDidChange')
        return instance

    @execute_once
    def load_contacts(self):
        """Load all contacts from the configuration"""
        configuration = ConfigurationManager()
        group_manager = ContactGroupManager()
        account_id = u'None' if self.account is None else unicode(self.account.id)
        group_ids = configuration.get_names([Contact.__group__, account_id])
        for group_id in group_ids:
            names = configuration.get_names([Contact.__group__, account_id, group_id])
            group = group_manager.get_group(group_id) if group_id != 'None' else None
            [Contact(uri, group, self.account) for uri in names]

    def purge_contacts(self):
        event = coros.event()
        def delete_contacts():
            try:
                for contact in self.contacts.values():
                    contact.delete()
            except:
                call_in_twisted_thread(event.send_exception, *sys.exc_info())
            else:
                call_in_twisted_thread(event.send, None)
        call_in_thread('file-io', delete_contacts)
        event.wait()

    def start(self):
        pass

    def stop(self):
        pass

    def has_contact(self, uri):
        return uri in self.contacts

    def get_contact(self, uri):
        return self.contacts[uri]

    def get_contacts(self):
        return self.contacts.values()

    def iter_contacts(self):
        return self.contacts.itervalues()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_ContactWasActivated(self, notification):
        contact = notification.sender
        if contact.account is self.account:
            self.contacts[contact.uri] = contact
            notification_center = NotificationCenter()
            notification_center.post_notification('ContactManagerDidAddContact', sender=self, data=TimestampedNotificationData(contact=contact))

    def _NH_ContactWasDeleted(self, notification):
        contact = notification.sender
        account = contact.__class__.account.get_old(contact) # we need the old account that wasn't yet saved
        if account is self.account:
            del self.contacts[contact.__class__.uri.get_old(contact)]
            notification_center = NotificationCenter()
            notification_center.post_notification('ContactManagerDidRemoveContact', sender=self, data=TimestampedNotificationData(contact=contact))

    def _NH_ContactDidChange(self, notification):
        contact = notification.sender
        modified_account = notification.data.modified.get('account', None)
        modified_uri = notification.data.modified.get('uri', None)
        if modified_account:
            notification_center = NotificationCenter()
            if modified_account.old is self.account:
                del self.contacts[modified_uri.old if modified_uri else contact.uri]
                notification_center.post_notification('ContactManagerDidRemoveContact', sender=self, data=TimestampedNotificationData(contact=contact))
            elif modified_account.new is self.account:
                self.contacts[contact.uri] = contact
                notification_center.post_notification('ContactManagerDidAddContact', sender=self, data=TimestampedNotificationData(contact=contact))
        elif modified_uri and contact.account is self.account:
            self.contacts[modified_uri.new] = self.contacts.pop(modified_uri.old)


class AccountContactManager(ContactManagerBase):
    """Manager for contacts that belong to an account"""

    def __init__(self, account):
        self.xcap_manager = account.xcap_manager
        self.xcap_transaction = self.xcap_manager.transaction()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=account, name='CFGSettingsObjectDidChange')
        notification_center.add_observer(self, sender=account, name='CFGSettingsObjectWasDeleted')
        notification_center.add_observer(self, sender=account, name='SIPAccountDidDiscoverXCAPSupport')
        notification_center.add_observer(self, sender=self.xcap_manager, name='XCAPManagerDidReloadData')

    def purge_contacts(self):
        with self.xcap_transaction:
            ContactManagerBase.purge_contacts(self)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        if '__id__' in notification.data.modified:
            configuration = ConfigurationManager()
            modified_id = notification.data.modified['__id__']
            if modified_id.old in configuration.get_names([Contact.__group__]):
                configuration.rename([Contact.__group__, modified_id.old], [Contact.__group__, modified_id.new])

    def _NH_CFGSettingsObjectWasDeleted(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='ContactWasActivated')
        notification_center.remove_observer(self, name='ContactWasDeleted')
        notification_center.remove_observer(self, name='ContactDidChange')
        notification_center.remove_observer(self, sender=self.account, name='CFGSettingsObjectDidChange')
        notification_center.remove_observer(self, sender=self.account, name='CFGSettingsObjectWasDeleted')
        notification_center.remove_observer(self, sender=self.account, name='SIPAccountDidDiscoverXCAPSupport')
        notification_center.remove_observer(self, sender=self.xcap_manager, name='XCAPManagerDidReloadData')

    def _NH_SIPAccountDidDiscoverXCAPSupport(self, notification):
         with self.xcap_transaction:
             for contact in self.contacts.values():
                 self.xcap_manager.add_contact(contact.__xcapcontact__)

    @run_in_thread('file-io')
    def _NH_XCAPManagerDidReloadData(self, notification):
        group_manager = ContactGroupManager()
        new_contact_uris = set(contact.uri for contact in notification.data.contacts)
        for contact in (contact for contact in self.contacts.values() if contact.uri not in new_contact_uris):
            contact._internal_delete(update_remote=False)
        for xcap_contact in notification.data.contacts:
            xcap_contact = XCAPContact.normalize_xcap_contact(xcap_contact)
            try:
                contact = self.contacts[xcap_contact.uri]
            except KeyError:
                if xcap_contact.group is None:
                    group = None
                else:
                    try:
                        group = group_manager.get_group_byname(xcap_contact.group)
                    except KeyError:
                        group = ContactGroup(xcap_contact.group)
                        group.save()
                try:
                    contact = Contact(xcap_contact.uri, group, self.account)
                except DuplicateIDError:
                    continue
            else:
                if xcap_contact.group is None:
                    contact.group = None
                elif contact.group is None or contact.group.name != xcap_contact.group:
                    try:
                        group = group_manager.get_group_byname(xcap_contact.group)
                    except KeyError:
                        group = ContactGroup(xcap_contact.group)
                        group.save()
                    contact.group = group
            contact.name = xcap_contact.name
            for name, value in xcap_contact.attributes.iteritems():
                setattr(contact, name, value)
            contact._internal_save(remote_xcap_contact=xcap_contact)


class ContactManager(ContactManagerBase):
    """Manager for contacts that do not belong to an account"""

    __metaclass__ = Singleton

    def __new__(cls):
        return ContactManagerBase.__new__(cls, None)




"""Implementation of an addressbook management system"""

from __future__ import absolute_import

__all__ = ['AddressbookManager', 'Contact', 'ContactURI', 'Group', 'Policy', 'SharedSetting', 'ContactExtension', 'ContactURIExtension', 'GroupExtension', 'PolicyExtension']

from functools import reduce
from operator import attrgetter
from random import randint
from threading import Lock
from time import time
from zope.interface import implements

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from application.python.decorator import execute_once
from application.python.types import Singleton, MarkerType
from application.python.weakref import defaultweakobjectmap

from sipsimple.account import xcap, AccountManager
from sipsimple.configuration import ConfigurationManager, ObjectNotFoundError, DuplicateIDError, PersistentKey, ModifiedValue, ModifiedList
from sipsimple.configuration import AbstractSetting, RuntimeSetting, SettingsObjectImmutableID, SettingsGroup, SettingsGroupMeta, SettingsState, ItemCollection, ItemManagement
from sipsimple.payloads.addressbook import PolicyValue, ElementAttributes
from sipsimple.payloads.datatypes import ID
from sipsimple.payloads.resourcelists import ResourceListsDocument
from sipsimple.threading import run_in_thread


def unique_id(prefix='id'):
    return "%s%d%06d" % (prefix, time()*1e6, randint(0, 999999))


def recursive_getattr(obj, name):
    return reduce(getattr, name.split('.'), obj)


class Local(object):
    __metaclass__ = MarkerType


class Remote(object):
    def __init__(self, account, xcap_object):
        self.account = account
        self.xcap_object = xcap_object
    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.account, self.xcap_object)


class Setting(AbstractSetting):
    """
    Descriptor representing a setting in an addressbook object.

    Unlike a standard Setting, this one will only use the default value as a
    template to fill in a missing value and explicitly set it when saving if
    it was not specified explicitly prior to that.
    """

    def __init__(self, type, default=None, nillable=False):
        if default is None and not nillable:
            raise TypeError("default must be specified if object is not nillable")
        self.type = type
        self.default = default
        self.nillable = nillable
        self.values = defaultweakobjectmap(lambda: default)
        self.oldvalues = defaultweakobjectmap(lambda: default)
        self.dirty = defaultweakobjectmap(bool)
        self.lock = Lock()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        with self.lock:
            return self.values[obj]

    def __set__(self, obj, value):
        if value is None and not self.nillable:
            raise ValueError("setting attribute is not nillable")
        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        with self.lock:
            self.values[obj] = value
            self.dirty[obj] = value != self.oldvalues[obj]

    def __getstate__(self, obj):
        with self.lock:
            value = self.values[obj]
        if value is None:
            pass
        elif issubclass(self.type, bool):
            value = u'true' if value else u'false'
        elif issubclass(self.type, (int, long, basestring)):
            value = unicode(value)
        elif hasattr(value, '__getstate__'):
            value = value.__getstate__()
        else:
            value = unicode(value)
        return value

    def __setstate__(self, obj, value):
        if value is None and not self.nillable:
            raise ValueError("setting attribute is not nillable")
        if value is None:
            pass
        elif issubclass(self.type, bool):
            if value.lower() in ('true', 'yes', 'on', '1'):
                value = True
            elif value.lower() in ('false', 'no', 'off', '0'):
                value = False
            else:
                raise ValueError("invalid boolean value: %s" % (value,))
        elif issubclass(self.type, (int, long, basestring)):
            value = self.type(value)
        elif hasattr(self.type, '__setstate__'):
            object = self.type.__new__(self.type)
            object.__setstate__(value)
            value = object
        else:
            value = self.type(value)
        with self.lock:
            self.oldvalues[obj] = self.values[obj] = value
            self.dirty[obj] = False

    def get_modified(self, obj):
        with self.lock:
            try:
                if self.dirty[obj]:
                    return ModifiedValue(old=self.oldvalues[obj], new=self.values[obj])
                else:
                    return None
            finally:
                self.oldvalues[obj] = self.values[obj]
                self.dirty[obj] = False

    def get_old(self, obj):
        with self.lock:
            return self.oldvalues[obj]

    def undo(self, obj):
        with self.lock:
            self.values[obj] = self.oldvalues[obj]
            self.dirty[obj] = False


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
        class ApplicationElementAttributes(ElementAttributes):
            _xml_namespace = 'urn:%s:xml:ns:addressbook' % namespace
        ResourceListsDocument.unregister_namespace(ElementAttributes._xml_namespace)
        ResourceListsDocument.register_namespace(ApplicationElementAttributes._xml_namespace, prefix=namespace.rpartition(':')[2])
        for cls, attribute_name in ((cls, name) for cls in ResourceListsDocument.element_map.values() for name, elem in cls._xml_element_children.items() if elem.type is ElementAttributes):
            cls.unregister_extension(attribute_name)
            cls.register_extension(attribute_name, ApplicationElementAttributes)


class AddressbookKey(object):
    def __init__(self, section):
        self.group = 'Addressbook'
        self.section = section
    def __get__(self, obj, objtype):
        if obj is None:
            return [self.group, self.section]
        else:
            return [self.group, self.section, PersistentKey(obj.__id__)]
    def __set__(self, obj, value):
        raise AttributeError('cannot set attribute')
    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class MultiAccountTransaction(object):
    def __init__(self, accounts):
        self.accounts = accounts

    def __enter__(self):
        for account in self.accounts:
            account.xcap_manager.start_transaction()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for account in self.accounts:
            account.xcap_manager.commit_transaction()

    def __iter__(self):
        return iter(self.accounts)


class XCAPGroup(xcap.Group):
    """An XCAP Group with attributes normalized to unicode"""

    __attributes__ = set()

    def __init__(self, id, name, contacts, **attributes):
        normalized_attributes = dict((name, unicode(value) if value is not None else None) for name, value in attributes.iteritems() if name in self.__attributes__)
        contacts = [XCAPContact.normalize(contact) for contact in contacts]
        super(XCAPGroup, self).__init__(id, name, contacts, **normalized_attributes)

    @classmethod
    def normalize(cls, group):
        return cls(group.id, group.name, group.contacts, **group.attributes)

    def get_modified(self, modified_keys):
        names = set(['name'])
        attributes = dict((name, getattr(self, name)) for name in names.intersection(modified_keys))
        attributes.update((name, self.attributes[name]) for name in self.__attributes__.intersection(modified_keys))
        return attributes


class XCAPContactURI(xcap.ContactURI):
    """An XCAP ContactURI with attributes normalized to unicode"""

    __attributes__ = set()

    def __init__(self, id, uri, type, **attributes):
        normalized_attributes = dict((name, unicode(value) if value is not None else None) for name, value in attributes.iteritems() if name in self.__attributes__)
        super(XCAPContactURI, self).__init__(id, uri, type, **normalized_attributes)

    @classmethod
    def normalize(cls, uri):
        return cls(uri.id, uri.uri, uri.type, **uri.attributes)

    def get_modified(self, modified_keys):
        names = set(['uri', 'type'])
        attributes = dict((name, getattr(self, name)) for name in names.intersection(modified_keys))
        attributes.update((name, self.attributes[name]) for name in self.__attributes__.intersection(modified_keys))
        return attributes


class XCAPContact(xcap.Contact):
    """An XCAP Contact with attributes normalized to unicode"""

    __attributes__ = set()

    def __init__(self, id, name, uris, presence_handling=None, dialog_handling=None, **attributes):
        normalized_attributes = dict((name, unicode(value) if value is not None else None) for name, value in attributes.iteritems() if name in self.__attributes__)
        uris = xcap.ContactURIList((XCAPContactURI.normalize(uri) for uri in uris), default=getattr(uris, 'default', None))
        super(XCAPContact, self).__init__(id, name, uris, presence_handling, dialog_handling, **normalized_attributes)

    @classmethod
    def normalize(cls, contact):
        return cls(contact.id, contact.name, contact.uris, contact.presence, contact.dialog, **contact.attributes)

    def get_modified(self, modified_keys):
        names = set(['name', 'uris.default', 'presence.policy', 'presence.subscribe', 'dialog.policy', 'dialog.subscribe'])
        attributes = dict((name, recursive_getattr(self, name)) for name in names.intersection(modified_keys))
        attributes.update((name, self.attributes[name]) for name in self.__attributes__.intersection(modified_keys))
        return attributes


class XCAPPolicy(xcap.Policy):
    """An XCAP Policy with attributes normalized to unicode"""

    __attributes__ = set()

    def __init__(self, id, uri, name, presence_handling=None, dialog_handling=None, **attributes):
        normalized_attributes = dict((name, unicode(value) if value is not None else None) for name, value in attributes.iteritems() if name in self.__attributes__)
        super(XCAPPolicy, self).__init__(id, uri, name, presence_handling, dialog_handling, **normalized_attributes)

    @classmethod
    def normalize(cls, policy):
        return cls(policy.id, policy.uri, policy.name, policy.presence, policy.dialog, **policy.attributes)

    def get_modified(self, modified_keys):
        names = set(['uri', 'name', 'presence.policy', 'presence.subscribe', 'dialog.policy', 'dialog.subscribe'])
        attributes = dict((name, recursive_getattr(self, name)) for name in names.intersection(modified_keys))
        attributes.update((name, self.attributes[name]) for name in self.__attributes__.intersection(modified_keys))
        return attributes


class ContactListDescriptor(AbstractSetting):
    def __init__(self):
        self.values = defaultweakobjectmap(ContactList)
        self.oldvalues = defaultweakobjectmap(ContactList)
        self.lock = Lock()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        with self.lock:
            return self.values[obj]

    def __set__(self, obj, value):
        if value is None:
            raise ValueError("setting attribute is not nillable")
        elif not isinstance(value, ContactList):
            value = ContactList(value)
        with self.lock:
            self.values[obj] = value

    def __getstate__(self, obj):
        with self.lock:
            return self.values[obj].__getstate__()

    def __setstate__(self, obj, value):
        if value is None:
            raise ValueError("setting attribute is not nillable")
        object = ContactList.__new__(ContactList)
        object.__setstate__(value)
        with self.lock:
            self.values[obj] = object
            self.oldvalues[obj] = ContactList(object)

    def get_modified(self, obj):
        with self.lock:
            old = self.oldvalues[obj]
            new = self.values[obj]
            with new.lock:
                old_ids = set(old.ids())
                new_ids = set(new.ids())
                added_contacts = [new[id] for id in new_ids - old_ids]
                removed_contacts = [old[id] for id in old_ids - new_ids]
                try:
                    if added_contacts or removed_contacts:
                        return ModifiedList(added=added_contacts, removed=removed_contacts, modified=None)
                    else:
                        return None
                finally:
                    self.oldvalues[obj] = ContactList(new)

    def get_old(self, obj):
        with self.lock:
            return self.oldvalues[obj]

    def undo(self, obj):
        with self.lock:
            self.values[obj] = ContactList(self.oldvalues[obj])


class ContactList(object):
    def __new__(cls, contacts=None):
        instance = object.__new__(cls)
        instance.lock = Lock()
        return instance

    def __init__(self, contacts=None):
        self.contacts = dict((contact.id, contact) for contact in contacts or [] if contact.__state__ != 'deleted')

    def __getitem__(self, key):
        return self.contacts[key]

    def __contains__(self, key):
        return key in self.contacts

    def __iter__(self):
        return iter(sorted(self.contacts.values(), key=attrgetter('id')))

    def __reversed__(self):
        return iter(sorted(self.contacts.values(), key=attrgetter('id'), reverse=True))

    __hash__ = None

    def __len__(self):
        return len(self.contacts)

    def __eq__(self, other):
        if isinstance(other, ContactList):
            return self.contacts == other.contacts
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, sorted(self.contacts.values(), key=attrgetter('id')))

    def __getstate__(self):
        return self.contacts.keys()

    def __setstate__(self, value):
        addressbook_manager = AddressbookManager()
        for id in [id for id in value if not addressbook_manager.has_contact(id)]:
            value.remove(id)
        with self.lock:
            self.contacts = dict((id, addressbook_manager.get_contact(id)) for id in value)

    def ids(self):
        return sorted(self.contacts.keys())

    def add(self, contact):
        if contact.__state__ == 'deleted':
            return
        with self.lock:
            self.contacts[contact.id] = contact

    def remove(self, contact):
        with self.lock:
            self.contacts.pop(contact.id, None)


class Group(SettingsState):
    __key__ = AddressbookKey('Groups')
    __id__  = SettingsObjectImmutableID(type=ID)

    id = __id__
    name = Setting(type=unicode, default='')
    contacts = ContactListDescriptor()

    def __new__(cls, id=None):
        with AddressbookManager.load.lock:
            if not AddressbookManager.load.called:
                raise RuntimeError("cannot instantiate %s before calling AddressbookManager.load" % cls.__name__)
        if id is None:
            id = unique_id()
        elif not isinstance(id, basestring):
            raise TypeError("id needs to be a string or unicode object")
        instance = SettingsState.__new__(cls)
        instance.__id__ = id
        instance.__state__ = 'new'
        instance.__xcapgroup__ = None
        configuration = ConfigurationManager()
        try:
            data = configuration.get(instance.__key__)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
            instance.__state__ = 'loaded'
            instance.__xcapgroup__ = instance.__toxcap__()
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded':
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('AddressbookGroupWasActivated', sender=self)

    def __repr__(self):
        return "%s(id=%r)" % (self.__class__.__name__, self.id)

    def __toxcap__(self):
        xcap_contacts = [contact.__xcapcontact__ for contact in self.contacts]
        attributes = dict((name, getattr(self, name)) for name, attr in vars(self.__class__).iteritems() if isinstance(attr, SharedSetting))
        return XCAPGroup(self.id, self.name, xcap_contacts, **attributes)

    @run_in_thread('file-io')
    def _internal_save(self, originator):
        if self.__state__ == 'deleted':
            return

        for contact in [contact for contact in self.contacts if contact.__state__ == 'deleted']:
            self.contacts.remove(contact)

        modified_settings = self.get_modified()

        if not modified_settings and self.__state__ != 'new':
            return

        account_manager = AccountManager()
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
            previous_xcapgroup = self.__xcapgroup__
        else:
            originator_account = originator.account
            previous_xcapgroup = originator.xcap_object

        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]

        self.__xcapgroup__ = self.__toxcap__()

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            for account in (account for account in xcap_accounts if account is not originator_account):
                account.xcap_manager.add_group(self.__xcapgroup__)
            modified_data = None
            notification_center.post_notification('AddressbookGroupWasActivated', sender=self)
            notification_center.post_notification('AddressbookGroupWasCreated', sender=self)
        elif all(isinstance(self.__settings__[key], RuntimeSetting) for key in modified_settings):
            notification_center.post_notification('AddressbookGroupDidChange', sender=self, data=NotificationData(modified=modified_settings))
            return
        else:
            configuration.update(self.__key__, self.__getstate__())

            attributes = self.__xcapgroup__.get_modified(modified_settings)

            if 'contacts' in modified_settings:
                added_contacts = [contact.__xcapcontact__ for contact in modified_settings['contacts'].added]
                removed_contacts = [contact.__xcapcontact__ for contact in modified_settings['contacts'].removed]
            else:
                added_contacts = []
                removed_contacts = []

            if self.__xcapgroup__ != previous_xcapgroup:
                outofsync_accounts = xcap_accounts
            elif originator is Local:
                outofsync_accounts = []
            else:
                outofsync_accounts = list(account for account in xcap_accounts if account is not originator_account)

            with MultiAccountTransaction(outofsync_accounts):
                for account in outofsync_accounts:
                    xcap_manager = account.xcap_manager
                    for xcapcontact in added_contacts:
                        xcap_manager.add_group_member(self.__xcapgroup__, xcapcontact)
                    for xcapcontact in removed_contacts:
                        xcap_manager.remove_group_member(self.__xcapgroup__, xcapcontact)
                    if attributes:
                        xcap_manager.update_group(self.__xcapgroup__, attributes)

            notification_center.post_notification('AddressbookGroupDidChange', sender=self, data=NotificationData(modified=modified_settings))
            modified_data = modified_settings

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def _internal_delete(self, originator):
        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        configuration = ConfigurationManager()
        account_manager = AccountManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
        else:
            originator_account = originator.account

        configuration.delete(self.__key__)

        for account in (account for account in account_manager.iter_accounts() if account.xcap.discovered and account is not originator_account):
            account.xcap_manager.remove_group(self.__xcapgroup__)

        notification_center.post_notification('AddressbookGroupWasDeleted', sender=self)

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='delete', exception=e))

    def save(self):
        """
        Store the group into persistent storage (local and xcap).

        This method will post the AddressbookGroupWasCreated and
        AddressbookGroupWasActivated notifications on the first save or a
        AddressbookGroupDidChange notification on subsequent saves, regardless
        of whether the contact has been saved to persistent storage or not.
        A CFGManagerSaveFailed notification is posted if saving to the
        persistent configuration storage fails.
        """
        self._internal_save(originator=Local)

    def delete(self):
        """Remove the group from the persistent storage."""
        self._internal_delete(originator=Local)

    def clone(self, new_id=None):
        """Create a copy of this group and all its sub-settings."""
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension for this class. All Settings and SettingsGroups
        defined in the extension will be added to this class, overwriting any
        attributes with the same name. Other attributes in the extension are
        ignored.
        """
        if not issubclass(extension, GroupExtension):
            raise TypeError("expected subclass of GroupExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, SharedSetting):
                if SharedSetting.__namespace__ is None:
                    raise RuntimeError("cannot use SharedSetting attributes without first calling SharedSetting.set_namespace")
                XCAPGroup.__attributes__.add(name)
            if isinstance(attribute, (AbstractSetting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class GroupExtension(object):
    """Base class for extensions of Groups"""
    def __new__(cls, *args, **kw):
        raise TypeError("GroupExtension subclasses cannot be instantiated")


class ContactURI(SettingsState):
    __id__ = SettingsObjectImmutableID(type=ID)

    id = __id__
    uri = Setting(type=unicode, default='')
    type = Setting(type=unicode, default=None, nillable=True)

    def __new__(cls, id=None, **state):
        if id is None:
            id = unique_id()
        elif not isinstance(id, basestring):
            raise TypeError("id needs to be a string or unicode object")
        instance = SettingsState.__new__(cls)
        instance.__id__ = id
        instance.__setstate__(state)
        return instance

    def __repr__(self):
        return "%s(id=%r)" % (self.__class__.__name__, self.id)

    def __toxcap__(self):
        attributes = dict((name, getattr(self, name)) for name, attr in vars(self.__class__).iteritems() if isinstance(attr, SharedSetting))
        return XCAPContactURI(self.id, self.uri, self.type, **attributes)

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension for this class. All Settings and SettingsGroups
        defined in the extension will be added to this class, overwriting any
        attributes with the same name. Other attributes in the extension are
        ignored.
        """
        if not issubclass(extension, ContactURIExtension):
            raise TypeError("expected subclass of ContactURIExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, SharedSetting):
                if SharedSetting.__namespace__ is None:
                    raise RuntimeError("cannot use SharedSetting attributes without first calling SharedSetting.set_namespace")
                XCAPContactURI.__attributes__.add(name)
            if isinstance(attribute, (AbstractSetting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class ContactURIExtension(object):
    """Base class for extensions of ContactURIs"""
    def __new__(cls, *args, **kw):
        raise TypeError("ContactURIExtension subclasses cannot be instantiated")


class DefaultContactURI(Setting):
    def __init__(self):
        super(DefaultContactURI, self).__init__(type=str, default=None, nillable=True)

    def __get__(self, obj, objtype):
        value = super(DefaultContactURI, self).__get__(obj, objtype)
        return value if value in (self, None) else obj._item_map.get(value)

    def __set__(self, obj, value):
        if value is not None:
            if not isinstance(value, ContactURI):
                raise TypeError("the default URI must be a ContactURI instance or None")
            with obj._lock:
                if value.id not in obj._item_map:
                    raise ValueError("the default URI can only be set to one of the URIs of the contact")
                super(DefaultContactURI, self).__set__(obj, value.id)
        else:
            super(DefaultContactURI, self).__set__(obj, None)

    def get_modified(self, obj):
        modified_value = super(DefaultContactURI, self).get_modified(obj)
        if modified_value is not None:
            old_uri = obj._item_map.old.get(modified_value.old) if modified_value.old is not None else None
            new_uri = obj._item_map.get(modified_value.new) if modified_value.new is not None else None
            modified_value = ModifiedValue(old=old_uri, new=new_uri)
        return modified_value

    def get_old(self, obj):
        value = super(DefaultContactURI, self).get_old(obj)
        return value if value is None else obj._item_map.old.get(value)


class ContactURIManagement(ItemManagement):
    def remove_item(self, item, collection):
        if collection.default is item:
            collection.default = None

    def set_items(self, items, collection):
        if collection.default is not None and collection.default not in items:
            collection.default = None


class ContactURIList(ItemCollection):
    _item_type = ContactURI
    _item_management = ContactURIManagement()

    default = DefaultContactURI()


class DialogSettings(SettingsGroup):
    policy = Setting(type=PolicyValue, default='default')
    subscribe = Setting(type=bool, default=False)


class PresenceSettings(SettingsGroup):
    policy = Setting(type=PolicyValue, default='default')
    subscribe = Setting(type=bool, default=False)


class Contact(SettingsState):
    __key__ = AddressbookKey('Contacts')
    __id__  = SettingsObjectImmutableID(type=ID)

    id = __id__
    name = Setting(type=unicode, default='')
    uris = ContactURIList
    dialog = DialogSettings
    presence = PresenceSettings

    def __new__(cls, id=None):
        with AddressbookManager.load.lock:
            if not AddressbookManager.load.called:
                raise RuntimeError("cannot instantiate %s before calling AddressbookManager.load" % cls.__name__)
        if id is None:
            id = unique_id()
        elif not isinstance(id, basestring):
            raise TypeError("id needs to be a string or unicode object")
        instance = SettingsState.__new__(cls)
        instance.__id__ = id
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
            instance.__xcapcontact__ = instance.__toxcap__()
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded':
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('AddressbookContactWasActivated', sender=self)

    def __repr__(self):
        return "%s(id=%r)" % (self.__class__.__name__, self.id)

    def __toxcap__(self):
        contact_uris = xcap.ContactURIList((uri.__toxcap__() for uri in self.uris), default=self.uris.default.id if self.uris.default is not None else None)
        dialog_handling = xcap.EventHandling(self.dialog.policy, self.dialog.subscribe)
        presence_handling = xcap.EventHandling(self.presence.policy, self.presence.subscribe)
        attributes = dict((name, getattr(self, name)) for name, attr in vars(self.__class__).iteritems() if isinstance(attr, SharedSetting))
        return XCAPContact(self.id, self.name, contact_uris, presence_handling, dialog_handling, **attributes)

    @run_in_thread('file-io')
    def _internal_save(self, originator):
        if self.__state__ == 'deleted':
            return

        modified_settings = self.get_modified()

        if not modified_settings and self.__state__ != 'new':
            return

        account_manager = AccountManager()
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
            previous_xcapcontact = self.__xcapcontact__
        else:
            originator_account = originator.account
            previous_xcapcontact = originator.xcap_object

        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]

        self.__xcapcontact__ = self.__toxcap__()

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            for account in (account for account in xcap_accounts if account is not originator_account):
                account.xcap_manager.add_contact(self.__xcapcontact__)
            modified_data = None
            notification_center.post_notification('AddressbookContactWasActivated', sender=self)
            notification_center.post_notification('AddressbookContactWasCreated', sender=self)
        elif all(isinstance(self.__settings__[key], RuntimeSetting) for key in modified_settings):
            notification_center.post_notification('AddressbookContactDidChange', sender=self, data=NotificationData(modified=modified_settings))
            return
        else:
            configuration.update(self.__key__, self.__getstate__())

            contact_attributes = self.__xcapcontact__.get_modified(modified_settings)

            if 'uris' in modified_settings:
                xcap_uris = self.__xcapcontact__.uris
                added_uris = [xcap_uris[uri.id] for uri in modified_settings['uris'].added]
                removed_uris = [uri.__toxcap__() for uri in modified_settings['uris'].removed]
                modified_uris = dict((xcap_uris[id], xcap_uris[id].get_modified(changemap)) for id, changemap in modified_settings['uris'].modified.iteritems())
            else:
                added_uris = []
                removed_uris = []
                modified_uris = {}

            if self.__xcapcontact__ != previous_xcapcontact:
                outofsync_accounts = xcap_accounts
            elif originator is Local:
                outofsync_accounts = []
            else:
                outofsync_accounts = list(account for account in xcap_accounts if account is not originator_account)

            with MultiAccountTransaction(outofsync_accounts):
                for account in outofsync_accounts:
                    xcap_manager = account.xcap_manager
                    for xcapuri in added_uris:
                        xcap_manager.add_contact_uri(self.__xcapcontact__, xcapuri)
                    for xcapuri in removed_uris:
                        xcap_manager.remove_contact_uri(self.__xcapcontact__, xcapuri)
                    for xcapuri, uri_attributes in modified_uris.iteritems():
                        xcap_manager.update_contact_uri(self.__xcapcontact__, xcapuri, uri_attributes)
                    if contact_attributes:
                        xcap_manager.update_contact(self.__xcapcontact__, contact_attributes)

            notification_center.post_notification('AddressbookContactDidChange', sender=self, data=NotificationData(modified=modified_settings))
            modified_data = modified_settings

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def _internal_delete(self, originator):
        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        configuration = ConfigurationManager()
        account_manager = AccountManager()
        addressbook_manager = AddressbookManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
        else:
            originator_account = originator.account

        configuration.delete(self.__key__)

        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]
        with MultiAccountTransaction(xcap_accounts):
            for group in (group for group in addressbook_manager.get_groups() if self.id in group.contacts):
                group.contacts.remove(self)
                group.save()
            for account in (account for account in xcap_accounts if account is not originator_account):
                account.xcap_manager.remove_contact(self.__xcapcontact__)

        notification_center.post_notification('AddressbookContactWasDeleted', sender=self)

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='delete', exception=e))

    def save(self):
        """
        Store the contact into persistent storage (local and xcap).

        This method will post the AddressbookContactWasCreated and
        AddressbookContactWasActivated notifications on the first save or
        a AddressbookContactDidChange notification on subsequent saves,
        regardless of whether the contact has been saved to persistent
        storage or not. A CFGManagerSaveFailed notification is posted
        if saving to the persistent configuration storage fails.
        """
        self._internal_save(originator=Local)

    def delete(self):
        """Remove the contact from the persistent storage."""
        self._internal_delete(originator=Local)

    def clone(self, new_id=None):
        """Create a copy of this contact and all its sub-settings."""
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension for this class. All Settings and SettingsGroups
        defined in the extension will be added to this class, overwriting any
        attributes with the same name. Other attributes in the extension are
        ignored.
        """
        if not issubclass(extension, ContactExtension):
            raise TypeError("expected subclass of ContactExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, SharedSetting):
                if SharedSetting.__namespace__ is None:
                    raise RuntimeError("cannot use SharedSetting attributes without first calling SharedSetting.set_namespace")
                XCAPContact.__attributes__.add(name)
            if isinstance(attribute, (AbstractSetting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class ContactExtension(object):
    """Base class for extensions of Contacts"""
    def __new__(cls, *args, **kw):
        raise TypeError("ContactExtension subclasses cannot be instantiated")


class Policy(SettingsState):
    __key__ = AddressbookKey('Policies')
    __id__  = SettingsObjectImmutableID(type=ID)

    id = __id__
    uri  = Setting(type=unicode, default='')
    name = Setting(type=unicode, default='')
    dialog = DialogSettings
    presence = PresenceSettings

    def __new__(cls, id=None):
        with AddressbookManager.load.lock:
            if not AddressbookManager.load.called:
                raise RuntimeError("cannot instantiate %s before calling AddressbookManager.load" % cls.__name__)
        if id is None:
            id = unique_id()
        elif not isinstance(id, basestring):
            raise TypeError("id needs to be a string or unicode object")
        instance = SettingsState.__new__(cls)
        instance.__id__ = id
        instance.__state__ = 'new'
        instance.__xcappolicy__ = None
        configuration = ConfigurationManager()
        try:
            data = configuration.get(instance.__key__)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
            instance.__state__ = 'loaded'
            instance.__xcappolicy__ = instance.__toxcap__()
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded':
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('AddressbookPolicyWasActivated', sender=self)

    def __repr__(self):
        return "%s(id=%r)" % (self.__class__.__name__, self.id)

    def __toxcap__(self):
        dialog_handling = xcap.EventHandling(self.dialog.policy, self.dialog.subscribe)
        presence_handling = xcap.EventHandling(self.presence.policy, self.presence.subscribe)
        attributes = dict((name, getattr(self, name)) for name, attr in vars(self.__class__).iteritems() if isinstance(attr, SharedSetting))
        return XCAPPolicy(self.id, self.uri, self.name, presence_handling, dialog_handling, **attributes)

    @run_in_thread('file-io')
    def _internal_save(self, originator):
        if self.__state__ == 'deleted':
            return

        modified_settings = self.get_modified()

        if not modified_settings and self.__state__ != 'new':
            return

        account_manager = AccountManager()
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
            previous_xcappolicy = self.__xcappolicy__
        else:
            originator_account = originator.account
            previous_xcappolicy = originator.xcap_object

        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]

        self.__xcappolicy__ = self.__toxcap__()

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            for account in (account for account in xcap_accounts if account is not originator_account):
                account.xcap_manager.add_policy(self.__xcappolicy__)
            modified_data = None
            notification_center.post_notification('AddressbookPolicyWasActivated', sender=self)
            notification_center.post_notification('AddressbookPolicyWasCreated', sender=self)
        elif all(isinstance(self.__settings__[key], RuntimeSetting) for key in modified_settings):
            notification_center.post_notification('AddressbookPolicyDidChange', sender=self, data=NotificationData(modified=modified_settings))
            return
        else:
            configuration.update(self.__key__, self.__getstate__())

            attributes = self.__xcappolicy__.get_modified(modified_settings)

            if self.__xcappolicy__ != previous_xcappolicy:
                outofsync_accounts = xcap_accounts
            elif originator is Local:
                outofsync_accounts = []
            else:
                outofsync_accounts = list(account for account in xcap_accounts if account is not originator_account)

            for account in outofsync_accounts:
                account.xcap_manager.update_policy(self.__xcappolicy__, attributes)

            notification_center.post_notification('AddressbookPolicyDidChange', sender=self, data=NotificationData(modified=modified_settings))
            modified_data = modified_settings

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def _internal_delete(self, originator):
        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        configuration = ConfigurationManager()
        account_manager = AccountManager()
        notification_center = NotificationCenter()

        if originator is Local:
            originator_account = None
        else:
            originator_account = originator.account

        configuration.delete(self.__key__)

        for account in (account for account in account_manager.iter_accounts() if account.xcap.discovered and account is not originator_account):
            account.xcap_manager.remove_policy(self.__xcappolicy__)

        notification_center.post_notification('AddressbookPolicyWasDeleted', sender=self)

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=NotificationData(object=self, operation='delete', exception=e))

    def save(self):
        """
        Store the policy into persistent storage (local and xcap).

        It will post the AddressbookPolicyWasCreated and
        AddressbookPolicyWasActivated notifications on the first save or
        a AddressbookPolicyDidChange notification on subsequent saves,
        regardless of whether the policy has been saved to persistent
        storage or not. A CFGManagerSaveFailed notification is posted
        if saving to the persistent configuration storage fails.
        """
        self._internal_save(originator=Local)

    def delete(self):
        """Remove the policy from the persistent storage."""
        self._internal_delete(originator=Local)

    def clone(self, new_id=None):
        """Create a copy of this policy and all its sub-settings."""
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension for this class. All Settings and SettingsGroups
        defined in the extension will be added to this class, overwriting any
        attributes with the same name. Other attributes in the extension are
        ignored.
        """
        if not issubclass(extension, PolicyExtension):
            raise TypeError("expected subclass of PolicyExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, SharedSetting):
                if SharedSetting.__namespace__ is None:
                    raise RuntimeError("cannot use SharedSetting attributes without first calling SharedSetting.set_namespace")
                XCAPPolicy.__attributes__.add(name)
            if isinstance(attribute, (AbstractSetting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class PolicyExtension(object):
    """Base class for extensions of Policies"""
    def __new__(cls, *args, **kw):
        raise TypeError("PolicyExtension subclasses cannot be instantiated")


class AddressbookManager(object):
    __metaclass__ = Singleton

    implements(IObserver)

    def __init__(self):
        self.contacts = {}
        self.groups = {}
        self.policies = {}
        self.__xcapaddressbook__ = None
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='AddressbookContactWasActivated')
        notification_center.add_observer(self, name='AddressbookContactWasDeleted')
        notification_center.add_observer(self, name='AddressbookGroupWasActivated')
        notification_center.add_observer(self, name='AddressbookGroupWasDeleted')
        notification_center.add_observer(self, name='AddressbookPolicyWasActivated')
        notification_center.add_observer(self, name='AddressbookPolicyWasDeleted')
        notification_center.add_observer(self, name='SIPAccountDidDiscoverXCAPSupport')
        notification_center.add_observer(self, name='XCAPManagerDidReloadData')

    @execute_once
    def load(self):
        configuration = ConfigurationManager()

        # temporary workaround to migrate contacts to the new format. to be removed later. -Dan
        if 'Contacts' in configuration.data or 'ContactGroups' in configuration.data:
            account_manager = AccountManager()
            old_data = dict(contacts=configuration.data.pop('Contacts', {}), groups=configuration.data.pop('ContactGroups', {}))
            if any(account.enabled and account.xcap.enabled and account.xcap.discovered for account in account_manager.get_accounts()):
                self.__old_data = old_data
            else:
                self.__migrate_contacts(old_data)
            return

        [Contact(id=id) for id in configuration.get_names(Contact.__key__)]
        [Group(id=id) for id in configuration.get_names(Group.__key__)]
        [Policy(id=id) for id in configuration.get_names(Policy.__key__)]

    def start(self):
        pass

    def stop(self):
        pass

    def has_contact(self, id):
        return id in self.contacts

    def get_contact(self, id):
        return self.contacts[id]

    def get_contacts(self):
        return self.contacts.values()

    def has_group(self, id):
        return id in self.groups

    def get_group(self, id):
        return self.groups[id]

    def get_groups(self):
        return self.groups.values()

    def has_policy(self, id):
        return id in self.policies

    def get_policy(self, id):
        return self.policies[id]

    def get_policies(self):
        return self.policies.values()

    @classmethod
    def transaction(cls):
        account_manager = AccountManager()
        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]
        return MultiAccountTransaction(xcap_accounts)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_AddressbookContactWasActivated(self, notification):
        contact = notification.sender
        self.contacts[contact.id] = contact
        notification.center.post_notification('AddressbookManagerDidAddContact', sender=self, data=NotificationData(contact=contact))

    def _NH_AddressbookContactWasDeleted(self, notification):
        contact = notification.sender
        del self.contacts[contact.id]
        notification.center.post_notification('AddressbookManagerDidRemoveContact', sender=self, data=NotificationData(contact=contact))

    def _NH_AddressbookGroupWasActivated(self, notification):
        group = notification.sender
        self.groups[group.id] = group
        notification.center.post_notification('AddressbookManagerDidAddGroup', sender=self, data=NotificationData(group=group))

    def _NH_AddressbookGroupWasDeleted(self, notification):
        group = notification.sender
        del self.groups[group.id]
        notification.center.post_notification('AddressbookManagerDidRemoveGroup', sender=self, data=NotificationData(group=group))

    def _NH_AddressbookPolicyWasActivated(self, notification):
        policy = notification.sender
        self.policies[policy.id] = policy
        notification.center.post_notification('AddressbookManagerDidAddPolicy', sender=self, data=NotificationData(policy=policy))

    def _NH_AddressbookPolicyWasDeleted(self, notification):
        policy = notification.sender
        del self.policies[policy.id]
        notification.center.post_notification('AddressbookManagerDidRemovePolicy', sender=self, data=NotificationData(policy=policy))

    @run_in_thread('file-io')
    def _NH_SIPAccountDidDiscoverXCAPSupport(self, notification):
        xcap_manager = notification.sender.xcap_manager
        with xcap_manager.transaction():
            for contact in self.contacts.values():
                xcap_manager.add_contact(contact.__xcapcontact__)
            for group in self.groups.values():
                xcap_manager.add_group(group.__xcapgroup__)
            for policy in self.policies.values():
                xcap_manager.add_policy(policy.__xcappolicy__)

    @run_in_thread('file-io')
    def _NH_XCAPManagerDidReloadData(self, notification):
        if notification.data.addressbook == self.__xcapaddressbook__:
            return

        self.__xcapaddressbook__ = notification.data.addressbook

        xcap_manager = notification.sender
        xcap_contacts = notification.data.addressbook.contacts
        xcap_groups = notification.data.addressbook.groups
        xcap_policies = notification.data.addressbook.policies

        account_manager = AccountManager()
        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]

        # temporary workaround to migrate contacts to the new format. to be removed later. -Dan
        if hasattr(self, '_AddressbookManager__old_data'):
            old_data = self.__old_data
            del self.__old_data
            if not xcap_contacts and not xcap_groups:
                self.__migrate_contacts(old_data)
                return

        with MultiAccountTransaction(xcap_accounts):
            # because groups depend on contacts, operation order is add/update contacts, add/update/remove groups & policies, remove contacts -Dan

            for xcap_contact in xcap_contacts:
                xcap_contact = XCAPContact.normalize(xcap_contact)
                try:
                    contact = self.contacts[xcap_contact.id]
                except KeyError:
                    try:
                        contact = Contact(xcap_contact.id)
                    except DuplicateIDError:
                        log.err()
                        continue
                contact.name = xcap_contact.name
                contact.presence.policy = xcap_contact.presence.policy
                contact.presence.subscribe = xcap_contact.presence.subscribe
                contact.dialog.policy = xcap_contact.dialog.policy
                contact.dialog.subscribe = xcap_contact.dialog.subscribe
                for name, value in xcap_contact.attributes.iteritems():
                    setattr(contact, name, value)
                for xcap_uri in xcap_contact.uris:
                    xcap_uri = XCAPContactURI.normalize(xcap_uri)
                    try:
                        uri = contact.uris[xcap_uri.id]
                    except KeyError:
                        try:
                            uri = ContactURI(xcap_uri.id)
                        except DuplicateIDError:
                            log.err()
                            continue
                        contact.uris.add(uri)
                    uri.uri = xcap_uri.uri
                    uri.type = xcap_uri.type
                    for name, value in xcap_uri.attributes.iteritems():
                        setattr(uri, name, value)
                for uri in (uri for uri in list(contact.uris) if uri.id not in xcap_contact.uris):
                    contact.uris.remove(uri)
                contact.uris.default = contact.uris.get(xcap_contact.uris.default, None)
                contact._internal_save(originator=Remote(xcap_manager.account, xcap_contact))

            for xcap_group in xcap_groups:
                xcap_group = XCAPGroup.normalize(xcap_group)
                try:
                    group = self.groups[xcap_group.id]
                except KeyError:
                    try:
                        group = Group(xcap_group.id)
                    except DuplicateIDError:
                        log.err()
                        continue
                group.name = xcap_group.name
                for name, value in xcap_group.attributes.iteritems():
                    setattr(group, name, value)
                old_contact_ids = set(group.contacts.ids())
                new_contact_ids = set(xcap_group.contacts.ids())
                for contact in (self.contacts[id] for id in new_contact_ids - old_contact_ids):
                    group.contacts.add(contact)
                for contact in (group.contacts[id] for id in old_contact_ids - new_contact_ids):
                    group.contacts.remove(contact)
                group._internal_save(originator=Remote(xcap_manager.account, xcap_group))

            for xcap_policy in xcap_policies:
                xcap_policy = XCAPPolicy.normalize(xcap_policy)
                try:
                    policy = self.policies[xcap_policy.id]
                except KeyError:
                    try:
                        policy = Policy(xcap_policy.id)
                    except DuplicateIDError:
                        log.err()
                        continue
                policy.uri = xcap_policy.uri
                policy.name = xcap_policy.name
                policy.presence.policy = xcap_policy.presence.policy
                policy.presence.subscribe = xcap_policy.presence.subscribe
                policy.dialog.policy = xcap_policy.dialog.policy
                policy.dialog.subscribe = xcap_policy.dialog.subscribe
                for name, value in xcap_policy.attributes.iteritems():
                    setattr(policy, name, value)
                policy._internal_save(originator=Remote(xcap_manager.account, xcap_policy))

            originator = Remote(xcap_manager.account, None)
            for policy in (policy for policy in self.policies.values() if policy.id not in xcap_policies):
                policy._internal_delete(originator=originator)
            for group in (group for group in self.groups.values() if group.id not in xcap_groups):
                group._internal_delete(originator=originator)
            for contact in (contact for contact in self.contacts.values() if contact.id not in xcap_contacts):
                contact._internal_delete(originator=originator)

    def __migrate_contacts(self, old_data):
        account_manager = AccountManager()
        xcap_accounts = [account for account in account_manager.get_accounts() if account.xcap.discovered]
        with MultiAccountTransaction(xcap_accounts):
            # restore the old contacts and groups
            old_groups = old_data['groups']
            old_contacts = old_data['contacts']
            group_idmap = {}
            for group_id, group_state in old_groups.iteritems():
                group_idmap[group_id] = group = Group()
                for name, value in group_state.iteritems():
                    try:
                        setattr(group, name, value)
                    except (ValueError, TypeError):
                        pass
            for account_id, account_contacts in old_contacts.iteritems():
                for group_id, contact_map in account_contacts.iteritems():
                    for uri, contact_data in contact_map.iteritems():
                        contact = Contact()
                        for name, value in contact_data.iteritems():
                            try:
                                setattr(contact, name, value)
                            except (ValueError, TypeError):
                                pass
                        contact.uris.add(ContactURI(uri=uri))
                        contact.save()
                        group = group_idmap.get(group_id, Null)
                        group.contacts.add(contact)
            for group in group_idmap.itervalues():
                group.save()



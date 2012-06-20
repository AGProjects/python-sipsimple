# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Generic configuration management"""

from __future__ import with_statement

__all__ = ['ConfigurationManager', 'ConfigurationError', 'ObjectNotFoundError', 'DuplicateIDError', 'DefaultValue',
           'Setting', 'CorrelatedSetting', 'SettingsStateMeta', 'SettingsState', 'SettingsGroup', 'SettingsObjectID',
           'SettingsObjectImmutableID', 'SettingsObject', 'SettingsObjectExtension']

from itertools import chain
from threading import Lock

from application import log
from application.notification import NotificationCenter
from application.python.descriptor import isdescriptor
from application.python.types import Singleton
from backports.weakref import WeakSet

from sipsimple.threading import run_in_thread
from sipsimple.util import TimestampedNotificationData, weakobjectmap


## Exceptions

class ConfigurationError(Exception): pass
class ObjectNotFoundError(ConfigurationError): pass

class DuplicateIDError(ValueError): pass


class PersistentKey(unicode):
    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, unicode.__repr__(self))


## ConfigurationManager

class ConfigurationManager(object):
    """
    Singleton class used for storing and retrieving options, organized in
    sections. A section contains a list of objects, each with an assigned name
    which allows access to the object.
    """
    __metaclass__ = Singleton

    def __init__(self):
        self.backend = None
        self.data = None

    def start(self):
        """
        Initialize the ConfigurationManager to use the specified backend. This
        method can only be called once, with an object which provides IBackend.
        The other methods of the object cannot be used unless this method was
        called.
        """
        from sipsimple.application import SIPApplication
        from sipsimple.configuration.backend import IConfigurationBackend
        if self.backend is not None:
            raise RuntimeError("ConfigurationManager already started")
        if SIPApplication.storage is None:
            raise RuntimeError("SIPApplication.storage must be defined before starting the ConfigurationManager")
        backend = SIPApplication.storage.configuration_backend
        if not IConfigurationBackend.providedBy(backend):
            raise TypeError("SIPApplication.storage.configuration_backend must implement the IConfigurationBackend interface")
        self.data = backend.load()
        self.backend = backend

    def update(self, key, data):
        """
        Save the object's data under the tree path specified by key (a list
        of strings). Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if not key:
            raise KeyError("key cannot be empty")
        self._update(self.data, list(key), data)

    def rename(self, old_key, new_key):
        """
        Rename the object identified by old_key to new_key (list of strings).
        Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if not old_key or not new_key:
            raise KeyError("old_key and/or new_key cannot be empty")
        try:
            data = self._pop(self.data, list(old_key))
        except KeyError:
            raise ObjectNotFoundError("object %s does not exist" % '/'.join(old_key))
        self._insert(self.data, list(new_key), data)

    def delete(self, key):
        """
        Delete the object in the tree path specified by key (list of strings).
        Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if not key:
            raise KeyError("key cannot be empty")
        try:
            self._pop(self.data, list(key))
        except KeyError:
            pass

    def get(self, key):
        """
        Get the object in the tree path specified by key (list of strings).
        Raises ObjectNotFoundError if the object does not exist. Cannot be
        called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if not key:
            raise KeyError("key cannot be empty")
        try:
            return self._get(self.data, list(key))
        except KeyError:
            raise ObjectNotFoundError("object %s does not exist" % '/'.join(key))

    def get_names(self, key):
        """
        Get all the names under the specified key (a list of strings).
        Returns a list containing the names. Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if not key:
            raise KeyError("key cannot be empty")
        try:
            data = self._get(self.data, list(key))
            return data.keys()
        except KeyError:
            return []

    def save(self):
        """
        Flush the modified objects. Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        self.backend.save(self.data)

    def _get(self, data_tree, key):
        subtree_key = key.pop(0)
        data_subtree = data_tree[subtree_key]
        if key:
            return self._get(data_subtree, key)
        else:
            return data_subtree

    def _insert(self, data_tree, key, data):
        subtree_key = key.pop(0)
        data_subtree = data_tree.setdefault(subtree_key, {})
        if key:
            self._insert(data_subtree, key, data)
        else:
            data_subtree.update(data)

    def _pop(self, data_tree, key):
        subtree_key = key.pop(0)
        data_subtree = data_tree[subtree_key]
        if key:
            data = self._pop(data_subtree, key)
            if not isinstance(subtree_key, PersistentKey) and not data_subtree:
                del data_tree[subtree_key]
            return data
        else:
            return data_tree.pop(subtree_key)

    def _update(self, data_tree, key, data):
        subtree_key = key.pop(0)
        data_subtree = data_tree.setdefault(subtree_key, {})
        if key:
            self._update(data_subtree, key, data)
        else:
            self._update_dict(data_subtree, data)
        if not isinstance(subtree_key, PersistentKey) and not data_subtree:
            del data_tree[subtree_key]

    def _update_dict(self, old_data, new_data):
        for key, value in new_data.iteritems():
            if value is DefaultValue:
                old_data.pop(key, None)
            elif type(value) is dict:
                if key in old_data and type(old_data[key]) is not dict:
                    del old_data[key]
                self._update_dict(old_data.setdefault(key, {}), value)
                if not old_data[key]:
                    del old_data[key]
            else:
                old_data[key] = value


## Descriptors and base classes used for represeting configuration settings

class DefaultValue(object):
    """
    This object can be set as the value for a setting and it will reset the
    setting to the default value.
    """


class ModifiedValue(object):
    """
    Instances of this class represent the state (the old and new values) of
    settings.
    """

    __slots__ = ('old', 'new')

    def __init__(self, old, new):
        self.old = old
        self.new = new

    def __repr__(self):
        return '%s(old=%r, new=%r)' % (self.__class__.__name__, self.old, self.new)


class SettingsObjectID(object):
    """
    Descriptor for dynamic configuration object IDs.
    """

    def __init__(self, type):
        self.type = type
        self.values = weakobjectmap()
        self.oldvalues = weakobjectmap()
        self.dirty = weakobjectmap()
        self.lock = Lock()

    def __get__(self, obj, objtype):
        return self if obj is None else self.values[obj]

    def __set__(self, obj, value):
        with self.lock:
            if not isinstance(value, self.type):
                value = self.type(value)
            if obj in self.values and self.values[obj] == value:
                return
            if obj in self.oldvalues and self.oldvalues[obj] == value:
                self.values[obj] = self.oldvalues[obj]
                self.dirty[obj] = False
                return
            try:
                other_obj = (key for key, val in chain(self.values.iteritems(), self.oldvalues.iteritems()) if val==value).next()
            except StopIteration:
                pass
            else:
                raise DuplicateIDError('SettingsObject ID already used by another %s' % other_obj.__class__.__name__)
            if obj in self.values:
                self.values[obj] = value
                self.dirty[obj] = True
            else:
                self.values[obj] = self.oldvalues[obj] = value
                self.dirty[obj] = False

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

    def get_old(self, obj):
        return self.oldvalues[obj]

    def undo(self, obj):
        with self.lock:
            self.values[obj] = self.oldvalues[obj]
            self.dirty[obj] = False


class SettingsObjectImmutableID(object):
    """
    Descriptor for immutable runtime allocated configuration object IDs.
    """

    def __init__(self, type):
        self.type = type
        self.values = weakobjectmap()
        self.lock = Lock()

    def __get__(self, obj, objtype):
        return self if obj is None else self.values[obj]

    def __set__(self, obj, value):
        with self.lock:
            if obj in self.values:
                raise AttributeError('attribute is read-only')
            if not isinstance(value, self.type):
                value = self.type(value)
            try:
                other_obj = (key for key, val in self.values.iteritems() if val==value).next()
            except StopIteration:
                pass
            else:
                raise DuplicateIDError('SettingsObject ID already used by another %s' % other_obj.__class__.__name__)
            self.values[obj] = value


class Setting(object):
    """
    Descriptor represeting a setting in a configuration object.

    If a setting is set to the object DefaultValue, it will be reset to the
    default. Also, only Setting attributes with nillable=True can be assigned
    the value None. All other values are passed to the type specified.
    """
    def __init__(self, type, default=None, nillable=False):
        if default is None and not nillable:
            raise TypeError("default must be specified if object is not nillable")
        self.type = type
        self.default = default
        self.nillable = nillable
        self.values = weakobjectmap()
        self.oldvalues = weakobjectmap()
        self.dirty = weakobjectmap()
        self.lock = Lock()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        return self.values.get(obj, self.default)

    def __set__(self, obj, value):
        with self.lock:
            if value is None and not self.nillable:
                raise ValueError("setting attribute is not nillable")
            if value is DefaultValue:
                if obj in self.values:
                    self.values.pop(obj)
                    self.dirty[obj] = obj in self.oldvalues
                return

            if value is not None and not isinstance(value, self.type):
                value = self.type(value)
            if obj in self.values and self.values[obj] == value:
                return
            self.values[obj] = value
            self.dirty[obj] = value != self.oldvalues.get(obj, DefaultValue)

    def __getstate__(self, obj):
        value = self.values.get(obj, DefaultValue)
        if value in (None, DefaultValue):
            pass
        elif issubclass(self.type, bool):
            value = u'true' if value else u'false'
        elif issubclass(self.type, (int, long, basestring)):
            value = unicode(value)
        else:
            try:
                value = value.__getstate__()
            except AttributeError:
                raise TypeError("Setting type %s does not provide __getstate__" % value.__class__.__name__)
        return value

    def __setstate__(self, obj, value):
        with self.lock:
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
            else:
                object = self.type.__new__(self.type)
                object.__setstate__(value)
                value = object
            self.oldvalues[obj] = self.values[obj] = value
            self.dirty[obj] = False

    def get_old(self, obj):
        return self.oldvalues.get(obj, self.default)

    def get_modified(self, obj):
        """
        Returns a ModifiedValue instance with references to the old and new
        values or None if not modified.
        """
        with self.lock:
            try:
                if self.dirty.get(obj, False):
                    return ModifiedValue(old=self.oldvalues.get(obj, self.default), new=self.values.get(obj, self.default))
                else:
                    return None
            finally:
                try:
                    self.oldvalues[obj] = self.values[obj]
                except KeyError:
                    self.oldvalues.pop(obj, None)
                self.dirty[obj] = False

    def undo(self, obj):
        with self.lock:
            if obj in self.oldvalues:
                self.values[obj] = self.oldvalues[obj]
            else:
                self.values.pop(obj, None)
            self.dirty[obj] = False


class CorrelatedSetting(Setting):
    """
    Descriptor represeting a setting in a configuration object that is
    correlated with another setting on the same configuration object.

    Sibling is the name of the sibling setting and validator is a callable
    that will receive the setting value and the sibling setting value and
    should raise an exception if the setting value is not acceptable relative
    to the sibling setting value.

    If a setting is set to the object DefaultValue, it will be reset to the
    default. Also, only Setting attributes with nillable=True can be assigned
    the value None. All other values are passed to the type specified.
    """

    correlation_lock = Lock()

    def __init__(self, type, sibling, validator, default=None, nillable=False):
        Setting.__init__(self, type, default, nillable)
        self.sibling = sibling
        self.validator = validator

    def __set__(self, obj, value):
        with self.correlation_lock:
            sibling_value = getattr(obj, self.sibling)
            self.validator(value, sibling_value)
            Setting.__set__(self, obj, value)


class SettingsStateMeta(type):
    __established__ = WeakSet()

    def __call__(cls, *args, **kw):
        instance = super(SettingsStateMeta, cls).__call__(*args, **kw)
        if hasattr(instance, '__establish__') and instance not in cls.__established__:
            cls.__established__.add(instance)
            instance.__establish__()
        return instance


class SettingsState(object):
    """
    This class represents configuration objects which can be saved and restored.
    """

    __metaclass__ = SettingsStateMeta

    def get_modified(self):
        """
        Returns a dictionary containing the settings which have been changed.
        The keys are the full paths to the attributes (from this object), which
        are mapped to a ModifiedValue instance with references to the old and
        new values.
        """
        modified = {}
        for name in dir(self.__class__):
            attribute = getattr(self.__class__, name, None)
            if isinstance(attribute, SettingsGroupMeta):
                modified_settings = getattr(self, name).get_modified()
                modified.update(dict((name+'.'+k if k else name, v) for k,v in modified_settings.iteritems()))
            elif isinstance(attribute, Setting):
                modified_value = attribute.get_modified(self)
                if modified_value is not None:
                    modified[name] = modified_value
        return modified

    def clone(self):
        """
        Create a copy of this object and all its sub settings.
        """
        raise NotImplementedError

    def update(self, object):
        """
        Update the settings and subsettings of this settings object using the
        ones in the specified object.
        """
        raise NotImplementedError

    def __getstate__(self):
        state = {}
        for name in dir(self.__class__):
            attribute = getattr(self.__class__, name, None)
            if isinstance(attribute, SettingsGroupMeta):
                state[name] = getattr(self, name).__getstate__()
            elif isinstance(attribute, Setting):
                state[name] = attribute.__getstate__(self)
        return state

    def __setstate__(self, state):
        configuration_manager = ConfigurationManager()
        notification_center = NotificationCenter()
        for name, value in state.iteritems():
            attribute = getattr(self.__class__, name, None)
            if isinstance(attribute, SettingsGroupMeta):
                group = getattr(self, name)
                try:
                    group.__setstate__(value)
                except ValueError, e:
                    notification_center.post_notification('CFGManagerLoadFailed', sender=configuration_manager, data=TimestampedNotificationData(attribute=name, container=self, error=e))
            elif isinstance(attribute, Setting):
                try:
                    attribute.__setstate__(self, value)
                except ValueError, e:
                    notification_center.post_notification('CFGManagerLoadFailed', sender=configuration_manager, data=TimestampedNotificationData(attribute=name, container=self, error=e))


class SettingsGroupMeta(SettingsStateMeta):
    """
    Metaclass for SettingsGroup and its subclasses which allows them to be used
    as descriptor instances.
    """
    def __init__(cls, name, bases, dct):
        super(SettingsGroupMeta, cls).__init__(name, bases, dct)
        cls.values = weakobjectmap()

    def __get__(cls, obj, objtype):
        if obj is None:
            return cls
        try:
            return cls.values[obj]
        except KeyError:
            return cls.values.setdefault(obj, cls())

    def __set__(cls, obj, value):
        raise AttributeError("cannot overwrite group of settings")


class SettingsGroup(SettingsState):
    """
    Base class for settings groups, i.e. non-leaf and non-root nodes in the
    configuration tree. All SettingsGroup subclasses are descriptor instances
    which return an instance of the subclass type when accessed. All
    SettingsGroup intances are created without passing any arguments to the
    constructor.

    class ContainedGroup(SettingsGroup):
        pass
    class ContainingGroup(SettingsGroup):
        subgroup = ContainedGroup
    """

    __metaclass__ = SettingsGroupMeta


class ConditionalSingleton(type):
    """A conditional singleton based on cls.__id__ being static or not"""

    lock = Lock()

    def __init__(cls, name, bases, dic):
        super(ConditionalSingleton, cls).__init__(name, bases, dic)
        cls.__instance__ = None

    def __call__(cls, *args, **kw):
        if isinstance(cls.__id__, basestring):
            if args or kw:
                raise TypeError("cannot have arguments for %s because it is a singleton" % cls.__name__)
            with cls.lock:
                if cls.__instance__ is None:
                    cls.__instance__ = super(ConditionalSingleton, cls).__call__(*args, **kw)
            return cls.__instance__
        else:
            return super(ConditionalSingleton, cls).__call__(*args, **kw)


class SettingsObjectMeta(SettingsStateMeta, ConditionalSingleton):
    """Metaclass to singleton-ize SettingsObject subclasses with static ids"""

    def __init__(cls, name, bases, dic):
        if not (cls.__id__ is None or isinstance(cls.__id__, basestring) or isdescriptor(cls.__id__)):
            raise TypeError("%s.__id__ must be None, a string instance or a descriptor" % name)
        super(SettingsObjectMeta, cls).__init__(name, bases, dic)


class SettingsObject(SettingsState):
    """
    Subclass for top-level configuration objects. These objects are identifiable
    by either a global id (set in the __id__ attribute of the class) or a local
    id passed as the sole argument when instantiating SettingsObjects.

    For SettingsObject subclasses which are meant to be used exclusively with a
    local id, the class attribute __id__ should be left to the value None; if
    __init__ is defined, it would have to accept exactly one argument: id.

    The local id takes precedence over the one specified as a class attribute.

    Note: __init__ and __new__ will be called not only when a new object is
    created (i.e. there weren't any settings saved in the configuration), but
    also when the object is retrieved from the configuration.
    """

    __metaclass__ = SettingsObjectMeta

    __group__ = None
    __id__ = None

    def __new__(cls, id=None):
        id = id or cls.__id__
        if id is None:
            raise ValueError("id is required for instantiating %s" % cls.__name__)
        if not isinstance(id, basestring):
            raise TypeError("id needs to be a string instance")
        configuration = ConfigurationManager()
        instance = SettingsState.__new__(cls)
        instance.__id__ = id
        instance.__state__ = 'new'
        try:
            data = configuration.get(instance.__key__)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
            instance.__state__ = 'loaded'
        return instance

    def __establish__(self):
        if self.__state__ == 'loaded' or self.__instance__ is not None:
            self.__state__ = 'active'
            notification_center = NotificationCenter()
            notification_center.post_notification('CFGSettingsObjectWasActivated', sender=self, data=TimestampedNotificationData())

    @property
    def __key__(self):
        if isinstance(self.__class__.__id__, (SettingsObjectID, SettingsObjectImmutableID)):
            id_key = PersistentKey(self.__id__)
        else:
            id_key = unicode(self.__id__)
        if self.__group__ is not None:
            return [self.__group__, id_key]
        else:
            return [id_key]

    @property
    def __oldkey__(self):
        if isinstance(self.__class__.__id__, SettingsObjectID):
            id_key = PersistentKey(self.__class__.__id__.get_old(self))
        elif isinstance(self.__class__.__id__, SettingsObjectImmutableID):
            id_key = PersistentKey(self.__id__)
        else:
            id_key = unicode(self.__id__)
        if self.__group__ is not None:
            return [self.__group__, id_key]
        else:
            return [id_key]

    @run_in_thread('file-io')
    def save(self):
        """
        Use the ConfigurationManager to store the object under its id in the
        specified group or top-level otherwise, depending on whether group is
        None.

        This method will also post a CFGSettingsObjectDidChange notification,
        regardless of whether the settings have been saved to persistent storage
        or not. If the save does fail, a CFGManagerSaveFailed notification is
        posted as well.
        """

        if self.__state__ == 'deleted':
            return

        configuration = ConfigurationManager()
        notification_center = NotificationCenter()

        oldkey = self.__oldkey__ # save this here as get_modified will reset it

        modified_id = self.__class__.__id__.get_modified(self) if isinstance(self.__class__.__id__, SettingsObjectID) else None
        modified_settings = self.get_modified()

        if not modified_id and not modified_settings and self.__state__ != 'new':
            return

        if self.__state__ == 'new':
            configuration.update(self.__key__, self.__getstate__())
            self.__state__ = 'active'
            notification_center.post_notification('CFGSettingsObjectWasActivated', sender=self, data=TimestampedNotificationData())
            notification_center.post_notification('CFGSettingsObjectWasCreated', sender=self, data=TimestampedNotificationData())
            modified_data = None
        else:
            if modified_id:
                configuration.rename(oldkey, self.__key__)
            if modified_settings:
                configuration.update(self.__key__, self.__getstate__())
            modified_data = modified_settings or {}
            if modified_id:
                modified_data['__id__'] = modified_id
            notification_center.post_notification('CFGSettingsObjectDidChange', sender=self, data=TimestampedNotificationData(modified=modified_data))

        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='save', modified=modified_data, exception=e))

    @run_in_thread('file-io')
    def delete(self):
        """
        Remove this object from the persistent configuration.
        """
        if self.__id__ is self.__class__.__id__:
            raise TypeError("cannot delete %s instance with default id" % self.__class__.__name__)
        if self.__state__ == 'deleted':
            return
        self.__state__ = 'deleted'

        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        configuration.delete(self.__oldkey__) # we need the key that wasn't yet saved
        notification_center.post_notification('CFGSettingsObjectWasDeleted', sender=self, data=TimestampedNotificationData())
        try:
            configuration.save()
        except Exception, e:
            log.err()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, operation='delete', exception=e))

    def clone(self, new_id):
        """
        Create a copy of this object and all its sub settings.
        """
        raise NotImplementedError

    @classmethod
    def register_extension(cls, extension):
        """
        Register an extension of this SettingsObject. All Settings and
        SettingsGroups defined in the extension will be added to this
        SettingsObject, overwriting any attributes with the same name.
        Other attributes in the extension are ignored.
        """
        if not issubclass(extension, SettingsObjectExtension):
            raise TypeError("expected subclass of SettingsObjectExtension, got %r" % (extension,))
        for name in dir(extension):
            attribute = getattr(extension, name, None)
            if isinstance(attribute, (Setting, SettingsGroupMeta)):
                setattr(cls, name, attribute)


class SettingsObjectExtension(object):
    """
    Base class for extensions of SettingsObjects.
    """
    def __new__(self, *args, **kwargs):
        raise TypeError("SettingsObjectExtension subclasses cannot be instantiated")



# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Generic configuration management.
"""

from weakref import WeakKeyDictionary

from application.notification import NotificationCenter
from application.python.util import Singleton

from sipsimple.util import TimestampedNotificationData

__all__ = ['ConfigurationError', 'ObjectNotFoundError', 'ConfigurationManager', 'DefaultValue',
           'SettingsObjectID', 'Setting', 'CorrelatedSetting', 'SettingsGroup', 'SettingsObject', 'SettingsObjectExtension']


## Exceptions

class ConfigurationError(Exception): pass
class ObjectNotFoundError(ConfigurationError): pass


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

    def start(self, backend):
        """
        Initialize the ConfigurationManager to use the specified backend. This
        method can only be called once, with an object which provides IBackend.
        The other methods of the object cannot be used unless this method was
        called.
        """
        from sipsimple.configuration.backend import IConfigurationBackend
        if self.backend is not None:
            raise RuntimeError("ConfigurationManager already started")
        if not IConfigurationBackend.providedBy(backend):
            raise TypeError("backend must implement the IConfigurationBackend interface")
        self.data = backend.load()
        self.backend = backend

    def update(self, group, name, data):
        """
        Save the object with an associated name in the specified group.
        Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if group is not None:
            self._update_dict(self.data.setdefault(group, {}).setdefault(name, {}), data)
        else:
            self._update_dict(self.data.setdefault(name, {}), data)

    def rename(self, group, old_name, new_name):
        """
        Rename the object identified by old_name within the specified group to
        new_name. Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        if group is not None:
            group_data = self.data.get(group, {})
            self.data.setdefault(group, {})[new_name] = group_data.pop(old_name, {})
            if not group_data:
                self.data.pop(group, None)
        else:
            self.data[new_name] = self.data.pop(old_name, {})

    def delete(self, group, name):
        """
        Delete an object identified by a name in the specified group. Cannot be
        called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        try:
            if group is not None:
                group_data = self.data[group]
                del group_data[name]
                if not group_data:
                    del self.data[group]
            else:
                del self.data[name]
        except KeyError:
            pass

    def get(self, group, name):
        """
        Get an object identified by a name in the specified group. Raises
        ObjectNotFoundError if such an object does not exist. Cannot be called
        before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        try:
            if group is not None:
                return self.data[group][name]
            else:
                return self.data[name]
        except KeyError:
            object_name = "%s in %s" % (name, group) if (group is not None) else name
            raise ObjectNotFoundError("object %s does not exist" % object_name)

    def get_names(self, group):
        """
        Get all the names from  the specified group. Returns a list containing
        the names. Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        try:
            return self.data[group].keys()
        except:
            return []

    def save(self):
        """
        Flush the modified objects. Cannot be called before start().
        """
        if self.backend is None:
            raise RuntimeError("ConfigurationManager cannot be used unless started")
        self.backend.save(self.data)

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
    Simple descriptor used for SettingsObject subclasses which have dynamic ids.
    """
    def __init__(self, type):
        self.type = type
        self.values = WeakKeyDictionary()
        self.oldvalues = WeakKeyDictionary()
        self.dirty = WeakKeyDictionary()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        try:
            return self.values[obj]
        except KeyError:
            raise AttributeError("SettingsObject ID has not been defined")

    def __set__(self, obj, value):
        if not isinstance(value, self.type):
            value = self.type(value)
        # check whether the old value is the same as the new value
        if obj in self.values and self.values[obj] == value:
            return
        self.dirty[obj] = obj in self.values
        self.oldvalues[obj] = self.values.get(obj, value)
        self.values[obj] = value

    def isdirty(self, obj):
        """
        Returns True if the ID has been changed on the specified configuration
        object.
        """
        return self.dirty.get(obj, False)

    def clear_dirty(self, obj):
        """
        Clears the dirty flag for the ID on the specified configuration object.
        """
        del self.dirty[obj]
        self.oldvalues[obj] = self.values[obj]

    def get_old(self, obj):
        return self.oldvalues.get(obj, None)

    def undo(self, obj):
        if obj in self.oldvalues:
            self.dirty.pop(obj, None)
            self.values[obj] = self.oldvalues[obj]


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
        self.values = WeakKeyDictionary()
        self.oldvalues = WeakKeyDictionary()
        self.dirty = WeakKeyDictionary()

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        return self.values.get(obj, self.default)

    def __set__(self, obj, value):
        if value is None and not self.nillable:
            raise ValueError("setting attribute is not nillable")
        if value is DefaultValue:
            if obj in self.values:
                self.values.pop(obj)
                self.dirty[obj] = True
            return

        if value is not None and not isinstance(value, self.type):
            value = self.type(value)
        # check whether the old value is the same as the new value
        if obj in self.values and self.values[obj] == value:
            return

        self.values[obj] = value
        self.dirty[obj] = True

    def isset(self, obj):
        """
        Returns True if the setting is set to a different value than the
        default on the specified configuration object.
        """
        return obj in self.values

    def isdirty(self, obj):
        """
        Returns True if the setting was changed on the specified configuration
        object.
        """
        return self.dirty.get(obj, False)

    def clear_dirty(self, obj):
        """
        Clears the dirty flag for this setting on the specified configuration
        object.
        """
        self.dirty.pop(obj, None)
        try:
            self.oldvalues[obj] = self.values[obj]
        except KeyError:
            self.oldvalues.pop(obj, None)

    def get_old(self, obj):
        return self.oldvalues.get(obj, self.default)

    def undo(self, obj):
        self.dirty.pop(obj, None)
        if obj in self.oldvalues:
            self.values[obj] = self.oldvalues[obj]
        else:
            self.values.pop(obj, None)


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
    def __init__(self, type, sibling, validator, default=None, nillable=False):
        Setting.__init__(self, type, default, nillable)
        self.sibling = sibling
        self.validator = validator

    def __set__(self, obj, value):
        sibling_value = getattr(obj, self.sibling)
        self.validator(value, sibling_value)
        Setting.__set__(self, obj, value)


class SettingsState(object):
    """
    This class represents configuration objects which can be saved and restored.
    """

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
            elif isinstance(attribute, Setting) and attribute.isdirty(self):
                modified[name] = ModifiedValue(old=attribute.get_old(self), new=getattr(self, name))
        return modified

    def clear_dirty(self):
        """
        Clears the dirty flag in all settings contained in this configuration
        object and all its descendents.
        """
        for name in dir(self.__class__):
            attribute = getattr(self.__class__, name, None)
            if isinstance(attribute, SettingsGroupMeta):
                getattr(self, name).clear_dirty()
            elif isinstance(attribute, Setting) and attribute.isdirty(self):
                attribute.clear_dirty(self)

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
                if attribute.isset(self):
                    value = getattr(self, name)
                    if value is None:
                        pass
                    elif issubclass(attribute.type, bool):
                        value = u'true' if value else u'false'
                    elif issubclass(attribute.type, (int, long, basestring)):
                        value = unicode(value)
                    else:
                        try:
                            value = value.__getstate__()
                        except AttributeError:
                            raise TypeError("Setting type %s does not provide __getstate__" % value.__class__.__name__)
                    state[name] = value
                else:
                    state[name] = DefaultValue
        return state

    def __setstate__(self, state):
        for name, value in state.iteritems():
            attribute = getattr(self.__class__, name, None)
            if isinstance(attribute, SettingsGroupMeta):
                group = getattr(self, name)
                try:
                    group.__setstate__(value)
                except ValueError, e:
                    configuration_manager = ConfigurationManager()
                    notification_center = NotificationCenter()
                    notification_center.post_notification('CFGManagerLoadFailed', sender=configuration_manager, data=TimestampedNotificationData(attribute=name, container=self, error=e))
            elif isinstance(attribute, Setting):
                try:
                    if value is None:
                        pass
                    elif issubclass(attribute.type, bool):
                        if value.lower() in ('true', 'yes', 'on', '1'):
                            value = True
                        elif value.lower() in ('false', 'no', 'off', '0'):
                            value = False
                        else:
                            raise ValueError("invalid boolean value: %s" % (value,))
                    elif issubclass(attribute.type, (int, long, basestring)):
                        value = attribute.type(value)
                    else:
                        object = attribute.type.__new__(attribute.type)
                        object.__setstate__(value)
                        value = object
                    setattr(self, name, value)
                except ValueError, e:
                    configuration_manager = ConfigurationManager()
                    notification_center = NotificationCenter()
                    notification_center.post_notification('CFGManagerLoadFailed', sender=configuration_manager, data=TimestampedNotificationData(attribute=name, container=self, error=e))
                else:
                    attribute.clear_dirty(self)


class SettingsGroupMeta(type):
    """
    Metaclass for SettingsGroup and its subclasses which allows them to be used
    as descriptor instances.
    """
    def __init__(cls, name, bases, dct):
        cls.values = WeakKeyDictionary()

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


class SettingsObject(SettingsState):
    """
    Subclass for top-level configuration objects. These objects are identifiable
    by either a global id (set in the __id__ attribute of the class) or a local
    id passed as the sole argument when instantiating SettingsObjects.

    For SettingsObject subclasses which are meant to be used exclusively with a
    local id, the class attribute __id__ should be left to the value None; if
    __init__ is defined, it would have to accept exactly one argument, id.

    The local id takes precedence over the one specified as a class attribute.

    Note: __init__ and __new__ will be called not only when a new object is
    created (i.e. there weren't any settings saved in the configuration), but
    also when the object is retrieved from the configuration.
    """

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
        try:
            data = configuration.get(cls.__group__, id)
        except ObjectNotFoundError:
            pass
        else:
            instance.__setstate__(data)
        return instance

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
        modified_settings = self.get_modified()
        id_descriptor = self.__class__.__id__ if isinstance(self.__class__.__id__, SettingsObjectID) else None
        if not modified_settings and not (id_descriptor and id_descriptor.isdirty(self)):
            return

        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        
        if id_descriptor and id_descriptor.isdirty(self):
            old = id_descriptor.get_old(self)
            new = self.__id__
            configuration.rename(self.__group__, old, new)
            notification_center.post_notification('CFGSettingsObjectDidChangeID', sender=self, data=TimestampedNotificationData(old_id=old, new_id=new))
        if modified_settings:
            notification_center.post_notification('CFGSettingsObjectDidChange', sender=self, data=TimestampedNotificationData(modified=modified_settings))
        configuration.update(self.__group__, self.__id__, self.__getstate__())
        try:
            configuration.save()
        except Exception, e:
            import traceback
            traceback.print_exc()
            notification_center.post_notification('CFGManagerSaveFailed', sender=configuration, data=TimestampedNotificationData(object=self, modified=modified_settings, exception=e))
        finally:
            self.clear_dirty()

    def delete(self):
        """
        Remove this object from the persistent configuration.
        """
        if self.__id__ is self.__class__.__id__:
            raise TypeError("cannot delete %s instance with default id" % self.__class__.__name__)
        configuration = ConfigurationManager()
        id_descriptor = self.__class__.__id__ if isinstance(self.__class__.__id__, SettingsObjectID) else None
        if id_descriptor and id_descriptor.isdirty(self):
            configuration.delete(self.__group__, id_descriptor.get_old(self))
        else:
            configuration.delete(self.__group__, self.__id__)
        configuration.save()

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
        SettingsObject, overwriting any attributes with the same name. Other
        attriutes in the extension are ignored.
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



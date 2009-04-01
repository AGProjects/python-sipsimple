# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from zope.interface import Interface

from sipsimple.configuration import ConfigurationError


__all__ = ['ConfigurationBackendError', 'IBackend']


## Exceptions

class ConfigurationBackendError(ConfigurationError): pass


class IBackend(Interface):
    """
    Interface describing a backend used for storing and retrieving configuration
    data.

    Data is kept as name, value pairs, with pairs kept in groups called
    sections. Name, value and section names can be arbitrary strings.
    """
    def add_section(section):
        """
        Add a section with a specified name or raise DuplicateSectionError if
        the section already exists.
        """
    def delete_section(section):
        """
        Delete a section identified by a name or raise UnknownSectionError if
        the section does not exist.
        """
    def set(section, name, value):
        """
        Set a name, value pair inside a section. Will overwrite the previous
        pair, if it exists; otherwise raise UnknownSectionError if the section
        does not exist.
        """
    def delete(section, name):
        """
        Delete a name, value pair from a section or raise UnknownSectionError if
        the section does not exist.
        """
    def get(section, name):
        """
        Get the value associated to the name, in the specified section or raise
        UnknownNameError if such a name, value pair does not exist and
        UnknownSectionError if the section does not exist.
        """
    def get_names(section):
        """
        Get all the names from  the specified section or raise
        UnknownSectionError if the section does not exist.
        """
    def save():
        """
        Flush the modified name, value pairs.
        """



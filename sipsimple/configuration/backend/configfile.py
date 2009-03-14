import base64
import ConfigParser
import os

from zope.interface import implements

from sipsimple.configuration import IBackend
from sipsimple.configuration import ConfigurationBackendError, DuplicateSectionError, UnknownNameError, UnknownSectionError


class ConfigFileBackend(object):
    """
    Implementation of a configuration backend that uses INI files for storage.
    """
    
    implements(IBackend)

    def __init__(self, filename=None):
        if filename is None:
            filename = os.path.expanduser("~/.sipclient/sipclient.ini")
        
        self.file = None
        self.parser = ConfigParser.SafeConfigParser()
        
        try:
            self.file = open(filename, 'r+')
            self.parser.readfp(self.file)
        except IOError, e:
            if e.errno == 2: # No such file
                self.file = open(filename, 'w+')
            else:
                raise ConfigurationBackendError(str(e))
    
    def add_section(self, section):
        """
        Add a section with a specified name or raise DuplicateSectionError if
        the section already exists.
        """
        try:
            self.parser.add_section(section)
        except ConfigParser.DuplicateSectionError:
            raise DuplicateSectionError("section `%s' already exists" % section)

    def delete_section(self, section):
        """
        Delete a section identified by a name or raise UnknownSectionError if
        the section does not exist.
        """
        if not self.parser.remove_section(section):
            raise UnknownSectionError("section `%s' does not exist" % section)
    
    def set(self, section, name, value):
        """
        Set a name, value pair inside a section. Will overwrite the previous
        pair, if it exists; otherwise raise UnknownSectionError if the section
        does not exist.
        """
        value = base64.encodestring(value).replace('\n', '')
        try:
            self.parser.set(section, name, value)
        except ConfigParser.NoSectionError:
            raise UnknownSectionError("section `%s' does not exist" % section)
    
    def delete(self, section, name):
        """
        Delete a name, value pair from a section or raise UnknownSectionError if
        the section does not exist.
        """
        try:
            self.parser.remove_option(section, name)
        except ConfigParser.NoSectionError:
            raise UnknownSectionError("section `%s' does not exist" % section)
    
    def get(self, section, name):
        """
        Get the value associated to the name, in the specified section or raise
        UnknownNameError if such a name, value pair does not exist and
        UnknownSectionError if the section does not exist.
        """
        try:
            return base64.decodestring(self.parser.get(section, name))
        except ConfigParser.NoSectionError:
            raise UnknownSectionError("section `%s' does not exist" % section)
        except ConfigParser.NoOptionError:
            raise UnknownNameError("section `%s' does not have an entry named `%s'" % (section, name))
        except Exception, e:
            raise ConfigurationBackendError("configuration is corrupted: %s" % str(e))
    
    def get_names(self, section):
        """
        Get all the names from  the specified section or raise
        UnknownSectionError if the section does not exist.
        """
        try:
            return [name for name, value in self.parser.items(section)]
        except ConfigParser.NoSectionError:
            raise UnknownSectionError("section `%s' does not exist" % section)
    
    def save(self):
        """
        Flush the modified name, value pairs.
        """
        self.file.seek(0)
        self.file.truncate()
        self.parser.write(self.file)
        self.file.flush()

    def __del__(self):
        if self.file is not None:
            self.file.close()




"""Definitions and implementations of storage backends"""

__all__ = ['ISIPSimpleStorage', 'ISIPSimpleApplicationDataStorage', 'FileStorage', 'MemoryStorage']

import os

from functools import partial
from zope.interface import Attribute, Interface, implements

from sipsimple.account.xcap.storage.file import FileStorage as XCAPFileStorage
from sipsimple.account.xcap.storage.memory import MemoryStorage as XCAPMemoryStorage
from sipsimple.configuration.backend.file import FileBackend as ConfigurationFileBackend
from sipsimple.configuration.backend.memory import MemoryBackend as ConfigurationMemoryBackend


class ISIPSimpleStorage(Interface):
    """Interface describing the backends used for storage throughout SIP Simple"""

    configuration_backend = Attribute("The backend used for the configuration")
    xcap_storage_factory  = Attribute("The factory used to create XCAP storage backends for each account")


class ISIPSimpleApplicationDataStorage(Interface):
    """Interface describing the directory used for application data storage """

    directory = Attribute("The directory used for application data")


class FileStorage(object):
    """Store/read SIP Simple data to/from files"""

    implements(ISIPSimpleStorage, ISIPSimpleApplicationDataStorage)

    def __init__(self, directory):
        self.configuration_backend = ConfigurationFileBackend(os.path.join(directory, 'config'))
        self.xcap_storage_factory  = partial(XCAPFileStorage, os.path.join(directory, 'xcap'))
        self.directory = directory


class MemoryStorage(object):
    """Store/read SIP Simple data to/from memory"""

    implements(ISIPSimpleStorage)

    def __init__(self):
        self.configuration_backend = ConfigurationMemoryBackend()
        self.xcap_storage_factory  = XCAPMemoryStorage




"""XCAP backend for storing data in memory"""

__all__ = ["MemoryStorage"]

from zope.interface import implements
from sipsimple.account.xcap.storage import IXCAPStorage, XCAPStorageError


class MemoryStorage(object):
    """Implementation of an XCAP backend that stores data in memory"""

    implements(IXCAPStorage)

    def __init__(self, account_id):
        """Initialize the backend for the specified account ID"""
        self.account_id = account_id
        self.data = {}

    def load(self, name):
        """Return the data given by name"""
        try:
            return self.data[name]
        except KeyError:
            raise XCAPStorageError("missing entry: %s/%s" % (self.account_id, name))

    def save(self, name, data):
        """Store the data under a key given by name"""
        self.data[name] = data

    def delete(self, name):
        """Delete the data identified by name"""
        self.data.pop(name, None)

    def purge(self):
        """Delete all the data that is stored in the backend"""
        self.data.clear()



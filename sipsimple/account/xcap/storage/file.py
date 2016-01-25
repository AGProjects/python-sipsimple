
"""XCAP backend for storing data in files"""

__all__ = ["FileStorage"]

import errno
import os
import platform
import random

from application.system import makedirs, openfile, unlink
from zope.interface import implements

from sipsimple.account.xcap.storage import IXCAPStorage, XCAPStorageError


class FileStorage(object):
    """Implementation of an XCAP backend that stores data in files."""

    implements(IXCAPStorage)

    def __init__(self, directory, account_id):
        """Initialize the storage for the specified directory and account ID"""
        self.directory = directory
        self.account_id = account_id
        self.names = set()

    def load(self, name):
        """Read the file given by name and return its content."""
        try:
            document = open(os.path.join(self.directory, self.account_id, name)).read()
        except (IOError, OSError), e:
            raise XCAPStorageError("failed to load XCAP data for %s/%s: %s" % (self.account_id, name, str(e)))
        else:
            self.names.add(name)
            return document

    def save(self, name, data):
        """Write the data in a file identified by name."""
        filename = os.path.join(self.directory, self.account_id, name)
        tmp_filename = '%s.%d.%08X' % (filename, os.getpid(), random.getrandbits(32))
        try:
            makedirs(os.path.join(self.directory, self.account_id))
            file = openfile(tmp_filename, 'wb', permissions=0600)
            file.write(data)
            file.close()
            if platform.system() == 'Windows':
                # os.rename does not work on Windows if the destination file already exists.
                # It seems there is no atomic way to do this on Windows.
                unlink(filename)
            os.rename(tmp_filename, filename)
        except (IOError, OSError), e:
            raise XCAPStorageError("failed to save XCAP data for %s/%s: %s" % (self.account_id, name, str(e)))
        else:
            self.names.add(name)

    def delete(self, name):
        """Delete the data stored in the file identified by name"""
        try:
            os.unlink(os.path.join(self.directory, self.account_id, name))
        except OSError, e:
            if e.errno == errno.ENOENT:
                self.names.discard(name)
                return
            raise XCAPStorageError("failed to delete XCAP data for %s/%s: %s" % (self.account_id, name, str(e)))
        else:
            self.names.remove(name)

    def purge(self):
        """Delete all the files stored by the backend"""
        failed = []
        for name in self.names:
            try:
                os.unlink(os.path.join(self.directory, self.account_id, name))
            except OSError, e:
                if e.errno == errno.ENOENT:
                    continue
                failed.append(name)
        self.names.clear()
        try:
            os.rmdir(os.path.join(self.directory, self.account_id))
        except OSError:
            pass
        if failed:
            raise XCAPStorageError("the following files could not be deleted for %s: %s" % (self.account_id, ', '.join(failed)))



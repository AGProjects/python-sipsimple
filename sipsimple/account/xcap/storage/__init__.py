
"""Base definitions for concrete implementations of XCAP storage backends"""

__all__ = ['IXCAPStorage', 'XCAPStorageError']


from zope.interface import Interface


class XCAPStorageError(Exception):
    """Base error to be used by backends implementing IXCAPStorage."""


class IXCAPStorage(Interface):
    """Interface describing a storage backend for XCAP data."""

    def load(name):
        """
        Load and return the data corresponding to the given name by
        using whatever means employed by the backend implementation.
        """

    def save(name, data):
        """
        Store the data associated with name by using whatever means
        employed by the backend implementation.
        """

    def delete(name):
        """Delete the data associated with name."""

    def purge():
        """Delete all the data stored by the backend."""



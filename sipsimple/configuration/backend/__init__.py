
"""Base definitions for concrete implementations of configuration backends"""

__all__ = ['ConfigurationBackendError', 'IConfigurationBackend']


from zope.interface import Interface


class ConfigurationBackendError(Exception):
    """Base error for use by backends implementing IConfigurationBackend."""


class IConfigurationBackend(Interface):
    """
    Interface describing a backend used for storing and retrieving configuration
    data.

    The data kept by the backend is a dictionary whose keys are unicode strings
    and values are one of four types: (a) a dictionary conforming to this
    definition; (b) a unicode string; (c) a list of unicode strings; (d) the
    value None.
    """
    def load():
        """
        Load the configuration data using whatever means employed by the backend
        implementation and return a dictionary conforming to the definition in
        this interface.
        """

    def save(data):
        """
        Given a dictionary conforming to the definition in this interface, save
        the data using whatever means employed by the backend implementation.
        """



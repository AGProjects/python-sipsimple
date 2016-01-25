
"""Configuration backend for storing settings in memory"""

__all__ = ["MemoryBackend"]

from zope.interface import implements
from sipsimple.configuration.backend import IConfigurationBackend


class MemoryBackend(object):
    """Implementation of a configuration backend that stores data in memory."""

    implements(IConfigurationBackend)

    def __init__(self):
        self.data = {}

    def load(self):
        return self.data

    def save(self, data):
        self.data = data



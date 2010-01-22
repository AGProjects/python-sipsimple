# Copyright (C) 2009 AG Projects. See LICENSE for details.
#

"""
This module automatically registers media streams to a stream registry
allowing for a plug and play mechanism of various types of media
negoticated in a SIP session that can be added to this library by using
a generic API.

For actual usage see rtp.py and msrp.py that implement media streams
based on their respective RTP and MSRP protocols.
"""


from operator import attrgetter
from application.python.util import Singleton
from zope.interface import Interface, Attribute


class StreamError(Exception): pass
class InvalidStreamError(StreamError): pass
class UnknownStreamError(StreamError): pass


# The MediaStream interface
#
class IMediaStream(Interface):
    type = Attribute("A string identifying the stream type (ex: audio, video, ...)")
    priority = Attribute("An integer value indicating the stream priority relative to the other streams types (higher numbers have higher priority).")

    hold_supported = Attribute("True if the stream supports hold")
    on_hold_by_local = Attribute("True if the stream is on hold by the local party")
    on_hold_by_remote = Attribute("True if the stream is on hold by the remote")
    on_hold = Attribute("True if either on_hold_by_local or on_hold_by_remote is true") 

    def __init__(self, account):
        pass

    # this should be a classmethod, but zopeinterface complains if we decorate it with @classmethod -Dan
    def new_from_sdp(cls, account, remote_sdp, stream_index):
        pass

    def get_local_media(self, for_offer):
        pass

    def initialize(self, session, direction):
        pass

    def start(self, local_sdp, remote_sdp, stream_index):
        pass

    def deactivate(self):
        pass

    def end(self):
        pass

    def validate_update(self, remote_sdp, stream_index):
        pass

    def update(self, local_sdp, remote_sdp, stream_index):
        pass

    def hold(self):
        pass

    def unhold(self):
        pass


# The MediaStream registry
#
class MediaStreamRegistry(object):
    __metaclass__ = Singleton

    def __init__(self):
        self.stream_types = []

    def __iter__(self):
        return iter(self.stream_types)

    def add(self, cls):
        if cls.priority is not None and cls not in self.stream_types:
            self.stream_types.append(cls)
            self.stream_types.sort(key=attrgetter('priority'), reverse=True)


class MediaStreamRegistrar(type):
    """Metaclass for adding a MediaStream to the media stream's class registry"""
    def __init__(cls, name, bases, dic):
        super(MediaStreamRegistrar, cls).__init__(name, bases, dic)
        MediaStreamRegistry().add(cls)


# Import the streams defined in submodules
#
from sipsimple.streams import rtp, msrp
from sipsimple.streams.rtp import *
from sipsimple.streams.msrp import *

__all__ = ['StreamError', 'InvalidStreamError', 'UnknownStreamError', 'IMediaStream', 'MediaStreamRegistry', 'MediaStreamRegistrar'] + rtp.__all__ + msrp.__all__


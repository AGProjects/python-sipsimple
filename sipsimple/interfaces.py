# Copyright (C) 2009 AG Projects. See LICENSE for details.
#

from zope.interface import Interface, Attribute

class IMediaStream(Interface):
    type = Attribute("A string identifying the stream type (ex: audio, video, ...)")

    hold_supported = Attribute("True if the stream supports hold")
    on_hold_by_local = Attribute("True if the stream is on hold by the local party")
    on_hold_by_remote = Attribute("True if the stream is on hold by the remeot")
    on_hold = Attribute("True if either on_hold_by_local or on_hold_by_remote is true") 

    def __init__(self, account):
        pass

    def get_local_media(self, for_offer):
        pass

    def validate_incoming(self, remote_sdp, stream_index):
        pass

    def initialize(self, session, direction):
        pass

    def start(self, local_sdp, remote_sdp, stream_index):
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



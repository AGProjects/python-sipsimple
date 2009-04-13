from zope.interface import Interface, Attribute

class IMediaStream(Interface):
     on_hold_by_local = Attribute("True if the stream is on hold by the local party")
     on_hold_by_remote = Attribute("True if the stream is on hold by the remeot")
     on_hold = Attribute("True if either on_hold_by_local or on_hold_by_remote is true") 

     def __init__(self, account):
         pass

     def get_local_media(self, for_offer, on_hold):
         pass

     def validate_incoming(self, remote_sdp, stream_index):
         pass

     def initialize(self, session):
         pass

     def start(self, local_sdp, remote_sdp, stream_index):
         pass

     def end(self):
         pass

     def validate_update(self, remote_sdp, stream_index):
         pass

     def update(self, local_sdp, remote_sdp, stream_index):
         pass


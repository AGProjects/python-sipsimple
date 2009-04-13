from zope.interface import Interface, Attribute

class IMediaStream(Interface):
     on_hold = Attribute()

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

     def validate_udpate(self, remote_sdp, stream_index):
         pass

     def update(self, local_sdp, remote_sdp, stream_index):
         pass



__all__ = ['VideoStream']

from application.notification import NotificationData
from zope.interface import implements

from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import VideoTransport
from sipsimple.streams import InvalidStreamError
from sipsimple.streams.rtp import RTPStream
from sipsimple.threading import call_in_thread, run_in_twisted_thread
from sipsimple.util import ExponentialTimer
from sipsimple.video import IVideoProducer


class VideoStream(RTPStream):
    implements(IVideoProducer)

    type = 'video'
    priority = 1

    def __init__(self):
        super(VideoStream, self).__init__()

        from sipsimple.application import SIPApplication
        self.device = SIPApplication.video_device
        self._keyframe_timer = None

    @property
    def producer(self):
        return self._transport.remote_video if self._transport else None

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        stream = super(VideoStream, cls).new_from_sdp(session, remote_sdp, stream_index)
        if stream.device.producer is None:
            raise InvalidStreamError("no video support available")
        if not stream.validate_update(remote_sdp, stream_index):
            raise InvalidStreamError("no valid SDP")
        return stream

    def initialize(self, session, direction):
        super(VideoStream, self).initialize(session, direction)
        self.notification_center.add_observer(self, name='VideoDeviceDidChangeCamera')

    def start(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.state != "INITIALIZED":
                raise RuntimeError("VideoStream.start() may only be called in the INITIALIZED state")
            settings = SIPSimpleSettings()
            self._transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
            self._transport.local_video.producer = self.device.producer
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._check_hold(self._transport.direction, True)
            if self._try_ice and self._ice_state == "NULL":
                self.state = 'WAIT_ICE'
            else:
                self._send_keyframes()
                self.state = 'ESTABLISHED'
                self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    def validate_update(self, remote_sdp, stream_index):
        with self._lock:
            remote_media = remote_sdp.media[stream_index]
            if 'H264' in remote_media.codec_list:
                rtpmap = next(attr for attr in remote_media.attributes if attr.name=='rtpmap' and 'h264' in attr.value.lower())
                payload_type = rtpmap.value.partition(' ')[0]
                has_profile_level_id = any('profile-level-id' in attr.value.lower() for attr in remote_media.attributes if attr.name=='fmtp' and attr.value.startswith(payload_type + ' '))
                if not has_profile_level_id:
                    return False
            return True

    def update(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            new_direction = local_sdp.media[stream_index].direction
            self._check_hold(new_direction, False)
            self._transport.update_direction(new_direction)
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._transport.update_sdp(local_sdp, remote_sdp, stream_index)
            self._hold_request = None

    def deactivate(self):
        with self._lock:
            self.notification_center.discard_observer(self, name='VideoDeviceDidChangeCamera')

    def end(self):
        with self._lock:
            if self.state == "ENDED" or self._done:
                return
            self._done = True
            if not self._initialized:
                self.state = "ENDED"
                self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason='Interrupted'))
                return
            if self._keyframe_timer is not None:
                self._keyframe_timer.stop()
                self.notification_center.remove_observer(self, sender=self._keyframe_timer)
            self._keyframe_timer = None
            self.notification_center.post_notification('MediaStreamWillEnd', sender=self)
            if self._transport is not None:
                self.notification_center.remove_observer(self, sender=self._transport)
                self.notification_center.remove_observer(self, sender=self._rtp_transport)
                call_in_thread('device-io', self._transport.stop)
                self._transport = None
                self._rtp_transport = None
            self.state = "ENDED"
            self.notification_center.post_notification('MediaStreamDidEnd', sender=self, data=NotificationData(error=self._failure_reason))
            self.session = None

    def reset(self, stream_index):
        pass

    def _NH_RTPTransportICENegotiationDidSucceed(self, notification):
        with self._lock:
            if self.state == "WAIT_ICE":
                self._send_keyframes()
        super(VideoStream, self)._NH_RTPTransportICENegotiationDidSucceed(notification)

    def _NH_RTPTransportICENegotiationDidFail(self, notification):
        with self._lock:
            if self.state == "WAIT_ICE":
                self._send_keyframes()
        super(VideoStream, self)._NH_RTPTransportICENegotiationDidFail(notification)

    def _NH_RTPVideoTransportDidTimeout(self, notification):
        self.notification_center.post_notification('RTPStreamDidTimeout', sender=self)

    def _NH_RTPVideoTransportRemoteFormatDidChange(self, notification):
        self.notification_center.post_notification('VideoStreamRemoteFormatDidChange', sender=self, data=notification.data)

    def _NH_RTPVideoTransportReceivedKeyFrame(self, notification):
        self.notification_center.post_notification('VideoStreamReceivedKeyFrame', sender=self, data=notification.data)

    def _NH_RTPVideoTransportMissedKeyFrame(self, notification):
        self._transport.request_keyframe()
        self.notification_center.post_notification('VideoStreamMissedKeyFrame', sender=self, data=notification.data)

    def _NH_RTPVideoTransportRequestedKeyFrame(self, notification):
        self._transport.send_keyframe()
        self.notification_center.post_notification('VideoStreamRequestedKeyFrame', sender=self, data=notification.data)

    def _NH_VideoDeviceDidChangeCamera(self, notification):
        new_camera = notification.data.new_camera
        if self._transport is not None and self._transport.local_video is not None:
            self._transport.local_video.producer = new_camera

    def _NH_ExponentialTimerDidTimeout(self, notification):
        if self._transport is not None:
            self._transport.send_keyframe()

    def _create_transport(self, rtp_transport, remote_sdp=None, stream_index=None):
        settings = SIPSimpleSettings()
        codecs = list(self.session.account.rtp.video_codec_list or settings.rtp.video_codec_list)
        return VideoTransport(rtp_transport, remote_sdp=remote_sdp, sdp_index=stream_index or 0, codecs=codecs)

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        self.direction = direction
        inactive = self.direction == "inactive"
        self.on_hold_by_local = was_on_hold_by_local if inactive else direction == "sendonly"
        self.on_hold_by_remote = "send" not in direction
        if self.on_hold_by_local or self.on_hold_by_remote:
            self._pause()
        elif not self.on_hold_by_local and not self.on_hold_by_remote and (was_on_hold_by_local or was_on_hold_by_remote):
            self._resume()
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=True))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=False))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=True))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=False))

    @run_in_twisted_thread
    def _send_keyframes(self):
        if self._keyframe_timer is None:
            self._keyframe_timer = ExponentialTimer()
            self.notification_center.add_observer(self, sender=self._keyframe_timer)
        self._keyframe_timer.start(0.5, immediate=True, iterations=5)

    def _pause(self):
        self._transport.pause()

    def _resume(self):
        self._transport.resume()
        self._send_keyframes()
        self._transport.request_keyframe()


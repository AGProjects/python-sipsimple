
"""Video support"""

from __future__ import absolute_import

__all__ = ['IVideoProducer', 'VideoDevice', 'VideoError']

from application.notification import NotificationCenter, NotificationData
from zope.interface import Attribute, Interface, implements

from sipsimple.core import SIPCoreError, VideoCamera


class IVideoProducer(Interface):
    """
    Interface describing an object which can produce video data.
    All attributes of this interface are read-only.
    """

    producer = Attribute("The core producer object which can be connected to a consumer")


class VideoError(Exception): pass


class VideoDevice(object):
    implements(IVideoProducer)

    def __init__(self, device_name, resolution, framerate):
        self._camera = self._open_camera(device_name, resolution, framerate)
        self._camera.start()

    def _open_camera(self, device_name, resolution, framerate):
        try:
            return VideoCamera(device_name, resolution, framerate)
        except SIPCoreError:
            try:
                return VideoCamera(u'system_default', resolution, framerate)
            except SIPCoreError:
                return VideoCamera(None, resolution, framerate)

    def set_camera(self, device_name, resolution, framerate):
        old_camera = self._camera
        old_camera.close()
        new_camera = self._open_camera(device_name, resolution, framerate)
        if not self.muted:
            new_camera.start()
        self._camera = new_camera
        notification_center = NotificationCenter()
        notification_center.post_notification('VideoDeviceDidChangeCamera', sender=self, data=NotificationData(old_camera=old_camera, new_camera=new_camera))

    @property
    def producer(self):
        return self._camera

    @property
    def name(self):
        return self._camera.name

    @property
    def real_name(self):
        return self._camera.real_name

    def _set_muted(self, value):
        if not isinstance(value, bool):
            raise ValueError('illegal value for muted property: %r' % (value,))
        if value == self.muted:
            return
        if value:
            self._camera.stop()
        else:
            self._camera.start()
        self.__dict__['muted'] = value

    def _get_muted(self):
        return self.__dict__.get('muted', False)

    muted = property(_get_muted, _set_muted)
    del _get_muted, _set_muted


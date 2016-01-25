
"""
This module provides classes to parse and generate SDP related to SIP sessions that negotiate Screen Sharing.
"""

__all__ = ['ScreenSharingStream', 'VNCConnectionError', 'ScreenSharingHandler', 'ScreenSharingServerHandler', 'ScreenSharingViewerHandler',
           'InternalVNCViewerHandler', 'InternalVNCServerHandler', 'ExternalVNCViewerHandler', 'ExternalVNCServerHandler']

from abc import ABCMeta, abstractmethod, abstractproperty
from application.notification import NotificationCenter, NotificationData, IObserver
from application.python.descriptor import WriteOnceAttribute
from eventlib.coros import queue
from eventlib.greenio import GreenSocket
from eventlib.proc import spawn
from eventlib.util import tcp_socket, set_reuse_addr
from msrplib.protocol import FailureReportHeader, SuccessReportHeader, ContentTypeHeader
from msrplib.transport import make_response, make_report
from twisted.internet.error import ConnectionDone
from zope.interface import implements

from sipsimple.core import SDPAttribute
from sipsimple.streams import InvalidStreamError, UnknownStreamError
from sipsimple.streams.msrp import MSRPStreamBase
from sipsimple.threading import run_in_twisted_thread


class VNCConnectionError(Exception): pass


class ScreenSharingHandler(object):
    __metaclass__ = ABCMeta

    implements(IObserver)

    def __init__(self):
        self.incoming_msrp_queue = None
        self.outgoing_msrp_queue = None
        self.msrp_reader_thread = None
        self.msrp_writer_thread = None

    def initialize(self, stream):
        self.incoming_msrp_queue = stream.incoming_queue
        self.outgoing_msrp_queue = stream.outgoing_queue
        NotificationCenter().add_observer(self, sender=stream)

    @abstractproperty
    def type(self):
        raise NotImplementedError

    @abstractmethod
    def _msrp_reader(self):
        raise NotImplementedError

    @abstractmethod
    def _msrp_writer(self):
        raise NotImplementedError

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_MediaStreamDidStart(self, notification):
        self.msrp_reader_thread = spawn(self._msrp_reader)
        self.msrp_writer_thread = spawn(self._msrp_writer)

    def _NH_MediaStreamWillEnd(self, notification):
        notification.center.remove_observer(self, sender=notification.sender)
        if self.msrp_reader_thread is not None:
            self.msrp_reader_thread.kill()
            self.msrp_reader_thread = None
        if self.msrp_writer_thread is not None:
            self.msrp_writer_thread.kill()
            self.msrp_writer_thread = None


class ScreenSharingServerHandler(ScreenSharingHandler):
    type = property(lambda self: 'passive')


class ScreenSharingViewerHandler(ScreenSharingHandler):
    type = property(lambda self: 'active')



class InternalVNCViewerHandler(ScreenSharingViewerHandler):
    @run_in_twisted_thread
    def send(self, data):
        self.outgoing_msrp_queue.send(data)

    def _msrp_reader(self):
        notification_center = NotificationCenter()
        while True:
            data = self.incoming_msrp_queue.wait()
            notification_center.post_notification('ScreenSharingStreamGotData', sender=self, data=NotificationData(data=data))

    def _msrp_writer(self):
        pass


class InternalVNCServerHandler(ScreenSharingServerHandler):
    @run_in_twisted_thread
    def send(self, data):
        self.outgoing_msrp_queue.send(data)

    def _msrp_reader(self):
        notification_center = NotificationCenter()
        while True:
            data = self.incoming_msrp_queue.wait()
            notification_center.post_notification('ScreenSharingStreamGotData', sender=self, data=NotificationData(data=data))

    def _msrp_writer(self):
        pass


class ExternalVNCViewerHandler(ScreenSharingViewerHandler):
    address = ('localhost', 0)
    connect_timeout = 5

    def __init__(self):
        super(ExternalVNCViewerHandler, self).__init__()
        self.vnc_starter_thread = None
        self.vnc_socket = GreenSocket(tcp_socket())
        set_reuse_addr(self.vnc_socket)
        self.vnc_socket.settimeout(self.connect_timeout)
        self.vnc_socket.bind(self.address)
        self.vnc_socket.listen(1)
        self.address = self.vnc_socket.getsockname()

    def _msrp_reader(self):
        while True:
            try:
                data = self.incoming_msrp_queue.wait()
                self.vnc_socket.sendall(data)
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='sending', reason=str(e)))
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.vnc_socket.recv(2048)
                if not data:
                    raise VNCConnectionError("connection with the VNC viewer was closed")
                self.outgoing_msrp_queue.send(data)
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='reading', reason=str(e)))
                break

    def _start_vnc_connection(self):
        try:
            sock, addr = self.vnc_socket.accept()
            self.vnc_socket.close()
            self.vnc_socket = sock
            self.vnc_socket.settimeout(None)
        except Exception, e:
            self.vnc_starter_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
            NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='connecting', reason=str(e)))
        else:
            self.msrp_reader_thread = spawn(self._msrp_reader)
            self.msrp_writer_thread = spawn(self._msrp_writer)
        finally:
            self.vnc_starter_thread = None

    def _NH_MediaStreamDidStart(self, notification):
        self.vnc_starter_thread = spawn(self._start_vnc_connection)

    def _NH_MediaStreamWillEnd(self, notification):
        if self.vnc_starter_thread is not None:
            self.vnc_starter_thread.kill()
            self.vnc_starter_thread = None
        super(ExternalVNCViewerHandler, self)._NH_MediaStreamWillEnd(notification)
        self.vnc_socket.close()


class ExternalVNCServerHandler(ScreenSharingServerHandler):
    address = ('localhost', 5900)
    connect_timeout = 5

    def __init__(self):
        super(ExternalVNCServerHandler, self).__init__()
        self.vnc_starter_thread = None
        self.vnc_socket = None

    def _msrp_reader(self):
        while True:
            try:
                data = self.incoming_msrp_queue.wait()
                self.vnc_socket.sendall(data)
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='sending', reason=str(e)))
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.vnc_socket.recv(2048)
                if not data:
                    raise VNCConnectionError("connection to the VNC server was closed")
                self.outgoing_msrp_queue.send(data)
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='reading', reason=str(e)))
                break

    def _start_vnc_connection(self):
        try:
            self.vnc_socket = GreenSocket(tcp_socket())
            self.vnc_socket.settimeout(self.connect_timeout)
            self.vnc_socket.connect(self.address)
            self.vnc_socket.settimeout(None)
        except Exception, e:
            self.vnc_starter_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
            NotificationCenter().post_notification('ScreenSharingHandlerDidFail', sender=self, data=NotificationData(context='connecting', reason=str(e)))
        else:
            self.msrp_reader_thread = spawn(self._msrp_reader)
            self.msrp_writer_thread = spawn(self._msrp_writer)
        finally:
            self.vnc_starter_thread = None

    def _NH_MediaStreamDidStart(self, notification):
        self.vnc_starter_thread = spawn(self._start_vnc_connection)

    def _NH_MediaStreamWillEnd(self, notification):
        if self.vnc_starter_thread is not None:
            self.vnc_starter_thread.kill()
            self.vnc_starter_thread = None
        super(ExternalVNCServerHandler, self)._NH_MediaStreamWillEnd(notification)
        if self.vnc_socket is not None:
            self.vnc_socket.close()


class ScreenSharingStream(MSRPStreamBase):
    type = 'screen-sharing'
    priority = 1

    media_type = 'application'
    accept_types = ['application/x-rfb']
    accept_wrapped_types = None

    ServerHandler = InternalVNCServerHandler
    ViewerHandler = InternalVNCViewerHandler

    handler = WriteOnceAttribute()

    def __init__(self, mode):
        if mode not in ('viewer', 'server'):
            raise ValueError("mode should be 'viewer' or 'server' not '%s'" % mode)
        super(ScreenSharingStream, self).__init__(direction='sendrecv')
        self.handler = self.ViewerHandler() if mode=='viewer' else self.ServerHandler()
        self.incoming_queue = queue()
        self.outgoing_queue = queue()
        self.msrp_reader_thread = None
        self.msrp_writer_thread = None

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'application':
            raise UnknownStreamError
        accept_types = remote_stream.attributes.getfirst('accept-types', None)
        if accept_types is None or 'application/x-rfb' not in accept_types.split():
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if session.account.msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in chat stream, got %s" % (expected_transport, remote_stream.transport))
        if remote_stream.formats != ['*']:
            raise InvalidStreamError("wrong format list specified")
        remote_rfbsetup = remote_stream.attributes.getfirst('rfbsetup', 'active')
        if remote_rfbsetup == 'active':
            stream = cls(mode='server')
        elif remote_rfbsetup == 'passive':
            stream = cls(mode='viewer')
        else:
            raise InvalidStreamError("unknown rfbsetup attribute in the remote screen sharing stream")
        stream.remote_role = remote_stream.attributes.getfirst('setup', 'active')
        return stream

    def _create_local_media(self, uri_path):
        local_media = super(ScreenSharingStream, self)._create_local_media(uri_path)
        local_media.attributes.append(SDPAttribute('rfbsetup', self.handler.type))
        return local_media

    def _msrp_reader(self):
        while True:
            try:
                chunk = self.msrp.read_chunk()
                if chunk.method in (None, 'REPORT'):
                    continue
                elif chunk.method == 'SEND':
                    if chunk.content_type in self.accept_types:
                        self.incoming_queue.send(chunk.data)
                        response = make_response(chunk, 200, 'OK')
                        report = make_report(chunk, 200, 'OK')
                    else:
                        response = make_response(chunk, 415, 'Invalid Content-Type')
                        report = None
                else:
                    response = make_response(chunk, 501, 'Unknown method')
                    report = None
                if response is not None:
                    self.msrp.write_chunk(response)
                if report is not None:
                    self.msrp.write_chunk(report)
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                if self.shutting_down and isinstance(e, ConnectionDone):
                    break
                self._failure_reason = str(e)
                NotificationCenter().post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='reading', reason=self._failure_reason))
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.outgoing_queue.wait()
                chunk = self.msrp.make_send_request(data=data)
                chunk.add_header(SuccessReportHeader('no'))
                chunk.add_header(FailureReportHeader('partial'))
                chunk.add_header(ContentTypeHeader('application/x-rfb'))
                self.msrp.write_chunk(chunk)
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                if self.shutting_down and isinstance(e, ConnectionDone):
                    break
                self._failure_reason = str(e)
                NotificationCenter().post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='sending', reason=self._failure_reason))
                break

    def _NH_MediaStreamDidInitialize(self, notification):
        notification.center.add_observer(self, sender=self.handler)
        self.handler.initialize(self)

    def _NH_MediaStreamDidStart(self, notification):
        self.msrp_reader_thread = spawn(self._msrp_reader)
        self.msrp_writer_thread = spawn(self._msrp_writer)

    def _NH_MediaStreamWillEnd(self, notification):
        notification.center.remove_observer(self, sender=self.handler)
        if self.msrp_reader_thread is not None:
            self.msrp_reader_thread.kill()
            self.msrp_reader_thread = None
        if self.msrp_writer_thread is not None:
            self.msrp_writer_thread.kill()
            self.msrp_writer_thread = None

    def _NH_ScreenSharingHandlerDidFail(self, notification):
        self._failure_reason = notification.data.reason
        notification.center.post_notification('MediaStreamDidFail', sender=self, data=notification.data)


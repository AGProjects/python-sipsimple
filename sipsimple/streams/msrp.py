# Copyright (C) 2009-2010 AG Projects. See LICENSE for details.
#

"""
Handling of MSRP media streams according to RFC4975, RFC4976, RFC5547
and RFC3994.

This module provides classes to parse and generate SDP related to SIP
sessions that negotiate Instant Messsaging, File Transfer and Desktop
Sharing and handling of the actual media streams.
"""

__all__ = ['MSRPStreamError', 'ChatStreamError', 'ChatStream', 'FileSelector', 'FileTransferStream', 'IDesktopSharingHandler', 'DesktopSharingHandlerBase',
           'InternalVNCViewerHandler', 'InternalVNCServerHandler', 'ExternalVNCViewerHandler', 'ExternalVNCServerHandler', 'DesktopSharingStream']


import os
import re
import random
import hashlib
import mimetypes
from datetime import datetime

from application.notification import NotificationCenter, NotificationData, IObserver
from application.system import host
from twisted.internet.error import ConnectionDone
from twisted.python.failure import Failure
from zope.interface import implements, Interface, Attribute

from eventlet import api
from eventlet.coros import queue
from eventlet.greenio import GreenSocket
from eventlet.proc import spawn, ProcExit
from eventlet.util import tcp_socket, set_reuse_addr
from msrplib.connect import get_acceptor, get_connector, MSRPRelaySettings
from msrplib.protocol import URI, FailureReportHeader, SuccessReportHeader, ContentTypeHeader, parse_uri
from msrplib.session import MSRPSession, contains_mime_type, OutgoingFile
from msrplib.transport import make_response, make_report

from sipsimple.streams import IMediaStream, MediaStreamRegistrar, StreamError, InvalidStreamError, UnknownStreamError
from sipsimple.core import SDPAttribute, SDPMediaStream
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.cpim import CPIMIdentity, MessageCPIM, MessageCPIMParser
from sipsimple.util import run_in_green_thread, run_in_twisted_thread, TimestampedNotificationData
from sipsimple.payloads.iscomposing import IsComposingMessage, State, LastActive, Refresh, ContentType


class MSRPStreamError(StreamError): pass
class ChatStreamError(MSRPStreamError): pass


class MSRPStreamBase(object):
    __metaclass__ = MediaStreamRegistrar

    implements(IMediaStream, IObserver)

    # Attributes that need to be defined by each MSRP stream type
    type = None
    priority = None
    use_msrp_session = False

    media_type = None
    accept_types = None
    accept_wrapped_types = None

    # These attributes are always False for any MSRP stream
    hold_supported = False
    on_hold = False
    on_hold_by_local = False
    on_hold_by_remote = False

    def __new__(cls, *args, **kw):
        if cls is MSRPStreamBase:
            raise TypeError("MSRPStreamBase cannot be instantiated directly")
        return object.__new__(cls)

    def __init__(self, account, direction='sendrecv'):
        self.account = account
        self.direction = direction
        self.greenlet = None
        self.local_identity = CPIMIdentity(self.account.uri, self.account.display_name)
        self.local_media = None
        self.remote_identity = None ## will be filled in by start()
        self.msrp = None ## Placeholder for the MSRPTransport that will be set when started
        self.msrp_connector = None
        self.cpim_enabled = None ## Boolean value. None means it was not negotiated yet
        self.session = None
        self.msrp_session = None
        self.shutting_down = False

    def _create_local_media(self, uri_path):
        transport = "TCP/TLS/MSRP" if uri_path[-1].use_tls else "TCP/MSRP"
        attributes = [SDPAttribute("path", " ".join(str(uri) for uri in uri_path))]
        if self.direction not in [None, 'sendrecv']:
            attributes.append(SDPAttribute(self.direction, ''))
        if self.accept_types is not None:
            attributes.append(SDPAttribute("accept-types", " ".join(self.accept_types)))
        if self.accept_wrapped_types is not None:
            attributes.append(SDPAttribute("accept-wrapped-types", " ".join(self.accept_wrapped_types)))
        return SDPMediaStream(self.media_type, uri_path[-1].port or 12345, transport, formats=["*"], attributes=attributes)

    ## The public API (the IMediaStream interface)

    def get_local_media(self, for_offer=True):
        return self.local_media

    def new_from_sdp(self, account, remote_sdp, stream_index):
        raise NotImplementedError

    @run_in_green_thread
    def initialize(self, session, direction):
        self.greenlet = api.getcurrent()
        settings = SIPSimpleSettings()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        try:
            self.session = session
            outgoing = direction=='outgoing'
            if (outgoing and self.account.nat_traversal.use_msrp_relay_for_outbound) or (not outgoing and self.account.nat_traversal.use_msrp_relay_for_inbound):
                credentials = self.account.credentials
                if self.account.nat_traversal.msrp_relay is None:
                    relay = MSRPRelaySettings(domain=self.account.uri.host,
                                              username=self.account.uri.user,
                                              password=credentials.password if credentials else '')
                    self.transport = settings.msrp.transport
                else:
                    relay = MSRPRelaySettings(domain=self.account.uri.host,
                                              username=self.account.uri.user,
                                              password=credentials.password if credentials else '',
                                              host=self.account.nat_traversal.msrp_relay.host,
                                              port=self.account.nat_traversal.msrp_relay.port,
                                              use_tls=self.account.nat_traversal.msrp_relay.transport=='tls')
                    self.transport = self.account.nat_traversal.msrp_relay.transport
                if self.transport != settings.msrp.transport:
                    raise MSRPStreamError("MSRP relay transport conflicts with MSRP transport setting")
            else:
                relay = None
                self.transport = settings.msrp.transport
            if not outgoing and relay is None and self.transport == 'tls' and None in (self.account.tls_credentials.cert, self.account.tls_credentials.key):
                raise MSRPStreamError("cannot create incoming MSRP stream without a certificate and private key")
            logger = NotificationProxyLogger()
            self.msrp_connector = get_connector(relay=relay, logger=logger) if outgoing else get_acceptor(relay=relay, logger=logger)
            local_uri = URI(host=host.default_ip,
                            port=0,
                            use_tls=self.transport=='tls',
                            credentials=self.account.tls_credentials)
            full_local_path = self.msrp_connector.prepare(local_uri)
            self.local_media = self._create_local_media(full_local_path)
        except api.GreenletExit:
            raise
        except Exception, ex:
            ndata = TimestampedNotificationData(context='initialize', failure=Failure(), reason=str(ex))
            notification_center.post_notification('MediaStreamDidFail', self, ndata)
        else:
            notification_center.post_notification('MediaStreamDidInitialize', self, data=TimestampedNotificationData())
        finally:
            if self.msrp_session is None and self.msrp is None and self.msrp_connector is None:
                notification_center.remove_observer(self, sender=self)
            self.greenlet = None

    @run_in_green_thread
    def start(self, local_sdp, remote_sdp, stream_index):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        try:
            context = 'sdp_negotiation'
            self.remote_identity = CPIMIdentity(self.session.remote_identity.uri, self.session.remote_identity.display_name)
            remote_media = remote_sdp.media[stream_index]
            remote_accept_types = remote_media.attributes.getfirst('accept-types')
            # TODO: update accept_types and accept_wrapped_types from remote_media
            self.cpim_enabled = contains_mime_type(self.accept_types, 'message/cpim')
            remote_uri_path = remote_media.attributes.getfirst('path')
            if remote_uri_path is None:
                raise AttributeError("remote SDP media does not have 'path' attribute")
            full_remote_path = [parse_uri(uri) for uri in remote_uri_path.split()]
            remote_transport = 'tls' if full_remote_path[0].use_tls else 'tcp'
            if self.transport != remote_transport:
                raise MSRPStreamError("remote transport ('%s') different from local transport ('%s')" % (remote_transport, self.transport))
            context = 'start'
            self.msrp = self.msrp_connector.complete(full_remote_path)
            if self.use_msrp_session:
                self.msrp_session = MSRPSession(self.msrp, accept_types=self.accept_types, on_incoming_cb=self._handle_incoming)
            self.msrp_connector = None
        except api.GreenletExit:
            raise
        except Exception, ex:
            ndata = TimestampedNotificationData(context=context, failure=Failure(), reason=str(ex) or type(ex).__name__)
            notification_center.post_notification('MediaStreamDidFail', self, ndata)
        else:
            notification_center.post_notification('MediaStreamDidStart', self, data=TimestampedNotificationData())
        finally:
            self.greenlet = None

    def deactivate(self):
        self.shutting_down = True

    @run_in_green_thread
    def end(self):
        if self.msrp_session is None and self.msrp is None and self.msrp_connector is None:
            return
        notification_center = NotificationCenter()
        notification_center.post_notification('MediaStreamWillEnd', self, data=TimestampedNotificationData())
        msrp, self.msrp = self.msrp, None
        msrp_session, self.msrp_session = self.msrp_session, None
        msrp_connector, self.msrp_connector = self.msrp_connector, None
        try:
            if self.greenlet is not None:
                api.kill(self.greenlet)
            if msrp_session is not None:
                msrp_session.shutdown()
            elif msrp is not None:
                msrp.loseConnection(wait=False)
            if msrp_connector is not None:
                msrp_connector.cleanup()
        finally:
            notification_center.post_notification('MediaStreamDidEnd', self, data=TimestampedNotificationData())
            notification_center.remove_observer(self, sender=self)

    def validate_update(self, remote_sdp, stream_index):
        return True #TODO

    def update(self, local_sdp, remote_sdp, stream_index):
        pass #TODO

    def hold(self):
        pass

    def unhold(self):
        pass

    ## Internal IObserver interface

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    ## Internal message handlers

    def _handle_incoming(self, chunk=None, error=None):
        notification_center = NotificationCenter()
        if error is not None:
            if self.shutting_down and isinstance(error.value, ConnectionDone):
                return
            ndata = TimestampedNotificationData(context='reading', failure=error, reason=error.getErrorMessage())
            notification_center.post_notification('MediaStreamDidFail', self, ndata)
        elif chunk is not None:
            method_handler = getattr(self, '_handle_%s' % chunk.method, None)
            if method_handler is not None:
                method_handler(chunk)

    def _handle_REPORT(self, chunk):
        pass

    def _handle_SEND(self, chunk):
        pass


class ChatStream(MSRPStreamBase):

    type = 'chat'
    priority = 1
    use_msrp_session = True

    media_type = 'message'
    accept_types = ['message/cpim', 'text/*', 'application/im-iscomposing+xml']
    accept_wrapped_types = ['*']

    def __init__(self, account, direction='sendrecv'):
        MSRPStreamBase.__init__(self, account, direction)
        self.message_queue = queue()
        self.sent_messages = set()

    @classmethod
    def new_from_sdp(cls, account, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message':
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if SIPSimpleSettings().msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in chat stream, got %s" % (expected_transport, remote_stream.transport))
        stream = cls(account)
        if (remote_stream.direction, stream.direction) not in (('sendrecv', 'sendrecv'), ('sendonly', 'recvonly'), ('recvonly', 'sendonly')):
            raise InvalidStreamError("mismatching directions in chat stream")
        return stream

    @property
    def private_messages_allowed(self):
        return self.cpim_enabled # and isfocus and 'private-messages' in chatroom

    # TODO: chatroom, recvonly/sendonly (in start)?

    def _NH_MediaStreamDidStart(self, notification):
        spawn(self._message_queue_handler)

    def _NH_MediaStreamDidEnd(self, notification):
        self.message_queue.send_exception(ProcExit)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        if chunk.message_id in self.sent_messages:
            self.sent_messages.remove(chunk.message_id)
            notification_center = NotificationCenter()
            data = TimestampedNotificationData(message_id=chunk.message_id, message=chunk, code=chunk.status.code, reason=chunk.status.comment)
            if chunk.status.code == 200:
                notification_center.post_notification('ChatStreamDidDeliverMessage', self, data)
            else:
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', self, data)
    
    def _handle_SEND(self, chunk):
        if self.direction=='sendonly':
            return
        if chunk.content_type.lower()=='message/cpim':
            cpim_headers, content = MessageCPIMParser.parse_string(chunk.data)
            content_type = cpim_headers.get('Content-Type', 'text/plain')
            remote_identity = cpim_headers.get('From', self.remote_identity)
        else:
            cpim_headers = {}
            content = chunk.data
            content_type = chunk.content_type
            remote_identity = self.remote_identity
        # Note: success reports are issued by msrplib
        # TODO: check wrapped content-type and issue a report if it's invalid
        if content_type.lower() == IsComposingMessage.content_type:
            data = IsComposingMessage.parse(content)
            ndata = TimestampedNotificationData(state=data.state.value,
                                                refresh=data.refresh.value if data.refresh is not None else None,
                                                content_type=data.contenttype.value if data.contenttype is not None else None,
                                                last_active=data.last_active.value if data.last_active is not None else None,
                                                remote_identity=remote_identity)
            NotificationCenter().post_notification('ChatStreamGotComposingIndication', self, ndata)
            return
        ndata = TimestampedNotificationData(content=content, content_type=content_type, cpim_headers=cpim_headers, message=chunk)
        NotificationCenter().post_notification('ChatStreamGotMessage', self, ndata)

    def _on_transaction_response(self, message_id, response):
        if message_id in self.sent_messages and response.code != 200:
            self.sent_message.remove(message_id)
            data = TimestampedNotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment)
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', self, data)

    def _message_queue_handler(self):
        notification_center = NotificationCenter()
        while True:
            message_id, message, content_type, failure_report, success_report, notify_progress = self.message_queue.wait()
            if self.msrp_session is None:
                # should we generate ChatStreamDidNotDeliver per each message in the queue here?
                break
            chunk = self.msrp_session.make_message(message, content_type=content_type, message_id=message_id)
            if failure_report is not None:
                chunk.add_header(FailureReportHeader(failure_report))
            if success_report is not None:
                chunk.add_header(SuccessReportHeader(success_report))
            try:
                self.msrp_session.send_chunk(chunk, response_cb=lambda response: self._on_transaction_response(message_id, response))
            except Exception, e:
                ndata = TimestampedNotificationData(context='sending', failure=Failure(), reason=str(e))
                notification_center.post_notification('MediaStreamDidFail', self, ndata)
                break
            else:
                if notify_progress and success_report == 'yes' and failure_report != 'no':
                    self.sent_messages.add(message_id)
                    notification_center.post_notification('ChatStreamDidSendMessage', self, TimestampedNotificationData(message=chunk))

    @run_in_twisted_thread
    def _enqueue_message(self, message_id, message, content_type, failure_report=None, success_report=None, notify_progress=True):
        self.message_queue.send((message_id, message, content_type, failure_report, success_report, notify_progress))

    def send_message(self, content, content_type='text/plain', remote_identity=None, dt=None):
        """Send IM message. Prefer Message/CPIM wrapper if it is supported.
        If called before the connection was established, the messages will be
        queued until MediaStreamDidStart notification.

        - content (str) - content of the message;
        - remote_identity (CPIMIdentity) - "To" header of CPIM wrapper;
          if None, use the default obtained from the session
          'remote_identity' may only differ from the one obtained from the session if the remote
          party supports private messages. If it does not, ChatStreamError will be raised;
        - content_type (str) - Content-Type of wrapped message;
          (Content-Type of MSRP message is always Message/CPIM in that case)
          If Message/CPIM is not supported, Content-Type of MSRP message.

        Return generated MSRP chunk (MSRPData); to get Message-ID use its 'message_id' attribute.

        These MSRP headers are used to enable end-to-end success reports and
        to disable hop-to-hop successful responses:
        Failure-Report: partial
        Success-Report: yes
        """
        if self.direction=='recvonly':
            raise ChatStreamError('Cannot send message on recvonly stream')
        if not contains_mime_type(self.accept_types, content_type):
            raise ChatStreamError('Invalid content_type for outgoing message: %r' % content_type)
        message_id = '%x' % random.getrandbits(64)
        if self.cpim_enabled:
            if remote_identity is None:
                remote_identity = self.remote_identity
            elif not self.private_messages_allowed and remote_identity != self.remote_identity:
                raise ChatStreamError('The remote end does not support private messages')
            if dt is None:
                dt = datetime.utcnow()
            msg = MessageCPIM(content, content_type, from_=self.local_identity, to=remote_identity, datetime=dt)
            self._enqueue_message(message_id, str(msg), 'message/cpim', failure_report='partial', success_report='yes', notify_progress=True)
        else:
            if remote_identity is not None and remote_identity != self.remote_identity:
                raise ChatStreamError('Private messages are not available, because CPIM wrapper is not used')
            self._enqueue_message(message_id, content, content_type, failure_report='partial', success_report='yes', notify_progress=True)
        return message_id

    def send_composing_indication(self, state, refresh, last_active=None, remote_identity=None):
        if self.direction == 'recvonly':
            raise ChatStreamError('Cannot send message on recvonly stream')
        if state not in ('active', 'idle'):
            raise ValueError('Invalid value for composing indication state')
        message_id = '%x' % random.getrandbits(64)
        content = IsComposingMessage(state=State(state), refresh=Refresh(refresh), last_active=LastActive(last_active or datetime.now()), content_type=ContentType('text')).toxml()
        if self.cpim_enabled:
            if remote_identity is None:
                remote_identity = self.remote_identity
            elif not self.private_messages_allowed and remote_identity != self.remote_identity:
                raise ChatStreamError('The remote end does not support private messages')
            msg = MessageCPIM(content, IsComposingMessage.content_type, from_=self.local_identity, to=remote_identity, datetime=datetime.utcnow())
            self._enqueue_message(message_id, str(msg), 'message/cpim', failure_report='partial', success_report='no')
        else:
            if remote_identity is not None and remote_identity != self.remote_identity:
                raise ChatStreamError('Private messages are not available, because CPIM wrapper is not used')
            self._enqueue_message(message_id, content, IsComposingMessage.content_type, failure_report='partial', success_report='no', notify_progress=False)
        return message_id


# File transfer
#

class FileSelector(object):
    class __metaclass__(type):
        _name_re = re.compile('name:"([^"]+)"')
        _size_re = re.compile('size:(\d+)')
        _type_re = re.compile('type:([^ ]+)')
        _hash_re = re.compile('hash:([^ ]+)')
        _byte_re = re.compile('..')

    def __init__(self, name=None, type=None, size=None, hash=None, fd=None):
        ## if present, hash should be in the form: hash:sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E
        ## according to the specification, only sha-1 is supported ATM.
        self.name = name
        self.type = type
        self.size = size
        self.hash = hash
        self.fd = fd

    @classmethod
    def parse(cls, string):
        name_match = cls._name_re.search(string)
        size_match = cls._size_re.search(string)
        type_match = cls._type_re.search(string)
        hash_match = cls._hash_re.search(string)
        name = name_match and name_match.group(1)
        size = size_match and int(size_match.group(1))
        type = type_match and type_match.group(1)
        hash = hash_match and hash_match.group(1)
        return cls(name, type, size, hash)

    @classmethod
    def for_file(cls, path, content_type=None, compute_hash=True):
        fd = open(path, 'r')
        name = os.path.basename(path)
        size = os.fstat(fd.fileno()).st_size
        if content_type is None:
            mime_type, encoding = mimetypes.guess_type(name)
            if encoding is not None:
                type = 'application/x-%s' % encoding
            elif mime_type is not None:
                type = mime_type
            else:
                type = 'application/octet-stream'
        else:
            type = content_type
        if compute_hash:
            sha1 = hashlib.sha1()
            while True:
                content = fd.read(65536)
                if not content:
                    break
                sha1.update(content)
            # unexpected as it may be, using a regular expression is the fastest method to do this
            hash = 'sha1:' + ':'.join(cls._byte_re.findall(sha1.hexdigest().upper()))
            fd.seek(0)
        else:
            hash = None
        return cls(name, type, size, hash, fd)

    @property
    def sdp_repr(self):
        items = [('name', self.name and '"%s"' % self.name), ('type', self.type), ('size', self.size), ('hash', self.hash)]
        return ' '.join('%s:%s' % (name, value) for name, value in items if value is not None)


class FileTransferStream(MSRPStreamBase):

    type = 'file-transfer'
    priority = 10
    use_msrp_session = True

    media_type = 'message'
    accept_types = ['*']
    accept_wrapped_types = ['*']

    def __init__(self, account, file_selector=None):
        MSRPStreamBase.__init__(self, account, direction='sendonly' if file_selector is not None else 'recvonly')
        self.file_selector = file_selector
        if file_selector is not None:
            self.outgoing_file = OutgoingFile(file_selector.fd, file_selector.size, content_type=file_selector.type)
            self.outgoing_file.headers['Success-Report'] = SuccessReportHeader('yes')
            self.outgoing_file.headers['Failure-Report'] = FailureReportHeader('partial')

    @classmethod
    def new_from_sdp(cls, account, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message' or 'file-selector' not in remote_stream.attributes:
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if SIPSimpleSettings().msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in file transfer stream, got %s" % (expected_transport, remote_stream.transport))
        stream = cls(account)
        stream.file_selector = FileSelector.parse(remote_stream.attributes.getfirst('file-selector'))
        if (remote_stream.direction, stream.direction) != ('sendonly', 'recvonly'):
            raise InvalidStreamError("mismatching directions in file transfer stream")
        return stream

    def _create_local_media(self, uri_path):
        local_media = MSRPStreamBase._create_local_media(self, uri_path)
        local_media.attributes.append(SDPAttribute('file-selector', self.file_selector.sdp_repr))
        return local_media

    def _NH_MediaStreamDidStart(self, notification):
        if self.direction == 'sendonly':
            self.msrp_session.send_file(self.outgoing_file)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        notification_center = NotificationCenter()
        data = TimestampedNotificationData(message_id=chunk.message_id, chunk=chunk, code=chunk.status.code, reason=chunk.status.comment)
        if chunk.status.code == 200:
            # Calculating the number of bytes transferred so far by looking at the Byte-Range of this message
            # only works as long as chunks are delivered in order. -Luci
            data.transferred_bytes = chunk.byte_range[1]
            data.file_size = chunk.byte_range[2]
            notification_center.post_notification('FileTransferStreamDidDeliverChunk', self, data)
            if data.transferred_bytes == data.file_size:
                notification_center.post_notification('FileTransferStreamDidFinish', self, TimestampedNotificationData())
        else:
            notification_center.post_notification('FileTransferStreamDidNotDeliverChunk', self, data)
    
    def _handle_SEND(self, chunk):
        if self.direction=='sendonly':
            return # should we just ignore this? -Dan
        if chunk.content_type.lower()=='message/cpim':
            cpim_headers, content = MessageCPIMParser.parse_string(chunk.data)
            content_type = cpim_headers.get('Content-Type')
        else:
            cpim_headers = {}
            content = chunk.data
            content_type = chunk.content_type
        # Note: success reports are issued by msrplib
        # TODO: check wrapped content-type and issue a report if it's invalid
        # Calculating the number of bytes transferred so far by looking at the Byte-Range of this message
        # only works as long as chunks are delivered in order. -Luci
        notification_center = NotificationCenter()
        ndata = TimestampedNotificationData(content=content, content_type=content_type, cpim_headers=cpim_headers, chunk=chunk, transferred_bytes=chunk.byte_range[0]+chunk.size-1, file_size=chunk.byte_range[2])
        notification_center.post_notification('FileTransferStreamGotChunk', self, ndata)
        if ndata.transferred_bytes == ndata.file_size:
            notification_center.post_notification('FileTransferStreamDidFinish', self, TimestampedNotificationData())


# Desktop sharing
#

class VNCConnectionError(Exception): pass


class IDesktopSharingHandler(Interface):
    type = Attribute("A string identifying the direction: passive for a server, active for a client")

    def initialize(self, stream):
        pass


class DesktopSharingHandlerBase(object):
    implements(IDesktopSharingHandler, IObserver)
    
    type = None
    
    def __new__(cls, *args, **kw):
        if cls is DesktopSharingHandlerBase:
            raise TypeError("DesktopSharingHandlerBase cannot be instantiated directly")
        return object.__new__(cls)

    def __init__(self):
        self.incoming_msrp_queue = None
        self.outgoing_msrp_queue = None
        self.msrp_reader_thread = None
        self.msrp_writer_thread = None

    def initialize(self, stream):
        self.incoming_msrp_queue = stream.incoming_queue
        self.outgoing_msrp_queue = stream.outgoing_queue
        NotificationCenter().add_observer(self, sender=stream)

    def _msrp_reader(self):
        raise NotImplementedError

    def _msrp_writer(self):
        raise NotImplementedError

    ## Internal IObserver interface

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_MediaStreamDidStart(self, notification):
        self.msrp_reader_thread = spawn(self._msrp_reader)
        self.msrp_writer_thread = spawn(self._msrp_reader)

    def _NH_MediaStreamWillEnd(self, notification):
        NotificationCenter().remove_observer(self, sender=notification.sender)
        if self.msrp_reader_thread is not None:
            self.msrp_reader_thread.kill()
            self.msrp_reader_thread = None
        if self.msrp_writer_thread is not None:
            self.msrp_writer_thread.kill()
            self.msrp_writer_thread = None


class InternalVNCViewerHandler(DesktopSharingHandlerBase):
    type = 'active'

    @run_in_twisted_thread
    def send(self, data):
        self.outgoing_msrp_queue.send(data)

    def _msrp_reader(self):
        notification_center = NotificationCenter()
        while True:
            data = self.incoming_msrp_queue.wait()
            notification_center.post_notification('DesktopSharingStreamGotData', self, NotificationData(data=data))

    def _msrp_writer(self):
        pass


class InternalVNCServerHandler(DesktopSharingHandlerBase):
    type = 'passive'

    @run_in_twisted_thread
    def send(self, data):
        self.outgoing_msrp_queue.send(data)

    def _msrp_reader(self):
        notification_center = NotificationCenter()
        while True:
            data = self.incoming_msrp_queue.wait()
            notification_center.post_notification('DesktopSharingStreamGotData', self, NotificationData(data=data))

    def _msrp_writer(self):
        pass


class ExternalVNCViewerHandler(DesktopSharingHandlerBase):
    type = 'active'

    def __init__(self, address=('localhost', 0), connect_timeout=3):
        DesktopSharingHandlerBase.__init__(self)
        self.vnc_starter_thread = None
        self.vnc_socket = GreenSocket(tcp_socket())
        set_reuse_addr(self.vnc_socket)
        self.vnc_socket.settimeout(connect_timeout)
        self.vnc_socket.bind(address)
        self.vnc_socket.listen(1)
        self.address = self.vnc_socket.getsockname()

    def _msrp_reader(self):
        while True:
            try:
                data = self.incoming_msrp_queue.wait()
                self.vnc_socket.sendall(data)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                ndata = TimestampedNotificationData(context='sending', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.vnc_socket.recv(2048)
                if not data:
                    raise VNCConnectionError("connection with the VNC viewer was closed")
                self.outgoing_msrp_queue.send(data)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                ndata = TimestampedNotificationData(context='reading', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
                break

    def _start_vnc_connection(self):
        try:
            sock, addr = self.vnc_socket.accept()
            self.vnc_socket.close()
            self.vnc_socket = sock
            self.vnc_socket.settimeout(None)
        except ProcExit:
            raise
        except Exception, e:
            self.vnc_starter_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
            ndata = TimestampedNotificationData(context='connecting', failure=Failure(), reason=str(e))
            NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
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
        DesktopSharingHandlerBase._NH_MediaStreamWillEnd(self, notification)


class ExternalVNCServerHandler(DesktopSharingHandlerBase):
    type = 'passive'
    
    def __init__(self, address, connect_timeout=3):
        DesktopSharingHandlerBase.__init__(self)
        self.address = address
        self.vnc_starter_thread = None
        self.vnc_socket = None
        self.connect_timeout = connect_timeout

    def _msrp_reader(self):
        while True:
            try:
                data = self.incoming_msrp_queue.wait()
                self.vnc_socket.sendall(data)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                ndata = TimestampedNotificationData(context='sending', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.vnc_socket.recv(2048)
                if not data:
                    raise VNCConnectionError("connection to the VNC server was closed")
                self.outgoing_msrp_queue.send(data)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                ndata = TimestampedNotificationData(context='reading', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
                break

    def _start_vnc_connection(self):
        try:
            self.vnc_socket = GreenSocket(tcp_socket())
            self.vnc_socket.settimeout(self.connect_timeout)
            self.vnc_socket.connect(self.address)
            self.vnc_socket.settimeout(None)
        except ProcExit:
            raise
        except Exception, e:
            self.vnc_starter_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
            ndata = TimestampedNotificationData(context='connecting', failure=Failure(), reason=str(e))
            NotificationCenter().post_notification('DesktopSharingHandlerDidFail', self, ndata)
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
        DesktopSharingHandlerBase._NH_MediaStreamWillEnd(self, notification)
        if self.vnc_socket is not None:
            self.vnc_socket.close()


class DesktopSharingStream(MSRPStreamBase):

    type = 'desktop-sharing'
    priority = 1
    use_msrp_session = False

    media_type = 'application'
    accept_types = ['application/x-rfb']
    accept_wrapped_types = None

    def __init__(self, account, handler):
        MSRPStreamBase.__init__(self, account, direction='sendrecv')
        self.handler = handler
        self.incoming_queue = queue()
        self.outgoing_queue = queue()
        self.msrp_reader_thread = None
        self.msrp_writer_thread = None

    def _get_handler(self):
        return self.__dict__['handler']

    def _set_handler(self, handler):
        if handler is None:
            raise TypeError("handler cannot be None")
        if 'handler' in self.__dict__ and self.handler.type != handler.type:
            raise TypeError("cannot replace the handler with one with a different type")
        self.__dict__['handler'] = handler

    handler = property(_get_handler, _set_handler)
    del _get_handler, _set_handler

    @classmethod
    def new_from_sdp(cls, account, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'application':
            raise UnknownStreamError
        accept_types = remote_stream.attributes.getfirst('accept-types', None)
        if accept_types is None or 'application/x-rfb' not in accept_types.split():
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if SIPSimpleSettings().msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in chat stream, got %s" % (expected_transport, remote_stream.transport))
        remote_setup = remote_stream.attributes.getfirst('setup', 'active')
        if remote_setup == 'active':
            return cls(account, handler=InternalVNCServerHandler())
        elif remote_setup == 'passive':
            return cls(account, handler=InternalVNCViewerHandler())
        else:
            raise InvalidStreamError("unknown setup attribute in the remote desktop sharing stream")

    def initialize(self, session, direction):
        NotificationCenter().add_observer(self, sender=self.handler)
        self.handler.initialize(self)
        MSRPStreamBase.initialize(self, session, direction)

    def _create_local_media(self, uri_path):
        local_media = MSRPStreamBase._create_local_media(self, uri_path)
        local_media.attributes.append(SDPAttribute('setup', self.handler.type))
        return local_media

    def _msrp_reader(self):
        while True:
            try:
                # it should be read_chunk(0) to read as much as available, but it doesn't work
                # as it sends 1-2 bytes more than provided by the app to the other side. -Dan
                chunk = self.msrp.read_chunk(None) # 0 means to return as much data as was read
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
                    self.msrp.write_chunk(response)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_reader_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                if self.shutting_down and isinstance(e, ConnectionDone):
                    break
                ndata = TimestampedNotificationData(context='reading', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('MediaStreamDidFail', self, ndata)
                break

    def _msrp_writer(self):
        while True:
            try:
                data = self.outgoing_queue.wait()
                chunk = self.msrp.make_chunk(data=data)
                chunk.add_header(FailureReportHeader('no'))
                chunk.add_header(ContentTypeHeader('application/x-rfb'))
                self.msrp.write_chunk(chunk)
            except ProcExit:
                raise
            except Exception, e:
                self.msrp_writer_thread = None # avoid issues caused by the notification handler killing this greenlet during post_notification
                if self.shutting_down and isinstance(e, ConnectionDone):
                    break
                ndata = TimestampedNotificationData(context='sending', failure=Failure(), reason=str(e))
                NotificationCenter().post_notification('MediaStreamDidFail', self, ndata)
                break

    def _NH_MediaStreamDidStart(self, notification):
        self.msrp_reader_thread = spawn(self._msrp_reader)
        self.msrp_writer_thread = spawn(self._msrp_writer)

    def _NH_MediaStreamWillEnd(self, notification):
        NotificationCenter().remove_observer(self, sender=self.handler)
        if self.msrp_reader_thread is not None:
            self.msrp_reader_thread.kill()
            self.msrp_reader_thread = None
        if self.msrp_writer_thread is not None:
            self.msrp_writer_thread.kill()
            self.msrp_writer_thread = None

    def _NH_DesktopSharingHandlerDidFail(self, notification):
        NotificationCenter().post_notification('MediaStreamDidFail', self, notification.data)



# temporary solution. to be replaced later by a better logging system in msrplib -Dan
class NotificationProxyLogger(object):
    def __init__(self):
        from application import log
        self.level = log.level
        self.stripped_data_transactions = set()
        self.text_transactions = set()
        self.transaction_data = {}

    def report_out(self, data, transport, new_chunk=True):
        pass

    def report_in(self, data, transport, new_chunk=False, packet_done=False):
        pass

    def received_new_chunk(self, data, transport, chunk):
        content_type = chunk.content_type.split('/')[0].lower() if chunk.content_type else None
        if chunk.method != 'SEND' or (chunk.content_type and content_type in ('text', 'message')):
            self.text_transactions.add(chunk.transaction_id)
        self.transaction_data[chunk.transaction_id] = data

    def received_chunk_data(self, data, transport, transaction_id):
        if transaction_id in self.text_transactions:
            self.transaction_data[transaction_id] += data
        elif transaction_id not in self.stripped_data_transactions:
            self.transaction_data[transaction_id] += '<stripped data>'
            self.stripped_data_transactions.add(transaction_id)

    def received_chunk_end(self, data, transport, transaction_id):
        chunk = self.transaction_data.pop(transaction_id) + data
        self.stripped_data_transactions.discard(transaction_id)
        self.text_transactions.discard(transaction_id)
        NotificationCenter().post_notification('MSRPTransportTrace', sender=transport, data=TimestampedNotificationData(direction='incoming', data=chunk))

    def sent_new_chunk(self, data, transport, chunk):
        content_type = chunk.content_type.split('/')[0].lower() if chunk.content_type else None
        if chunk.method != 'SEND' or (chunk.content_type and content_type in ('text', 'message')):
            self.text_transactions.add(chunk.transaction_id)
        self.transaction_data[chunk.transaction_id] = data

    def sent_chunk_data(self, data, transport, transaction_id):
        if transaction_id in self.text_transactions:
            self.transaction_data[transaction_id] += data
        elif transaction_id not in self.stripped_data_transactions:
            self.transaction_data[transaction_id] += '<stripped data>'
            self.stripped_data_transactions.add(transaction_id)

    def sent_chunk_end(self, data, transport, transaction_id):
        chunk = self.transaction_data.pop(transaction_id) + data
        self.stripped_data_transactions.discard(transaction_id)
        self.text_transactions.discard(transaction_id)
        NotificationCenter().post_notification('MSRPTransportTrace', sender=transport, data=TimestampedNotificationData(direction='outgoing', data=chunk))

    def debug(self, message, **context):
        pass

    def info(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.INFO))
    msg = info

    def warn(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.WARNING))

    def error(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.ERROR))

    def fatal(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.CRITICAL))



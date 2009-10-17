# Copyright (C) 2009 AG Projects. See LICENSE for details.
#

import os
import re
import random
import hashlib
import mimetypes
from datetime import datetime

from application.notification import NotificationCenter, IObserver
from twisted.internet.error import ConnectionDone
from twisted.python.failure import Failure
from zope.interface import implements

from eventlet.twistedutil import callInGreenThread
from eventlet.proc import ProcExit
from eventlet.coros import queue
from msrplib.connect import get_acceptor, get_connector, MSRPRelaySettings
from msrplib.protocol import URI, FailureReportHeader, SuccessReportHeader, parse_uri
from msrplib.session import MSRPSession, contains_mime_type, OutgoingFile

from sipsimple.core import SDPAttribute, SDPMediaStream
from sipsimple.interfaces import IMediaStream
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.cpim import CPIMIdentity, MessageCPIM, MessageCPIMParser
from sipsimple.util import run_in_green_thread, TimestampedNotificationData


class MSRPStreamError(Exception): pass

class ChatStreamError(MSRPStreamError): pass


class MSRPStreamBase(object):
    implements(IMediaStream, IObserver)

    type = None

    # Attributes that need to be defined by each MSRP stream type
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
        return object.__new__(cls, *args, **kw)

    def __init__(self, account, direction='sendrecv'):
        self.account = account
        self.direction = direction
        self.local_identity = CPIMIdentity(self.account.uri, self.account.display_name)
        self.local_media = None
        self.remote_identity = None ## will be filled in by start()
        self.msrp = None ## Placeholder for the MSRPTransport that will be set when started
        self.msrp_connector = None
        self.cpim_enabled = None ## Boolean value. None means it was not negotiated yet
        self.session = None
        self.msrp_session = None

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

    def validate_incoming(self, remote_sdp, stream_index):
        raise NotImplementedError

    @run_in_green_thread
    def initialize(self, session, direction):
        settings = SIPSimpleSettings()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        try:
            self.session = session
            outgoing = direction=='outgoing'
            if (outgoing and self.account.nat_traversal.use_msrp_relay_for_outbound) or (not outgoing and self.account.nat_traversal.use_msrp_relay_for_inbound):
                if self.account.nat_traversal.msrp_relay is None:
                    relay = MSRPRelaySettings(domain=self.account.uri.host,
                                              username=self.account.uri.user,
                                              password=self.account.credentials.password if self.account.credentials else '')
                    self.transport = 'tls'
                else:
                    relay = MSRPRelaySettings(domain=self.account.uri.host,
                                              username=self.account.uri.user,
                                              password=self.account.credentials.password if self.account.credentials else '',
                                              host=self.account.nat_traversal.msrp_relay.host,
                                              port=self.account.nat_traversal.msrp_relay.port,
                                              use_tls=self.account.nat_traversal.msrp_relay.transport=='tls')
                    self.transport = self.account.nat_traversal.msrp_relay.transport
            else:
                relay = None
                self.transport = settings.msrp.transport
            logger = NotificationProxyLogger()
            self.msrp_connector = get_connector(relay=relay, logger=logger) if outgoing else get_acceptor(relay=relay, logger=logger)
            local_uri = URI(host=settings.sip.ip_address.normalized,
                            port=settings.msrp.port,
                            use_tls=self.transport=='tls',
                            credentials=self.account.tls_credentials)
            full_local_path = self.msrp_connector.prepare(local_uri)
            self.local_media = self._create_local_media(full_local_path)
        except Exception, ex:
            ndata = TimestampedNotificationData(context='initialize', failure=Failure(), reason=str(ex))
            notification_center.post_notification('MediaStreamDidFail', self, ndata)
        else:
            notification_center.post_notification('MediaStreamDidInitialize', self, data=TimestampedNotificationData())

    @run_in_green_thread
    def start(self, local_sdp, remote_sdp, stream_index):
        notification_center = NotificationCenter()
        try:
            context = 'sdp_negotiation'
            self.remote_identity = CPIMIdentity(self.session.remote_identity.uri, self.session.remote_identity.display_name)
            remote_media = remote_sdp.media[stream_index]
            media_attributes = dict((attr.name, attr.value) for attr in remote_media.attributes)
            remote_accept_types = media_attributes.get('accept-types')
            # TODO: update accept_types and accept_wrapped_types from remote_media
            self.cpim_enabled = contains_mime_type(self.accept_types, 'message/cpim')
            remote_uri_path = media_attributes.get('path')
            if remote_uri_path is None:
                raise AttributeError("remote SDP media does not have 'path' attribute")
            full_remote_path = [parse_uri(uri) for uri in remote_uri_path.split()]
            context = 'start'
            self.msrp = self.msrp_connector.complete(full_remote_path)
            self.msrp_session = MSRPSession(self.msrp, accept_types=self.accept_types, on_incoming_cb=self._handle_incoming)
            self.msrp_connector = None
        except Exception, ex:
            ndata = TimestampedNotificationData(context=context, failure=Failure(), reason=str(ex) or type(ex).__name__)
            notification_center.post_notification('MediaStreamDidFail', self, ndata)
        else:
            notification_center.post_notification('MediaStreamDidStart', self, data=TimestampedNotificationData())

    @run_in_green_thread
    def end(self):
        if self.msrp_session is None and self.msrp_connector is None:
            return
        msrp_session, self.msrp_session = self.msrp_session, None
        msrp_connector, self.msrp_connector = self.msrp_connector, None
        notification_center = NotificationCenter()
        notification_center.post_notification('MediaStreamWillEnd', self, data=TimestampedNotificationData())
        try:
            if msrp_session is not None:
                msrp_session.shutdown()
            if msrp_connector is not None:
                msrp_connector.cleanup()
        finally:
            notification_center.post_notification('MediaStreamDidEnd', self, data=TimestampedNotificationData())

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

    def _NH_MediaStreamDidFail(self, notification):
        NotificationCenter().remove_observer(self, sender=self)
        if self.msrp_session is not None:
            msrp_session, self.msrp_session = self.msrp_session, None
            msrp_session.shutdown()
        if self.msrp_connector is not None:
            msrp_connector, self.msrp_connector = self.msrp_connector, None
            msrp_connector.cleanup()

    def _NH_MediaStreamDidEnd(self, notification):
        NotificationCenter().remove_observer(self, sender=self)

    ## Internal message handlers

    def _handle_incoming(self, chunk=None, error=None):
        notification_center = NotificationCenter()
        if error is not None:
            if isinstance(error.value, ConnectionDone):
                notification_center.post_notification('MediaStreamDidEnd', self, data=TimestampedNotificationData())
            else:
                ndata = TimestampedNotificationData(context='reading', failure=error, reason=error.getErrorMessage())
                notification_center.post_notification('MediaStreamDidFail', self, ndata)
            return
        method_handler = getattr(self, '_handle_%s' % chunk.method, None)
        if method_handler is not None:
            method_handler(chunk)

    def _handle_REPORT(self, chunk):
        pass
    
    def _handle_SEND(self, chunk):
        pass

    
class ChatStream(MSRPStreamBase):

    type = 'chat'

    media_type = 'message'
    accept_types = ['message/cpim', 'text/*']
    accept_wrapped_types = ['*']

    def __init__(self, account, direction='sendrecv'):
        MSRPStreamBase.__init__(self, account, direction)
        self.message_queue = queue()

    @property
    def private_messages_allowed(self):
        return self.cpim_enabled # and isfocus and 'private-messages' in chatroom

    def validate_incoming(self, remote_sdp, stream_index):
        media = remote_sdp.media[stream_index]
        media_attributes = dict((attr.name, attr.value) for attr in media.attributes)
        direction = media_attributes.get('direction', 'sendrecv')
        if (direction, self.direction) not in (('sendrecv', 'sendrecv'), ('sendonly', 'recvonly'), ('recvonly', 'sendonly')):
            return False
        return True

    # TODO: chatroom, recvonly/sendonly (in start)?

    def _NH_MediaStreamDidStart(self, notification):
        callInGreenThread(self._message_queue_handler)

    def _NH_MediaStreamDidFail(self, notification):
        MSRPStreamBase._NH_MediaStreamDidFail(self, notification)
        self.message_queue.send_exception(ProcExit)
        # should we generate ChatStreamDidNotDeliver per each message here?

    def _NH_MediaStreamDidEnd(self, notification):
        MSRPStreamBase._NH_MediaStreamDidEnd(self, notification)
        self.message_queue.send_exception(ProcExit)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
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
            content_type = cpim_headers.get('Content-Type')
        else:
            cpim_headers = {}
            content = chunk.data
            content_type = chunk.content_type
        # Note: success reports are issued by msrplib
        # TODO: check wrapped content-type and issue a report if it's invalid
        ndata = TimestampedNotificationData(content=content, content_type=content_type, cpim_headers=cpim_headers, message=chunk)
        NotificationCenter().post_notification('ChatStreamGotMessage', self, ndata)

    def _on_transaction_response(self, message_id, response):
        if response.code!=200:
            data = TimestampedNotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment)
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', self, data)

    def _message_queue_handler(self):
        notification_center = NotificationCenter()
        while True:
            message_id, message, content_type, failure_report, success_report = self.message_queue.wait()
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
                notification_center.post_notification('ChatStreamDidSendMessage', self, TimestampedNotificationData(message=chunk))

    @run_in_green_thread
    def _enqueue_message(self, message_id, message, content_type, failure_report=None, success_report=None):
        self.message_queue.send((message_id, message, content_type, failure_report, success_report))
    
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
            raise ChatStreamError('Invalid content_type for outgoing message: %r' % (content_type, ))
        message_id = '%x' % random.getrandbits(64)
        if self.cpim_enabled:
            if remote_identity is None:
                remote_identity = self.remote_identity
            elif not self.private_messages_allowed and remote_identity != self.remote_identity:
                raise ChatStreamError('The remote end does not support private messages')
            if dt is None:
                dt = datetime.utcnow()
            msg = MessageCPIM(content, content_type, from_=self.local_identity, to=remote_identity, datetime=dt)
            self._enqueue_message(message_id, str(msg), 'message/cpim', failure_report='partial', success_report='yes')
        else:
            if remote_identity is not None and remote_identity != self.remote_identity:
                raise ChatStreamError('Private messages are not available, because CPIM wrapper is not used')
            self._enqueue_message(message_id, content, content_type)
        return message_id


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

    def _create_local_media(self, uri_path):
        local_media = MSRPStreamBase._create_local_media(self, uri_path)
        local_media.attributes.append(SDPAttribute('file-selector', self.file_selector.sdp_repr))
        return local_media

    def validate_incoming(self, remote_sdp, stream_index):
        media = remote_sdp.media[stream_index]
        media_attributes = dict((attr.name, attr.value) for attr in media.attributes)
        self.file_selector = FileSelector.parse(media_attributes['file-selector'])
        direction = media.get_direction()
        if (direction, self.direction) != ('sendonly', 'recvonly'):
            return False
        return True

    def _NH_MediaStreamDidStart(self, notification):
        if self.direction == 'sendonly':
            self.msrp_session.send_file(self.outgoing_file)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        notification_center = NotificationCenter()
        data = TimestampedNotificationData(message_id=chunk.message_id, chunk=chunk, code=chunk.status.code, reason=chunk.status.comment)
        if chunk.status.code == 200:
            notification_center.post_notification('FileTransferStreamDidDeliverChunk', self, data)
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
        ndata = TimestampedNotificationData(content=content, content_type=content_type, cpim_headers=cpim_headers, chunk=chunk)
        NotificationCenter().post_notification('FileTransferStreamGotChunk', self, ndata)


# temporary solution. to be replaced later by a better logging system in msrplib -Dan
class NotificationProxyLogger(object):
    def __init__(self):
        from weakref import WeakKeyDictionary
        from application import log
        self.transport_data_in = WeakKeyDictionary()
        self.level = log.level

    def report_out(self, data, transport, new_chunk=True):
        NotificationCenter().post_notification('MSRPTransportTrace', sender=transport, data=TimestampedNotificationData(direction='outgoing', data=data))

    def report_in(self, data, transport, new_chunk=False, packet_done=False):
        if new_chunk or packet_done:
            old_data = self.transport_data_in.pop(transport, None)
            if old_data is not None:
                NotificationCenter().post_notification('MSRPTransportTrace', sender=transport, data=TimestampedNotificationData(direction='incoming', data=old_data))
        if data:
            self.transport_data_in[transport] = self.transport_data_in.get(transport, '') + data

    def debug(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.DEBUG))

    def info(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.INFO))
    msg = info

    def warn(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.WARNING))

    def error(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.ERROR))

    def fatal(self, message, **context):
        NotificationCenter().post_notification('MSRPLibraryLog', data=TimestampedNotificationData(message=message, level=self.level.CRITICAL))



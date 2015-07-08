# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""
Handling of MSRP media streams according to RFC4975, RFC4976, RFC5547
and RFC3994.

This module provides classes to parse and generate SDP related to SIP
sessions that negotiate Instant Messsaging, File Transfer and Screen
Sharing and handling of the actual media streams.
"""

__all__ = ['ChatStream', 'FileTransferStream', 'ScreenSharingStream', 'MSRPStreamError', 'ChatStreamError', 'VNCConnectionError', 'FileSelector', 'ScreenSharingHandler',
           'ScreenSharingServerHandler', 'ScreenSharingViewerHandler', 'InternalVNCViewerHandler', 'InternalVNCServerHandler', 'ExternalVNCViewerHandler', 'ExternalVNCServerHandler']

import cPickle as pickle
import errno
import hashlib
import mimetypes
import os
import random
import re
import sys
import time
import uuid

from abc import ABCMeta, abstractmethod, abstractproperty
from application.notification import NotificationCenter, NotificationData, IObserver
from application.python.descriptor import WriteOnceAttribute
from application.python.threadpool import ThreadPool, run_in_threadpool
from application.python.types import MarkerType
from application.system import host, makedirs, unlink
from collections import defaultdict
from functools import partial
from itertools import count
from Queue import Queue
from threading import Event, Lock
from twisted.internet.error import ConnectionDone
from zope.interface import implements

from eventlib import api
from eventlib.coros import queue
from eventlib.greenio import GreenSocket
from eventlib.proc import spawn, ProcExit
from eventlib.util import tcp_socket, set_reuse_addr
from msrplib.connect import DirectConnector, DirectAcceptor, RelayConnection, MSRPRelaySettings
from msrplib.protocol import URI, MSRPHeader, FailureReportHeader, SuccessReportHeader, ContentTypeHeader, UseNicknameHeader, parse_uri
from msrplib.session import MSRPSession, contains_mime_type
from msrplib.transport import make_response, make_report

from sipsimple.account import Account, BonjourAccount
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import SDPAttribute, SDPConnection, SDPMediaStream
from sipsimple.payloads.iscomposing import IsComposingDocument, State, LastActive, Refresh, ContentType
from sipsimple.storage import ISIPSimpleApplicationDataStorage
from sipsimple.streams import IMediaStream, MediaStreamType, StreamError, InvalidStreamError, UnknownStreamError
from sipsimple.streams.applications.chat import ChatIdentity, ChatMessage, CPIMMessage, CPIMParserError
from sipsimple.threading import run_in_twisted_thread, run_in_thread
from sipsimple.threading.green import run_in_green_thread
from sipsimple.util import ISOTimestamp, sha1


class MSRPStreamError(StreamError): pass
class ChatStreamError(MSRPStreamError): pass

class VNCConnectionError(Exception): pass


class MSRPStreamBase(object):
    __metaclass__ = MediaStreamType

    implements(IMediaStream, IObserver)

    # Attributes that need to be defined by each MSRP stream type
    type = None
    priority = None
    msrp_session_class = None

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

    def __init__(self, direction='sendrecv'):
        self.direction = direction
        self.greenlet = None
        self.local_media = None
        self.remote_media = None
        self.msrp = None ## Placeholder for the MSRPTransport that will be set when started
        self.msrp_connector = None
        self.cpim_enabled = None ## Boolean value. None means it was not negotiated yet
        self.session = None
        self.msrp_session = None
        self.shutting_down = False
        self.local_role = None
        self.remote_role = None
        self.transport = None
        self.remote_accept_types = None
        self.remote_accept_wrapped_types = None

        self._initialized = False
        self._done = False
        self._failure_reason = None

    @property
    def local_uri(self):
        return URI(host=host.default_ip, port=0, use_tls=self.transport=='tls', credentials=self.session.account.tls_credentials)

    def _create_local_media(self, uri_path):
        transport = "TCP/TLS/MSRP" if uri_path[-1].use_tls else "TCP/MSRP"
        attributes = [SDPAttribute("path", " ".join(str(uri) for uri in uri_path))]
        if self.direction not in [None, 'sendrecv']:
            attributes.append(SDPAttribute(self.direction, ''))
        if self.accept_types is not None:
            attributes.append(SDPAttribute("accept-types", " ".join(self.accept_types)))
        if self.accept_wrapped_types is not None:
            attributes.append(SDPAttribute("accept-wrapped-types", " ".join(self.accept_wrapped_types)))
        attributes.append(SDPAttribute("setup", self.local_role))
        local_ip = uri_path[-1].host
        connection = SDPConnection(local_ip)
        return SDPMediaStream(self.media_type, uri_path[-1].port or 2855, transport, connection=connection, formats=["*"], attributes=attributes)

    ## The public API (the IMediaStream interface)

    def get_local_media(self, remote_sdp=None, index=0):
        return self.local_media

    def new_from_sdp(self, session, remote_sdp, stream_index):
        raise NotImplementedError

    @run_in_green_thread
    def initialize(self, session, direction):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        try:
            self.session = session
            self.transport = self.session.account.msrp.transport
            outgoing = direction=='outgoing'
            logger = NotificationProxyLogger()
            if self.session.account is BonjourAccount():
                if outgoing:
                    self.msrp_connector = DirectConnector(logger=logger)
                    self.local_role = 'active'
                else:
                    if self.transport=='tls' and None in (self.session.account.tls_credentials.cert, self.session.account.tls_credentials.key):
                        raise MSRPStreamError("Cannot accept MSRP connection without a TLS certificate")
                    self.msrp_connector = DirectAcceptor(logger=logger)
                    self.local_role = 'passive'
            else:
                if self.session.account.msrp.connection_model == 'relay':
                    if not outgoing and self.remote_role in ('actpass', 'passive'):
                        # 'passive' not allowed by the RFC but play nice for interoperability. -Saul
                        self.msrp_connector = DirectConnector(logger=logger, use_sessmatch=True)
                        self.local_role = 'active'
                    elif outgoing and not self.session.account.nat_traversal.use_msrp_relay_for_outbound:
                        self.msrp_connector = DirectConnector(logger=logger, use_sessmatch=True)
                        self.local_role = 'active'
                    else:
                        if self.session.account.nat_traversal.msrp_relay is None:
                            relay_host = relay_port = None
                        else:
                            if self.transport != self.session.account.nat_traversal.msrp_relay.transport:
                                raise MSRPStreamError("MSRP relay transport conflicts with MSRP transport setting")
                            relay_host = self.session.account.nat_traversal.msrp_relay.host
                            relay_port = self.session.account.nat_traversal.msrp_relay.port
                        relay = MSRPRelaySettings(domain=self.session.account.uri.host,
                                                  username=self.session.account.uri.user,
                                                  password=self.session.account.credentials.password,
                                                  host=relay_host,
                                                  port=relay_port,
                                                  use_tls=self.transport=='tls')
                        self.msrp_connector = RelayConnection(relay, 'passive', logger=logger, use_sessmatch=True)
                        self.local_role = 'actpass' if outgoing else 'passive'
                else:
                    if not outgoing and self.remote_role in ('actpass', 'passive'):
                        # 'passive' not allowed by the RFC but play nice for interoperability. -Saul
                        self.msrp_connector = DirectConnector(logger=logger, use_sessmatch=True)
                        self.local_role = 'active'
                    else:
                        if not outgoing and self.transport=='tls' and None in (self.session.account.tls_credentials.cert, self.session.account.tls_credentials.key):
                            raise MSRPStreamError("Cannot accept MSRP connection without a TLS certificate")
                        self.msrp_connector = DirectAcceptor(logger=logger, use_sessmatch=True)
                        self.local_role = 'actpass' if outgoing else 'passive'
            full_local_path = self.msrp_connector.prepare(self.local_uri)
            self.local_media = self._create_local_media(full_local_path)
        except Exception, e:
            notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason=str(e)))
        else:
            self._initialized = True
            notification_center.post_notification('MediaStreamDidInitialize', sender=self)
        finally:
            self.greenlet = None

    @run_in_green_thread
    def start(self, local_sdp, remote_sdp, stream_index):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        try:
            context = 'sdp_negotiation'
            remote_media = remote_sdp.media[stream_index]
            self.remote_media = remote_media
            self.remote_accept_types = remote_media.attributes.getfirst('accept-types', '').split()
            self.remote_accept_wrapped_types = remote_media.attributes.getfirst('accept-wrapped-types', '').split()
            self.cpim_enabled = contains_mime_type(self.accept_types, 'message/cpim') and contains_mime_type(self.remote_accept_types, 'message/cpim')
            remote_uri_path = remote_media.attributes.getfirst('path')
            if remote_uri_path is None:
                raise AttributeError("remote SDP media does not have 'path' attribute")
            full_remote_path = [parse_uri(uri) for uri in remote_uri_path.split()]
            remote_transport = 'tls' if full_remote_path[0].use_tls else 'tcp'
            if self.transport != remote_transport:
                raise MSRPStreamError("remote transport ('%s') different from local transport ('%s')" % (remote_transport, self.transport))
            if isinstance(self.session.account, Account) and self.local_role == 'actpass':
                remote_setup = remote_media.attributes.getfirst('setup', 'passive')
                if remote_setup == 'passive':
                    # If actpass is offered connectors are always started as passive
                    # We need to switch to active if the remote answers with passive
                    if self.session.account.msrp.connection_model == 'relay':
                        self.msrp_connector.mode = 'active'
                    else:
                        local_uri = self.msrp_connector.local_uri
                        logger = self.msrp_connector.logger
                        self.msrp_connector = DirectConnector(logger=logger, use_sessmatch=True)
                        self.msrp_connector.prepare(local_uri)
            context = 'start'
            self.msrp = self.msrp_connector.complete(full_remote_path)
            if self.msrp_session_class is not None:
                self.msrp_session = self.msrp_session_class(self.msrp, accept_types=self.accept_types, on_incoming_cb=self._handle_incoming, automatic_reports=False)
            self.msrp_connector = None
        except Exception, e:
            self._failure_reason = str(e)
            notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context=context, reason=self._failure_reason))
        else:
            notification_center.post_notification('MediaStreamDidStart', sender=self)
        finally:
            self.greenlet = None

    def deactivate(self):
        self.shutting_down = True

    @run_in_green_thread
    def end(self):
        if self._done:
            return
        self._done = True
        notification_center = NotificationCenter()
        if not self._initialized:
            if self.greenlet is not None:
                # we are in the middle of initialize()
                api.kill(self.greenlet)
            notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason='Interrupted'))
            return
        notification_center.post_notification('MediaStreamWillEnd', sender=self)
        msrp = self.msrp
        msrp_session = self.msrp_session
        msrp_connector = self.msrp_connector
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
            notification_center.post_notification('MediaStreamDidEnd', sender=self, data=NotificationData(error=self._failure_reason))
            notification_center.remove_observer(self, sender=self)
            self.msrp = None
            self.msrp_session = None
            self.msrp_connector = None
            self.session = None

    def validate_update(self, remote_sdp, stream_index):
        return True #TODO

    def update(self, local_sdp, remote_sdp, stream_index):
        pass #TODO

    def hold(self):
        pass

    def unhold(self):
        pass

    def reset(self, stream_index):
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
            self._failure_reason = error.getErrorMessage()
            notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='reading', reason=self._failure_reason))
        elif chunk is not None:
            method_handler = getattr(self, '_handle_%s' % chunk.method, None)
            if method_handler is not None:
                method_handler(chunk)

    def _handle_REPORT(self, chunk):
        pass

    def _handle_SEND(self, chunk):
        pass


class Message(object):
    __slots__ = ('id', 'content', 'content_type', 'sender', 'recipients', 'courtesy_recipients', 'subject', 'timestamp', 'required', 'additional_headers', 'failure_report', 'success_report', 'notify_progress')

    def __init__(self, id, content, content_type, sender=None, recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None, failure_report='yes', success_report='yes', notify_progress=False):
        self.id = id
        self.content = content
        self.content_type = content_type
        self.sender = sender
        self.recipients = recipients
        self.courtesy_recipients = courtesy_recipients
        self.subject = subject
        self.timestamp = timestamp
        self.required = required
        self.additional_headers = additional_headers
        self.failure_report = failure_report
        self.success_report = success_report
        self.notify_progress = notify_progress


class ChatStream(MSRPStreamBase):
    type = 'chat'
    priority = 1
    msrp_session_class = MSRPSession

    media_type = 'message'
    accept_types = ['message/cpim', 'text/*', 'image/*', 'application/im-iscomposing+xml']
    accept_wrapped_types = ['text/*', 'image/*', 'application/im-iscomposing+xml']

    def __init__(self, direction='sendrecv'):
        super(ChatStream, self).__init__(direction=direction)
        self.message_queue = queue()
        self.sent_messages = set()
        self.incoming_queue = defaultdict(list)
        self.message_queue_thread = None

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message':
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if session.account.msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in chat stream, got %s" % (expected_transport, remote_stream.transport))
        if remote_stream.formats != ['*']:
            raise InvalidStreamError("wrong format list specified")
        stream = cls()
        stream.remote_role = remote_stream.attributes.getfirst('setup', 'active')
        if (remote_stream.direction, stream.direction) not in (('sendrecv', 'sendrecv'), ('sendonly', 'recvonly'), ('recvonly', 'sendonly')):
            raise InvalidStreamError("mismatching directions in chat stream")
        remote_accept_types = remote_stream.attributes.getfirst('accept-types')
        if remote_accept_types is None:
            raise InvalidStreamError("remote SDP media does not have 'accept-types' attribute")
        if not any(contains_mime_type(cls.accept_types, mime_type) for mime_type in remote_accept_types.split()):
            raise InvalidStreamError("no compatible media types found")
        return stream

    @property
    def local_identity(self):
        try:
            return ChatIdentity(self.session.local_identity.uri, self.session.account.display_name)
        except AttributeError:
            return None

    @property
    def remote_identity(self):
        try:
            return ChatIdentity(self.session.remote_identity.uri, self.session.remote_identity.display_name)
        except AttributeError:
            return None

    @property
    def private_messages_allowed(self):
        return 'private-messages' in self.chatroom_capabilities

    @property
    def nickname_allowed(self):
        return 'nickname' in self.chatroom_capabilities

    @property
    def chatroom_capabilities(self):
        try:
            if self.cpim_enabled and self.session.remote_focus:
                return ' '.join(self.remote_media.attributes.getall('chatroom')).split()
        except AttributeError:
            pass
        return []

    def _NH_MediaStreamDidStart(self, notification):
        self.message_queue_thread = spawn(self._message_queue_handler)

    def _NH_MediaStreamDidNotInitialize(self, notification):
        message_queue, self.message_queue = self.message_queue, queue()
        while message_queue:
            message = message_queue.wait()
            data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream was closed')
            notification.center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _NH_MediaStreamDidEnd(self, notification):
        if self.message_queue_thread is not None:
            self.message_queue_thread.kill()
        else:
            message_queue, self.message_queue = self.message_queue, queue()
            while message_queue:
                message = message_queue.wait()
                data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                notification.center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        if chunk.message_id in self.sent_messages:
            self.sent_messages.remove(chunk.message_id)
            notification_center = NotificationCenter()
            data = NotificationData(message_id=chunk.message_id, message=chunk, code=chunk.status.code, reason=chunk.status.comment)
            if chunk.status.code == 200:
                notification_center.post_notification('ChatStreamDidDeliverMessage', sender=self, data=data)
            else:
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _handle_SEND(self, chunk):
        if chunk.size == 0:
            # keep-alive
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        if self.direction=='sendonly':
            self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
            return
        content_type = chunk.content_type.lower()
        if not contains_mime_type(self.accept_types, content_type):
            self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
            return
        if chunk.contflag == '#':
            self.incoming_queue.pop(chunk.message_id, None)
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        elif chunk.contflag == '+':
            self.incoming_queue[chunk.message_id].append(chunk.data)
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        else:
            data = ''.join(self.incoming_queue.pop(chunk.message_id, [])) + chunk.data
        if content_type == 'message/cpim':
            try:
                message = CPIMMessage.parse(data)
            except CPIMParserError:
                self.msrp_session.send_report(chunk, 400, 'CPIM Parser Error')
                return
            else:
                if not contains_mime_type(self.accept_wrapped_types, message.content_type):
                    self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
                    return
                if message.timestamp is None:
                    message.timestamp = ISOTimestamp.now()
                if message.sender is None:
                    message.sender = self.remote_identity
                private = self.session.remote_focus and len(message.recipients) == 1 and message.recipients[0] != self.remote_identity
        else:
            message = ChatMessage(data.decode('utf-8'), content_type, self.remote_identity, self.local_identity, ISOTimestamp.now())
            private = False
        self.msrp_session.send_report(chunk, 200, 'OK')
        notification_center = NotificationCenter()
        if message.content_type.lower() == IsComposingDocument.content_type:
            data = IsComposingDocument.parse(message.body)
            ndata = NotificationData(state=data.state.value,
                                     refresh=data.refresh.value if data.refresh is not None else 120,
                                     content_type=data.content_type.value if data.content_type is not None else None,
                                     last_active=data.last_active.value if data.last_active is not None else None,
                                     sender=message.sender, recipients=message.recipients, private=private)
            notification_center.post_notification('ChatStreamGotComposingIndication', sender=self, data=ndata)
        else:
            notification_center.post_notification('ChatStreamGotMessage', sender=self, data=NotificationData(message=message, private=private))

    def _on_transaction_response(self, message_id, response):
        if message_id in self.sent_messages and response.code != 200:
            self.sent_messages.remove(message_id)
            data = NotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment)
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _on_nickname_transaction_response(self, message_id, response):
        notification_center = NotificationCenter()
        if response.code == 200:
            notification_center.post_notification('ChatStreamDidSetNickname', sender=self, data=NotificationData(message_id=message_id, response=response))
        else:
            notification_center.post_notification('ChatStreamDidNotSetNickname', sender=self, data=NotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment))

    def _message_queue_handler(self):
        notification_center = NotificationCenter()
        try:
            while True:
                message = self.message_queue.wait()
                if self.msrp_session is None:
                    data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    break
                try:
                    if self.cpim_enabled:
                        if not contains_mime_type(self.remote_accept_wrapped_types, message.content_type):
                            raise ChatStreamError('Invalid content_type for outgoing message: %r' % message.content_type)
                        if not message.recipients:
                            message.recipients = [self.remote_identity]
                        elif not self.private_messages_allowed and message.recipients != [self.remote_identity]:
                            raise ChatStreamError('The remote end does not support private messages')
                        if message.sender is None:
                            message.sender = self.local_identity
                        if message.timestamp is None:
                            message.timestamp = ISOTimestamp.now()
                        msg = CPIMMessage(message.content, message.content_type, sender=message.sender,
                                          recipients=message.recipients, courtesy_recipients=message.courtesy_recipients,
                                          subject=message.subject, timestamp=message.timestamp,
                                          required=message.required, additional_headers=message.additional_headers)
                        content = str(msg)
                        content_type = 'message/cpim'
                    else:
                        if not contains_mime_type(self.remote_accept_types, message.content_type):
                            raise ChatStreamError('Invalid content_type for outgoing message: %r' % message.content_type)
                        if message.recipients is not None and message.recipients != [self.remote_identity]:
                            raise ChatStreamError('Private messages are not available, because CPIM wrapper is not used')
                        if message.courtesy_recipients or message.subject or message.timestamp or message.required or message.additional_headers:
                            raise ChatStreamError('Additional message meta-data cannot be sent, because CPIM wrapper is not used')
                        if isinstance(message.content, unicode):
                            message.content = message.content.encode('utf-8')
                        content = message.content
                        content_type = message.content_type
                except ChatStreamError, e:
                    data = NotificationData(message_id=message.id, message=None, code=0, reason=e.args[0])
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    continue

                message_id = message.id
                failure_report = message.failure_report
                success_report = message.success_report
                notify_progress = message.notify_progress

                chunk = self.msrp_session.make_message(content, content_type=content_type, message_id=message_id)
                if failure_report is not None:
                    chunk.add_header(FailureReportHeader(failure_report))
                if success_report is not None:
                    chunk.add_header(SuccessReportHeader(success_report))
                try:
                    self.msrp_session.send_chunk(chunk, response_cb=partial(self._on_transaction_response, message_id))
                except Exception, e:
                    data = NotificationData(message_id=message_id, message=None, code=0, reason=str(e))
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                except ProcExit:
                    data = NotificationData(message_id=message_id, message=None, code=0, reason='Stream ended')
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    raise
                else:
                    if notify_progress and success_report == 'yes' and failure_report != 'no':
                        self.sent_messages.add(message_id)
                        notification_center.post_notification('ChatStreamDidSendMessage', sender=self, data=NotificationData(message=chunk))
        finally:
            self.message_queue_thread = None
            while self.sent_messages:
                message_id = self.sent_messages.pop()
                data = NotificationData(message_id=message_id, message=None, code=0, reason='Stream ended')
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
            message_queue, self.message_queue = self.message_queue, queue()
            while message_queue:
                message = message_queue.wait()
                data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    @run_in_twisted_thread
    def _enqueue_message(self, message):
        if self._done:
            data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
        else:
            self.message_queue.send(message)

    @run_in_green_thread
    def _set_local_nickname(self, nickname, message_id):
        if self.msrp_session is None:
            # should we generate ChatStreamDidNotSetNickname here?
            return
        chunk = self.msrp.make_request('NICKNAME')
        chunk.add_header(UseNicknameHeader(nickname or u''))
        try:
            self.msrp_session.send_chunk(chunk, response_cb=partial(self._on_nickname_transaction_response, message_id))
        except Exception, e:
            self._failure_reason = str(e)
            NotificationCenter().post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='sending', reason=self._failure_reason))

    def send_message(self, content, content_type='text/plain', recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None):
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
        """
        if self.direction=='recvonly':
            raise ChatStreamError('Cannot send message on recvonly stream')
        message_id = '%x' % random.getrandbits(64)
        message = Message(message_id, content, content_type, recipients=recipients, courtesy_recipients=courtesy_recipients, subject=subject, timestamp=timestamp, required=required, additional_headers=additional_headers, failure_report='yes', success_report='yes', notify_progress=True)
        self._enqueue_message(message)
        return message_id

    def send_composing_indication(self, state, refresh=None, last_active=None, recipients=None):
        if self.direction == 'recvonly':
            raise ChatStreamError('Cannot send message on recvonly stream')
        message_id = '%x' % random.getrandbits(64)
        content = IsComposingDocument.create(state=State(state), refresh=Refresh(refresh) if refresh is not None else None, last_active=LastActive(last_active) if last_active is not None else None, content_type=ContentType('text'))
        message = Message(message_id, content, IsComposingDocument.content_type, recipients=recipients, failure_report='partial', success_report='no', notify_progress=False)
        self._enqueue_message(message)
        return message_id

    def set_local_nickname(self, nickname):
        if not self.nickname_allowed:
            raise ChatStreamError('Setting nickname is not supported')
        message_id = '%x' % random.getrandbits(64)
        self._set_local_nickname(nickname, message_id)
        return message_id


# File transfer
#

class RandomID:    __metaclass__ = MarkerType


class FileSelector(object):
    class __metaclass__(type):
        _name_re = re.compile('name:"([^"]+)"')
        _size_re = re.compile('size:(\d+)')
        _type_re = re.compile('type:([^ ]+)')
        _hash_re = re.compile('hash:([^ ]+)')
        _byte_re = re.compile('..')

    def __init__(self, name=None, type=None, size=None, hash=None, fd=None):
        ## If present, hash should be a sha1 object or a string in the form: sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E
        ## According to the specification, only sha1 is supported ATM.
        self.name = name
        self.type = type
        self.size = size
        self.hash = hash
        self.fd = fd

    def _get_hash(self):
        return self.__dict__['hash']

    def _set_hash(self, value):
        if value is None:
            self.__dict__['hash'] = value
        elif isinstance(value, str) and value.startswith('sha1:'):
            self.__dict__['hash'] = value
        elif hasattr(value, 'hexdigest') and hasattr(value, 'name'):
            if value.name != 'sha1':
                raise TypeError("Invalid hash type: '%s'. Only sha1 hashes are supported" % value.name)
            # unexpected as it may be, using a regular expression is the fastest method to do this
            self.__dict__['hash'] = 'sha1:' + ':'.join(self.__class__._byte_re.findall(value.hexdigest().upper()))
        else:
            raise ValueError("Invalid hash value")

    hash = property(_get_hash, _set_hash)
    del _get_hash, _set_hash

    @classmethod
    def parse(cls, string):
        name_match = cls._name_re.search(string)
        size_match = cls._size_re.search(string)
        type_match = cls._type_re.search(string)
        hash_match = cls._hash_re.search(string)
        name = name_match and name_match.group(1).decode('utf-8')
        size = size_match and int(size_match.group(1))
        type = type_match and type_match.group(1)
        hash = hash_match and hash_match.group(1)
        return cls(name, type, size, hash)

    @classmethod
    def for_file(cls, path, type=None, hash=None):
        name = unicode(path)
        fd = open(name.encode(sys.getfilesystemencoding()), 'rb')
        size = os.fstat(fd.fileno()).st_size
        if type is None:
            mime_type, encoding = mimetypes.guess_type(name)
            if encoding is not None:
                type = 'application/x-%s' % encoding
            elif mime_type is not None:
                type = mime_type
            else:
                type = 'application/octet-stream'
        return cls(name, type, size, hash, fd)

    @property
    def sdp_repr(self):
        items = [('name', self.name and '"%s"' % os.path.basename(self.name).encode('utf-8')), ('type', self.type), ('size', self.size), ('hash', self.hash)]
        return ' '.join('%s:%s' % (name, value) for name, value in items if value is not None)


class UniqueFilenameGenerator(object):
    @classmethod
    def generate(cls, name):
        yield name
        prefix, extension = os.path.splitext(name)
        for x in count(1):
            yield "%s-%d%s" % (prefix, x, extension)


class FileMetadataEntry(object):
    def __init__(self, hash, filename, partial_hash=None):
        self.hash = hash
        self.filename = filename
        self.mtime = os.path.getmtime(self.filename)
        self.partial_hash = partial_hash

    @classmethod
    def from_selector(cls, file_selector):
        return cls(file_selector.hash.lower(), file_selector.name)


class FileTransfersMetadata(object):
    __filename__ = 'transfer_metadata'
    __lifetime__ = 60*60*24*7

    def __init__(self):
        self.data = {}
        self.lock = Lock()
        self.loaded = False
        self.directory = None

    def _load(self):
        if self.loaded:
            return
        from sipsimple.application import SIPApplication
        if ISIPSimpleApplicationDataStorage.providedBy(SIPApplication.storage):
            self.directory = SIPApplication.storage.directory
        if self.directory is not None:
            try:
                with open(os.path.join(self.directory, self.__filename__), 'rb') as f:
                    data = pickle.loads(f.read())
            except Exception:
                data = {}
            now = time.time()
            for hash, entry in data.items():
                try:
                    mtime = os.path.getmtime(entry.filename)
                except OSError:
                    data.pop(hash)
                else:
                    if mtime != entry.mtime or now - mtime > self.__lifetime__:
                        data.pop(hash)
            self.data.update(data)
        self.loaded = True

    @run_in_thread('file-io')
    def _save(self, data):
        if self.directory is not None:
            with open(os.path.join(self.directory, self.__filename__), 'wb') as f:
                f.write(data)

    def __enter__(self):
        self.lock.acquire()
        self._load()
        return self.data

    def __exit__(self, exc_type, exc_val, exc_tb):
        if None is exc_type is exc_val is exc_tb:
            self._save(pickle.dumps(self.data))
        self.lock.release()


class FileTransferHandler(object):
    __metaclass__ = ABCMeta

    implements(IObserver)

    threadpool = ThreadPool(name='FileTransfers', min_threads=0, max_threads=100)
    threadpool.start()

    def __init__(self):
        self.stream = None
        self._started = False
        self._initialize_done = False

    def initialize(self, stream):
        self.stream = stream
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=stream)
        notification_center.add_observer(self, sender=self)

    @property
    def filename(self):
        return self.stream.file_selector.name if self.stream is not None else None

    @abstractmethod
    def start(self):
        raise NotImplementedError

    @abstractmethod
    def end(self):
        raise NotImplementedError

    @abstractmethod
    def process_chunk(self, chunk):
        raise NotImplementedError

    def __terminate(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.stream)
        notification_center.remove_observer(self, sender=self)
        if self.stream.file_selector.fd is not None:
            self.stream.file_selector.fd.close()
        self.stream = None

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_MediaStreamDidNotInitialize(self, notification):
        if not self._initialize_done:
            self.end()
        self.__terminate()

    def _NH_MediaStreamDidStart(self, notification):
        self._started = True
        self.start()

    def _NH_MediaStreamWillEnd(self, notification):
        if self._started:
            self.end()
        else:
            notification.center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Cancelled'))

    def _NH_FileTransferHandlerDidInitialize(self, notification):
        self._initialize_done = True

    def _NH_FileTransferHandlerDidNotInitialize(self, notification):
        self._initialize_done = True

    def _NH_FileTransferHandlerDidEnd(self, notification):
        self.__terminate()


class EndTransfer: __metaclass__ = MarkerType


class IncomingFileTransferHandler(FileTransferHandler):
    metadata = FileTransfersMetadata()

    def __init__(self):
        super(IncomingFileTransferHandler, self).__init__()
        self.hash = sha1()
        self.queue = Queue()
        self.offset = 0
        self.received_chunks = 0

    def _get_save_directory(self):
        return self.__dict__.get('save_directory')

    def _set_save_directory(self, value):
        if self.stream is not None:
            raise AttributeError('cannot set save_directory, transfer is in progress')
        self.__dict__['save_directory'] = value

    save_directory = property(_get_save_directory, _set_save_directory)
    del _get_save_directory, _set_save_directory

    def initialize(self, stream):
        super(IncomingFileTransferHandler, self).initialize(stream)
        try:
            directory = self.save_directory or SIPSimpleSettings().file_transfer.directory.normalized
            makedirs(directory)
            with self.metadata as metadata:
                try:
                    prev_file = metadata.pop(stream.file_selector.hash.lower())
                    mtime = os.path.getmtime(prev_file.filename)
                    if mtime != prev_file.mtime:
                        raise ValueError('file was modified')
                    filename = os.path.join(directory, os.path.basename(stream.file_selector.name))
                    try:
                        os.link(prev_file.filename, filename)
                    except (AttributeError, OSError):
                        stream.file_selector.name = prev_file.filename
                    else:
                        stream.file_selector.name = filename
                        unlink(prev_file.filename)
                    stream.file_selector.fd = open(stream.file_selector.name.encode(sys.getfilesystemencoding()), 'ab')
                    if sys.platform == 'win32':
                        stream.file_selector.fd.seek(0, os.SEEK_END)
                    self.offset = stream.file_selector.fd.tell()
                    self.hash = prev_file.partial_hash
                except (KeyError, EnvironmentError, ValueError):
                    filename = None
                    fd = None
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if sys.platform == 'win32':
                        flags |= os.O_BINARY
                    for name in UniqueFilenameGenerator.generate(os.path.join(directory, os.path.basename(stream.file_selector.name))):
                        try:
                            fd = os.open(name, flags, 0644)
                        except OSError, e:
                            if e.args[0] == errno.EEXIST:
                                continue
                            raise
                        filename = name
                        break
                    stream.file_selector.name = filename
                    stream.file_selector.fd = os.fdopen(fd, 'wb')
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason=str(e)))
        else:
            NotificationCenter().post_notification('FileTransferHandlerDidInitialize', sender=self)

    def end(self):
        self.queue.put(EndTransfer)

    def process_chunk(self, chunk):
        if chunk.method == 'SEND':
            if not self.received_chunks and chunk.byte_range[0] == 1:
                self.stream.file_selector.fd.truncate(0)
                self.stream.file_selector.fd.seek(0)
                self.hash = sha1()
                self.offset = 0
            self.received_chunks += 1
            self.queue.put(chunk)
        elif chunk.method == 'FILE_OFFSET':
            if self.received_chunks > 0:
                response = make_response(chunk, 413, 'Unwanted message')
            else:
                offset = self.stream.file_selector.fd.tell()
                response = make_response(chunk, 200, 'OK')
                response.headers['Offset'] = MSRPHeader('Offset', offset)
            self.stream.msrp_session.send_chunk(response)

    @run_in_threadpool(FileTransferHandler.threadpool)
    def start(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerDidStart', sender=self)
        file_selector = self.stream.file_selector
        fd = file_selector.fd

        while True:
            chunk = self.queue.get()
            if chunk is EndTransfer:
                break
            try:
                fd.write(chunk.data)
            except EnvironmentError, e:
                fd.close()
                notification_center.post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))
                notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason=str(e)))
                return
            self.hash.update(chunk.data)
            self.offset += chunk.size
            transferred_bytes = chunk.byte_range[0] + chunk.size - 1
            total_bytes = file_selector.size = chunk.byte_range[2]
            notification_center.post_notification('FileTransferHandlerProgress', sender=self, data=NotificationData(transferred_bytes=transferred_bytes, total_bytes=total_bytes))
            if transferred_bytes == total_bytes:
                break

        fd.close()

        # Transfer is finished

        if self.offset != self.stream.file_selector.size:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Incomplete file'))
            return
        local_hash = 'sha1:' + ':'.join(re.findall(r'..', self.hash.hexdigest()))
        remote_hash = self.stream.file_selector.hash.lower()
        if local_hash != remote_hash:
            unlink(self.filename)    # something got corrupted, better delete the file
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='File hash mismatch'))
            return

        notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=False, reason=None))

    def _NH_MediaStreamDidNotInitialize(self, notification):
        if self.stream.file_selector.fd is not None:
            position = self.stream.file_selector.fd.tell()
            self.stream.file_selector.fd.close()
            if position == 0:
                unlink(self.stream.file_selector.name)
        super(IncomingFileTransferHandler, self)._NH_MediaStreamDidNotInitialize(notification)

    def _NH_FileTransferHandlerDidEnd(self, notification):
        if notification.data.error and self.stream.file_selector.hash is not None:
            if os.path.getsize(self.stream.file_selector.name) == 0:
                unlink(self.stream.file_selector.name)
            else:
                with self.metadata as metadata:
                    entry = FileMetadataEntry.from_selector(self.stream.file_selector)
                    entry.partial_hash = self.hash
                    metadata[entry.hash] = entry
        super(IncomingFileTransferHandler, self)._NH_FileTransferHandlerDidEnd(notification)


class OutgoingFileTransferHandler(FileTransferHandler):
    file_part_size = 64*1024

    def __init__(self):
        super(OutgoingFileTransferHandler, self).__init__()
        self.stop_event = Event()
        self.finished_event = Event()
        self.file_offset_event = Event()
        self.message_id = '%x' % random.getrandbits(64)
        self.offset = 0
        self.headers = {}

    def initialize(self, stream):
        super(OutgoingFileTransferHandler, self).initialize(stream)
        if stream.file_selector.fd is None:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='file descriptor not specified'))
            return
        if stream.file_selector.size == 0:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='file is empty'))
            return

        self.headers[ContentTypeHeader.name] = ContentTypeHeader(stream.file_selector.type)
        self.headers[SuccessReportHeader.name] = SuccessReportHeader('yes')
        self.headers[FailureReportHeader.name] = FailureReportHeader('yes')

        if stream.file_selector.hash is None:
            self._calculate_file_hash()
        else:
            NotificationCenter().post_notification('FileTransferHandlerDidInitialize', sender=self)

    @run_in_threadpool(FileTransferHandler.threadpool)
    def _calculate_file_hash(self):
        file_hash = hashlib.sha1()
        processed = 0

        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerHashProgress', sender=self, data=NotificationData(processed=0, total=self.stream.file_selector.size))

        file_selector = self.stream.file_selector
        fd = file_selector.fd
        while not self.stop_event.is_set():
            try:
                content = fd.read(self.file_part_size)
            except EnvironmentError, e:
                fd.close()
                notification_center.post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason=str(e)))
                return
            if not content:
                # unexpected as it may be, using a regular expression is the fastest method to do this
                file_selector.hash = 'sha1:' + ':'.join(FileSelector._byte_re.findall(file_hash.hexdigest().upper()))
                notification_center.post_notification('FileTransferHandlerDidInitialize', sender=self)
                break
            file_hash.update(content)
            processed += len(content)
            notification_center.post_notification('FileTransferHandlerHashProgress', sender=self, data=NotificationData(processed=processed, total=file_selector.size))
        else:
            fd.close()
            notification_center.post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='Interrupted transfer'))

    def end(self):
        self.stop_event.set()
        self.file_offset_event.set()    # in case we are busy waiting on it

    @run_in_threadpool(FileTransferHandler.threadpool)
    def start(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerDidStart', sender=self)

        if self.stream.file_offset_supported:
            self._send_file_offset_chunk()
            self.file_offset_event.wait()

        finished = False
        failure_reason = None
        fd = self.stream.file_selector.fd
        fd.seek(self.offset)

        try:
            while not self.stop_event.is_set():
                try:
                    data = fd.read(self.file_part_size)
                except EnvironmentError, e:
                    failure_reason = str(e)
                    break
                if not data:
                    finished = True
                    break
                self._send_chunk(data)
        finally:
            fd.close()

        if not finished:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason=failure_reason or 'Interrupted transfer'))
            return

        # Wait until the stream ends or we get all reports
        self.stop_event.wait()
        if self.finished_event.is_set():
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=False, reason=None))
        else:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Incomplete transfer'))

    def _on_transaction_response(self, response):
        if self.stop_event.is_set():
            return
        if response.code != 200:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=response.comment))
            self.end()

    @run_in_twisted_thread
    def _send_chunk(self, data):
        if self.stop_event.is_set():
            return
        data_len = len(data)
        chunk = self.stream.msrp.make_send_request(message_id=self.message_id,
                                                   data=data,
                                                   start=self.offset+1,
                                                   end=self.offset+data_len,
                                                   length=self.stream.file_selector.size)
        chunk.headers.update(self.headers)
        try:
            self.stream.msrp_session.send_chunk(chunk, response_cb=self._on_transaction_response)
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))
        else:
            self.offset += data_len

    @run_in_twisted_thread
    def _send_file_offset_chunk(self):
        def response_cb(response):
            if not self.stop_event.is_set() and response.code == 200:
                try:
                    offset = int(response.headers['Offset'].decoded)
                except (KeyError, ValueError):
                    offset = 0
                self.offset = offset
            self.file_offset_event.set()

        if self.stop_event.is_set():
            self.file_offset_event.set()
            return

        chunk = self.stream.msrp.make_request('FILE_OFFSET')
        try:
            self.stream.msrp_session.send_chunk(chunk, response_cb=response_cb)
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))

    def process_chunk(self, chunk):
        # here we process the REPORT chunks
        notification_center = NotificationCenter()
        if chunk.status.code == 200:
            transferred_bytes = chunk.byte_range[1]
            total_bytes = chunk.byte_range[2]
            notification_center.post_notification('FileTransferHandlerProgress', sender=self, data=NotificationData(transferred_bytes=transferred_bytes, total_bytes=total_bytes))
            if transferred_bytes == total_bytes:
                self.finished_event.set()
                self.end()
        else:
            notification_center.post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=chunk.status.comment))
            self.end()


class FileTransferMSRPSession(MSRPSession):
    def _handle_incoming_FILE_OFFSET(self, chunk):
        self._on_incoming_cb(chunk)


class FileTransferStream(MSRPStreamBase):
    type = 'file-transfer'
    priority = 10
    msrp_session_class = FileTransferMSRPSession

    media_type = 'message'
    accept_types = ['*']
    accept_wrapped_types = None

    IncomingTransferHandler = IncomingFileTransferHandler
    OutgoingTransferHandler = OutgoingFileTransferHandler

    def __init__(self, file_selector, direction, transfer_id=RandomID):
        if direction not in ('sendonly', 'recvonly'):
            raise ValueError("direction must be one of 'sendonly' or 'recvonly'")
        super(FileTransferStream, self).__init__(direction=direction)
        self.file_selector = file_selector
        self.transfer_id = transfer_id if transfer_id is not RandomID else str(uuid.uuid4())
        if direction == 'sendonly':
            self.handler = self.OutgoingTransferHandler()
        else:
            self.handler = self.IncomingTransferHandler()

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message' or 'file-selector' not in remote_stream.attributes:
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if session.account.msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in file transfer stream, got %s" % (expected_transport, remote_stream.transport))
        if remote_stream.formats != ['*']:
            raise InvalidStreamError("wrong format list specified")
        file_selector = FileSelector.parse(remote_stream.attributes.getfirst('file-selector'))
        transfer_id = remote_stream.attributes.getfirst('file-transfer-id', None)
        if remote_stream.direction == 'sendonly':
            stream = cls(file_selector, 'recvonly', transfer_id)
        elif remote_stream.direction == 'recvonly':
            stream = cls(file_selector, 'sendonly', transfer_id)
        else:
            raise InvalidStreamError("wrong stream direction specified")
        stream.remote_role = remote_stream.attributes.getfirst('setup', 'active')
        return stream

    def initialize(self, session, direction):
        self._initialize_args = session, direction
        NotificationCenter().add_observer(self, sender=self.handler)
        self.handler.initialize(self)

    def _create_local_media(self, uri_path):
        local_media = super(FileTransferStream, self)._create_local_media(uri_path)
        local_media.attributes.append(SDPAttribute('file-selector', self.file_selector.sdp_repr))
        local_media.attributes.append(SDPAttribute('x-file-offset', ''))
        if self.transfer_id is not None:
            local_media.attributes.append(SDPAttribute('file-transfer-id', self.transfer_id))
        return local_media

    @property
    def file_offset_supported(self):
        try:
            return 'x-file-offset' in self.remote_media.attributes
        except AttributeError:
            return False

    @run_in_twisted_thread
    def _NH_FileTransferHandlerDidInitialize(self, notification):
        session, direction = self._initialize_args
        del self._initialize_args
        if not self._done:
            super(FileTransferStream, self).initialize(session, direction)

    @run_in_twisted_thread
    def _NH_FileTransferHandlerDidNotInitialize(self, notification):
        del self._initialize_args
        if not self._done:
            notification.center.post_notification('MediaStreamDidNotInitialize', sender=self, data=notification.data)

    @run_in_twisted_thread
    def _NH_FileTransferHandlerError(self, notification):
        self._failure_reason = notification.data.error
        notification.center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='transferring', reason=self._failure_reason))

    def _NH_MediaStreamDidNotInitialize(self, notification):
        notification.center.remove_observer(self, sender=self.handler)

    def _NH_MediaStreamWillEnd(self, notification):
        notification.center.remove_observer(self, sender=self.handler)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        self.handler.process_chunk(chunk)

    def _handle_SEND(self, chunk):
        notification_center = NotificationCenter()
        if chunk.size == 0:
            # keep-alive
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        if self.direction=='sendonly':
            self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
            return
        if chunk.content_type.lower() == 'message/cpim':
            # In order to properly support the CPIM wrapper, msrplib needs to be refactored. -Luci
            self.msrp_session.send_report(chunk, 415, 'Invalid Content-Type')
            self._failure_reason = "CPIM wrapper is not supported"
            notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='reading', reason=self._failure_reason))
            return
        try:
            self.msrp_session.send_report(chunk, 200, 'OK')
        except Exception:
            pass    # Best effort approach: even if we couldn't send the REPORT keep writing the chunks, we might have them all -Saul
        self.handler.process_chunk(chunk)

    def _handle_FILE_OFFSET(self, chunk):
        if self.direction != 'recvonly':
            response = make_response(chunk, 413, 'Unwanted message')
            self.msrp_session.send_chunk(response)
            return
        self.handler.process_chunk(chunk)


# Screen sharing
#

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


# temporary solution. to be replaced later by a better logging system in msrplib -Dan
class NotificationProxyLogger(object):
    def __init__(self):
        from application import log
        self.level = log.level
        self.stripped_data_transactions = set()
        self.text_transactions = set()
        self.transaction_data = {}
        self.notification_center = NotificationCenter()
        self.log_settings = SIPSimpleSettings().logs

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
        if self.log_settings.trace_msrp:
            notification_data = NotificationData(direction='incoming', local_address=transport.getHost(), remote_address=transport.getPeer(), data=chunk)
            self.notification_center.post_notification('MSRPTransportTrace', sender=transport, data=notification_data)

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
        if self.log_settings.trace_msrp:
            notification_data = NotificationData(direction='outgoing', local_address=transport.getHost(), remote_address=transport.getPeer(), data=chunk)
            self.notification_center.post_notification('MSRPTransportTrace', sender=transport, data=notification_data)

    def debug(self, message, **context):
        pass

    def info(self, message, **context):
        if self.log_settings.trace_msrp:
            self.notification_center.post_notification('MSRPLibraryLog', data=NotificationData(message=message, level=self.level.INFO))
    msg = info

    def warn(self, message, **context):
        if self.log_settings.trace_msrp:
            self.notification_center.post_notification('MSRPLibraryLog', data=NotificationData(message=message, level=self.level.WARNING))

    def error(self, message, **context):
        if self.log_settings.trace_msrp:
            self.notification_center.post_notification('MSRPLibraryLog', data=NotificationData(message=message, level=self.level.ERROR))
    err = error

    def fatal(self, message, **context):
        if self.log_settings.trace_msrp:
            self.notification_center.post_notification('MSRPLibraryLog', data=NotificationData(message=message, level=self.level.CRITICAL))


# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#
# on reports
# ----------
#
# If you set Success-Report header in an outgoing chunk to 'yes', then the
# remote party is required by MSRP protocol to generate a Success report, acknowledging
# your message. Upon receiving such a report, MSRPChat will post MSRPChatDidDeliverMessage
# notification.
#
# If you set Failure-Report to 'partial' or 'yes' or leave it out completely,
# you may get either error transaction response or a failure report. Any of this will
# be converted to MSRPChatDidNotDeliverMessage.
#
# To customize the values of these headers use success_report and failure_report arguments
# of _send_raw_message.
#
# The default setting of _send_raw_message is to leave out these headers completely,
# thus enabling MSRP's default:
#   * Success-Report: no
#   * Failure-Report: yes
#
# The default setting of send_message is to enable end-to-end success reports but
# disable hop-to-hop successful confirmations:
#   * Success-Report: yes
#   * Failure-Report: partial
#
# For is-composing notification, you don't need a success report (what would you
# do with it?), however, you should receive failure notifications as their indicate
# problems with the connection. Therefore, the following settings should be used:
#   * Failure-Report: partial
#   * Success-Report: no (default)

import os
import random
from datetime import datetime
from collections import deque
from twisted.python.failure import Failure
from twisted.internet.error import ConnectionDone
from application.notification import NotificationCenter, NotificationData
from application.python.util import Singleton
from gnutls.interfaces.twisted import X509Credentials
from gnutls.crypto import X509Certificate,  X509PrivateKey
from msrplib.connect import get_acceptor, get_connector, MSRPRelaySettings
from msrplib.session import MSRPSession, contains_mime_type
from msrplib.protocol import URI, FailureReportHeader, SuccessReportHeader, parse_uri
from msrplib.trafficlog import Logger
from sipsimple.green.sessionold import make_SDPMedia
from sipsimple.cpim import MessageCPIM, MessageCPIMParser, CPIMIdentity
from sipsimple.green import callFromAnyThread, spawn_from_thread
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.util import makedirs, SilenceableWaveFile


class MSRPChatError(Exception):
    pass

class LoggerSingleton(object):

    __metaclass__ = Singleton

    def __init__(self):
        self.logger = None
        self.msrptrace_filename = None
        if SIPSimpleSettings().logging.trace_msrp:
            makedirs(SIPSimpleSettings().logging.directory.normalized)
            log_directory = SIPSimpleSettings().logging.directory.normalized
            self.msrptrace_filename = os.path.join(log_directory, 'msrp_trace.txt')
            self.logger = Logger(fileobj=file(self.msrptrace_filename, 'a+'))


NULL, INITIALIZING, INITIALIZED, STARTING, STARTED, ENDING, ENDED, ERROR = range(8)

class MSRPChat(object):

    def __init__(self, account, remote_identity, outgoing):
        """Initialize MSRPChat instance.

        - account (Account)
        - remote_identity (CPIMIdentity) - what to put in 'To' CPIM header;
        - outgoing (bool) - True for outgoing connection, False otherwise.
        """
        self.state = NULL
        self.notification_center = NotificationCenter()
        self.remote_identity = remote_identity
        self.local_identity = CPIMIdentity(account.uri, account.display_name)

        settings = SIPSimpleSettings()
        self.accept_types = list(settings.chat.accept_types)
        self.accept_wrapped_types = list(settings.chat.accept_wrapped_types)

        if (outgoing and account.msrp.use_relay_for_outbound) or (not outgoing and account.msrp.use_relay_for_inbound):
            if account.msrp.relay is None:
                relay = MSRPRelaySettings(domain=account.id.domain,
                                          username=account.id.username,
                                          password=account.password)
                self.transport = 'tls'
            else:
                relay = MSRPRelaySettings(domain=account.id.domain,
                                          username=account.id.username,
                                          password=account.password,
                                          host=account.msrp.relay.host,
                                          port=account.msrp.relay.port,
                                          use_tls=account.msrp.relay.transport=='tls')
                self.transport = account.msrp.relay.transport
        else:
            relay = None
            self.transport = settings.msrp.transport

        logger = LoggerSingleton().logger

        self.msrp_connector = get_connector(relay=relay, logger=logger) if outgoing else get_acceptor(relay=relay, logger=logger)
        self.local_media = None
        self.msrp = None ## Placeholder for the MSRPSession that will be added when started
        self.cpim_enabled = None             # Boolean value. None means it was not negotiated yet
        self.private_messages_allowed = None # Boolean value. None means it was not negotiated yet
        self.message_queue = deque() # messages stored here until the connection established

        # TODO: history
        if settings.chat.message_received_sound:
            self.message_received_sound = SilenceableWaveFile(settings.chat.message_received_sound.path.normalized, settings.chat.message_received_sound.volume)
        else:
            self.message_received_sound = None
        if settings.chat.message_sent_sound:
            self.message_sent_sound = SilenceableWaveFile(settings.chat.message_sent_sound.path.normalized, settings.chat.message_sent_sound.volume)
        else:
            self.message_sent_sound = None

    @property
    def is_active(self):
        return self.state in [STARTING, STARTED]

    @property
    def is_started(self):
        return self.state == STARTED

    def initialize(self):
        """Initialize the MSRP connection; connect to the relay if necessary.
        When done, fire MSRPChatDidInitialize (with 'sdpmedia' attribute,
        containing the appropriate 'SDPMedia' instance)
        """
        assert self.state == NULL, self.state
        spawn_from_thread(self._do_initialize)

    def _do_initialize(self):
        self.state = INITIALIZING
        try:
            settings = SIPSimpleSettings()
            local_uri = URI(host=settings.local_ip.normalized,
                            port=settings.msrp.local_port,
                            use_tls=self.transport=='tls',
                            credentials=get_X509Credentials())
            full_local_path = self.msrp_connector.prepare(local_uri)
            self.local_media = make_SDPMedia(full_local_path, self.accept_types, self.accept_wrapped_types)
        except Exception, ex:
            self.state = ERROR
            ndata = NotificationData(context='initialize', failure=Failure(), reason=str(ex))
            self.notification_center.post_notification('MSRPChatDidFail', self, ndata)
            raise
        else:
            self.state = INITIALIZED
            self.notification_center.post_notification('MSRPChatDidInitialize', self)

    def start(self, remote_media):
        """Complete the MSRP connection establishment; this includes binding the MSRP session.

        When done, fire MSRPChatDidStart. At this point each incoming message
        is posted as a notification, MSRPChatGotMessage, with the following
        attributes:
        - cpim_headers (dict); if cpim wrapper was not used, empty dict
        - message (MSRPData)
        - content (str) - the actual string that the remote user has typed
        """
        assert self.state == INITIALIZED, self.state
        spawn_from_thread(self._do_start, remote_media)

    def _do_start(self, remote_media):
        self.state = STARTING
        try:
            context = 'sdp_negotiation'
            media_attributes = dict((attr.name, attr.value) for attr in remote_media.attributes)
            remote_accept_types = media_attributes.get('accept-types')
            # TODO: update accept_types and accept_wrapped_types from remote_media
            # TODO: chatroom, recvonly/sendonly?
            self.cpim_enabled = contains_mime_type(self.accept_types, 'message/cpim')
            self.private_messages_allowed = self.cpim_enabled # and isfocus and 'private-messages' in chatroom
            remote_uri_path = media_attributes.get('path')
            if remote_uri_path is None:
                raise AttributeError("remote SDP media does not have 'path' attribute")
            full_remote_path = [parse_uri(uri) for uri in remote_uri_path.split()]
            context = 'start'
            msrp_transport = self.msrp_connector.complete(full_remote_path)
            self.msrp = MSRPSession(msrp_transport, accept_types=self.accept_types, on_incoming_cb=self._on_incoming)
        except Exception, ex:
            self.state = ERROR
            ndata = NotificationData(context=context, failure=Failure(), reason=str(ex) or type(ex).__name__)
            self.notification_center.post_notification('MSRPChatDidFail', self, ndata)
            raise
        else:
            self.state = STARTED
            self.notification_center.post_notification('MSRPChatDidStart', self)
            for send_args in self.message_queue:
                spawn_from_thread(self._send_raw_message, *send_args)
            self.message_queue.clear()
        # what if starting has failed? should I generate MSRPChatDidNotDeliver per each message?

    def end(self):
        """Close the MSRP connection or cleanup after initialize(), whatever is necessary.

        Before doing anything post MSRPChatWillEnd.
        When done, post MSRPChatDidEnd. If there was an error, post MSRPChatDidFail.
        MSRPChatDidEnd will be posted anyway.
        """
        if self.state in [ENDING, ENDED]:
            return
        spawn_from_thread(self._do_end)

    def _do_end(self):
        if self.state in [ENDING, ENDED]:
            return
        self.state = ENDING
        self.notification_center.post_notification('MSRPChatWillEnd', self)
        try:
            if self.msrp is not None:
                self.msrp.shutdown()
                self.msrp = None
            if self.msrp_connector is not None:
                self.msrp_connector.cleanup()
                self.msrp_connector = None
        finally:
            self.state = ENDED
            self.notification_center.post_notification('MSRPChatDidEnd', self)

    def _on_incoming(self, chunk=None, error=None):
        if error is not None:
            self.state = ERROR
            if isinstance(error.value, ConnectionDone):
                self.notification_center.post_notification('MSRPChatDidEnd', self)
            else:
                ndata = NotificationData(context='reading', failure=error, reason=error.getErrorMessage())
                self.notification_center.post_notification('MSRPChatDidFail', self, ndata)
        elif chunk.method=='REPORT':
            # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
            data = NotificationData(message_id=chunk.message_id, message=chunk, code=chunk.status.code, reason=chunk.status.comment)
            if chunk.status.code == 200:
                self.notification_center.post_notification('MSRPChatDidDeliverMessage', self, data)
            else:
                self.notification_center.post_notification('MSRPChatDidNotDeliverMessage', self, data)
        elif chunk.method=='SEND':
            if chunk.content_type.lower()=='message/cpim':
                cpim_headers, content = MessageCPIMParser.parse_string(chunk.data)
                content_type = cpim_headers.get('Content-Type')
            else:
                cpim_headers = {}
                content = chunk.data
                content_type = chunk.content_type
            # Note: success reports are issued by msrplib
            # TODO: check wrapped content-type and issue a report if it's invalid
            ndata = NotificationData(content=content, content_type=content_type, cpim_headers=cpim_headers, message=chunk)
            self.notification_center.post_notification('MSRPChatGotMessage', self, ndata)
            if self.message_received_sound is not None and not self.message_received_sound.is_active:
                self.message_received_sound.start(loop_count=1)

    def _on_transaction_response(self, message_id, response):
        if response.code!=200:
            data = NotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment)
            self.notification_center.post_notification('MSRPChatDidNotDeliverMessage', self, data)

    def _send_raw_message(self, message, content_type, failure_report=None, success_report=None):
        """Send raw MSRP message. For IM prefer send_message.
        If called before the connection was established, the messages will be
        queued until MSRPChatDidStart notification.

        Return generated MSRP chunk (MSRPData); to get Message-ID use its 'message_id' attribute.
        """
        if self.state!=STARTED:
            self.message_queue.append((message, content_type, failure_report, success_report))
            return
        assert self.msrp is not None, self.msrp
        if not contains_mime_type(self.accept_types, content_type):
            raise MSRPChatError('Invalid content_type for outgoing message: %r' % (content_type, ))
        message_id = '%x' % random.getrandbits(64)
        chunk = self.msrp.make_message(message, content_type=content_type, message_id=message_id)
        if failure_report is not None:
            chunk.add_header(FailureReportHeader(failure_report))
        if success_report is not None:
            chunk.add_header(SuccessReportHeader(success_report))
        if self.message_sent_sound is not None and not self.message_sent_sound.is_active:
            self.message_sent_sound.start(loop_count=1)
        callFromAnyThread(self.msrp.send_chunk, chunk, response_cb=lambda response: self._on_transaction_response(message_id, response))
        return chunk

    def send_message(self, content, content_type='text/plain', remote_identity=None, dt=None):
        """Send IM message. Prefer Message/CPIM wrapper if it is supported.
        If called before the connection was established, the messages will be
        queued until MSRPChatDidStart notification.

        - content (str) - content of the message;
        - remote_identity (CPIMIdentity) - "To" header of CPIM wrapper;
          if None, use the default supplied in __init__
          'remote_identity' may only differ from the one supplied in __init__ if the remote
          party supports private messages. If it does not, MSRPChatError will be raised;
        - content_type (str) - Content-Type of wrapped message;
          (Content-Type of MSRP message is always Message/CPIM in that case)
          If Message/CPIM is not supported, Content-Type of MSRP message.

        Return generated MSRP chunk (MSRPData); to get Message-ID use its 'message_id' attribute.

        These MSRP headers are used to enable end-to-end success reports and
        to disable hop-to-hop successful responses:
        Failure-Report: partial
        Success-Report: yes
        """
        if self.cpim_enabled:
            if remote_identity is None:
                remote_identity = self.remote_identity
            elif not self.private_messages_allowed and remote_identity != self.remote_identity:
                raise MSRPChatError('The remote end does not support private messages')
            if dt is None:
                dt = datetime.utcnow()
            msg = MessageCPIM(content, content_type, from_=self.local_identity, to=remote_identity, datetime=dt)
            return self._send_raw_message(str(msg), 'message/cpim', failure_report='partial', success_report='yes')
        else:
            if remote_identity is not None and remote_identity != self.remote_identity:
                raise MSRPChatError('Private messages are not available, because CPIM wrapper is not used')
            return self._send_raw_message(content, content_type)


def get_X509Credentials():
    settings = SIPSimpleSettings()
    if settings.tls.certificate_file is not None:
        cert = X509Certificate(file(settings.tls.certificate_file.normalized).read())
    else:
        cert = None
    if settings.tls.private_key_file is not None:
        key = X509PrivateKey(file(settings.tls.private_key_file.normalized).read())
    else:
        key = None
    cred = X509Credentials(cert, key)
    cred.verify_peer = settings.tls.verify_server
    return cred


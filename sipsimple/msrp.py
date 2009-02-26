"""

on reports
----------

If you set Success-Report header in an outgoing chunk to 'yes', then the
remote party is required by MSRP protocol to generate a Success report, acknowledging
your message. Upon receiving such a report, MSRPChat will post MSRPChatDidDeliverMessage
notification.

If you set Failure-Report to 'partial' or 'yes' or leave it out completely,
you may get either error transaction response or a failure report. Any of this will
be converted to MSRPChatDidNotDeliverMessage.

To customize the values of these headers use success_report and failure_report arguments
of the send_message or send_raw_message.

The default setting of send_raw_message is to leave out these headers completely,
thus enabling MSRP's default:
  * Success-Report: no
  * Failure-Report: yes

The default setting of send_message is to enable end-to-end success reports but
disable hop-to-hop successful confirmations:
  * Success-Report: yes
  * Failure-Report: partial

For is-composing notification, you don't need a success report (what would you
do with it?), however, you should receive failure notifications as their indicate
problems with the connection. Therefore, the following settings should be used:
  * Failure-Report: partial
  * Success-Report: no (default)
"""

import random
from datetime import datetime
from application.notification import NotificationCenter, NotificationData
from msrplib.connect import MSRPRelaySettings, get_acceptor, get_connector
from msrplib.session import MSRPSession, contains_mime_type
from msrplib.protocol import URI, FailureReportHeader, SuccessReportHeader, parse_uri
from sipsimple.green.session import make_SDPMedia
from sipsimple.clients.cpim import MessageCPIM, MessageCPIMParser
from sipsimple.eventletutil import spawn_from_thread


class MSRPChatError(Exception):
    pass


class MSRPChat(object):

    def __init__(self, from_uri, to_uri, outgoing, relay=None, accept_types=['message/cpim', 'text/*'], accept_wrapped_types=['*']):
        """Initialize MSRPChat instance.

        - outgoing (bool) - whether you are an active endpoint or not;
        - relay (MSRPRelaySettings) - if None, no relay is used;
        - from_uri (SIPURI) - what to put in 'From' CPIM header;
        - to_uri (SIPURI) - what to put in 'To' CPIM header;
        - accept_types (list of strings) - to put in SDP media;
          MSRP transport will reject incoming chunks with an invalid media type;
        - accept_wrapped_types (list of strings) - to put in SDP media;
          is not enforced by the transport.
        """
        self.notification_center = NotificationCenter()
        self.from_uri = from_uri
        self.to_uri = to_uri
        self.outgoing = outgoing
        self.accept_types = accept_types
        self.accept_wrapped_types = accept_wrapped_types
        self._message_received_sound = None
        self._message_sent_sound = None
        self._sound_level = 20
        if outgoing:
            self.msrp_connector = get_connector(relay, accept_types=accept_types, accept_wrapped_types=accept_wrapped_types)
        else:
            self.msrp_connector = get_acceptor(relay, accept_types=accept_types, accept_wrapped_types=accept_wrapped_types)
        self.cpim_enabled = None
        self.private_messages_allowed = None

    def initialize(self, ip=None, port=None, use_tls=True):
        """Initialize the MSRP connection; connect to the relay if necessary.
        When done, fire MSRPChatDidInitialize (with 'sdpmedia' attribute,
        containing the appropriate 'SDPMedia' instance)
        """
        local_uri = URI(host=ip, port=port, use_tls=use_tls)
        spawn_from_thread(self.msrp_connector.prepare, local_uri, on_success=self._on_initialize_succeed, on_failure=self._on_initialize_failed)

    # NOTE: _on_* functions will be called in a foreign thread

    def _on_initialize_succeed(self, full_local_path):
        self.local_media = make_SDPMedia(full_local_path, self.accept_types, self.accept_wrapped_types)
        self.notification_center.post_notification('MSRPChatDidInitialize', self)

    def _on_initialize_failed(self, reason):
        self._post_failure('initialize', reason)

    def _post_failure(self, context, reason):
        self.notification_center.post_notification('MSRPChatDidFail', self, NotificationData(context=context, reason=reason))

    def start(self, remote_media):
        """Complete the MSRP connection establishment; this includes binding
        MSRP session.

        When done, fire MSRPChatDidStart. At this point each incoming message
        is posted as a notification, MSRPChatGotMessage, with the following
        attributes:
        - cpim_headers (dict); if cpim wrapper was not used, empty dict
        - msrpdata (MSRPData)
        - content (str) - the actual string that the remote user has typed
        """
        full_remote_path = None
        attrs = dict((attr.name, attr.value)for attr in remote_media.attributes)
        remote_uri_path = attrs.get('path')
        # TODO: update accept_types and accept_wrapped_types from remote_media
        # TODO: chatroom, recvonly/sendonly?
        self.cpim_enabled = contains_mime_type(self.accept_types, 'message/cpim')
        self.private_messages_allowed = self.cpim_enabled # and isfocus and 'private-messages' in chatroom
        if remote_uri_path is None:
            self._post_failure('sdp_negotiation', Exception('remote SDP media does not have "path" attribute'))
        else:
            full_remote_path = [parse_uri(uri) for uri in remote_uri_path]
            spawn_from_thread(self.msrp_connector.complete, full_remote_path,
                              on_success=self._on_start_succeed, on_failure=self._on_start_failed)

    def _on_start_succeed(self, msrptransport):
        self.msrp = MSRPSession(msrptransport, accept_types=self.accept_types, on_incoming_cb=self._on_incoming)
        self.notification_center.post_notification('MSRPChatDidStart', self)

    def _on_start_failed(self, reason):
        self.msrp_connector.cleanup()
        self._post_failure('start', reason)

    def end(self):
        """Close the MSRP connection or cleanup after initialize(), whatever is necessary.

        Before doing anything post MSRPChatWillEnd.
        After end is complete, post MSRPChatDidEnd. If there was an error during closure
        procedure, post MSRPChatDidFail first (MSRPChatDidEnd will be posted anyway).
        """
        self.notification_center.post_notification('MSRPChatWillEnd', self)
        if hasattr(self, 'msrp'):
            spawn_from_thread(self.msrp.shutdown, on_success=self._post_did_end, on_failure=self._post_did_end_fail)
        else:
            spawn_from_thread(self.msrp_connector.cleanup, on_success=self._post_did_end, on_failure=self._post_did_end_fail)

    def _post_did_end(self, _result):
        self.notification_center.post_notification('MSRPChatDidEnd', self)

    def _post_did_end_fail(self, reason):
        self.notification_center.post_notification('MSRPChatDidFail', self, reason)
        self.notification_center.post_notification('MSRPChatDidEnd', self)

    def _send_raw_message(self, message, content_type, failure_report=None, success_report=None):
        """Send raw MSRP message. For IM prefer send_message.

        Return Message-ID (str), unique string identifying the message.
        """
        if not contains_mime_type(self.accept_types, content_type):
            raise MSRPChatError('Invalid content_type for outgoing message: %r' % (content_type, ))
        message_id = '%x' % random.getrandbits(64)
        chunk = self.msrp.make_message(message, content_type=content_type, message_id=message_id)
        if failure_report is not None:
            chunk.add_header(FailureReportHeader(failure_report))
        if success_report is not None:
            chunk.add_header(SuccessReportHeader(success_report))
        from twisted.internet import reactor
        reactor.callFromThread(self.msrp.send_chunk, chunk, response_cb=self._on_transaction_response)
        return message_id

    def _on_transaction_response(self, response):
        if response.code!=200:
            self.notification_center.post_notification('MSRPChatDidNotDeliverMessage', self, NotificationData(msrpdata=response))

    def _on_incoming(self, chunk=None, error=None):
        if error is not None:
            self._post_failure('reading', error)
        if chunk.method=='REPORT':
            # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to
            # the part of the message.
            if chunk.status.code == 200:
                self.notification_center.post_notification('MSRPChatDidDeliverMessage', self, NotificationData(msrpdata=chunk))
            else:
                self.notification_center.post_notification('MSRPChatDidNotDeliverMessage', self, NotificationData(msrpdata=chunk))
        elif chunk.method=='SEND':
            if chunk.content_type.lower()=='message/cpim':
                cpim_headers, content = MessageCPIMParser.parse_string(chunk.data)
            else:
                cpim_headers = {}
                content = chunk.data
            # TODO: issue a success report if needed
            # TODO: check wrapped content-type and issue a report if it's invalid
            ndata = NotificationData(cpim_headers=cpim_headers, msrpdata=chunk, content=content)
            self.notification_center.post_notification('MSRPChatGotMessage', self, ndata)

    def send_message(self, content, content_type='text/plain', to_uri=None):
        """Send IM message. Prefer Message/CPIM wrapper if it is supported.
        If called before the connection was established, the messages will be
        queued until MSRPChatDidStart notification. (TODO)

        - content (str) - content of the message;
        - to_uri (SIPURI) - "To" header of CPIM wrapper;
          if None, use the default supplied in __init__
          'to_uri' may only differ from the one supplied in __init__ if the remote
          party supports private messages. If it does not, MSRPChatError will be raised;
        - content_type (str) - Content-Type of wrapped message;
          (Content-Type of MSRP message is always Message/CPIM in that case)
          If Message/CPIM is not supported, Content-Type of MSRP message.

        Return Message-ID (str), unique string identifying the message.

        These MSRP headers are used to enable end-to-end success reports and
        to disable hop-to-hop successful responses:
        Failure-Report: partial
        Success-Report: yes
        """
        if self.cpim_enabled:
            if to_uri is None:
                to_uri = self.to_uri
            elif self.private_messages_allowed and to_uri != self.to_uri:
                raise MSRPChatError('The remote end does not support private messages')
            msg = MessageCPIM(content, content_type, from_=self.from_uri, to=to_uri, datetime=datetime.now())
            return self._send_raw_message(str(msg), 'message/cpim', failure_report='partial', success_report='yes')
        else:
            if to_uri is not None and to_uri != self.to_uri:
                raise MSRPChatError('Private messages are not available, because CPIM wrapper is not used')
            return self._send_raw_message(content, content_type)
